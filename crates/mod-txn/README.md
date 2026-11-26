# mod-txn

Stateful [transaction](../../docs/glossary.md#transaction) handling with
[forking](../../docs/glossary.md#forking). Use it whenever the proxy should
follow a request to the end: retransmit it over UDP, ring several targets,
pick the best reply, or try again after a failure. It is a port of
[Kamailio](../../docs/glossary.md#kamailio)'s [`tm`](../../docs/glossary.md#tm)
module. It implements RFC 3261 §16 (proxy behaviour), §17 (transactions)
and §9.1 ([CANCEL](../../docs/glossary.md#cancel)).

How it works in short:

- `t_relay()` creates a server transaction with one client
  [branch](../../docs/glossary.md#branch) per target.
- tm aggregates the responses as in §16.7.
- tm runs the timers and [retransmissions](../../docs/glossary.md#retransmission).
- tm runs the script's [`failure_route`](../../docs/glossary.md#failure-route),
  [`onreply_route`](../../docs/glossary.md#onreply-route) and
  [`branch_route`](../../docs/glossary.md#branch-route).

In ferrosip, tm also resolves the next hop
([RFC 3263](../../docs/glossary.md#dns-resolution) NAPTR/SRV/A with DNS
failover). It also feeds the
[destination blocklist](../../docs/glossary.md#destination-blocklist). In
Kamailio these two are core features.

Other modules use tm through its API (`Registry::api::<Tm>()`):

- `t_uac` sends requests that ferrosip makes itself: dialog BYEs, REFERs and
  `dlg_bridge` INVITEs, keep-alive probes, NOTIFYs, and `t_uac_send`.
- Hooks on replies sent upstream are used by dialog and acc.
- Hooks on requests that get a transaction are used by dialog's `dlg_flag`.
  This is Kamailio's TMCB_REQUEST_IN.
- [Suspend and resume](../../docs/glossary.md#suspend-and-resume) is used by
  `async` and `http_async_client`.
- Adding branches to a running transaction is used by `tsilo`.

The tmx functions (`t_is_failure_route()` and others) are in `mod-extra`.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `txn` | `tm` (+ core DNS / `dst_blocklist` settings, `tmx` `t_uac_send`) | `t_relay()`, forking, CANCEL, timers, failure/reply/branch routes, suspend/continue, serial forking from the script |

## Quick start

[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml). `txn` is tm's
ferrosip name. Durations are typed:

```toml
[modules.txn]
fr_timer = "5s"         # no provisional within this: 408
fr_inv_timer = "60s"    # an INVITE branch must be answered within this
fork_by_q = true        # serial forking by q-groups
```

The routing ([`.fsr`](../../docs/glossary.md#fsr)):

```rust
import location

route main(msg: Request) {
    if msg.method == REGISTER {
        location.save(msg)
    }
    guard location.lookup() else reply(NotFound, "Not Found")

    let res = await txn.relay(msg)       // t_relay() + failure_route
    match res {
        // all branches failed (no 2xx)
        Timeout => {                     // our own 408 (t_branch_timeout())
            msg.headers["X-Reason"] = "no-answer"
            voicemail(msg)
        }
        Final(r) if r.code == BusyHere || r.code == RequestTimeout => voicemail(msg)
        Final(r) => forward(r)           // the best reply goes upstream
    }
}

fn voicemail(msg: Request) -> Action {
    msg.ruri = "sip:vm@10.0.0.9"
    relay(msg)                           // new branch, same transaction
}

on reply(r: Reply) {
    if r.code == SessionProgress {
        drop                             // drop a provisional
    }
    r.headers.remove("X-Internal")
}
```

How the `.cfg` functions map to `.fsr`:

- `t_relay()` is `relay(msg)` or `txn.relay()`.
- `t_on_failure()` + `failure_route` are `await txn.relay(msg)` and the code
  after it. The result is `Final(r)` or `Timeout`. See
  [await](../../docs/glossary.md#await).
- `on reply` is the global [`reply_route`](../../docs/glossary.md#reply-route).
  The per-transaction `t_on_reply()` and `t_on_branch()` (branch routes)
  have no `.fsr` form.
- `t_set_fr()` is `txn.set_timeout()`. `t_load_contacts()` /
  `t_next_contacts()` are `txn.load_contacts()` / `txn.next_contacts()`.
- `t_suspend()` / `t_continue()` are replaced by `await`.

The full list is in `docs/functions-reference.md` (section `txn`).

## Parameters

Times are in milliseconds unless noted. These are the `.cfg`
[`modparam`](../../docs/glossary.md#modparam) values. In `[modules.txn]` they
are durations (`"5s"`, `"500ms"`). `ferrosip schema tm` lists the TOML types.

| Name | Default | Description |
|---|---|---|
| `fr_timer` | 30000 | [Final response timer](../../docs/glossary.md#final-response-timer) per branch: time allowed without a provisional (non-INVITE: without a final). Minimum 100. |
| `fr_inv_timer` | 120000 | INVITE branches that got a provisional must get a final within this time. It counts from when the branch was sent. Minimum 100. |
| `wait_timer` | 5000 | How long a completed transaction is kept to absorb retransmissions. Minimum 100. |
| `retr_timer1` | 500 | T1: the first UDP retransmission interval. Minimum 10. |
| `retr_timer2` | 4000 | T2: the cap on the retransmission interval for non-INVITE requests and CANCELs. Minimum 10. |
| `fork_by_q` | 0 | 1: serial forking. Branches are sent in groups of descending [q](../../docs/glossary.md#q-value). Equal q are sent in parallel. |
| `max_branches` | 12 | Branches per transaction (1..30), over all failure rounds, DNS failover and `t_suspend()` included (each takes one, as Kamailio's blind UAC). A relay's targets beyond it are dropped. A failure route's `t_relay()` that has no branch left fails with `500 Forking capacity exceeded (12/TM)`. In Kamailio this is the core `max_branches`, and the core parameter `max_branches=N` in a `.cfg` sets it too (the importer writes it here). It also limits the destination set to `max_branches - 1` entries (see `append_branch()`). |
| `failure_reply_mode` | 3 | Which earlier replies stop competing for the final when a failure route ends. 0: none. 1: all. 2: those of the last relay. 3: all, if the route added branches. If replies were dropped and the route added no branch and didn't reply, the caller gets a 500 (the route's relay error, else `I'm terribly sorry, server error occurred (1/TM)`). `t_drop_replies()` sets it for one round. |
| `contacts_avp` | `tm_contacts` | [XAVP](../../docs/glossary.md#xavp) used by `t_load_contacts()` / `t_next_contacts()`. `$xavp(name)` is accepted too. |
| `contact_flows_avp` | `tm_contact_flows` | XAVP holding the extra RFC 5626 flows for `t_next_contact_flow()`. |
| `use_dns_failover` | 0 | On a 503, a timeout or a send failure, retry the branch at the next address of the same DNS name. |
| `dns_server` | first `nameserver` in `/etc/resolv.conf` | `ip[:port]` of the DNS server. |
| `dns_try_naptr` | 0 | Try NAPTR before SRV, when the URI has neither a port nor a transport. |
| `dns_srv_lookup` | 1 | Do SRV lookups. |
| `dns_srv_lb` | 0 | Weighted random order among SRV records of the same priority. Otherwise the heaviest goes first. |
| `dns_timeout` | 1000 | DNS query timeout (minimum 50). |
| `dns_cache_negative_ttl` | 60 | Seconds a failed lookup is cached. |
| `use_dst_blocklist` | 0 | Block next hops that failed to send or never answered. |
| `dst_blocklist_expire` | 60 | Seconds a hop stays blocked. |
| `blst_503` | 0 | Also block a hop that answered 503, for its Retry-After. |
| `blst_503_def_timeout` | 0 | Seconds to block a 503 without Retry-After (0 = don't). |

The DNS and blocklist settings apply to the whole process. In Kamailio they
are core parameters. An unknown parameter is a config error.

## Functions

| Function | Description |
|---|---|
| `t_relay()` | Relays the request statefully. The main branch goes to `$du` if set, else to the [R-URI](../../docs/glossary.md#r-uri), resolved per RFC 3263. Every [destination-set](../../docs/glossary.md#destination-set) entry (`append_branch()`, `lookup()` with `append_branches`) gets a branch too. See the return codes below. |
| `t_relay("proto:host:port")` | Same, but the main branch goes to this fixed next hop (`udp`, `tcp`, `tls`, `ws`, `wss`). The name is resolved once at startup. |
| `t_on_failure("name")` | Arms `failure_route[name]` for the transaction. |
| `t_on_reply("name")` | Arms `onreply_route[name]` for the transaction's replies. |
| `t_on_branch("name")` | Arms `branch_route[name]`, which runs for each branch before it is sent. |
| `t_check_status("regex")` | Matches the status code against an anchored regex (`"486\|408\|5[0-9][0-9]"`). In a failure_route this is the winning reply. In a reply route it is the current reply. 1 on match, else -1. |
| `t_branch_timeout()` | In a failure_route: 1 if the winning reply is our own 408 (no final in time), else -1. |
| `t_drop_replies([mode])` | In a failure_route: this round's `failure_reply_mode`. No mode: 1 (drop all), `"l"`: 2 (the last relay's), `"n"`: 0 (none). It applies when the route ends, so `t_check_status()` still sees the replies. |
| `t_reply(code, reason)` | Final reply 200–699. In a failure_route or a resumed request it answers the transaction: it is its only final, and the best reply is not relayed after the route. Elsewhere it sends a stateless reply, which after a failed `t_relay()` replaces tm's error reply (see the return codes). `reason` may contain variables. -1 if the transaction already has its final. |
| `t_reply_error()` | `t_reply()` with the error of the last failed function, in tm's words (Kamailio `tm.c` `ki_t_reply_error()`): `500 Forking capacity exceeded (12/TM)`, `477 … (477/TM)`, and with no error `500 I'm terribly sorry, server error occurred (1/TM)`. -2 after an `sl_send_reply()` final. |
| `t_set_fr(fr_inv[, fr])` | Per-transaction `fr_inv_timer` and `fr_timer` (ms) for the following `t_relay()`. 0 keeps the default. |
| `t_load_contacts([mode])` | Puts the R-URI and destination set into the `contacts_avp` XAVP, in the order they will be tried. Then it clears the destination set (tm `t_serial.c`). Each item has `uri`, `dst_uri`, `path`, `instance` and `q_flag`. `q_flag` is 1 where a group of parallel branches ends. Items also have ferrosip's `q` (when given) and `reg_id`. A contact without q counts as -1 (Kamailio's unspecified q), below q=0. **Mode 0** (standard, the default): highest q first. Equal q form one group, which is forked in parallel. **Mode 1** (proportional): first the contacts with q > 0, one at a time (serial forking). Their order is random: a contact comes next with probability q / (sum of the remaining q). Then the contacts with q = 0 or none, one at a time, in their order. If one `+sip.instance` has several RFC 5626 flows (reg-ids), only the first is kept. The rest wait in `contact_flows_avp` for `t_next_contact_flow()`. Does nothing if there is one target. Another mode is a config error. Returns 1. |
| `t_next_contacts()` | Makes the next group of the XAVP the R-URI and destination set. A group runs up to the item with `q_flag` = 1. Items without `q_flag` (an XAVP the script built) are grouped by equal q. 1 if loaded, -2 if nothing is left. Use it in `request_route`, and again in a `failure_route` before `t_relay()`. |
| `t_next_contact_flow()` | In a failure_route (e.g. after `430 Flow Failed`): the next flow of the instance becomes the R-URI. 1 if loaded, -1 if none is left. See [SIP Outbound](../../docs/glossary.md#sip-outbound). |
| `t_forward_nonack([ip, port])` | Forwards a request statefully in its transaction, like `t_relay()`, but refuses an ACK (-1, with a warning). As in Kamailio, the transaction must exist: call `t_newtran()` first, or use it in a failure_route. Without one it returns -1. Without arguments it sends to `$du` or the R-URI. With `ip, port` it sends there over UDP. Return codes are as for `t_relay()`. Unlike `t_relay()`, a failure is not answered (Kamailio's `t_forward_nonack()` doesn't): the script answers it, with `t_reply_error()` for instance. |
| `t_forward_nonack_udp(ip, port)`, `_tcp`, `_tls` | The same over this transport. `t_forward_nonack_sctp()` is a config error (no SCTP). |
| `t_lookup_request()` | 1 if the request belongs to an existing transaction, else -1. That is a retransmission, or an ACK for a negative final that tm sent. Unlike `t_check_trans()` it sends nothing and doesn't stop the script. |
| `t_save_lumps()` | Use it after `t_newtran()` or in a resumed request. The script's edits so far (`append_hdr()`, `remove_hdr()`, …, `record_route()` too) become the request that failure_route and `await` start from. So their new branches carry these edits. Later edits don't count. Without this call, tm takes the edits at the first relay (Kamailio's `save_msg_lumps()`). So `t_save_lumps()` only matters for edits made between it and `t_relay()`. Once the edits are taken, and in a failure_route, it does nothing (1). -1 without a transaction. See [lumps](../../docs/glossary.md#lumps). |
| `t_newtran()` | Creates the request's transaction now, before slow work in the route such as a database lookup or a blocking call. From then on retransmissions are absorbed, and INVITEs get `100 Trying`. `t_relay()` adds branches to it. `t_suspend()` and `await` park it. Any reply, `sl_send_reply()` included, becomes its reply, and is sent again to retransmissions. If nothing relays or answers it within `fr_timer` (`fr_inv_timer` for INVITE), it is answered 500. Returns 1 on success, or if it already exists for this request. 0 for a retransmission (the script stops). -1 for ACK, CANCEL or in a branch route. |
| `t_suspend()` | Parks the request in a transaction without branches. INVITEs get `100 Trying`, retransmissions are absorbed, and a CANCEL gets 487. If nothing resumes it within `fr_timer` (`fr_inv_timer` for INVITE), it is answered `500 Server Internal Error - Suspended Too Long`. Sets `$T(id_index)` / `$T(id_label)`. Returns 1 on success. 0 for a retransmission of a parked request (the script stops). -1 where it can't suspend: in a failure or branch route, for ACK or CANCEL, or with no Via branch. |
| `t_continue(index, label, "route")` | Resumes a parked transaction by running `route[route]` on it. In that route, `t_relay()` forks on the parked transaction, and `t_reply()` or a stateless reply answers it. Arguments may be variables. 1 if resumed. -1 if the transaction is gone, answered or CANCELed. |
| `t_uac_send(method, ruri, nexthop, socket, headers, body)` | Sends a request of our own (tmx). `nexthop` may be empty, and then the R-URI is resolved. `socket` is ignored. `headers` are CRLF-terminated lines. INVITE, ACK and CANCEL are refused. 1 if sent, -1 on error. |
| `t_stats()` | Prints the number of active transactions to stderr. Returns 1. |

### t_relay() return codes

See the [return code convention](../../docs/glossary.md#return-code-convention).

| Code | When |
|---|---|
| 1 | Relayed. For an ACK to a 2xx: forwarded statelessly. |
| 0 | Handled without relaying, and the script stops (as with Kamailio's 0). This happens for a retransmission (answered with the last reply), for an ACK for a non-2xx that tm already ACKed, and for a CANCEL (answered 200, or 481 if no INVITE transaction matches). |
| -1 | Failed: 400 bad Via or no Via branch (left for `sl_reply_error()`), `478 Unresolvable destination (478/TM)`, or `477 Unfortunately error on sending to next hop occurred (477/TM)` when nothing could be sent (all next hops blocklisted included). In a failure_route: `500 Forking capacity exceeded (12/TM)` (no branch left under `max_branches`), or the transaction was already answered. tm's errors are Kamailio's (core `error.c` `err2reason_phrase()`, as tm's `kill_transaction()` answers): the code, then the text with `(<errno>/TM)`. |

**A relay that fails in request_route is answered by tm.** As in Kamailio
(tm's `delayed_reply`, default on: `t_funcs.c` `t_relay_to()`,
`t_lookup.c` `t_unref()`), the 478 / 477 / 500 above goes out when the
script ends (an INVITE has its `100 Trying` first), unless the script
answered through tm before: `t_reply()`, `send_reply()` or
`t_reply_error()`. `sl_reply_error()` and `send_reply_error()` send nothing
meanwhile (Kamailio's `FL_DELAYED_REPLY`). So the stock
`if (!t_relay()) { sl_reply_error(); }` puts one final on the wire, tm's,
and so does a bare `t_relay()`. `sl_send_reply()` is stateless and doesn't
count: tm's error reply follows it, as in Kamailio. The same holds for
`t_relay_to_*()` and `t_relay_await()` (`.fsr`'s `await txn.relay` that
fails at once), not for `t_forward_nonack()`, nor in a failure_route. If a
later `t_relay()` in the same script succeeds, the error reply still goes
out when the script ends and its branches are canceled, as in Kamailio.
Without a transaction kept for it, the reply is not retransmitted and a
retransmitted request runs the script again.

## Pseudo-variables

| Variable | Description |
|---|---|
| `$T_reply_code` | In a failure_route, the winning reply's status. In a reply route, the reply's status. In `event_route[tm:local-response]`, the local reply's status. Otherwise `$null`. |
| `$T_branch_idx` | Index of the branch in `branch_route` and `onreply_route`. |
| `$T(id_index)`, `$T(id_label)` | Handle of the transaction parked by `t_suspend()`, for `t_continue()`. |

## RPC commands

| Command | Description |
|---|---|
| `tm.stats` | All `tm:` statistics, plus `current` (transactions), `branch_index` (branch → transaction entries) and `handles` (parked transactions). |
| `dns.lookup <uri>` | The next hops a SIP URI resolves to (RFC 3263). |
| `dns.flush` | Clears the DNS cache and tm's resolution cache. |
| `dst_blocklist.list` | Blocked destinations, with the seconds left. |
| `dst_blocklist.add <uri\|proto:ip:port> [secs]` | Blocks a destination. |
| `dst_blocklist.del <uri\|proto:ip:port>` | Unblocks one. |
| `dst_blocklist.flush` | Empties the blocklist. |

## Statistics

The names are Kamailio's. The `tm:2xx`…`tm:6xx` counters count
[final replies](../../docs/glossary.md#final-reply) sent upstream or to a
local request's callback. `rpl_sent` counts every reply sent upstream.

| Name | Kind | Meaning |
|---|---|---|
| `tm:total` | counter | Transactions created by `t_relay()` / `t_suspend()` |
| `tm:total_local` | counter | Requests sent by ferrosip itself (`t_uac`) |
| `tm:rpl_received` | counter | Replies received |
| `tm:rpl_sent` | counter | Replies sent upstream |
| `tm:rpl_generated` | counter | Replies generated by tm (408, 477, 487, 500…) |
| `tm:2xx` … `tm:6xx` | counter | Finals by class |
| `tm:current` | gauge | Transactions in the table |
| `tm:retransmissions` | counter | Requests resent by the retransmission timer (UDP) |
| `tm:timeouts` | counter | Branches that got no final in time (local 408) |

## Behaviour notes

- **One final per request.** Sometimes every branch fails to send. Then the
  relay claims the transaction under its lock before it returns −1, and tm
  answers 477 when the script ends. A reader thread may already have
  answered 477 for a connection that failed at once. In that case the relay
  succeeds (1) and nothing else is sent.
- **Graceful shutdown.** `busy()` reports the transactions still waiting for
  their final reply. `main` waits for them, up to `--shutdown-timeout`. See
  [graceful shutdown](../../docs/glossary.md#graceful-shutdown).
- **Panics.** Each timer command runs inside `sip_core::panic::catch`. So a
  bug in one transaction's timer can't stop the timers of every other
  transaction.
- **Shared buffers.** Replies, transaction keys and timer ids are shared
  (`Arc`) or moved rather than copied (allocations per request: `bench/BASELINE.md`).

**Transactions and matching**

- A server transaction is keyed by the top [Via](../../docs/glossary.md#via)
  `branch` plus the method. Requests without a Via branch (RFC 2543) are
  refused. A CANCEL matches the INVITE with the same branch.
- Replies are matched by the Via
  [branch parameter](../../docs/glossary.md#branch-parameter) that tm
  generated for the branch (`z9hG4bKfs.…`). Replies that match no
  transaction are dropped. They are not forwarded statelessly.
- One transaction holds all its branches under one shard lock. A reply or a
  timer can cause forwarding, CANCELs, the next q-group and new timers. All of
  this is decided under the lock and sent after the lock is released. The
  transaction is published before the first send. So a reply handled by
  another thread can always find it.

**Forking and response aggregation (§16.7)**

- There is one branch per target. The R-URI (or the fixed `t_relay`
  destination) goes first, then the destination set, up to `max_branches`.
  Each branch gets its own R-URI and Via branch. It gets a
  [Record-Route](../../docs/glossary.md#record-route)/[Path](../../docs/glossary.md#path)
  rendered for its transport, and the contact's Path as Route.
- 1xx replies other than 100 are forwarded at once. So is every 2xx to an
  INVITE, because each 2xx may be a separate [dialog](../../docs/glossary.md#dialog).
  For other methods only the first 2xx goes upstream.
- The first 2xx or any 6xx CANCELs the other branches.
- Otherwise, once all branches are final, the best response goes upstream:
  - a 6xx, else the lowest class;
  - within 4xx, 401/407/415/420/484 come first;
  - a received reply beats our own 408/477 of the same rank;
  - a chosen 503 is not forwarded: as in Kamailio (`t_reply.c`
    `relay_reply()`, `remap_503_500`), tm answers with its own
    `500 Service Unavailable`, built from the request (none of the 503's
    headers, such as Retry-After, and tm's To-tag). A `t_uac` request
    gets the 503 itself;
  - if the winner is a 401/407, the
    [challenges](../../docs/glossary.md#challenge) of all 401/407 branches
    are merged into it.
- INVITEs get `100 Trying` at once. Non-2xx finals are
  [ACKed](../../docs/glossary.md#ack) hop by hop. The same ACK is resent for
  retransmitted finals. ACKs for 2xx are forwarded statelessly (end to end).
- A retransmitted request is answered with the last reply. It is not
  forwarded again.
- With `fork_by_q`, the next q-group starts when every branch of the current
  one has failed. A 2xx, a 6xx or an upstream CANCEL stops serial forking.

**Timers**

There is one `tm-timer` thread with a 20 ms timer wheel. Workers queue
timers in per-worker inboxes. So the timer thread is never woken for each
transaction.

- UDP retransmission starts at T1. INVITE branches double the interval until
  they get a provisional. Non-INVITE branches double it, up to T2, until they
  get a final.
- `fr_timer` starts when a branch is sent. When it fires, an INVITE branch
  that has received a provisional may run on until `fr_inv_timer` after
  sending. Otherwise the branch gets a local 408. A ringing INVITE branch is
  also CANCELed.
- `wait_timer` keeps the completed transaction. Then it is deleted.
- An outbound TCP/TLS connection may never come up: refused, TLS failure, or
  connect timeout. Then its waiting branches fail at once with 477, instead
  of a later 408.

**CANCEL (§9.1)**

- An upstream CANCEL is answered 200 and fanned out. A branch without a
  [provisional reply](../../docs/glossary.md#provisional-reply) gets its
  CANCEL as soon as one arrives. Pending q-groups are dropped.
- tm's CANCEL is a client transaction of its own. It is retransmitted over
  UDP (T1 doubling, capped at T2) until answered. After 64·T1 without a
  final, the branch is given up as a local 408. A canceled INVITE then
  answers 487 upstream.
- Replies to our CANCEL (same Via branch, CSeq method CANCEL) are absorbed.
  They are not taken for the INVITE's final.

**Script routes**

- `failure_route` runs when the transaction would send a final ≥ 300
  upstream and a route is armed. It does not run after the caller CANCELed.
  - It runs on a context rebuilt from the original request (Kamailio's
    "faked" request), with the transaction's AVPs and flags.
  - There, `t_relay()` adds branches to the same transaction, up to
    `max_branches` in all.
  - `t_reply()` answers, and `t_on_failure()` re-arms the route for another
    round. `send_reply()`, `send_reply_error()` and `t_reply_error()`
    answer through the transaction too (Kamailio's sl calls tm's `t_reply`
    when a transaction exists, `sl.c` `send_reply()`). That reply is the
    transaction's only final: the best reply is not relayed after it.
  - `sl_send_reply()` and `sl_reply_error()` are request_route functions,
    as in Kamailio: in a failure_route block they are a config error. In a
    `route[…]` a failure route calls, they reply statelessly, and the best
    reply still goes upstream after the route: two finals, as in Kamailio.
  - If the route neither relays nor replies, the best reply goes upstream.
  - When the route ends, `failure_reply_mode` (or `t_drop_replies()`)
    decides which earlier replies still compete with those of the new
    branches. With the default 3, a route that adds branches drops them
    all: the caller gets the best reply of the new branches only.
- `onreply_route` runs for each reply of the transaction before tm processes
  it, after the global `reply_route`. It can edit the reply or `drop` a
  provisional. Finals can't be dropped.
- `branch_route` runs once per branch before it is sent. It can change
  `$ru` / `$du`, and the branch is then re-resolved. It can change headers,
  or `drop` the branch.
- `event_route[tm:local-request]` runs on every request that tm sends of its
  own through `t_uac`, before it is sent. These are `t_uac_send()`, dialog's
  BYEs and keep-alives, presence NOTIFYs, uac's requests, and the ACK for a
  2xx that a module sends with `send_stateless`.
  - Header and body edits (`append_hdr()`, `remove_hdr()`, …) are applied.
    R-URI and `$du` changes are not.
  - `drop` stops the request, and the function that sent it fails.
  - A request sent from inside the route doesn't run it again.
  - Hop-by-hop CANCELs and ACKs for negative finals don't run it.
- `event_route[tm:local-response]` runs after tm sent upstream a final reply
  that it made itself: `t_reply()`, a 408 on timeout, a 487 after CANCEL,
  477, or 500 for a parked request.
  - As in Kamailio (`t_reply.c` `_reply_light()`), the route's message is
    that reply (`$rs`, `$rr`, its headers), with the transaction's AVPs.
    `$T_reply_code` is its status too.
  - It can't change the reply.
  - It doesn't run for provisional replies (Kamailio runs it for those that
    `t_reply()` sends too), nor for replies to local requests.
- tm can't depend on the script engine. So it runs routes through sip-core's
  `RouteHub`. Route names in `t_on_*()` are resolved at startup, so a typo is
  a config error.

See [event route](../../docs/glossary.md#event-route).

**Next hop and DNS**

- Without `$du`, the R-URI decides. `;transport=` is used, `sips:` means
  TLS, default ports apply, and IP literals are used directly. Host names go
  through NAPTR → SRV → A/AAAA. tm caches resolutions for 30 s. It does not
  cache with `dns_srv_lb`, which draws a new order for each request.
- With `use_dst_blocklist`, blocked hops are skipped when forking and in DNS
  failover. If none are left, `t_relay()` fails with 477 (E_SEND).
- DNS failover sends the same request to the next address as a new client
  transaction, with a new Via branch. The failed attempt is left out of
  aggregation.

## Differences from Kamailio

- `t_reply()` outside a failure_route or a resumed request replies
  statelessly. It does not create a transaction.
- `fr_inv_timer` counts from when the branch was sent, not from the first
  provisional.
- Replies that match no transaction are dropped instead of being forwarded
  statelessly.
- No RFC 2543 transaction matching: requests need a Via branch.
- `t_uac_send` can't send INVITE, ACK or CANCEL. The `t_uac` API can start
  an INVITE, but not ACK or CANCEL. For such an INVITE, tm ACKs a non-2xx,
  and the caller ACKs the 2xx with `send_stateless`. The `socket` argument
  of `t_uac_send` is ignored.
- DNS resolution, DNS failover and the destination blocklist are configured
  with tm modparams. In Kamailio they are core parameters.
- `event_route[tm:local-request]` doesn't run for the hop-by-hop CANCELs and
  the ACKs for negative finals that tm sends. Kamailio runs it for those in
  `t_cancel.c` and `t_reply.c`. In ferrosip they are built on the reply and
  timer path, where no script runs. R-URI / `$du` changes in the route are
  ignored.
- `t_release()` is accepted and does nothing. Transactions end by
  themselves.

## Testing

- `tests/e2e_fork.py`: 100 Trying, parallel and serial (`fork_by_q`)
  forking, the §16.7 best response (503 → 500, merged 401/407 challenges,
  6xx), CANCEL fan-out and §9.1, `fr_timer` / `fr_inv_timer`, `t_set_fr`,
  two 2xx, request retransmissions.
- `tests/e2e_tm.py`: CANCEL retransmission and the 64·T1 give-up, ACK reuse
  for retransmitted finals, RFC 5626 flow failover with `t_load_contacts()` /
  `t_next_contact_flow()`, `t_forward_nonack*()` (and its refusal of an
  ACK), `t_lookup_request()`, `t_save_lumps()`,
  `event_route[tm:local-request]` (header added, `drop`),
  `event_route[tm:local-response]`, and `t_load_contacts()` modes 0 (equal q
  in parallel) and 1 (one at a time).
- `tests/e2e_routes.py`: failure_route (voicemail, timeouts, chains,
  `t_reply`, not after CANCEL), onreply_route and reply_route.
- `tests/e2e_script.py`: `branch_route` with `$T_branch_idx`,
  `$T_reply_code`, `t_uac_send`, `tm.stats` and `tm:` statistics.
- `tests/e2e_dns.py`: NAPTR/SRV routing, DNS failover, `dns_srv_lb`, the
  blocklist (477 when the only target is blocked), `max_branches`,
  `t_load_contacts()` / `t_next_contacts()`, 478 for an unresolvable R-URI,
  and the `dns.*` / `dst_blocklist.*` RPCs.
- `tests/e2e_async.py`: `t_suspend()` / `t_continue()`, `$T(id_index)` /
  `$T(id_label)`, the 500 for a request parked too long.
- `tests/interop_sipp.py` and `tests/soak.py`. In both, transactions must
  drain to 0.
- Unit tests in `src/lib.rs`: the next-hop string round trip, best-response
  ranking, header line extraction, and the proportional order of
  `t_load_contacts(1)`.
