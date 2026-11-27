# sip-ua: design note

The SIP UA engine for an external softswitch / B2BUA: audit of what
ferrosip already had, the architecture chosen, how it plugs into ferrosip
and rtpflux, what was measured, and what is left. API reference:
[`crates/sip-ua/README.md`](../crates/sip-ua/README.md). RFC coverage:
[`sip-ua-rfc-matrix.md`](sip-ua-rfc-matrix.md).

## 1. Audit of the existing building blocks

What the code does today (read from source, not only the READMEs), and
what that means for a UA engine.

| Component | What it provides | Gap for a B2BUA UA engine |
|---|---|---|
| `sip-parser` | Zero-copy, lazy parser; slices of the receive buffer, allocated in a per-worker `Bump` that is reset after every message. `body()` is everything after the blank line. | Nothing can be kept past the worker iteration, and Content-Length is not applied to datagram bodies. → sip-ua converts to owned messages once (applying Content-Length and limits) at the engine boundary. |
| `mod-txn` (tm) | Proxy transactions: §16.7 response aggregation across branches, failure/reply/branch routes, DNS failover, blocklist. `t_uac()` for locally generated requests. | `t_uac` reports **one** callback with the final status; no provisional events, no early-dialog state; the caller ACKs a 2xx itself and gets only the first one (forked 2xx are not surfaced); ACK/CANCEL can't be sent through it. Hostnames are resolved **synchronously on the calling thread** on a cache miss (`ruri_dests` → `resolver().resolve_uri`, up to `dns_timeout`). The transaction struct carries proxy-only state (branches, failure routes, suspend). → UA transactions are a different machine; sharing it would mean changing proxy semantics. sip-ua has its own §17 + RFC 6026 machines; nothing in `mod-txn` changed. |
| `mod-dialog` | Dialog tracking for a proxy (state from relayed messages), timeouts with BYEs, `dlg_refer`, and `dlg_bridge`. | `dlg_bridge` is click-to-dial: INVITE one party with on-hold SDP, REFER it to the target, then BYE — not a persistent two-leg bridge. It doesn't own dialog state as a UA (CSeq, route set, offer/answer). |
| `mod-ai` | A specialized UAS inside the routing script (`ai_answer` / `ai_dialog`): replies through the request context, handles retransmissions, CANCEL, BYE, re-INVITE, OPTIONS/INFO/UPDATE, its own RTP. | Tied to the script context and to its own media; no UAC side. A candidate to migrate onto sip-ua (§6). |
| `sip-core::net` | `Dest` (proto, address, connection id), `Outbound::send`, transport events (`TransportEvent::Closed`). | Reused as is: sip-ua addresses everything with `Dest`, so a driver can hand transmits to `Outbound` and keep connection affinity. |
| `sip-core::timer::TimerWheel` | Tick-based wheel driven by the tm timer thread. | It can't say when the next timer is due, which a sans-IO engine must expose (`next_timeout`) so any driver can sleep exactly. sip-ua uses a binary heap with lazy cancellation (stale entries are skipped when popped); a ferrosip-worker driver can still tick it from the wheel. |
| `sip-core::dns` | RFC 3263 resolver with cache (NAPTR → SRV → A/AAAA). Blocking UDP/TCP queries. | Reused through the driver (`SystemResolver`), on a helper thread, never on the engine thread. |
| `mod-carrier::uac` | Client digest (MD5/SHA-256/SHA-512-256, qop, `-sess`). Private to the module. | Re-implemented in `sip-ua::auth` (same algorithms, same RFC vectors) rather than making mod-carrier a dependency. Could be shared later by moving it to `sip-core`. |

Proxy regression risk: **none by construction** in this milestone — the
only changes outside the new crate are a CI build step, the fuzz harness
and these documents. `bin/ferrosip` does not link `sip-ua`; the workspace
test suite passes unchanged.

## 2. Architecture

```
            commands (bounded)                    transmits / resolve requests
 softswitch ───────────────────► ┌──────────────┐ ──────────────────────────► driver
 (owns calls,                    │   UaEngine   │                              (UDP runtime, or
  bridges, media)  ◄──────────── │  sans-IO     │ ◄──────────────────────────  ferrosip workers)
            events (bounded)     └──────────────┘   datagrams, clock, DNS results
                                   legs → dialogs → transactions → timers
```

- **One owner per leg.** An engine is single-threaded (`&mut self`); every
  transition of a leg is serialized. Scale out by running one engine per
  worker and sharding legs (e.g. by Call-ID hash for inbound, by choice for
  outbound). There is no global lock and no thread per call.
- **Effects outside state mutation.** Transactions return effects (send,
  arm timer, pass up); the engine applies them after the state change.
  Slow work (DNS) is requested as `ResolveRequest` and completed by
  `resolved()`, correlated by id; a leg that ended meanwhile is simply gone.
- **Time** is a `u64` of milliseconds supplied by the driver, so the whole
  engine runs under a fake clock in tests.
- **Layers.** `txn.rs` (RFC 3261 §17 + RFC 6026, pure), `engine.rs` (legs,
  dialogs, offer/answer, CANCEL, auth, routing), `api.rs` (the contract),
  `msg.rs` (owned messages, limits), `auth.rs`, `cause.rs`, `sdp.rs`
  (validity and the reject-everything answer only — SDP stays opaque),
  `runtime.rs` (a driver).
- **Identifiers.** `UaLegId`, `OperationId`, `Generation`, `TxnId` and
  `SipDialogId` are distinct types; SIP Call-IDs, tags and Via branches are
  generated per leg from a cryptographic RNG and never copied between legs
  (`tests/b2bua.rs` checks it). The softswitch owns `CallUuid` and maps
  legs to media ids.

### Ownership

| Resource | Owner |
|---|---|
| Transactions, retransmissions, dialog state, local CSeq, route set | sip-ua |
| Offer/answer *sequencing* (one offer at a time, glare, rollback, deadlines) | sip-ua |
| Offer/answer *policy* (what to answer), call ids, bridges, routing, billing | softswitch |
| SDP content, RTP ports, codecs, media graph | rtpflux (via the softswitch) |
| Registration, trunk discovery, ACLs | existing ferrosip modules / adapters |

## 3. Failure strategies

| Situation | Engine behaviour |
|---|---|
| Our early-offer INVITE gets a 2xx | ACK immediately (no application round trip), then `Accepted`. |
| Our delayed-offer INVITE gets a 2xx with an offer | ACK held for the application's answer until `min(answer_timeout_ms, 64·T1)`; then ACK with an answer rejecting every stream (RFC 3264 port 0) and BYE (RFC 3261 §13.2.2.4). |
| 2xx lacking the required answer / offer | ACK, `Failed{ProtocolViolation}`, BYE. |
| Further 2xx from other forks | ACK each, BYE each once (`Reason: SIP;cause=200;text="Call completed elsewhere"`); retransmissions are re-ACKed without new BYEs. |
| CANCEL crosses a 2xx | ACK + BYE that dialog; the leg ends `Cancelled`; the application never sees `Accepted`. |
| No final after CANCEL | the leg ends after 64·T1 (CancelGuard) and its INVITE transaction is dropped. |
| Our 2xx never ACKed | 2xx retransmitted (T1 doubling to T2) for 64·T1, then `Failed{NoAck}` and BYE. |
| Application never answers an inbound INVITE | 480 after `uas_answer_timeout_ms`. |
| Application never answers a re-INVITE/UPDATE offer | 488, offer rolled back, `Failed{AnswerTimeout, leg_failed: false}`. |
| DNS failure / no local address / send error | `Failed{Dns | Transport}` (Q.850 38) + `Terminated` for the leg's INVITE; operation failure otherwise. |
| 481 / 408 to an in-dialog request | the leg ends (408: with BYE). |
| Event queue full | the affected leg is failed explicitly (see the README). |

Teardown is idempotent: repeated `Hangup`, crossing BYEs, BYE during
CANCEL, and late responses after `Terminated` all end in exactly one
`Terminated` event (checked by every scenario and the property test).

## 4. Integration

### With ferrosip

The `runtime` module is a std UDP driver, enough for the example and tests.
The production integration (not done yet) is a driver inside the
`sip-transport` workers:

- inbound: requests/responses that belong to the UA (by listener, by a
  routing-script decision such as `ua.handle()`, or by Call-ID/dialog
  lookup) go to `UaEngine::handle_message` with the `Dest` the transport
  already has (connection id included, which gives reliable-transport and
  RFC 5626 flow affinity for free);
- outbound: `Transmit`s go to `Outbound::send`; a send error or a
  `TransportEvent::Closed` goes back through `handle_send_error` /
  `handle_flow_closed`;
- timers: from the tm timer thread's tick, or a per-engine deadline;
- DNS: the existing resolver on a helper thread, as the runtime does.

Proxy defaults and semantics are untouched: the proxy path never reaches
the engine unless the configuration routes requests to it.

### With rtpflux

The softswitch, not either repository, joins the two: it maps `UaLegId` +
`Generation` to `MediaSessionId`/`MediaEndpointId` and an `OperationId` of
its own. The example's `MediaAdapter` trait is the seam
(`examples/b2bua/bridge.rs`): `offer` / `answer` return the SDP for the
other leg, `release` frees the session when both legs are gone.

- Each `RemoteOffer` / `IncomingInvite` / `Accepted` carries the generation
  the media operation must be tagged with; a `RespondToOffer` for a stale
  generation is refused (`StaleGeneration`), so a late media answer can't
  be applied to a newer offer.
- A SIP 2xx and a media command are separate effects. If media fails after
  the remote leg was accepted, the compensation is `Hangup` (the engine
  sends ACK first where required, then BYE). Media failures enter as
  application decisions, never as direct SIP actions by rtpflux.
- Not done yet: an rtpflux client implementing `MediaAdapter` with ng
  `offer`/`answer` (or the companion spec's endpoint API) and the
  cross-repo test against a real rtpflux. The example runs media
  passthrough only.

## 5. Restart and drain

- `drain()` (runtime: `UaHandle::drain`): new INVITEs get 503 + Retry-After
  and `Originate` fails with `Draining`; established legs keep working
  (`overload_drain_and_event_backpressure`). `is_idle()` says when every leg
  and transaction is gone.
- State is in memory only. A restart loses every dialog: peers will see
  481 for in-dialog requests and the calls end. Recoverable state,
  ownership fencing and lost TCP/TLS/WS flows are P2; no transparent
  failover is claimed.

## 6. Migration guide: mod-ai onto sip-ua (P1)

1. Route `ai_answer` to a UA engine owned by the module: the INVITE goes
   to `handle_message` instead of being answered through `Ctx`; the
   module's `IncomingInvite` handler calls `Accept` with the SDP it builds
   today.
2. Replace `ai_dialog()`'s hand-written ACK/BYE/CANCEL/re-INVITE handling
   with `Ack`, `RemoteBye`, `Cancelled`, `RemoteOffer` events
   (`RespondToOffer` with the same "new media address" answer).
3. The model's `end_call` and provider failures become `Hangup`.
4. Keep the script API (`ai.answer`, `ai.dialog`) and the reply table in
   its README unchanged; the e2e suite `tests/e2e_ai.py` is the regression
   gate.

## 7. Benchmarks

Methodology (`cargo run --release -p sip-ua --example bench -- CALLS CONCURRENT`):

- Two engines in one process exchange messages directly (no sockets, no
  media, no logging), one thread. This measures SIP engine work only —
  parsing to owned messages, transactions, dialogs, serialization, timers —
  for **both** the UAC and the UAS side of each call. It is not
  complete-call CPS over a network.
- Throughput: CALLS complete calls (INVITE, 100, 180, 200, ACK, BYE, 200 =
  7 messages each) in batches of 1000, all transaction timers run out
  after each batch; the engines must be idle at the end.
- Latency: wall time of every `handle_message` call (p50/p95/p99).
- Memory: RSS growth for CONCURRENT established calls set up in batches of
  1000 (so transient queues don't dominate), transactions expired;
  includes allocator overhead and stale timer-heap entries.
- Report all three runs, with the CPU and commit.

Results on this branch (base commit 7dd691d + the sip-ua changes), Intel
Xeon E5-1620 v3 @ 3.50 GHz (4 cores / 8 threads), release build, three
consecutive runs of `bench 50000 20000` (machine load not controlled):

| Run | Calls/s (engine, both sides) | Messages/s | p50 | p95 | p99 | Bytes per established call (UAC + UAS leg) |
|---|---|---|---|---|---|---|
| 1 | 13 792 | 96 542 | 4.60 µs | 10.19 µs | 15.14 µs | 5 579 |
| 2 | 14 541 | 101 790 | 4.40 µs | 9.69 µs | 11.93 µs | 5 573 |
| 3 | 14 655 | 102 585 | 4.33 µs | 9.59 µs | 11.62 µs | 5 566 |

These are single-machine engineering numbers, not a capacity claim.

The proxy was not modified, so the proxy before/after comparison the
specification asks for (≥5 % median throughput or ≥10 % p99 regression
gate) has nothing to measure yet; it applies when the worker-integrated
driver lands (`bench/kamailio/` and `tools/sipflood` are the harness for
it).

## 8. Status and next steps

Done (P0a, P0b, most of P0c's offer/answer):
audit, contract, deterministic harness, transactions, UAC/UAS dialogs,
CANCEL and its races, forked 2xx, digest auth, early/delayed offer,
re-INVITE/UPDATE with glare and rollback, overload/drain/backpressure,
UDP runtime, example B2BUA, interop with independent UAs, fuzzing.

Not done — in order:

1. **P0c**: RFC 3262 PRACK / reliable provisionals; RFC 4028 session
   timers (422 handling, refresh, expiry per leg); RFC 3263 failover to the
   next target; rtpflux `MediaAdapter` and the cross-repo test.
2. **Transports**: the `sip-transport` worker driver (TCP, TLS, WS, WSS,
   SIP Outbound), with the scenario suite run over each; proxy
   before/after benchmark.
3. **Interop**: FreeSWITCH, Asterisk, PJSIP; SIPp runs in CI only (not
   installed where this was developed); `tc netem` impaired-UDP runs;
   packet-capture assertions.
4. **P1**: REFER/NOTIFY, Replaces, transfers, fork policy hooks, 3xx
   policy, INFO packages / DTMF de-duplication, identity/privacy policy,
   registrar/trunk adapters, mod-ai migration.
5. **P2**: recoverable state, cluster ownership.
