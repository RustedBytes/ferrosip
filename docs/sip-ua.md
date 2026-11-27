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
| `mod-ai` | A specialized UAS inside the routing script (`ai_answer` / `ai_dialog`): replied through the request context, handled retransmissions, CANCEL, BYE, re-INVITE, OPTIONS/INFO/UPDATE, its own RTP. | Tied to the script context and to its own media; no UAC side. **Migrated onto sip-ua (§6).** |
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
 (owns calls,                    │   UaEngine   │                              (sip-transport,
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

### Sharding

One engine is one thread and one ordering domain. `RuntimeConfig::shards`
runs several behind the same listeners (`src/shard.rs`):

- **Routing.** A received message goes to the shard of its Call-ID
  (FNV-1a of the Call-ID, modulo the count: stable across processes).
  Every message of a dialog carries the Call-ID, so requests, responses,
  ACK, CANCEL and retransmissions of a call reach one engine without
  shared state. A shard generates only Call-IDs that hash to itself
  (`UaConfig::shard`), so responses to its own requests come back to it.
- **Commands.** Each shard allocates leg and operation ids from a striped
  allocator (shard *i* of *n*: *i*+1, *i*+1+*n*, …): a command goes to
  `shard_of_leg(leg)` with no lookup table. New outbound calls are spread
  round robin.
- **Across shards.** An INVITE with `Replaces` is routed by its own
  Call-ID (the dialog it creates must live where its later requests
  arrive); the replaced dialog is found in a shared `DialogDirectory`,
  where each shard lists its dialogs with a live role/phase cell, and the
  RFC 3891 checks run against that. Flow closures go to every shard.
- **Events** of all shards arrive on one channel (`seq` per leg, `log_seq`
  per shard); one DNS thread serves all shards; the UDP front end runs one
  reader per shard on the shared socket.
- **Durable shards** (recovery): one journal per shard, each restored with
  its striped allocator and the same shard count, then
  `set_dialog_directory` republishes its dialogs. Changing the count moves
  Call-IDs between shards: not supported for live or journaled calls.

Tests: `tests/runtime_udp.rs` — 120 calls between two 4-shard runtimes
over UDP (answered, cancelled while ringing, hung up), every event's leg
on its Call-ID's shard; attended transfer into a 4-shard runtime where
the `Replaces` INVITE and the replaced dialog are on different shards
(the replaced leg is reported; the new dialog's BYE reaches it); both
routing rules were checked by mutation (no directory; routing by the
replaced Call-ID) and fail the test. `tests/recovery.rs`: a restored
durable shard keeps striped ids and own-shard Call-IDs and republishes
its dialogs.

Scaling (`examples/bench_shards`, two runtimes on loopback UDP with
their application threads, 20 000 calls, 500 in flight, Xeon E5-1620 v3
4 cores / 8 threads, three runs):

| Shards per runtime | Calls/s |
|---|---|
| 1 | 15 001 – 16 606 |
| 2 | 19 829 – 21 038 |
| 4 | 16 795 – 26 478 |

The first run of this benchmark had a single UDP reader per runtime and
did not scale at all (1, 2 and 4 shards all ≈ 15–17 k calls/s); one
reader per shard fixed that. At 4 shards both runtimes, their readers
and both application threads (≈ 20 busy threads) share 4 cores, so the
numbers spread widely; this setup cannot show more than that sharding
removes the single-engine limit. Measure on the target machine with the
peer elsewhere.

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

`runtime::spawn_transport` (feature `transport`) runs an engine on
ferrosip's transport layer, the same `sip_transport::start()` the proxy
binary uses:

- inbound: the engine is the transport's `Handler`; each message (Via
  already stamped with `received`/`rport`) is copied with its `Dest`
  (connection id included) into the engine's bounded input queue. When the
  queue is full, new requests get a stateless 503 + Retry-After and other
  messages are dropped (their senders retransmit); both are counted in
  `RuntimeStats`;
- outbound: `Transmit`s go to `Net::send` (`Outbound`), which reuses the
  connection a dialog arrived on, or dials TCP/TLS/WS/WSS; a failed send
  goes back through `handle_send_error`, a `TransportEvent::Closed`
  through `handle_flow_closed`;
- Via/Contact use the addresses the transport advertises per protocol;
- DNS: ferrosip's resolver on a helper thread; timers: the engine's own
  deadline (`next_timeout`) drives the loop's wait.

One engine thread owns every leg; scaling further means several engines
sharded by Call-ID (not done). The proxy binary does not use this; proxy
defaults and semantics are untouched.

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
- `examples/b2bua/rtpflux.rs` implements `MediaAdapter` over rtpflux's ng
  protocol (`offer`/`answer`/`delete`, retried with the same cookie on a
  lost datagram). The two SIP legs have independent Call-IDs, so the media
  session gets synthetic ids: `call-id = b2b-<call>`, one tag per leg; a
  re-offer names the other leg's tag, and rtpflux swaps roles when the
  first answerer re-offers. No undocumented ng flags are used.
- `tests/b2bua_rtpflux.rs` starts a real rtpflux (skipped without the
  binary): both parties see only relay ports, RTP flows both ways through
  the relay, a hold re-INVITE from the callee keeps the relay ports, and
  hangup deletes the media session.
- Media failure handling in the example: an offer the relay refuses
  rejects the inbound INVITE with 488; an answer it refuses hangs up the
  outbound leg (ACK + BYE), which then tears down the inbound one.

## 5. Restart and drain

- `drain()` (runtime: `UaHandle::drain`): new INVITEs get 503 + Retry-After
  and `Originate` fails with `Draining`; established legs keep working
  (`overload_drain_and_event_backpressure`). `is_idle()` says when every leg
  and transaction is gone.
- State is in memory only. A restart loses every dialog: peers will see
  481 for in-dialog requests and the calls end. Recoverable state,
  ownership fencing and lost TCP/TLS/WS flows are P2; no transparent
  failover is claimed.

## 6. mod-ai on sip-ua (migrated)

mod-ai's hand-rolled SIP (stateless replies from the request context, its
own 200 OK retransmission and ACK wait, BYE through `t_uac`) is replaced by
a module-owned engine (`crates/mod-ai/src/ua.rs`):

- `ai_answer()` keeps its own checks and their replies unchanged (488,
  486, 503, 400, 500 with a `Warning`), then hands the INVITE to the
  engine, which sends 100 Trying and owns the transaction;
- `ai_dialog()` feeds every message of an AI call (by Call-ID) to the
  engine: ACK, BYE, CANCEL, re-INVITE, retransmissions, OPTIONS/INFO/UPDATE;
- the call thread answers (`Accept` with its SDP), rejects (`Reject` with
  the same Warning) and hangs up (`Hangup`); engine events become its
  existing `Ev`s (`Ack`, `Bye`, `Remote` for a re-INVITE's new address,
  `Ended` when the engine ended the dialog, e.g. no ACK);
- a 10 ms ticker runs the engine's timers; transmissions go through the
  proxy's transport (`Outbound`); the engine sits behind a mutex (AI call
  rates are low and every section is short);
- session timers of our own stay off (`session_expires: None`), so the
  wire behaviour stays as before unless the caller asks for one;
- `lenient_matching` (off by default in the engine) keeps accepting
  callers that resend an INVITE or send a CANCEL with a new Via branch,
  which mod-ai matched by Call-ID before (its e2e suite does this).

Regression gate: `tests/e2e_ai.py` (mock OpenAI and Gemini), all 53
checks, before and after. One check's setup changed: the 487 to a CANCEL
now comes from the SIP stack at once instead of after the call thread
noticed, so the test waits for that call to be recorded before starting
the next one whose ordering it compares.

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

Cost of the later features (session timers on by default, PRACK, REFER,
identity, failover, DTMF), same machine, A/B back to back against the
first version, three runs each:

| Build | Calls/s | Bytes per established call |
|---|---|---|
| first version (P0a/P0b) | 13 096 – 13 687 | 5 558 – 5 570 |
| current | 12 065 – 12 895 | 7 349 – 7 358 |

About −6 % call rate and +1.8 KB per call (two legs). Disabling session
timers (`session_expires: None`) saves ≈ 0.4 KB and no measurable time.
The rest of the memory is per-leg extension state (≈ 400 B inline per leg,
PRACK state alone 168 B, unused on most calls) and the last local SDP each
leg keeps for re-INVITE refreshes; boxing the rarely used parts lazily is
the next step if it matters. (Profiling with perf was not possible on the
development machine: `perf_event_paranoid` = 4.)

Recoverable state (`docs/sip-ua-recovery.md`): in memory mode, the
outcome tombstones and operation records it added cost −2.5 % call rate
and +0.4 % memory against the commit before it (A/B, interleaved); the
cost of durable mode itself is measured there (§8b).

The proxy was not modified, so the proxy before/after comparison the
specification asks for (≥5 % median throughput or ≥10 % p99 regression
gate) has nothing to measure yet; it applies when the worker-integrated
driver lands (`bench/kamailio/` and `tools/sipflood` are the harness for
it).

## 8. Status and next steps

Done:

- P0a/P0b: audit, contract, deterministic harness, transactions, UAC/UAS
  dialogs, CANCEL and its races, forked 2xx (bounded per leg), digest
  auth, overload, drain and event backpressure;
- P0c: offer/answer (early, delayed, re-INVITE, UPDATE, glare, rollback),
  RFC 3262 PRACK and early UPDATE, RFC 4028 session timers, RFC 3263
  failover, the rtpflux media adapter with a cross-repo test;
- transports: UDP, TCP, TLS, WS and WSS through `sip-transport`;
- P1: REFER/NOTIFY and Replaces (blind and attended transfer
  signalling), 3xx policy with loop protection, trusted identity and
  privacy by policy, SIP INFO DTMF with the RTP-DTMF flag, registrar
  (usrloc) and trunk routing adapters, mod-ai migrated;
- interop with independent UAs (Python, UDP and TCP), fuzzing, benchmarks.
- RFC 6086 Info Packages; sharding by Call-ID (§2); recoverable state,
  ownership fencing and leases (`docs/sip-ua-recovery.md`).

Not done:

1. **Interop**: FreeSWITCH, Asterisk, PJSIP; SIPp runs in CI only (not
   installed where this was developed); `tc netem` impaired-UDP runs;
   packet-capture assertions; long soak; the scenario suite over TCP/TLS
   (the simulated scenarios are UDP; reliable transports have loopback tests).
2. Offers inside PRACK;
   early UPDATE from a UAC with several early dialogs; REFER outside a
   dialog and multiple concurrent REFER subscriptions per dialog.
3. A proxy before/after benchmark once something in the proxy path
   changes. (Sharding by Call-ID: done, see §2.)
4. **P2**: recoverable state, cluster ownership.
