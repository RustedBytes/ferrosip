# sip-ua recovery: design (ADR) and status

Recoverable state for the [`sip-ua`](../crates/sip-ua/README.md) engine:
what the engine persists, the durability contract a driver follows, how a
restore works, and what is (and is not) supported yet. Feature `recovery`
of the `sip-ua` crate; the in-memory mode is unchanged without it.

## 1. Audit (baseline 60b20fc)

- The engine is sans-IO and single-owner (`&mut self`); every leg and
  transaction lives in in-memory maps with derived indexes (dialog, merged
  request, transaction keys) and a timer heap of absolute engine-clock
  deadlines.
- Effects were queued (`poll_transmit`, `poll_event`) as soon as a
  transition computed them: nothing tied an effect to the state that
  justified it, so a crash between the two could lose either.
- Identifiers came from one allocator (legs, operations) and per-engine
  counters (transactions, DNS requests); events had a per-leg sequence only.
- There was no idempotency for commands, no record of operation outcomes
  and no memory of ended legs.

Deviations from the baseline in this work: the engine gained an
engine-wide event sequence (`EventEnvelope::log_seq`), an owner epoch on
every transmit, keyed commands with recorded outcomes, bounded leg
tombstones, a `halt` state, change tracking for durable deltas, and the
`recovery` feature with records, transitions, restore and two journals.

## 2. Identity and the side-effect contract

| Identity | Owner | Notes |
|---|---|---|
| tenant, call, channel, durable effect ids | the softswitch (Ferroswitch) | never interpreted by sip-ua |
| operation key (`submit_keyed`) | the softswitch | idempotency key for a mutating command; stored with a fingerprint of the command's semantic parameters and its outcome |
| `UaLegId`, `OperationId` | sip-ua | allocated from one allocator; restore advances it past every id it restores |
| Call-ID, tags, Via branches, CSeq | sip-ua | recorded per leg / transaction; never regenerated on restore |
| `Generation` | sip-ua | offer/answer revision per leg |
| per-leg `seq`, engine-wide `log_seq` | sip-ua | event order; replay keeps both |
| media ids and revisions | rtpflux (via the softswitch) | not known to sip-ua |

`submit_keyed(key, command)`: the same key with the same command again
(a retry after an ambiguous outcome, e.g. a timeout waiting for the
engine, or a restart) creates nothing new and returns the recorded
operation, leg and status (`replayed: true`); the same key with a
different command is `KeyConflict`. The record is part of the durable
state, so this holds across restarts once the submitting transition was
committed (before that, nothing of it exists anywhere — see §4).

States of an effect: *accepted* (command returned Ok), *committed* (its
transition is durable), *dispatched* (handed to the transport), *protocol
completed* (a SIP outcome event), *failed*, *unknown* (`LegOutcome::Unknown`
/ no op record: never committed, or forgotten by retention). Dispatch does
not mean the peer received it; SIP gives no exactly-once delivery.

## 3. The record

`StateRecord` (JSON) holds, per format version (`FORMAT_VERSION` = 1,
readable range `MIN_FORMAT_VERSION..=FORMAT_VERSION`; older formats are
upcast on load, newer or unknown ones refused with `Incompatible`):

- every leg: role, phase, Call-ID, tags, local/remote header values and
  Contacts, remote target, route set, local/remote CSeq, transport flow,
  early dialogs, the selected fork and killed forks with their ACKs,
  offer/answer state, generation, last local SDP, event sequence, every
  armed leg timer, pending 2xx and its retransmission state, PRACK/RSeq
  state and queued provisionals, session timer, REFER subscription state,
  auth attempt count and a credential *reference*, redirect and failover
  state;
- every transaction except server transactions that belong to no leg's
  durable state (stateless replies, BYE): kind, state, destination, the
  request and the bytes sent, the last response, the non-2xx ACK, the
  retransmission interval, every armed timer, and its matching key;
- pending DNS resolutions, keyed operations, leg tombstones, counters;
- committed effects not yet known to be dispatched;
- the owner epoch and the journal position.

Encoding rules: byte buffers are base64; deadlines are stored *remaining*
relative to the record's `ClockAnchor` (engine clock and wall clock at
the same instant); connection ids are dropped; credentials keep username
and realm only (the password comes from `RestoreOptions::credentials`);
no random generator state is stored (a restored engine has fresh
entropy, and only generates new tags/branches). Leg and transaction
records are opaque JSON values inside the state, so a store can keep and
fold them without understanding them.

## 4. The durable transition boundary

In durable mode (`UaConfig::durable`), `poll_transmit` and `poll_event`
return nothing. After any input the driver calls
`take_transition(now, wall)` until it returns `None`; each `Transition`
holds the delta (records of every leg and transaction the input touched,
removals, operation and tombstone changes) and the transmits and events
it produced:

1. `needs_commit` (state changed): append `record` to the journal; only
   when that succeeded, dispatch `record.transmits` and deliver
   `record.events`; then record the dispatch (`dispatched(seq)`, may be
   batched).
2. `!needs_commit` (only stateless replies, e.g. 481, 405, OPTIONS, 503 to
   unknown requests): dispatch at once; nothing to persist.
3. An append that fails: `halt()` the engine. A halted engine sends
   nothing, ignores input, refuses commands (`Halted`) and has no timers.
   Recovery is a restart from the journal.

Invariants:

- no message leaves the process before the state that produced it is
  durable (outbound INVITE with its Call-ID, branch and CSeq; a 200 with
  the leg's accepted state and retransmission cache; an in-dialog request
  with its CSeq advance; the ACK/BYE of a forked or cancelled 2xx);
- no event reaches the application before it is durable;
- after a commit, effects are delivered at least once: a restart replays
  every committed transition whose dispatch was not recorded
  (`RestoreReport::replay_*`). A replayed transmit is the same message
  (same branch): a retransmission to the peer. A replayed event has the
  same leg, `seq` and `log_seq`: consumers deduplicate on them
  (`Terminated` is one logical transition that may be delivered twice);
- transitions are appended in order (`seq` consecutive; a gap or a
  duplicate is refused by the store); one engine is one ordering domain,
  so independent legs of one engine share the sequence. Run several
  engines (shards) for independent progress.

Costs: one append per input that changes state, including every
retransmission of a persisted transaction (its interval and timers
change). Deltas carry only touched legs and transactions. Protocol
deadlines include the commit latency: a store slower than T1 delays
retransmissions accordingly, and one slower than the transaction timers
turns into timeouts; the engine never fakes success — a failed or slow
commit halts or delays, it does not dispatch.

## 5. Restore

`UaEngine::restore(cfg, entropy, ids, &state, &opts, now, wall)` builds a
new engine (quiescent by construction: nothing is sent): it checks the
format and the epoch, decodes each leg and transaction, validates it,
rebuilds the dialog, merged-request and transaction indexes and the timer
heap, re-asks pending DNS resolutions, restores operation records and
tombstones, and advances the id allocator and counters past every
restored id. It reports per leg `Restored { overdue }`, `Unsupported`,
`Conflicted` or `Corrupt` (with reasons), dropped transactions, and the
effects to replay. Anything not restored is removed from the journal by
the next transition. Corrupt or incompatible input never panics and
never sends anything.

Clock policy. The engine clock is monotonic and per process; a record
keeps remaining time relative to its anchor. On restore, the time since
the anchor is taken from the wall clock (`wall − anchor.wall`); a
negative difference (the wall clock went back) counts as zero and is
reported (`clock_skew`). Each deadline becomes `now + remaining −
elapsed`, at least `now`. Timers already due fire on the first
`handle_timeout`, in deadline order; a due retransmission timer sends
once and continues from `now` with its doubled interval (no burst of
missed retransmissions). A session timer that expired during the
downtime ends the session at once: downtime never becomes a fresh
session lifetime. A wall clock that jumps forward shortens deadlines; one
that jumps back is clamped as above.

Transport policy. Connections do not survive a process. A leg whose
dialog runs over a connection *we* opened (UAC over TCP/TLS) is restored
and will dial a new connection of the same transport (never a TLS
downgrade; certificate checks as for any new connection). A leg bound to
an inbound connection (a UAS over TCP/TLS/WS/WSS) is reported
`Unsupported`: the peer must reconnect, and SIP gives us no way to reach
it. Server transactions on a lost connection are dropped (their response
can't be delivered). UDP dialogs are fully restorable.

Application reconciliation. Events delivered before a crash are not
re-emitted unless their dispatch wasn't recorded. After a restart the
application should query restored legs (`snapshot`, `leg_outcome`,
`op_outcome`) and act on any it had not finished handling — e.g. an
inbound leg still `Calling` whose `IncomingInvite` it had seen but whose
answer was never committed (the example `recoverable_ua` answers those).

## 6. Events: replay and retention

Every committed event carries `log_seq`. A store keeps a bounded event
log (`MemoryJournal::events_after`); a consumer that lost its connection
asks for events after its last `log_seq`. If those are no longer
retained the answer is `ReconciliationRequired`: the consumer must query
leg and operation outcomes instead — events are never fabricated. Ended
legs keep a tombstone (bounded, `max_tombstones`) so an outcome query
answers even after the leg is gone.

## 7. Ownership and fencing

The owner epoch comes from an external authority (lease, election,
operator); sip-ua only carries and enforces it. It is stamped on every
transmit and transition (`set_epoch`; it can only grow). Three
enforcement points:

- **The store.** A new owner fences it before it reads the state it takes
  over: `MemoryJournal::fence`; `FileJournal::open_as(dir, Some(epoch))`
  raises a `fence` file under an advisory lock (`owner.lock`) that every
  append, dispatch record and checkpoint holds while it checks the fence,
  so "check, then write" is atomic between processes. A distributed store
  does the same with a conditional write. An older owner's append fails;
  its engine halts before any effect of that transition.
- **Stateless replies.** Transitions with no state change need no commit,
  but a stale owner must not send them either (a 481 from a stale owner
  ends the peer's dialog that the new owner holds). Drivers check
  `admit(epoch)` against the store before dispatching them; a refusal
  halts the engine. The cost is one fence read per stateless reply.
- **Egress.** `EgressFence` (a shared epoch, `RuntimeConfig::egress_fence`)
  drops transmits of an older epoch at the last point before the socket and
  halts the engine (`RuntimeStats::fenced`). It covers what the store
  cannot: a transition committed by the old owner whose dispatch was
  delayed past the takeover (paused process). Where the egress point is
  not shared with the new owner, this window remains (see residual risks).
- **Restore.** `require_newer_epoch` refuses a takeover with an epoch that
  is not newer than the state's.
- **Lease (self-fencing).** `UaEngine::set_lease(until)` /
  `UaHandle::renew_lease`: at `until` (its own monotonic clock) the
  engine halts at its next input, timer or transition — before producing
  anything — without reaching the store or the egress. This covers an old
  owner cut off from everything but the peers. Safe use: compute `until`
  from when the lease was requested, and have the authority start a new
  owner only after the lease plus a margin for clock-rate drift and for
  the driver's delay between an input and dispatching its output.

A halted engine sends nothing, has no timers and refuses commands; the
process should exit (the example does, status 3).

Tested (`tests/fencing.rs`, simulated network, the old engine kept
running beside the new one at the same address):

| Scenario | Old owner | Result |
|---|---|---|
| hears all traffic, reaches the store | re-INVITE for the restored call | its commit is refused, it halts; the new owner answers; no packet of epoch 1 after the takeover |
| hears all traffic, partitioned from the store | OPTIONS and BYE-for-unknown-dialog (stateless); a new INVITE | it answers nothing; exactly one answer each, epoch 2 |
| paused through the takeover, then its timers fire | session refresh due | refused, halted; the new owner refreshes, the session survives |
| committed a BYE, paused before sending it | resumes and sends | the egress drops it; the new owner sent the BYE once (replay, epoch 2) |
| takeover with epoch ≤ state's | — | refused |
| two `FileJournal` handles on one directory | appends, dispatch, checkpoint after the fence | all refused; reopening shows only the new owner's history |
| lease not renewed (cut off from the authority) | peer re-INVITEs after the lease's end | halted at the lease's end by its own clock; no packet after it |
| lease renewed every 2 s for 2 min, with session refreshes | — | keeps running; a renewal never shortens the lease |

And with real processes (`tests/e2e_sip_ua_recovery.py`, takeover case):
the epoch-1 process is SIGSTOPped with a call up, an epoch-2 process
takes over the directory and binds the same UDP address (`SO_REUSEPORT`),
a stale `--epoch 1 --takeover` is refused, the old process resumes and
receives some of the caller's traffic: it halts on `StaleEpoch` and sends
nothing; the re-INVITE and BYE are answered by the new owner. And the
lease case: a process renewing an 800 ms lease keeps running; when
renewals stop it halts by itself in under 2 s and answers nothing after.
`tests/runtime_udp.rs` checks the same with the threaded runtime.

Residual risks: a message handed to the network before the takeover may
still arrive after it; with an unshared egress, a transition the old owner
committed before the fence and dispatches after it can leak (the new owner
replays the same message, so the peer sees a retransmission, not a
conflicting message — the same branch, CSeq and content); a lease is only
as safe as its margins (a process paused for longer than the lease and
resumed between an input and its dispatch can still send that one
output: the egress fence or the store covers it, the lease alone does
not).

## 8. Tests

| Evidence | Where |
|---|---|
| confirmed UDP UAC and UAS restored: tags, Call-ID, route, CSeq continue; re-INVITE, session refresh and BYE after restore; journals drain | `tests/recovery.rs` `confirmed_udp_call_survives_restarts_of_both_sides` |
| keyed Originate at pre-commit / post-commit / post-send: one INVITE transaction, retry finds the call, conflict on another command | `keyed_originate_is_one_logical_call_at_every_crash_boundary` |
| 200 committed but not sent is sent after restore; nothing visible from a transition that was never committed | `uas_200_committed_but_not_sent_is_sent_after_restore`, `a_crash_before_commit_never_shows_its_effects` |
| restart while ringing; CANCEL after restart | `early_invite_survives_a_caller_restart` |
| downtime past the session interval ends the session at once | `downtime_past_the_session_interval_is_not_a_fresh_lifetime` |
| allocator never reissues restored ids | `restored_ids_are_never_handed_out_again` |
| corrupt leg, bad JSON, unknown format, stale epoch: refused without panic | `invalid_incompatible_and_stale_records_are_refused_without_panic` |
| storage failure halts before any effect | `storage_failure_halts_the_engine_before_any_effect` |
| event replay; pruned history → reconciliation required | `committed_events_replay_and_pruned_history_requires_reconciliation` |
| fenced old owner can neither commit nor send; the new owner continues the dialog | `a_fenced_old_owner_cannot_commit_or_send`, and `tests/fencing.rs` (§7) |
| random crashes at random boundaries with random downtime over a lossy network: drains, no CSeq reuse, one call per key, consistent events (2 000 seeds, 7 455 restarts) | `tests/recovery_property.rs` |
| real processes, fsync'd file journal, SIGKILL and aborts at each boundary, takeover by a second live process, against independent UAs | `tests/e2e_sip_ua_recovery.py` (37 checks) |
| real rtpflux media (native API, pinned revision): RTP keeps flowing while the B2BUA is SIGKILLed; after the restart the same endpoints, no second INVITE, BYE destroys the media; a B2BUA killed while the callee rings bridges and answers after the restart | `tests/e2e_sip_ua_rtpflux.py` (26 checks) with `interop/sip-ua-rtpflux` |

## 8b. Cost of durable mode

`cargo run --release -p sip-ua --features recovery --example bench_durable -- CALLS FSYNC_CALLS BATCH`:
the in-process two-engine benchmark of `docs/sip-ua.md` §7 (complete
calls, both sides, one thread, no sockets) in memory mode, in durable mode
with every record encoded and dropped (the engine's own cost: change
tracking, records, JSON), and in durable mode into a `FileJournal` per
engine (one `fdatasync` per commit). `BATCH` calls are set up together;
everything pending when the driver takes a transition goes into one
record, so 1000 is group commit and 1 is one call at a time.

Intel Xeon E5-1620 v3, NVMe (ext4, 95 % full, other load not
controlled), three runs each (ranges):

| Mode | Batch | Calls/s | Commits per call (both sides) | Bytes per call | Bytes per commit | Commit p50 / p99 |
|---|---|---|---|---|---|---|
| memory | 1 | 11 075 – 11 276 | — | — | — | — |
| durable, encode only | 1 | 2 093 – 2 119 | 11 | 35 209 | 3 201 | 9 µs / 16–18 µs |
| durable, fsync | 1 | 18 – 56 | 11 | 35 206 | 3 201 | 1.4–1.7 ms / 2.4–40 ms |
| memory | 1000 | 12 651 – 12 924 | — | — | — | — |
| durable, encode only | 1000 | 2 142 – 2 199 | 0.01 | 31 342 | 2.8 MB | 8.6–8.7 ms / 12 ms |
| durable, fsync | 1000 | 138 – 210 | 0.01 | 31 150 | 2.8 MB | 0.36–0.78 s / 0.7–1.1 s |

Reading it:

- The engine's own durability cost is about 5.7× the CPU of a call in
  memory mode, nearly all of it building and encoding JSON records: each
  commit carries the full record of every leg and transaction the input
  touched (3.2 KB on average; 11 commits per call over both sides).
- With a synchronous fsync per commit, the disk dominates completely
  (≈ 1.6 ms per fdatasync here, with long tails). Group commit helps only
  as far as the disk keeps up with ~30 KB per call.
- One change came out of these measurements: client transactions stored
  both the parsed request and its wire bytes, and all bytes were base64.
  Requests are now stored once, in wire form (re-parsed on load, the
  retransmitted bytes rebuilt from them; `a_restored_client_transaction_retransmits_the_same_bytes`),
  and UTF-8 bytes (SIP, SDP) are stored as text: −15 % bytes and about
  +25 % call rate in durable mode (1 675 → 2 093–2 119 calls/s, batch 1).
- Memory mode (the default) was checked against the baseline commit
  with `examples/bench.rs`, binaries interleaved run by run. The first
  version of this work cost −19 % call rate there; nearly all of it came
  from keeping 10 000 tombstones as small heap allocations (the
  bookkeeping itself was 31 ms of a 4.6 s run; the rest was allocator
  fragmentation felt by everything else). Tombstones now live in two
  contiguous rings (`engine/graves.rs`) and the termination cause is kept
  on the leg instead of searched for in the event queue. After that:
  12 786 – 12 913 vs 13 081 – 13 212 calls/s (−2.5 %), 7 402 – 7 426 vs
  7 370 – 7 378 bytes per established call (+0.4 %). `max_tombstones: 0`
  removes the remainder of the tombstone cost.
- Next steps if durable throughput matters: smaller deltas (field-level
  instead of whole-record), a binary encoding, not rewriting a
  transaction's request on every timer change, and a store with group
  commit or replication instead of local fsync.

These are engineering numbers for one machine and disk, not a capacity
claim.

## 9. Media (rtpflux native API)

`interop/sip-ua-rtpflux` is a media B2BUA built on durable sip-ua and
`rtpflux-client-async` (native control API over TCP), pinned to rtpflux
`cac94112d993ae1e61614b0c4bbb8e416d45059c` in its own `Cargo.toml` and
lockfile. It is a separate cargo workspace: neither `sip-ua` nor the
ferrosip workspace depends on rtpflux or tokio. The pattern it shows:

- signalling state is sip-ua's journal; the application's own per-call
  state (A's leg and offer, B's answer, endpoint ids) is a separate small
  durable record written before each action that depends on it;
- every media action is idempotent — `endpoint.create` and
  `bridge.attach` with idempotency keys derived from the Call-ID, destroy
  of a destroyed endpoint succeeds — and the outbound INVITE is a keyed
  command (`b2b:<Call-ID>`), so recovery is "repeat the current step of
  each call": nothing is created twice and no second INVITE is sent;
- the relay is independent of the B2BUA process: a crash does not
  interrupt RTP, and a disconnecting client destroys nothing.

Limits of this tool (not of sip-ua): a call whose `IncomingInvite` was
delivered but not yet written to the application's record before a crash
is refused (480) after the restart; re-INVITEs are not renegotiated
through `endpoint.prepare`/`commit`; media events (`gap`, timeouts) are
not consumed. A crash of the relay itself is rtpflux's recovery (state
file or Redis), not tested here.

## 10. Scope and residual risks

Supported now: single-node restart recovery of UDP dialogs in any phase
the record covers (early, confirmed, terminating; pending ACK, CANCEL,
forked 2xx, PRACK, renegotiation, session timers, REFER state), and of
UAC dialogs over TCP/TLS by reconnecting; ownership takeover with
fencing (§7). Not supported or not yet tested: inbound stream connections
(reported, not restored), a distributed store.
Durable shards: one journal per shard (`docs/sip-ua.md`, Sharding). Media continuity is tested for
B2BUA crashes with a single relay (§9). Engine-microbenchmark numbers are not softswitch capacity.
