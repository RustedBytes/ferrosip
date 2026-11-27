# sip-ua

A reusable SIP user agent engine — UAC and UAS — for building B2BUAs and
softswitches on ferrosip. It terminates inbound dialogs and originates
independent outbound ones; the application (the softswitch) owns call
policy, bridging and media.

- **Sans-IO.** The engine does no I/O, never blocks and never sleeps. A
  driver feeds it received messages, the clock (monotonic milliseconds) and
  DNS results, and sends what it emits. Tests drive it with a fake clock and
  a simulated network; [`runtime`](src/runtime.rs) is a ready-made UDP
  driver on std threads.
- **Owned data at the boundary.** `sip-parser`'s zero-copy messages are
  converted once into owned [`SipMessage`](src/msg.rs)s after validation;
  nothing the engine keeps or emits borrows a receive buffer.
- **No proxy code loaded.** It depends on `sip-parser` and `sip-core`
  (addresses, DNS), not on the routing language, `mod-txn` or the proxy
  binary, and the proxy does not link it.

Design, audit and integration notes: [`docs/sip-ua.md`](../../docs/sip-ua.md).
RFC coverage: [`docs/sip-ua-rfc-matrix.md`](../../docs/sip-ua-rfc-matrix.md).

## Quick start

```rust
use sip_ua::*;

let local = "192.0.2.10:5060".parse().unwrap();
let mut ua = UaEngine::new(UaConfig { local: vec![(Proto::Udp, local)], ..UaConfig::default() });

// Originate: the result is acceptance, not completion.
let acc = ua.submit(UaCommand::Originate(Box::new(OriginateRequest {
    request_uri: "sip:bob@198.51.100.7".into(),
    from: "\"Alice\" <sip:alice@example.com>".into(),
    sdp: Some(offer),
    ..Default::default()
})), now)?;

// The driver loop.
loop {
    while let Some(t) = ua.poll_transmit() { /* send t.data to t.dest; on failure: ua.handle_send_error(txn, now) */ }
    while let Some(r) = ua.poll_resolve() { /* resolve off-thread, then ua.resolved(r.id, result, now) */ }
    while let Some(ev) = ua.poll_event() { /* hand to the application */ }
    // wait for a datagram or until ua.next_timeout(); then:
    ua.handle_message(&datagram, source, now);
    ua.handle_timeout(now);
}
```

`cargo run -p sip-ua --example b2bua -- 127.0.0.1:5070 127.0.0.1:5080` runs
a two-leg B2BUA (every inbound call is originated as an independent call to
the target, media passed through a `MediaAdapter`).

## Contract

Every accepted command gets an `OperationId`; `Accepted` means the command
was valid and its first effect is queued, **not** that the protocol
exchange finished. Events carry the leg, a per-leg sequence number
(1, 2, 3 …; a gap means events were missed — reconcile with
`UaEngine::snapshot`), the offer/answer `Generation`, the operation they
answer, the SIP dialog id, and SIP status / Q.850 cause where relevant.
`Terminated` is the last event of every leg and is emitted exactly once.

### Commands

| Command | Valid when | The engine does | Completion |
|---|---|---|---|
| `Originate` | not draining, under `max_legs` | INVITE (early offer with `sdp`, delayed offer without); resolves via `poll_resolve` unless `next_hop`; arms the no-answer timer | `Provisional`*, then `Accepted` or `Failed`+`Terminated` |
| `Provisional` | inbound, unanswered | 101–199 with our tag and Contact; SDP only as the answer to the INVITE's offer (no reliable 1xx) | — |
| `Accept` | inbound, unanswered | 200 with the answer (or our offer, if the INVITE had none); retransmits it until ACK | `Ack` (with the answer, for delayed offer) or `Failed{NoAck}` |
| `Reject` | inbound, unanswered | 300–699; the transaction absorbs the ACK | `Terminated` |
| `Cancel` | outbound, unanswered | CANCEL, after the first provisional (RFC 3261 §9.1); a 2xx that crosses it is ACKed and BYEd | `Terminated{Cancelled}` |
| `Hangup` | any; idempotent | the right teardown: CANCEL, a final (default 480), or BYE — an inbound leg waits for the ACK of its 2xx first | `Terminated` |
| `Negotiate` | confirmed, no offer outstanding | re-INVITE or UPDATE with our offer | `Completed{sdp: answer}` or `Failed{leg_failed: false}` (rolled back; 491 carries `retry_after_ms`) |
| `SendInfo` | confirmed | INFO | `Completed` / `Failed` |
| `RespondToOffer` | a `RemoteOffer` is outstanding and `generation` matches | answers it (2xx / ACK body), or rejects with `sdp: None` (488, rollback) | — |

Header fields the engine owns (Via, From, To, Call-ID, CSeq, Contact,
Content-Type, Max-Forwards, Route, Record-Route, …) cannot be set through
`headers`; names must be tokens and values must not contain line breaks.

### Events and the application's duty

| Event | Meaning | Application must |
|---|---|---|
| `IncomingInvite` | new inbound leg (100 Trying already sent) | `Provisional`/`Accept`/`Reject` within `uas_answer_timeout_ms` (else 480) |
| `Provisional` | 1xx with a to-tag (forked early dialogs differ in `remote_tag`) | — |
| `Accepted` | the outbound leg is confirmed and ACKed (early offer) | if a `RemoteOffer{InviteResponse}` follows, answer it |
| `RemoteOffer` | an offer to answer (`kind`: 2xx of our delayed-offer INVITE, re-INVITE, UPDATE) | `RespondToOffer` before `deadline`, else the engine rejects it (and, for the 2xx case, ACKs with an all-streams-rejected answer and sends BYE) |
| `Ack` | our 2xx was ACKed (with the answer if we offered) | — |
| `Cancelled` | the caller cancelled the inbound INVITE (487 sent) | — (`Terminated` follows) |
| `RemoteBye` | the peer hung up (200 sent) | — (`Terminated` follows) |
| `Info` | INFO received (200 sent) | — |
| `Completed` / `Failed` | an operation ended; `Failed.leg_failed` says whether the leg is going away | on 491, retry after `retry_after_ms` if still wanted |
| `Terminated` | the leg is gone; all its state is released | release resources mapped to the leg |
| `CommandRejected` | (runtime handle only) a queued command was refused | — |

Mandatory protocol actions never wait for the application: 100 Trying, the
ACK of an early-offer 2xx, ACK/BYE of forked or cancelled 2xx, 2xx and
request retransmissions, 481/487/491/500 answers.

## Overload and backpressure

- `max_legs`: new inbound INVITEs get 503 + Retry-After, `Originate` gets
  `CommandError::Overloaded`. Teardown is never limited.
- `drain()`: new calls are refused the same way; established ones continue.
- `max_pending_events`: when the application stops reading, the next
  non-critical event for a leg is not queued; that leg is failed explicitly
  (`Failed{Overload}` + `Terminated`, 503 / CANCEL / BYE on the wire)
  instead of losing the event silently. `Failed`/`Terminated` are always
  queued (at most one each per leg, and legs are bounded).
- The runtime's command and event channels are bounded; `submit` fails
  with `Overloaded` instead of blocking.

## Tests

```bash
cargo test -p sip-ua                                   # unit, scenarios, property, B2BUA, UDP runtime
SIP_UA_SEEDS=5000 cargo test --release -p sip-ua --test property
cargo build --release -p sip-ua --example b2bua && python3 tests/e2e_sip_ua.py
cargo run --release -p sip-ua --example bench -- 50000 20000
```

- `tests/scenarios.rs`: engines over a deterministic simulated network
  (fake clock, loss/duplication rules, scripted peers): basic call, lost
  INVITE/2xx, CANCEL (before a provisional, while ringing, racing a 2xx),
  forked 2xx, delayed offer (and its timeout), re-INVITE/UPDATE, rejection
  and rollback, glare, digest retries, missing ACK, BYE races, timeouts,
  overload/drain/event backpressure, transport failure.
- `tests/property.rs`: hundreds of seeds of random loss, duplication,
  reordering and application timing; checks that every leg ends exactly
  once, event sequences have no gaps, nothing reaches the application
  twice and no state is left.
- `tests/b2bua.rs`: the example's bridge, three engines.
- `tests/runtime_udp.rs`: real loopback sockets.
- `tests/e2e_sip_ua.py`: the example binary between independent SIP
  implementations (the Python UAs of `tests/sipkit.py`; SIPp when installed).
- `fuzz/fuzz_targets/sip_ua.rs`: parse/serialize round trip and the engine
  on arbitrary input; inputs it found are in `tests/fuzz_inputs/`.
