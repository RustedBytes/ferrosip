# sip-ua

A reusable SIP user agent engine — UAC and UAS — for building B2BUAs and
softswitches on ferrosip. It terminates inbound dialogs and originates
independent outbound ones; the application (the softswitch) owns call
policy, bridging and media.

- **Sans-IO.** The engine does no I/O, never blocks and never sleeps. A
  driver feeds it received messages, the clock (monotonic milliseconds) and
  DNS results, and sends what it emits. Tests drive it with a fake clock and
  a simulated network. [`runtime`](src/runtime.rs) has two drivers:
  `spawn_transport` runs the engine on ferrosip's own transport layer
  (UDP, TCP, TLS, WS, WSS — feature `transport`, on by default) and
  `spawn_udp` is a minimal std-only one.
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

With a driver, the application only submits commands and reads events:

```rust
use sip_ua::runtime::{spawn_transport, RuntimeConfig, SystemResolver};

let tcfg = sip_transport::Config {
    listen: vec![sip_transport::Listen::parse("udp:192.0.2.10:5060")?, sip_transport::Listen::parse("tls:192.0.2.10:5061")?],
    ..cfg_with_tls_files
};
let ua = spawn_transport(UaConfig::default(), &tcfg, Box::new(SystemResolver), RuntimeConfig::default())?;
let acc = ua.submit(UaCommand::Originate(Box::new(req)))?;   // never blocks
for ev in ua.events() { /* … */ }
```

`cargo run -p sip-ua --example b2bua -- udp:127.0.0.1:5070,tcp:127.0.0.1:5070 127.0.0.1:5080 [--rtpflux 127.0.0.1:2223]`
runs a two-leg B2BUA: every inbound call is originated as an independent
call to the target; media is passed through, or anchored in rtpflux over
its ng protocol (`examples/b2bua/rtpflux.rs`).

### Configuration (`UaConfig`)

| Field | Default | Meaning |
|---|---|---|
| `local` | from the driver | Via/Contact address per transport |
| `timers` | T1 500, T2 4000, T4 5000 ms | RFC 3261 timers |
| `limits` | 64 KiB message, 128 headers, 8 KiB header, 32 KiB body | received messages beyond these are dropped |
| `max_legs` | 10 000 | new legs beyond this: 503 / `Overloaded` |
| `max_pending_events` | 4 096 | see Overload below |
| `max_auth_attempts` | 2 | digest retries per INVITE |
| `answer_timeout_ms` | 5 000 | time to answer a `RemoteOffer` |
| `no_answer_timeout_ms` | 120 000 | outbound: CANCEL without a 2xx |
| `uas_answer_timeout_ms` | 180 000 | inbound: 480 without a final |
| `session_expires` / `min_se` | 1800 s / 90 s | RFC 4028 (None: only honour the peer's) |
| `failover_timeout_ms` | 4 000 | RFC 3263: next target when nothing answered (0: errors/timeouts/503 only) |
| `refer_timeout_ms` | 180 000 | our REFER's subscription must end within this |
| `max_redirects` | 0 | follow up to this many 3xx (0: report contacts to the application) |
| `trust` | nobody | RFC 3325 trust domain (CIDR list) for P-Asserted-Identity |
| `max_early_dialogs` | 16 | forked early dialogs kept per outbound leg |
| `lenient_matching` | false | match INVITE retransmissions / CANCELs that change the Via branch (RFC 2543 style) |

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
| `Provisional` | inbound, unanswered | 101–199 with our tag and Contact. Sent reliably (RFC 3262: Require 100rel, RSeq, retransmitted until PRACK) when the caller requires 100rel, or supports it and the 1xx carries SDP; then the SDP may also be our offer (delayed-offer INVITE). Body-less reliable 1xx wait for the previous one's PRACK | our offer in a reliable 1xx: `Completed{sdp: answer}` when the PRACK arrives |
| `Accept` | inbound, unanswered; not while our offer in a reliable 1xx awaits its PRACK (`OfferPending`) | 200 with the answer (or our offer, if the INVITE had none; no SDP needed if the exchange completed in a reliable 1xx); Session-Expires; retransmits it until ACK | `Ack` (with the answer, for delayed offer) or `Failed{NoAck}` |
| `Reject` | inbound, unanswered | 300–699; the transaction absorbs the ACK | `Terminated` |
| `Cancel` | outbound, unanswered | CANCEL, after the first provisional (RFC 3261 §9.1); a 2xx that crosses it is ACKed and BYEd | `Terminated{Cancelled}` |
| `Hangup` | any; idempotent | the right teardown: CANCEL, a final (default 480), or BYE — an inbound leg waits for the ACK of its 2xx first | `Terminated` |
| `Negotiate` | confirmed, no offer outstanding; UPDATE also in an early dialog after a reliable exchange | re-INVITE or UPDATE with our offer | `Completed{sdp: answer}` or `Failed{leg_failed: false}` (rolled back; 491 carries `retry_after_ms`) |
| `SendInfo` | confirmed | INFO | `Completed` / `Failed` |
| `SendDtmf` | confirmed | INFO `application/dtmf-relay` | `Completed` / `Failed` |
| `Refer` | confirmed, no REFER of ours running | REFER (Refer-To; attended transfer: `refer::refer_to_with_replaces`) | `Completed` (202), then `ReferProgress` until `last` |
| `RespondToRefer` | a `ReferRequested` is pending | 202 + NOTIFY "100 Trying", or 603 | — |
| `NotifyRefer` | we accepted a REFER | NOTIFY with a sipfrag status; `last` ends the subscription | — |
| `RespondToOffer` | a `RemoteOffer` is outstanding and `generation` matches | answers it (2xx / ACK body), or rejects with `sdp: None` (488, rollback) | — |

Header fields the engine owns (Via, From, To, Call-ID, CSeq, Contact,
Content-Type, Max-Forwards, Route, Record-Route, …) cannot be set through
`headers`; names must be tokens and values must not contain line breaks.

### Events and the application's duty

| Event | Meaning | Application must |
|---|---|---|
| `IncomingInvite` | new inbound leg (100 Trying already sent); `replaces` names the leg an RFC 3891 INVITE replaces; `asserted_identity` only from trusted sources | `Provisional`/`Accept`/`Reject` within `uas_answer_timeout_ms` (else 480) |
| `Provisional` | 1xx with a to-tag (forked early dialogs differ in `remote_tag`) | — |
| `Accepted` | the outbound leg is confirmed and ACKed (early offer) | if a `RemoteOffer{InviteResponse}` follows, answer it |
| `RemoteOffer` | an offer to answer (`kind`: 2xx of our delayed-offer INVITE, reliable provisional, re-INVITE, UPDATE) | `RespondToOffer` before `deadline`, else the engine rejects it (2xx case: ACK with an all-streams-rejected answer, then BYE; reliable 1xx: PRACK with that answer, then CANCEL) |
| `Ack` | our 2xx was ACKed (with the answer if we offered) | — |
| `Cancelled` | the caller cancelled the inbound INVITE (487 sent) | — (`Terminated` follows) |
| `RemoteBye` | the peer hung up (200 sent) | — (`Terminated` follows) |
| `Info` | INFO received (200 sent); `dtmf` parsed, `rtp_dtmf_negotiated` when the peer's SDP has telephone-event | act on DTMF from one source only |
| `ReferRequested` | the peer asks us to call `target` (with `replaces` for an attended transfer) | `RespondToRefer` before `deadline` (else 603); if accepted, `Originate` (pass `replaces`) and report with `NotifyRefer` |
| `ReferProgress` | a NOTIFY for our REFER (sipfrag status; `last`) | — |
| `Completed` / `Failed` | an operation ended; `Failed.leg_failed` says whether the leg is going away | on 491, retry after `retry_after_ms` if still wanted |
| `Terminated` | the leg is gone; all its state is released | release resources mapped to the leg |
| `CommandRejected` | (runtime handle only) a queued command was refused | — |

Mandatory protocol actions never wait for the application: 100 Trying, the
ACK of an early-offer 2xx, ACK/BYE of forked or cancelled 2xx, PRACKs of
reliable 1xx without an offer, 2xx / reliable 1xx / request
retransmissions, session refreshes and their expiry BYE, RFC 3263
failover, 422 retries, 481/487/491/500 answers.

## Routing adapters

`routing` turns where-to-call decisions into `OriginateRequest` fields:
`ContactLookup` (registered users; `UsrlocContacts` reads ferrosip's
usrloc with `--features location`: best q first, the NAT-safe address and
connection the REGISTER came from as next hop, Path as route set) and
`TrunkRouter` (`PrefixTrunks`: longest prefix, failover order, strip/add
digits, per-trunk credentials).

## Overload and backpressure

- `max_legs`: new inbound INVITEs get 503 + Retry-After, `Originate` gets
  `CommandError::Overloaded`. Teardown is never limited.
- `drain()`: new calls are refused the same way; established ones continue.
- `max_pending_events`: when the application stops reading, the next
  non-critical event for a leg is not queued; that leg is failed explicitly
  (`Failed{Overload}` + `Terminated`, 503 / CANCEL / BYE on the wire)
  instead of losing the event silently. `Failed`/`Terminated` are always
  queued (at most one each per leg, and legs are bounded).
- The runtime's input and event channels are bounded; `submit` fails
  with `Overloaded` instead of blocking; with `spawn_transport`, a full
  input queue answers new requests 503 (`RuntimeStats`).

## Tests

```bash
cargo test -p sip-ua                                   # unit, scenarios, property, B2BUA, runtimes (TLS/WSS need etc/tls/gen-certs.sh)
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
- `tests/session_timers.rs`, `tests/prack.rs`, `tests/failover.rs`:
  RFC 4028, RFC 3262 (+ early UPDATE), RFC 3263 failover;
  `tests/transfer.rs` (REFER, Replaces), `tests/redirect.rs` (3xx),
  `tests/identity.rs` (RFC 3325/3323), `tests/dtmf.rs`,
  `tests/routing_location.rs` (usrloc adapter; `--features location`).
- `tests/b2bua.rs`: the example's bridge, three engines;
  `tests/b2bua_rtpflux.rs`: the same with a real rtpflux and real RTP
  (skipped without the binary; `RTPFLUX=path`).
- `tests/runtime_udp.rs`, `tests/runtime_transport.rs`: real loopback
  sockets — std UDP, and ferrosip's transports (UDP, TCP, TLS, WS, WSS).
- `tests/e2e_sip_ua.py`: the example binary between independent SIP
  implementations (the Python UAs of `tests/sipkit.py`, UDP and TCP;
  SIPp when installed).
- `fuzz/fuzz_targets/sip_ua.rs`: parse/serialize round trip and the engine
  on arbitrary input; inputs it found are in `tests/fuzz_inputs/`.
