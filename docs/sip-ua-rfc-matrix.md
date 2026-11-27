# sip-ua RFC compliance matrix

Status of [`sip-ua`](../crates/sip-ua/README.md) against the RFCs the
specification names. **Tested** means a test exercises the behaviour (the
test is named); **implemented** means the code exists but no test covers it
yet, so it is not claimed as supported. Test names refer to
`crates/sip-ua/tests/scenarios.rs` unless another file is given.

| Area | Status | Evidence / notes |
|---|---|---|
| **RFC 3261** | | |
| §17.1.1 INVITE client txn: timers A/B/D, ACK for non-2xx, absorb retransmitted finals | Tested | `txn.rs` unit tests (`invite_client_*`); `lost_invite_and_lost_200_*`; `unanswered_invite_times_out_with_408` |
| §17.1.2 non-INVITE client txn: E (capped at T2, T2 after 1xx), F, K | Tested | `txn.rs` `non_invite_client_caps_at_t2` |
| §17.2.1 INVITE server txn: immediate 100, G (capped), H, I | Tested | `txn.rs` `invite_server_*`; `missing_ack_ends_the_call_with_bye` |
| §17.2.2 non-INVITE server txn: J, final replayed for retransmissions | Tested | `txn.rs` `non_invite_server_replays_final`; `uas_rejects_bad_requests_statelessly_enough` |
| §17.1.1.2 / §17.1.2.2 reliable transports: no retransmissions, D/K = 0 | Tested (state machine) | `invite_client_reliable_*`, `non_invite_server_replays_final`; no TCP/TLS/WS driver yet (see below) |
| §17.2.3 server txn matching (branch + sent-by + method; ACK → INVITE) | Tested | duplicates in `lost_invite_*` and the property test |
| §17.2.3 RFC 2543 (no magic cookie) matching | Implemented | fallback key on Call-ID/From-tag/CSeq/sent-by; no test |
| §8.1.3.5 / §21.4.29 bounded auth retries, new CSeq and branch per retry | Tested | `digest_challenge_is_retried_a_bounded_number_of_times` |
| §8.2.2.2 merged requests → 482 | Implemented | no test |
| §8.2.2.3 `Require` we don't support → 420 + Unsupported | Tested | `uas_rejects_bad_requests_statelessly_enough` |
| §8.2.6 / §18.2.2 response routing: received / rport (RFC 3581), connection reuse on reliable transports | Tested (UDP) | `engine.rs` `response_destination`; reliable path untested |
| §9.1 CANCEL client: waits for a provisional, same branch, own txn, 64·T1 guard | Tested | `cancel_waits_for_a_provisional`, `cancel_before_answer_*` |
| §9.2 CANCEL server: 200 + 487, unmatched → 481 | Tested (200/487) | `cancel_before_answer_*`; 481 path untested |
| §12.1 dialog creation (UAC/UAS), route set, Record-Route order | Tested | `basic_call_*`, `forked_2xx_*` (Record-Route reversal is exercised only without proxies) |
| §12.2.1.1 strict-router compatibility | Unit-tested | `engine.rs` `routing_rules` |
| §12.2.2 remote CSeq must increase (500 otherwise) | Implemented | no test |
| §12.2.1.2 481/408 to an in-dialog request ends the dialog | Implemented | no test |
| §13.2.2.4 ACK every 2xx; forked 2xx: ACK + BYE; ACK retransmitted 2xx | Tested | `forked_2xx_are_all_acked_and_losers_get_bye`, `lost_invite_and_lost_200_*` |
| §13.3.1.4 UAS 2xx retransmission (T1 doubling to T2) until ACK; 64·T1 → BYE | Tested | `missing_ack_ends_the_call_with_bye` |
| §14 re-INVITE: one outstanding, 491 glare with §14.1 retry windows, 500 + Retry-After | Tested | `reinvite_glare_*`, `rejected_reinvite_*`, property test (500 when a re-INVITE overtakes the ACK) |
| §15 BYE: UAS waits for its ACK; simultaneous BYE | Tested | `bye_before_ack_from_uas_waits_for_the_ack`, `simultaneous_bye_is_idempotent` |
| §15.1.2 pending requests answered 487 when the dialog ends | Implemented | partially covered by `cancel_*`; re-INVITE pending at BYE untested |
| §19.3 tags, branches, Call-IDs cryptographically random | Implemented | `SystemEntropy` (ring `SystemRandom`) |
| §22 digest (client): MD5, SHA-256, SHA-512-256, qop=auth, `-sess`, realm pinning, credential redaction | Tested (MD5 vectors) | `auth.rs` tests (RFC 2617 vectors); SHA variants only checked for header form |
| §26.2 SIPS: `sips:` R-URI over non-TLS rejected; sips Contact over TLS | Implemented | no test; no TLS driver yet |
| **RFC 3263** locating servers | Partial | delegated to the driver (`ResolveRequest`; the runtime uses ferrosip's NAPTR/SRV/A resolver off the engine thread). Only the first target is used: no failover to the next SRV target yet. DNS failure tested in `runtime_udp.rs` |
| **RFC 3264** offer/answer | Tested | early offer (`basic_call_*`), delayed offer with the answer in the ACK (`delayed_offer_*`), one offer at a time (`OfferPending`), rejection + rollback (`rejected_reinvite_*`), safe failure when the application doesn't answer (`delayed_offer_without_application_answer_acks_then_byes`), early answer in an unreliable 1xx. Hold/resume is an application SDP change carried by `Negotiate` |
| **RFC 3262** PRACK / 100rel | Not implemented | `Require: 100rel` → 420; incoming PRACK → 481; reliable provisionals are never sent. P0c work |
| **RFC 3311** UPDATE | Tested (confirmed dialogs) | `reinvite_and_update_*`, glare rules shared with re-INVITE; UPDATE in early dialogs is not supported (needs RFC 3262) |
| **RFC 3326** Reason | Tested | Q.850 cause read from responses/BYE (`cause.rs`), sent on CANCEL/BYE (`no_answer_timeout_cancels`) |
| **RFC 3398** SIP → Q.850 mapping | Tested | `cause.rs` `mapping_and_reason_override` |
| **RFC 3515 / 3891** REFER, Replaces | Not implemented | REFER → 501. P1 |
| **RFC 4028** session timers | Not implemented | `Require: timer` → 420; `Session-Expires` ignored. P0c work |
| **RFC 5626** SIP Outbound flows | Partial | flow affinity kept for reliable transports (`Leg::flow`), cleared by `handle_flow_closed`; no keep-alive or flow-token handling; untested |
| **RFC 6026** Accepted states (timers L, M) | Tested | `txn.rs` `invite_client_accepted_state_passes_every_2xx`, `invite_server_accepted_absorbs_retransmissions` |
| **RFC 6086** INFO | Tested (no packages) | `info_is_delivered_and_completed`; Info-Package negotiation and DTMF de-duplication are P1 |
| **RFC 6337** offer/answer usage | Partial | followed for glare, rollback and delayed offer; not audited section by section |
| **RFC 7092** taxonomy of B2BUAs | Informative | the example is a signalling-only B2BUA with an optional media adapter |

## Transports

The engine is transport-neutral (every message carries a `Dest` with its
protocol, and connection affinity is kept per leg), but only UDP has a
driver today (`runtime.rs`). TCP, TLS, WS and WSS need the driver that
plugs the engine into `sip-transport`'s workers; until that exists and is
tested, they are not supported.
