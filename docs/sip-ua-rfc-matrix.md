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
| §17.1.1.2 / §17.1.2.2 reliable transports: no retransmissions, D/K = 0 | Tested | `invite_client_reliable_*`, `non_invite_server_replays_final`; calls over TCP/TLS/WS/WSS in `runtime_transport.rs` |
| §17.2.3 server txn matching (branch + sent-by + method; ACK → INVITE) | Tested | duplicates in `lost_invite_*` and the property test |
| §17.2.3 RFC 2543 (no magic cookie) matching | Implemented | fallback key on Call-ID/From-tag/CSeq/sent-by; no test |
| §8.1.3.5 / §21.4.29 bounded auth retries, new CSeq and branch per retry | Tested | `digest_challenge_is_retried_a_bounded_number_of_times` |
| §8.2.2.2 merged requests → 482 | Tested | `branch_changing_clients_are_strict_by_default_and_lenient_on_request` (with the opt-in RFC 2543-style matching for clients that change the branch) |
| §8.2.2.3 `Require` we don't support → 420 + Unsupported (only the unknown tags; `100rel` and `timer` are supported) | Tested | `uas_rejects_bad_requests_statelessly_enough` |
| §8.2.6 / §18.2.2 response routing: received / rport (RFC 3581), connection reuse on reliable transports | Tested | `engine` `response_destination`; responses and in-dialog requests over the arrival connection in `runtime_transport.rs` and `e2e_sip_ua.py` (TCP caller) |
| §9.1 CANCEL client: waits for a provisional, same branch, own txn, 64·T1 guard | Tested | `cancel_waits_for_a_provisional`, `cancel_before_answer_*` |
| §9.2 CANCEL server: 200 + 487, unmatched → 481 | Tested | `cancel_before_answer_*`, `branch_changing_clients_*` |
| §12.1 dialog creation (UAC/UAS), route set, Record-Route order | Tested | `basic_call_*`, `forked_2xx_*` (Record-Route reversal is exercised only without proxies) |
| §12.2.1.1 strict-router compatibility | Unit-tested | `engine.rs` `routing_rules` |
| §12.2.2 remote CSeq must increase (500 otherwise) | Implemented | no test |
| §12.2.1.2 481/408 to an in-dialog request ends the dialog | Implemented | no test |
| §13.2.2.4 ACK every 2xx; forked 2xx: ACK + BYE; ACK retransmitted 2xx | Tested | `forked_2xx_are_all_acked_and_losers_get_bye`, `lost_invite_and_lost_200_*` |
| §13.3.1.4 UAS 2xx retransmission (T1 doubling to T2) until ACK; 64·T1 → BYE | Tested | `missing_ack_ends_the_call_with_bye` |
| §14 re-INVITE: one outstanding, 491 glare with §14.1 retry windows, 500 + Retry-After | Tested | `reinvite_glare_*`, `rejected_reinvite_*`, property test (500 when a re-INVITE overtakes the ACK) |
| §15 BYE: UAS waits for its ACK; simultaneous BYE | Tested | `bye_before_ack_from_uas_waits_for_the_ack`, `simultaneous_bye_is_idempotent` |
| §15.1.2 pending requests answered 487 when the dialog ends | Tested | every server transaction of a leg still owed a final (INVITE, re-INVITE, UPDATE, REFER) gets 487 when the leg ends; the property test hangs up with a REFER pending and requires no state left (`cancel_*` cover the INVITE case) |
| §19.3 tags, branches, Call-IDs cryptographically random | Implemented | `SystemEntropy` (ring `SystemRandom`) |
| §22 digest (client): MD5, SHA-256, SHA-512-256, qop=auth, `-sess`, realm pinning, credential redaction | Tested (MD5 vectors) | `auth.rs` tests (RFC 2617 vectors); SHA variants only checked for header form |
| §26.2 SIPS: `sips:` R-URI over non-TLS rejected; sips Contact over TLS | Implemented | no test (TLS itself is tested with `sip:` URIs) |
| **RFC 3263** locating servers | Tested | resolution delegated to the driver (`ResolveRequest`; the runtimes use ferrosip's NAPTR/SRV/A resolver off the engine thread). §4.3 failover of the initial INVITE to the next target on transport error, timeout, 503, or no response within `failover_timeout_ms`: `failover.rs` tests. DNS failure: `dns_failure_is_reported_as_dns`, `runtime_udp.rs` |
| **RFC 3264** offer/answer | Tested | early offer (`basic_call_*`), delayed offer with the answer in the ACK (`delayed_offer_*`), one offer at a time (`OfferPending`), rejection + rollback (`rejected_reinvite_*`), safe failure when the application doesn't answer (`delayed_offer_without_application_answer_acks_then_byes`), early answer in an unreliable 1xx. Hold/resume is an application SDP change carried by `Negotiate` |
| **RFC 3262** PRACK / 100rel | Tested | `tests/prack.rs`: reliable 1xx when required, or supported and carrying SDP; retransmission until PRACK and 5xx after 64·T1; one outstanding, later ones queued with consecutive RSeq; RAck matching (481 otherwise); UAC PRACKs in RSeq order, drops duplicates and out-of-order 1xx; offer in a reliable 1xx answered in the PRACK; no 2xx before the PRACK of our offer; loss of 1xx and PRACK. Not done: offers in the PRACK itself (ignored) |
| **RFC 3311** UPDATE | Tested | confirmed dialogs: `reinvite_and_update_*`; early dialogs after a reliable exchange, both directions: `early_update_both_ways_after_reliable_exchange` (a UAC sends early UPDATE only with a single early dialog) |
| **RFC 3326** Reason | Tested | Q.850 cause read from responses/BYE (`cause.rs`), sent on CANCEL/BYE (`no_answer_timeout_cancels`) |
| **RFC 3398** SIP → Q.850 mapping | Tested | `cause.rs` `mapping_and_reason_override` |
| §8.1.3.4 redirection (3xx) | Tested | `tests/redirect.rs`: contacts reported in q order by default; followed with `max_redirects`, never revisiting a URI, capped |
| **RFC 3515** REFER and its implicit subscription | Tested | `tests/transfer.rs`: REFER → 202 + NOTIFY "100 Trying" → progress NOTIFYs (`message/sipfrag`) until `Subscription-State: terminated`; declined (603) and unanswered (603 at the deadline); a NOTIFY may overtake the 202; stray NOTIFY → 481, other event package → 489; one REFER per direction and dialog (a second gets 500). Not done: REFER outside a dialog, several subscriptions (`id`) per dialog |
| **RFC 3891** Replaces | Tested | `tests/transfer.rs`: attended transfer end to end (Refer-To with an escaped Replaces built from our dialog id, the target maps it to its leg); 481 unknown dialog or our own early one, 486 `early-only` on a confirmed one, 400 malformed. Replacing (accepting, ending the old leg) is the application's decision |
| **RFC 3325** P-Asserted-Identity / **RFC 3323** Privacy | Tested | `tests/identity.rs`: PAI surfaced only from trusted sources (CIDR trust list), sent only to trusted next hops (removed at the single request egress point, counted), not settable through free-form headers; Privacy values validated and passed both ways |
| **RFC 4028** session timers | Tested | `tests/session_timers.rs`: negotiation and refresher choice (§7, §9), refresh by UPDATE at half the interval or re-INVITE with our last SDP when the peer lacks UPDATE, 422/Min-SE renegotiation, BYE at interval − min(32 s, interval/3) without refresh, UAS as refresher for a caller without timer support. Refreshes are internal: no application event |
| **RFC 5626** SIP Outbound flows | Partial | flow affinity kept for reliable transports (the leg's `Dest` with connection id; tested over TCP/TLS/WS/WSS), cleared on `TransportEvent::Closed`; no keep-alive, `ob`/flow-token or flow-failure handling |
| **RFC 6026** Accepted states (timers L, M) | Tested | `txn.rs` `invite_client_accepted_state_passes_every_2xx`, `invite_server_accepted_absorbs_retransmissions` |
| **RFC 6086** INFO and Info Packages | Tested | `info_is_delivered_and_completed`; DTMF in `application/dtmf-relay` / `application/dtmf` parsed, sent with `SendDtmf`, and flagged when the peer's SDP has RFC 4733 telephone-event (`tests/dtmf.rs`). Info Packages (`UaConfig::recv_info`): `Recv-Info` on INVITE, re-INVITE, UPDATE and our 18x/2xx to them (empty when we accept none); the peer's latest list per leg (`LegSnapshot::peer_recv_info`); `SendInfo { package }` refused unless the peer listed it; an INFO for a package we did not list gets 469 with our `Recv-Info`; legacy INFO without `Info-Package` still delivered (`tests/info_packages.rs`). Not done: `Recv-Info` in PRACK/ACK, per-leg lists, package-specific body rules |
| **RFC 6337** offer/answer usage | Partial | followed for glare, rollback and delayed offer; not audited section by section |
| **RFC 7092** taxonomy of B2BUAs | Informative | the example is a signalling-only B2BUA with an optional media adapter |

## Transports

`runtime::spawn_transport` runs the engine on ferrosip's own transport
layer (`sip-transport`): UDP workers, TCP, TLS, WS and WSS listeners, the
connection table and outbound connects (feature `transport`, on by
default). `tests/runtime_transport.rs` places calls over each of them on
loopback, with the callee's BYE reusing the inbound connection;
`tests/e2e_sip_ua.py` has a TCP caller reaching a UDP callee through the
example B2BUA. `runtime::spawn_udp` is a minimal std-only UDP driver.
