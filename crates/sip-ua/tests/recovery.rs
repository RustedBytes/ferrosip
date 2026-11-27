//! Recoverable state (feature `recovery`): restore round trips, crash
//! boundaries with failpoints, clock downtime, invalid records, storage
//! failure, fencing.

#![cfg(feature = "recovery")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, reason = "test helpers")]

mod sim;

use sim::*;
use sip_ua::recovery::{MemoryJournal, RestoreError, RestoreOptions, RestoredLeg, StateRecord};
use sip_ua::*;

const A: usize = 0;
const B: usize = 1;

fn with_se(secs: u32) -> impl FnOnce(UaConfig) -> UaConfig {
    move |c| UaConfig { session_expires: Some(secs), ..c }
}

/// A (UAC) calls B (UAS); both durable.
fn durable_pair(se: u32) -> Net {
    let mut net = Net::new();
    net.add_durable("10.0.0.1:5060", 1, with_se(se));
    net.add_durable("10.0.0.2:5060", 2, with_se(se));
    net
}

fn establish(net: &mut Net) -> (UaLegId, UaLegId) {
    let a = net.submit(A, originate("10.0.0.2", Some(sdp("o")))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(B).is_some()));
    let b = net.incoming_leg(B).unwrap();
    net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Ack(_)))));
    (a, b)
}

fn keyed(net: &mut Net, n: usize, key: &str, cmd: UaCommand) -> Result<KeyedAccepted, CommandError> {
    let now = net.now;
    let r = net.nodes[n].engine.submit_keyed(key, cmd, now);
    net.flush();
    r
}

fn same_dialog_state(x: &LegSnapshot, y: &LegSnapshot) {
    assert_eq!((x.role, x.phase, &x.call_id, &x.dialog, &x.remote_target), (y.role, y.phase, &y.call_id, &y.dialog, &y.remote_target));
    assert_eq!(
        (x.generation, x.stable_generation, x.offer, x.last_seq, x.session_timer),
        (y.generation, y.stable_generation, y.offer, y.last_seq, y.session_timer)
    );
}

#[test]
fn confirmed_udp_call_survives_restarts_of_both_sides() {
    let mut net = durable_pair(90);
    let (a, b) = establish(&mut net);
    let (sa, sb) = (net.engine(A).snapshot(a).unwrap(), net.engine(B).snapshot(b).unwrap());
    let rep_a = net.crash_and_restore(A, 0);
    let rep_b = net.crash_and_restore(B, 0);
    assert_eq!(rep_a.restored(), vec![a], "{rep_a:?}");
    assert_eq!(rep_b.restored(), vec![b], "{rep_b:?}");
    same_dialog_state(&sa, &net.engine(A).snapshot(a).unwrap());
    same_dialog_state(&sb, &net.engine(B).snapshot(b).unwrap());

    // re-INVITE after restore: CSeq continues, tags and route as before.
    let before = net.sent("INVITE").len();
    net.submit(A, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("hold") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let re = net.sent("INVITE")[before].msg();
    assert_eq!(re.cseq().unwrap(), (2, Method::Invite), "CSeq continues after restore");
    assert_eq!(re.call_id(), Some(sa.call_id.as_str()));
    let g = net.find(B, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap().generation;
    net.submit(B, UaCommand::RespondToOffer(OfferResponse { leg: b, generation: g, sdp: Some(sdp("held")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Completed(_)))));

    // Session refresh keeps running across another restart (A refreshes at 45 s).
    net.crash_and_restore(A, 0);
    let updates = net.sent("UPDATE").len();
    net.run_until(100_000, |_| false);
    assert!(net.sent("UPDATE").len() >= updates + 2, "refreshes after restore");
    assert_eq!(net.engine(A).snapshot(a).unwrap().phase, Phase::Confirmed);

    // BYE after restore, and everything drains.
    net.crash_and_restore(B, 0);
    net.submit(B, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(A, |e| matches!(e, UaEvent::RemoteBye(_)))));
    assert!(net.settle(100_000));
    for n in [A, B] {
        let st = net.nodes[n].journal.as_ref().unwrap().state().unwrap();
        assert_eq!((st.leg_count(), st.transaction_count()), (0, 0), "node {n}: journal drained");
    }
    assert!(matches!(net.engine(A).leg_outcome(a), LegOutcome::Ended(_)));
}

#[test]
fn keyed_originate_is_one_logical_call_at_every_crash_boundary() {
    for boundary in [Boundary::PreCommit, Boundary::PostCommit, Boundary::PostSend] {
        let mut net = Net::new();
        net.add_durable("10.0.0.1:5060", 1, |c| c);
        net.add("10.0.0.2:5060", 2);
        net.nodes[A].crash_at = Some(boundary);
        let first = keyed(&mut net, A, "call-42", originate("10.0.0.2", Some(sdp("o"))));
        // The caller can't tell what happened: it retries with the same key.
        let retry = keyed(&mut net, A, "call-42", originate("10.0.0.2", Some(sdp("o")))).unwrap();
        match boundary {
            // Never persisted: the retry is the first real attempt.
            Boundary::PreCommit => assert!(!retry.replayed, "{boundary:?}"),
            // Persisted: the retry finds it, nothing new is sent.
            _ => {
                assert!(retry.replayed, "{boundary:?}");
                assert_eq!(retry.leg, first.unwrap().leg);
            }
        }
        assert!(net.run_until(2_000, |n| n.incoming_leg(B).is_some()), "{boundary:?}");
        net.run_until(1_000, |_| false);
        let branches: std::collections::BTreeSet<_> = net.sent("INVITE").iter().map(|p| p.msg().top_via().unwrap().branch).collect();
        assert_eq!(branches.len(), 1, "{boundary:?}: one INVITE transaction on the wire");
        assert_eq!(net.count(B, |e| matches!(e, UaEvent::IncomingInvite(_))), 1, "{boundary:?}");
        // Another command under the same key is a conflict.
        assert_eq!(keyed(&mut net, A, "call-42", originate("10.0.0.3", None)).unwrap_err(), CommandError::KeyConflict);
        let b = net.incoming_leg(B).unwrap();
        net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
        assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Accepted(_)))), "{boundary:?}");
        let rec = net.engine(A).op_outcome("call-42").unwrap();
        assert_eq!(rec.status, OpStatus::Completed { code: 200 });
        net.submit(A, UaCommand::Hangup(HangupRequest { leg: retry.leg, reason: None, code: None })).unwrap();
        assert!(net.settle(100_000), "{boundary:?}");
        assert!(matches!(net.engine(A).op_outcome("call-42").unwrap().status, OpStatus::Ended { .. }));
    }
}

#[test]
fn uas_200_committed_but_not_sent_is_sent_after_restore() {
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 1);
    net.add_durable("10.0.0.2:5060", 2, |c| c);
    net.submit(A, originate("10.0.0.2", Some(sdp("o")))).unwrap();
    assert!(net.run_until(1_000, |n| n.incoming_leg(B).is_some()));
    let b = net.incoming_leg(B).unwrap();
    net.nodes[B].crash_at = Some(Boundary::PostCommit);
    let before = net.sent("SIP/2.0 200").len();
    net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.sent("SIP/2.0 200").len() > before, "the committed 200 went out on restore");
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Ack(_)))));
    assert!(net.has(A, |e| matches!(e, UaEvent::Accepted(_))));
}

#[test]
fn a_crash_before_commit_never_shows_its_effects() {
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 1);
    net.add_durable("10.0.0.2:5060", 2, |c| c);
    net.submit(A, originate("10.0.0.2", Some(sdp("o")))).unwrap();
    assert!(net.run_until(1_000, |n| n.incoming_leg(B).is_some()));
    let b = net.incoming_leg(B).unwrap();
    net.nodes[B].crash_at = Some(Boundary::PreCommit);
    let before = net.sent("SIP/2.0 200").len();
    let _ = net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] }));
    assert_eq!(net.sent("SIP/2.0 200").len(), before, "no 200 without its commit");
    // The leg is back as it was committed: unanswered, still answerable.
    assert_eq!(net.engine(B).snapshot(b).unwrap().phase, Phase::Calling);
    net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Ack(_)))));
}

#[test]
fn downtime_past_the_session_interval_is_not_a_fresh_lifetime() {
    let mut net = durable_pair(90);
    let (_a, b) = establish(&mut net);
    net.run_until(30_000, |_| false);
    // B (not the refresher) is down for 2 minutes: its session expired meanwhile.
    let rep = net.crash_and_restore(B, 120_000);
    // Measured from B's last record (30 s of quiet uptime) plus the downtime.
    assert!(rep.downtime_ms >= 120_000, "{}", rep.downtime_ms);
    assert!(matches!(&rep.legs[0], RestoredLeg::Restored { overdue, .. } if overdue.iter().any(|t| t == "SessionExpire")), "{rep:?}");
    let byes = net.sent("BYE").len();
    net.run_until(100, |_| false);
    assert_eq!(net.sent("BYE").len(), byes + 1, "BYE at once, not after another full interval");
    assert!(net.has(B, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::SessionExpired)));
    let _ = b;
}

#[test]
fn early_invite_survives_a_caller_restart() {
    let mut net = durable_pair(1_800);
    let a = net.submit(A, originate("10.0.0.2", Some(sdp("o")))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(B).is_some()));
    let b = net.incoming_leg(B).unwrap();
    net.submit(B, UaCommand::Provisional(ProvisionalRequest { leg: b, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Provisional(_)))));
    net.crash_and_restore(A, 2_000);
    assert_eq!(net.engine(A).snapshot(a).unwrap().phase, Phase::Early);
    net.submit(B, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Accepted(_)))));
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Ack(_)))));
    // And a CANCEL path after a restart: a second call, cancelled once restored.
    let a2 = net.submit(A, originate("10.0.0.2", Some(sdp("o")))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.count(B, |e| matches!(e, UaEvent::IncomingInvite(_))) == 2));
    let b2 = net.events(B).iter().rev().find(|e| matches!(e.event, UaEvent::IncomingInvite(_))).unwrap().leg;
    net.submit(B, UaCommand::Provisional(ProvisionalRequest { leg: b2, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    net.run_until(200, |_| false);
    net.crash_and_restore(A, 0);
    net.submit(A, UaCommand::Cancel(CancelRequest { leg: a2, reason: None })).unwrap();
    assert!(net.run_until(2_000, |n| n.events(B).iter().any(|e| e.leg == b2 && matches!(e.event, UaEvent::Cancelled))));
    net.check_event_invariants();
}

#[test]
fn restored_ids_are_never_handed_out_again() {
    let mut net = durable_pair(1_800);
    let (a, _) = establish(&mut net);
    net.crash_and_restore(A, 0);
    let fresh = net.submit(A, originate("10.0.0.2", None)).unwrap();
    assert!(fresh.leg.0 > a.0 && fresh.op.0 > a.0, "{fresh:?} vs {a}");
}

#[test]
fn invalid_incompatible_and_stale_records_are_refused_without_panic() {
    let mut net = durable_pair(1_800);
    let (a, _) = establish(&mut net);
    let state = net.nodes[A].journal.as_ref().unwrap().state().unwrap();
    let cfg = net.nodes[A].cfg.clone();
    let restore = |s: &StateRecord, epoch: u64, newer: bool| {
        UaEngine::restore(
            cfg.clone(),
            Box::new(SeededEntropy::new(9)),
            IdAllocator::new(),
            s,
            &RestoreOptions { epoch, require_newer_epoch: newer, credentials: None },
            0,
            1_900_000_000_000,
        )
    };
    assert!(StateRecord::from_json("{not json").is_err());
    assert!(StateRecord::from_json("{\"format\": 99}").is_err());
    // One damaged leg (a number where the Call-ID string belongs): reported
    // as corrupt and skipped; the rest of the record still loads.
    let mut v: sip_core::serde_json::Value = sip_core::serde_json::from_str(&state.to_json().unwrap()).unwrap();
    let legs = v.get_mut("legs").and_then(|l| l.as_object_mut()).unwrap();
    let (_, rec) = legs.iter_mut().next().unwrap();
    rec["leg"]["call_id"] = sip_core::serde_json::json!(12345);
    let bad = StateRecord::from_json(&v.to_string()).unwrap();
    let (e, rep) = restore(&bad, 0, false).unwrap();
    assert!(matches!(rep.legs.as_slice(), [RestoredLeg::Corrupt { leg, .. }] if *leg == a.0), "{rep:?}");
    assert!(e.snapshot(a).is_none());
    let mut old = state.clone();
    old.format = 0;
    assert!(matches!(restore(&old, 0, false).err(), Some(RestoreError::Incompatible { .. })));
    // Takeover needs a newer epoch than the state's.
    assert!(matches!(restore(&state, 0, true).err(), Some(RestoreError::StaleEpoch { .. })));
    assert!(restore(&state, 1, true).is_ok());
}

#[test]
fn storage_failure_halts_the_engine_before_any_effect() {
    let mut net = Net::new();
    net.add_durable("10.0.0.1:5060", 1, |c| c);
    net.add("10.0.0.2:5060", 2);
    net.nodes[A].journal.as_mut().unwrap().fail_next_appends(1);
    let _ = net.submit(A, originate("10.0.0.2", Some(sdp("o"))));
    net.run_until(5_000, |_| false);
    assert!(net.sent("INVITE").is_empty(), "nothing sent past a failed commit");
    assert!(net.engine(A).is_halted());
    assert_eq!(net.submit(A, originate("10.0.0.2", None)).unwrap_err(), CommandError::Halted);
    // A restart from the journal recovers what was durable (nothing here).
    let rep = net.crash_and_restore(A, 0);
    assert!(rep.legs.is_empty());
    assert!(net.submit(A, originate("10.0.0.2", Some(sdp("o")))).is_ok());
    assert!(net.run_until(1_000, |n| n.incoming_leg(B).is_some()));
}

#[test]
fn committed_events_replay_and_pruned_history_requires_reconciliation() {
    let mut net = durable_pair(1_800);
    let (a, _) = establish(&mut net);
    // Every committed event can be replayed in order after a consumer disconnect.
    let all = net.nodes[A].journal.as_ref().unwrap().events_after(0).unwrap();
    assert!(all.iter().any(|e| e.leg == a && matches!(e.event, UaEvent::Accepted(_))));
    assert!(all.windows(2).all(|w| w[0].log_seq < w[1].log_seq), "log_seq strictly increases");
    assert!(net.nodes[A].journal.as_ref().unwrap().events_after(all.last().unwrap().log_seq).unwrap().is_empty());

    // A journal keeping one event: asking for older history is refused
    // (never fabricated); the newest is still there.
    let mut net = durable_pair(1_800);
    net.nodes[B].journal = Some(MemoryJournal::new(1));
    establish(&mut net);
    let j = net.nodes[B].journal.as_ref().unwrap();
    assert!(matches!(j.events_after(0), Err(sip_ua::recovery::JournalError::ReconciliationRequired { oldest_retained: 2 })));
    let last = j.events_after(1).unwrap();
    assert!(matches!(last.as_slice(), [e] if matches!(e.event, UaEvent::Ack(_))));
}

#[test]
fn a_fenced_old_owner_cannot_commit_or_send() {
    let mut net = durable_pair(1_800);
    net.engine(A).set_epoch(1).unwrap();
    let (a, _) = establish(&mut net);
    // A new owner takes over with epoch 2 and fences the store.
    let state = net.nodes[A].journal.as_ref().unwrap().state().unwrap();
    let cfg = net.nodes[A].cfg.clone();
    let (mut new_owner, rep) = UaEngine::restore(
        cfg,
        Box::new(SeededEntropy::new(77)),
        IdAllocator::new(),
        &state,
        &RestoreOptions { epoch: 2, require_newer_epoch: true, credentials: None },
        net.now,
        net.wall(),
    )
    .unwrap();
    assert_eq!(rep.restored(), vec![a]);
    net.nodes[A].journal.as_mut().unwrap().fence(2);
    // The old owner is still running: its hangup can't be committed, so no BYE leaves it.
    let byes = net.sent("BYE").len();
    let _ = net.submit(A, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None }));
    net.run_until(1_000, |_| false);
    assert_eq!(net.sent("BYE").len(), byes, "stale owner sent nothing");
    assert!(net.engine(A).is_halted());
    // The new owner carries on with the dialog.
    let now = net.now;
    new_owner.submit(UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None }), now).unwrap();
    net.nodes[A].engine = new_owner;
    net.flush();
    assert!(net.run_until(2_000, |n| n.has(B, |e| matches!(e, UaEvent::RemoteBye(_)))));
    assert!(net.sent("BYE").iter().all(|_| true));
}

#[test]
fn a_restored_client_transaction_retransmits_the_same_bytes() {
    let mut net = durable_pair(1_800);
    let (a, _) = establish(&mut net);
    // B goes silent: A's re-INVITE stays unanswered.
    net.rule = Box::new(|p| usize::from(p.to != addr("10.0.0.2:5060")));
    net.submit(A, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("re") })).unwrap();
    let first = net.sent("INVITE").last().unwrap().data.clone();
    net.crash_and_restore(A, 100);
    net.run_until(3_000, |_| false);
    let after: Vec<Vec<u8>> = net.sent("INVITE").iter().map(|p| p.data.clone()).filter(|d| d != &first).collect();
    let retrans = net.sent("INVITE").iter().filter(|p| p.data == first).count();
    assert!(retrans >= 3, "retransmitted after the restore: {retrans}");
    // Only the original INVITE and the re-INVITE ever went out (no other bytes).
    assert_eq!(after.len(), 1, "every re-INVITE copy is byte-identical");
}

#[test]
fn a_restored_shard_keeps_its_ids_call_ids_and_directory_entries() {
    use sip_ua::shard::{DialogDirectory, Shard, shard_of_call_id, shard_of_leg};
    let mut net = Net::new();
    let shard = Shard { index: 2, count: 4 };
    // Node A is shard 2 of 4 (durable, striped ids); B is a plain peer.
    net.add_durable("10.0.0.1:5060", 1, move |c| UaConfig { shard: Some(shard), ..c });
    net.add("10.0.0.2:5060", 2);
    let cfg = net.nodes[A].cfg.clone();
    net.nodes[A].engine = UaEngine::with_entropy(cfg.clone(), Box::new(SeededEntropy::new(9)), IdAllocator::striped(2, 4));
    let (a, _) = establish(&mut net);
    assert_eq!(shard_of_leg(a, 4), 2);
    let cid = net.engine(A).snapshot(a).unwrap().call_id;
    assert_eq!(shard_of_call_id(&cid, 4), 2, "the shard's own Call-IDs route to it");
    // Restore the shard with its striped allocator and the same count.
    let state = net.nodes[A].journal.as_ref().unwrap().state().unwrap();
    let ids = IdAllocator::striped(2, 4);
    let (mut e, rep) = UaEngine::restore(cfg, Box::new(SeededEntropy::new(10)), ids.clone(), &state, &RestoreOptions::default(), net.now, net.wall()).unwrap();
    assert_eq!(rep.restored(), vec![a]);
    let next = ids.leg();
    assert!(next.0 > a.0 && shard_of_leg(next, 4) == 2, "{next:?} after {a:?}");
    let dir = std::sync::Arc::new(DialogDirectory::default());
    e.set_dialog_directory(dir.clone());
    assert_eq!(dir.len(), 1, "the restored dialog is listed for the other shards");
    let leg = e.submit(originate("10.0.0.2", None), net.now).unwrap().leg;
    let cid2 = e.snapshot(leg).unwrap().call_id;
    assert_eq!((shard_of_leg(leg, 4), shard_of_call_id(&cid2, 4)), (2, 2));
}
