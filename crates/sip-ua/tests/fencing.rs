//! Ownership fencing with two incarnations (feature `recovery`): a new
//! owner takes a node over while the old one keeps running — it hears the
//! node's traffic, its timers fire, it may or may not reach the store —
//! and nothing the old owner does after the takeover reaches the wire.

#![cfg(feature = "recovery")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, reason = "test helpers")]

mod sim;

use sim::*;
use sip_ua::recovery::{FileJournal, JournalError, RestoreOptions};
use sip_ua::*;

const A: usize = 0;
const B: usize = 1;
const A_ADDR: &str = "10.0.0.1:5060";

fn pair(se: u32) -> Net {
    let mut net = Net::new();
    net.add_durable(A_ADDR, 1, |c| UaConfig { session_expires: Some(se), ..c });
    net.add_durable("10.0.0.2:5060", 2, |c| UaConfig { session_expires: Some(se), ..c });
    net.engine(A).set_epoch(1).unwrap();
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

/// Packets the node at `from` put on the wire at or after `t` under an epoch older than `epoch`.
fn stale_packets(net: &Net, from: &str, t: u64, epoch: u64) -> Vec<String> {
    net.log.iter().filter(|p| p.from == addr(from) && p.at >= t && p.epoch < epoch).map(Packet::first_line).collect()
}

fn answer_offer(net: &mut Net, n: usize) {
    let e = net.events(n).iter().rev().find(|e| matches!(e.event, UaEvent::RemoteOffer(_))).cloned().expect("an offer");
    net.submit(n, UaCommand::RespondToOffer(OfferResponse { leg: e.leg, generation: e.generation, sdp: Some(sdp("r")) })).unwrap();
}

#[test]
fn a_zombie_that_hears_everything_and_reaches_the_store_sends_nothing() {
    let mut net = pair(1_800);
    let (a, b) = establish(&mut net);
    let t0 = net.now;
    let rep = net.take_over(A, 2, true, true);
    assert_eq!(rep.restored(), vec![a]);
    // The peer renegotiates: both incarnations get the re-INVITE.
    net.submit(B, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("re") })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(A, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    answer_offer(&mut net, A);
    assert!(net.run_until(2_000, |n| n.nodes[B].engine.snapshot(b).is_some_and(|s| s.offer == OfferState::Stable && s.stable_generation == s.generation)));
    let st = net.nodes[A].stale.as_ref().unwrap();
    assert!(st.engine.is_halted(), "the zombie's commit was refused: it halted");
    assert!(st.events.is_empty(), "the zombie's application heard nothing");
    // The call goes on with the new owner, to the end.
    net.submit(B, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(A, |e| matches!(e, UaEvent::RemoteBye(_)))));
    assert!(net.settle(60_000));
    assert_eq!(stale_packets(&net, A_ADDR, t0, 2), Vec::<String>::new());
    let st = net.nodes[A].journal.as_ref().unwrap().state().unwrap();
    assert_eq!((st.leg_count(), st.transaction_count(), st.epoch), (0, 0, 2));
}

#[test]
fn a_zombie_partitioned_from_the_store_does_not_even_answer_statelessly() {
    let mut net = pair(1_800);
    let (_, b) = establish(&mut net);
    let t0 = net.now;
    net.take_over(A, 2, true, false);
    // Requests the engine answers without state (OPTIONS; BYE for a dialog
    // it does not know) from a third party: one answer each, the new owner's.
    let probe = |method: &str, branch: &str| {
        format!(
            "{method} sip:a@10.0.0.1:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK{branch}\r\nMax-Forwards: 70\r\nFrom: <sip:x@10.0.0.9>;tag=x1\r\nTo: <sip:a@10.0.0.1>{}\r\nCall-ID: probe-{branch}\r\nCSeq: 1 {method}\r\nContent-Length: 0\r\n\r\n",
            if method == "BYE" { ";tag=nope" } else { "" }
        )
        .into_bytes()
    };
    for (m, br) in [("OPTIONS", "o1"), ("BYE", "b1")] {
        let p = Packet { from: addr("10.0.0.9:5060"), to: addr(A_ADDR), data: probe(m, br), epoch: 0, at: net.now };
        net.put_on_wire(p);
    }
    net.run_until(1_000, |_| false);
    let answers: Vec<(String, u64)> = net.captured.iter().filter(|p| p.to == addr("10.0.0.9:5060")).map(|p| (p.first_line(), p.epoch)).collect();
    assert_eq!(answers.len(), 2, "{answers:?}");
    assert!(answers.iter().all(|(_, e)| *e == 2), "only the new owner answered: {answers:?}");
    assert!(net.nodes[A].stale.as_ref().unwrap().engine.is_halted());
    // A new call to the node after the takeover: the new owner's.
    let leg = net.submit(B, originate("10.0.0.1", Some(sdp("o2")))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(A).is_some()));
    let inbound = net.incoming_leg(A).unwrap();
    net.submit(A, UaCommand::Accept(AcceptRequest { leg: inbound, sdp: Some(sdp("a2")), headers: vec![] })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(B, |e| matches!(e, UaEvent::Accepted(_)))));
    for l in [b, leg] {
        net.submit(B, UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None })).unwrap();
    }
    assert!(net.settle(60_000));
    assert_eq!(stale_packets(&net, A_ADDR, t0, 2), Vec::<String>::new());
}

#[test]
fn a_paused_zombie_wakes_to_its_timers_and_sends_nothing() {
    // A is the session refresher (90 s); the old owner is paused through
    // the takeover and resumes with every timer due.
    let mut net = pair(90);
    let (a, b) = establish(&mut net);
    let t0 = net.now;
    net.take_over(A, 2, false, true);
    // The new owner refreshes; the zombie's refresh is refused at commit.
    net.run_until(100_000, |_| false);
    let st = net.nodes[A].stale.as_ref().unwrap();
    assert!(st.engine.is_halted());
    assert_eq!(stale_packets(&net, A_ADDR, t0, 2), Vec::<String>::new());
    assert!(net.nodes[A].engine.snapshot(a).is_some_and(|s| s.phase == Phase::Confirmed), "refreshed by the new owner");
    assert!(net.nodes[B].engine.snapshot(b).is_some_and(|s| s.phase == Phase::Confirmed), "the peer's session did not expire");
    net.submit(A, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    assert!(net.settle(60_000));
}

#[test]
fn a_takeover_between_commit_and_dispatch_sends_the_message_once_from_the_new_owner() {
    let mut net = pair(1_800);
    net.egress = Some((addr(A_ADDR), EgressFence::new(1)));
    let (a, _) = establish(&mut net);
    // The old owner commits its BYE, then pauses before sending it.
    let now = net.now;
    net.nodes[A].engine.submit(UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None }), now).unwrap();
    let wall = net.wall();
    let t = net.nodes[A].engine.take_transition(now, wall).unwrap();
    assert!(t.needs_commit);
    net.nodes[A].journal.as_mut().unwrap().append(&t.record).unwrap();
    // The new owner replays the committed BYE (re-stamped with its epoch).
    net.take_over(A, 2, false, true);
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::RemoteBye(_)))));
    // The old owner resumes and sends what it held: the egress drops it.
    for tx in &t.record.transmits {
        let p = Packet { from: addr(A_ADDR), to: tx.dest.addr, data: tx.data.to_vec(), epoch: tx.epoch, at: net.now };
        net.put_on_wire(p);
    }
    assert_eq!(net.egress_dropped.iter().map(|p| (p.first_line().starts_with("BYE"), p.epoch)).collect::<Vec<_>>(), vec![(true, 1)]);
    let byes: Vec<u64> = net.sent("BYE").iter().map(|p| p.epoch).collect();
    assert_eq!(byes, vec![2], "one BYE on the wire, the new owner's");
    assert!(net.settle(60_000));
}

#[test]
fn a_takeover_needs_a_newer_epoch() {
    let mut net = pair(1_800);
    establish(&mut net);
    let state = net.nodes[A].journal.as_ref().unwrap().state().unwrap();
    for epoch in [0, 1] {
        let r = UaEngine::restore(
            net.nodes[A].cfg.clone(),
            Box::new(SeededEntropy::new(5)),
            IdAllocator::new(),
            &state,
            &RestoreOptions { epoch, require_newer_epoch: true, credentials: None },
            net.now,
            net.wall(),
        );
        assert!(r.is_err(), "epoch {epoch} is not newer than the state's");
    }
}

/// Two FileJournal handles on one directory (two processes, in effect:
/// the lock is per open file).
#[test]
fn file_journal_fences_the_old_owner_across_handles() {
    let dir = std::env::temp_dir().join(format!("sip-ua-fence-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = UaConfig { durable: true, ..config(addr(A_ADDR)) };
    let mut old = UaEngine::with_entropy(cfg.clone(), Box::new(SeededEntropy::new(1)), IdAllocator::new());
    old.set_epoch(1).unwrap();
    let mut j1 = FileJournal::open_as(&dir, Some(1)).unwrap();
    let leg = old.submit(originate("10.0.0.2", Some(sdp("o"))), 0).unwrap().leg;
    let t = old.take_transition(0, 1_000).unwrap();
    j1.append(&t.record).unwrap();
    j1.dispatched(t.record.seq).unwrap();
    // The new owner opens as epoch 2: the fence rises before it reads.
    let j2 = FileJournal::open_as(&dir, Some(2)).unwrap();
    assert_eq!(j2.state().leg_count(), 1);
    assert!(matches!(FileJournal::open_as(&dir, Some(1)), Err(JournalError::StaleEpoch { fence: 2, got: 1 })));
    // Everything the old handle tries now is refused.
    old.submit(UaCommand::Cancel(CancelRequest { leg, reason: None }), 10).unwrap();
    let t2 = old.take_transition(10, 1_010).unwrap();
    assert!(matches!(j1.append(&t2.record), Err(JournalError::StaleEpoch { fence: 2, got: 1 })));
    assert!(j1.dispatched(t.record.seq).is_err());
    assert!(j1.checkpoint().is_err());
    assert!(j1.admit(1).is_err() && j2.admit(2).is_ok());
    // The new owner continues the state.
    let (mut new, rep) = UaEngine::restore(
        cfg,
        Box::new(SeededEntropy::new(2)),
        IdAllocator::new(),
        j2.state(),
        &RestoreOptions { epoch: 2, require_newer_epoch: true, credentials: None },
        20,
        1_020,
    )
    .unwrap();
    assert_eq!(rep.restored(), vec![leg]);
    let mut j2 = j2;
    new.submit(UaCommand::Cancel(CancelRequest { leg, reason: None }), 20).unwrap();
    while let Some(t) = new.take_transition(20, 1_020) {
        if t.needs_commit {
            j2.append(&t.record).unwrap();
        }
    }
    j2.checkpoint().unwrap();
    let j3 = FileJournal::open(&dir).unwrap();
    assert_eq!((j3.owner(), j3.state().epoch), (2, 2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_lapsed_lease_halts_the_engine_before_anything_leaves() {
    let mut net = pair(1_800);
    let (_, b) = establish(&mut net);
    let lease = net.now + 1_000;
    net.engine(A).set_lease(Some(lease));
    // Within the lease: the peer's re-INVITE is answered.
    net.submit(B, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("r1") })).unwrap();
    assert!(net.run_until(500, |n| n.has(A, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    answer_offer(&mut net, A);
    assert!(net.run_until(500, |n| n.nodes[B].engine.snapshot(b).is_some_and(|s| s.offer == OfferState::Stable && s.generation == s.stable_generation)));
    // The lease runs out with nobody renewing it (partitioned from the authority).
    net.run_until(lease + 100 - net.now, |_| false);
    assert!(net.nodes[A].engine.is_halted() && net.nodes[A].engine.stats().lease_lapsed, "halted at the lease's end by its own clock");
    // The peer keeps trying: nothing from A any more, not even a 481.
    let _ = net.submit(B, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("r2") }));
    net.run_until(40_000, |_| false);
    let after: Vec<String> = net.log.iter().filter(|p| p.from == addr(A_ADDR) && p.at >= lease).map(Packet::first_line).collect();
    assert_eq!(after, Vec::<String>::new());
}

#[test]
fn a_renewed_lease_keeps_the_engine_going() {
    let mut net = pair(90);
    let (a, _) = establish(&mut net);
    // Renewed every 2 s for 2 minutes (session refreshes happen meanwhile).
    for _ in 0..60 {
        let until = net.now + 3_000;
        net.engine(A).set_lease(Some(until));
        let end = net.now + 2_000;
        while net.now < end {
            if !net.step_capped(end) {
                net.now = end;
            }
        }
    }
    assert!(!net.nodes[A].engine.is_halted());
    assert!(net.nodes[A].engine.snapshot(a).is_some_and(|s| s.phase == Phase::Confirmed));
    // A renewal never shortens the lease.
    let l = net.nodes[A].engine.lease().unwrap();
    net.engine(A).set_lease(Some(l - 2_000));
    assert_eq!(net.nodes[A].engine.lease(), Some(l));
    // The authority lifts the lease (`None`); teardown can take as long as it needs.
    net.engine(A).set_lease(None);
    net.submit(A, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    assert!(net.settle(60_000));
}
