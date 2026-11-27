//! End-to-end scenarios between engines over the simulated network, plus
//! hand-scripted peers for forking and authentication.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test helpers outside #[test] fns"
)]

mod sim;

use sim::*;
use sip_ua::*;

const A: &str = "10.0.0.1:5060";
const B: &str = "10.0.0.2:5060";
const P: &str = "10.0.0.9:5060"; // scripted peer (no engine)

fn two() -> Net {
    let mut n = Net::new();
    n.add(A, 1);
    n.add(B, 2);
    n
}

fn is_incoming(e: &UaEvent) -> bool {
    matches!(e, UaEvent::IncomingInvite(_))
}
fn is_accepted(e: &UaEvent) -> bool {
    matches!(e, UaEvent::Accepted(_))
}
fn is_terminated(e: &UaEvent) -> bool {
    matches!(e, UaEvent::Terminated(_))
}
fn term_kind(net: &Net, n: usize) -> CauseKind {
    match net.find(n, is_terminated).map(|e| e.event) {
        Some(UaEvent::Terminated(t)) => t.cause.kind,
        other => panic!("no Terminated: {other:?}"),
    }
}

/// A calls B; B rings and answers with an answer SDP. Returns (A leg, B leg).
fn establish(net: &mut Net, offer: Option<Vec<u8>>) -> (UaLegId, UaLegId) {
    let a = net.submit(0, originate("10.0.0.2", offer)).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.has(1, is_incoming)));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Provisional(ProvisionalRequest { leg: b, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Provisional(_)))));
    (a, b)
}

#[test]
fn basic_call_and_bye_leave_no_state() {
    let mut net = two();
    let (a, b) = establish(&mut net, Some(sdp("offer")));
    let inv = net.find(1, is_incoming).unwrap();
    let UaEvent::IncomingInvite(ii) = inv.event else { panic!() };
    assert_eq!(ii.sdp.as_deref(), Some(&sdp("offer")[..]));
    assert_eq!(inv.generation, Generation(1));

    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("answer")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, is_accepted) && n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    let UaEvent::Accepted(acc) = net.find(0, is_accepted).unwrap().event else { panic!() };
    assert_eq!(acc.sdp.as_deref(), Some(&sdp("answer")[..]));
    assert_eq!(acc.status.code, 200);

    // Independent dialog identities on each side.
    let sa = net.engine(0).snapshot(a).unwrap();
    let sb = net.engine(1).snapshot(b).unwrap();
    assert_eq!(sa.phase, Phase::Confirmed);
    assert_eq!(sb.phase, Phase::Confirmed);
    let (da, db) = (sa.dialog.unwrap(), sb.dialog.unwrap());
    assert_eq!(da.call_id, db.call_id);
    assert_eq!((da.local_tag.as_str(), da.remote_tag.as_str()), (db.remote_tag.as_str(), db.local_tag.as_str()));
    assert_eq!(sa.stable_generation, Generation(1));

    net.submit(0, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert!(net.has(1, |e| matches!(e, UaEvent::RemoteBye(_))));
    assert_eq!(term_kind(&net, 0), CauseKind::Local);
    assert_eq!(term_kind(&net, 1), CauseKind::NormalClearing);
    assert!(net.settle(60_000), "state left: {:?} / {:?}", net.engine(0).stats(), net.engine(1).stats());
    assert_eq!(net.sent("ACK").len(), 1);
    net.check_event_invariants();
}

#[test]
fn lost_invite_and_lost_200_are_recovered_without_duplicate_events() {
    let mut net = two();
    let mut dropped_invite = false;
    let mut dropped_ok = 0;
    net.rule = Box::new(move |p| {
        let l = p.first_line();
        if l.starts_with("INVITE") && !dropped_invite {
            dropped_invite = true;
            return 0;
        }
        if l.starts_with("SIP/2.0 200") && p.msg().cseq().unwrap().1 == Method::Invite && dropped_ok < 2 {
            dropped_ok += 1;
            return 0;
        }
        // Duplicate every provisional on the wire.
        if l.starts_with("SIP/2.0 18") { 2 } else { 1 }
    });
    let (a, b) = establish(&mut net, Some(sdp("o")));
    assert_eq!(net.count(1, is_incoming), 1);
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(10_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    assert_eq!(net.count(0, is_accepted), 1);
    assert_eq!(net.count(1, |e| matches!(e, UaEvent::Ack(_))), 1);
    assert!(net.sent("INVITE").len() >= 2, "INVITE retransmitted");
    assert!(net.sent("SIP/2.0 200").len() >= 3, "2xx retransmitted by the UAS core");
    net.submit(1, UaCommand::Hangup(HangupRequest { leg: b, reason: Some("Q.850;cause=16".into()), code: None })).unwrap();
    assert!(net.run_until(5_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    let _ = a;
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn cancel_before_answer_gives_487_and_cleans_up() {
    let mut net = two();
    let (a, _b) = establish(&mut net, Some(sdp("o")));
    net.submit(0, UaCommand::Cancel(CancelRequest { leg: a, reason: Some("Q.850;cause=16".into()) })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert!(net.has(1, |e| matches!(e, UaEvent::Cancelled)));
    assert_eq!(term_kind(&net, 0), CauseKind::Cancelled);
    assert_eq!(term_kind(&net, 1), CauseKind::Cancelled);
    assert_eq!(net.sent("SIP/2.0 487").len(), 1);
    assert_eq!(net.sent("CANCEL").len(), 1);
    // The CANCEL got its own 200.
    assert!(net.sent("SIP/2.0 200").iter().any(|p| p.msg().cseq().unwrap().1 == Method::Cancel));
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn cancel_waits_for_a_provisional() {
    let mut net = Net::new();
    net.add(A, 1);
    let a = net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap().leg;
    net.submit(0, UaCommand::Cancel(CancelRequest { leg: a, reason: None })).unwrap();
    net.run_until(100, |_| false);
    assert!(net.captured("CANCEL").is_empty(), "no CANCEL before a provisional");
    let inv = net.captured("INVITE")[0].msg();
    net.inject(0, P, &respond(&inv, 180, Some("x"), &[("Contact", "<sip:bob@10.0.0.9>")], None));
    let c = net.captured("CANCEL");
    assert_eq!(c.len(), 1);
    let cm = c[0].msg();
    assert_eq!(cm.top_via().unwrap().branch, inv.top_via().unwrap().branch);
    assert_eq!(cm.cseq(), Some((inv.cseq().unwrap().0, Method::Cancel)));
    // No Provisional event after cancelling; 487 ends the leg.
    assert!(!net.has(0, |e| matches!(e, UaEvent::Provisional(_))));
    net.inject(0, P, &respond(&cm, 200, None, &[], None));
    net.inject(0, P, &respond(&inv, 487, Some("x"), &[], None));
    assert_eq!(term_kind(&net, 0), CauseKind::Cancelled);
    assert_eq!(net.captured("ACK").len(), 1);
    assert!(net.settle(60_000));
}

#[test]
fn cancel_racing_2xx_ends_with_ack_and_bye() {
    let mut net = two();
    let (a, b) = establish(&mut net, Some(sdp("o")));
    // Both act at the same instant: the 200 and the CANCEL cross.
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    net.submit(0, UaCommand::Cancel(CancelRequest { leg: a, reason: None })).unwrap();
    assert!(net.run_until(5_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert!(!net.has(0, is_accepted), "the application never sees the 2xx it cancelled");
    assert_eq!(term_kind(&net, 0), CauseKind::Cancelled);
    assert!(net.has(1, |e| matches!(e, UaEvent::RemoteBye(_))));
    assert_eq!(net.sent("BYE").len(), 1);
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn forked_2xx_are_all_acked_and_losers_get_bye() {
    let mut net = Net::new();
    net.add(A, 1);
    let a = net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap().leg;
    let inv = net.captured("INVITE")[0].msg();
    let ok = |tag: &str, host: &str| respond(&inv, 200, Some(tag), &[("Contact", &format!("<sip:bob@{host}>"))], Some(&sdp(tag)));
    net.inject(0, P, &respond(&inv, 180, Some("x"), &[("Contact", "<sip:bob@10.0.0.9>")], None));
    net.inject(0, P, &respond(&inv, 183, Some("y"), &[("Contact", "<sip:bob@10.0.0.9>")], Some(&sdp("y"))));
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Provisional(_))), 2);
    net.inject(0, P, &ok("x", "10.0.0.9"));
    net.inject(0, P, &ok("y", "10.0.0.9"));
    // Retransmission of the losing 2xx: ACK again, no second BYE.
    net.inject(0, P, &ok("y", "10.0.0.9"));
    // Retransmission of the winning 2xx: ACK again.
    net.inject(0, P, &ok("x", "10.0.0.9"));
    let acks: Vec<SipMessage> = net.captured("ACK").iter().map(Packet::msg).collect();
    assert_eq!(acks.iter().filter(|m| m.to_tag().as_deref() == Some("x")).count(), 2);
    assert_eq!(acks.iter().filter(|m| m.to_tag().as_deref() == Some("y")).count(), 2);
    let byes: Vec<SipMessage> = net.captured("BYE").iter().map(Packet::msg).collect();
    assert_eq!(byes.len(), 1);
    assert_eq!(byes[0].to_tag().as_deref(), Some("y"));
    assert_eq!(net.count(0, is_accepted), 1);
    let snap = net.engine(0).snapshot(a).unwrap();
    assert_eq!(snap.dialog.unwrap().remote_tag, "x");
    // The loser's BYE completes.
    net.inject(0, P, &respond(&byes[0], 200, None, &[], None));
    // Remote hangs up the winner.
    let mut bye = SipMessage::request(Method::Bye, "sip:alice@10.0.0.1");
    bye.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKbye1");
    bye.push_header("From", inv.header("To").unwrap().to_string() + ";tag=x");
    bye.push_header("To", acks[0].header("From").unwrap());
    bye.push_header("Call-ID", inv.call_id().unwrap());
    bye.push_header("CSeq", "10 BYE");
    net.inject(0, P, &bye.to_bytes());
    assert!(net.has(0, |e| matches!(e, UaEvent::RemoteBye(_))));
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn delayed_offer_answer_goes_in_the_ack() {
    let mut net = two();
    let (a, b) = establish(&mut net, None);
    let UaEvent::IncomingInvite(ii) = net.find(1, is_incoming).unwrap().event else { panic!() };
    assert!(ii.sdp.is_none());
    // Without an offer, accept must carry one.
    assert!(matches!(net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: None, headers: vec![] })), Err(CommandError::InvalidArgument(_))));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("offer2xx")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let ro = net.find(0, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    let UaEvent::RemoteOffer(r) = &ro.event else { panic!() };
    assert_eq!(r.kind, OfferKind::InviteResponse);
    // The ACK is held for the answer.
    assert!(net.sent("ACK").is_empty());
    assert_eq!(
        net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: Generation(ro.generation.0 + 5), sdp: Some(sdp("x")) })).unwrap_err(),
        CommandError::StaleGeneration
    );
    net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: ro.generation, sdp: Some(sdp("answerack")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    let UaEvent::Ack(ack) = net.find(1, |e| matches!(e, UaEvent::Ack(_))).unwrap().event else { panic!() };
    assert_eq!(ack.sdp.as_deref(), Some(&sdp("answerack")[..]));
    assert_eq!(net.engine(1).snapshot(b).unwrap().offer, OfferState::Stable);
    net.check_event_invariants();
}

#[test]
fn delayed_offer_without_application_answer_acks_then_byes() {
    let mut net = Net::new();
    net.add(A, 1);
    net.add_with(B, 2, |c| c);
    let (_a, b) = establish(&mut net, None);
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("offer2xx")), headers: vec![] })).unwrap();
    // A never answers: after the answer deadline it ACKs with a rejecting answer and hangs up.
    assert!(net.run_until(20_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert!(net.has(0, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::AnswerTimeout)));
    let ack = net.sent("ACK")[0].msg();
    assert!(String::from_utf8_lossy(&ack.body).contains("m=audio 0 RTP/AVP 0"));
    assert!(net.has(1, |e| matches!(e, UaEvent::RemoteBye(_))));
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

fn confirmed() -> (Net, UaLegId, UaLegId) {
    let mut net = two();
    let (a, b) = establish(&mut net, Some(sdp("o")));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    (net, a, b)
}

#[test]
fn reinvite_and_update_renegotiate_with_generations() {
    let (mut net, a, b) = confirmed();
    for (method, kind) in [(NegotiateMethod::ReInvite, OfferKind::ReInvite), (NegotiateMethod::Update, OfferKind::Update)] {
        let before = net.count(0, |e| matches!(e, UaEvent::Completed(_)));
        let op = net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method, sdp: sdp("hold") })).unwrap().op;
        // One offer at a time.
        assert_eq!(net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method, sdp: sdp("x") })).unwrap_err(), CommandError::OfferPending);
        assert!(net.run_until(1_000, |n| n.events(1).last().is_some_and(|e| matches!(&e.event, UaEvent::RemoteOffer(r) if r.kind == kind))));
        let ro = net.events(1).last().unwrap().clone();
        net.submit(1, UaCommand::RespondToOffer(OfferResponse { leg: b, generation: ro.generation, sdp: Some(sdp("held")) })).unwrap();
        assert!(net.run_until(1_000, |n| n.count(0, |e| matches!(e, UaEvent::Completed(_))) > before));
        let done = net.events(0).last().unwrap().clone();
        assert_eq!(done.op, Some(op));
        let UaEvent::Completed(c) = done.event else { panic!() };
        assert_eq!(c.sdp.as_deref(), Some(&sdp("held")[..]));
        let s = net.engine(0).snapshot(a).unwrap();
        assert_eq!((s.offer, s.generation, s.stable_generation), (OfferState::Stable, done.generation, done.generation));
    }
    assert_eq!(net.engine(0).snapshot(a).unwrap().generation, Generation(3));
    // re-INVITE 2xx was ACKed (2 ACKs total: initial + re-INVITE).
    net.run_until(2_000, |_| false);
    assert_eq!(net.sent("ACK").len(), 2);
    net.check_event_invariants();
}

#[test]
fn rejected_reinvite_rolls_back_and_keeps_the_call() {
    let (mut net, a, b) = confirmed();
    net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("video") })).unwrap();
    assert!(net.run_until(1_000, |n| n.events(1).last().is_some_and(|e| matches!(e.event, UaEvent::RemoteOffer(_)))));
    let g = net.events(1).last().unwrap().generation;
    net.submit(1, UaCommand::RespondToOffer(OfferResponse { leg: b, generation: g, sdp: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Failed(_)))));
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert!(!f.leg_failed);
    assert_eq!(f.cause.sip.unwrap().code, 488);
    let s = net.engine(0).snapshot(a).unwrap();
    assert_eq!((s.phase, s.offer, s.stable_generation), (Phase::Confirmed, OfferState::Stable, Generation(1)));
    // The session still works.
    net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::Update, sdp: sdp("again") })).unwrap();
    assert!(net.run_until(1_000, |n| n.events(1).last().is_some_and(|e| matches!(e.event, UaEvent::RemoteOffer(_)))));
    net.check_event_invariants();
}

#[test]
fn reinvite_glare_gives_491_both_ways_then_retry_succeeds() {
    let (mut net, a, b) = confirmed();
    net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("a2") })).unwrap();
    net.submit(1, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("b2") })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(0, |e| matches!(e, UaEvent::Failed(_))) && n.has(1, |e| matches!(e, UaEvent::Failed(_)))));
    for (n, owner) in [(0, true), (1, false)] {
        let UaEvent::Failed(f) = net.find(n, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
        assert_eq!(f.cause.sip.unwrap().code, 491);
        assert!(!f.leg_failed);
        let ra = f.retry_after_ms.unwrap();
        // RFC 3261 §14.1: Call-ID owner 2.1–4 s, the other 0–2 s.
        assert!(if owner { (2_100..=4_000).contains(&ra) } else { ra <= 2_000 }, "{n}: {ra}");
    }
    assert!(!net.has(0, |e| matches!(e, UaEvent::RemoteOffer(_))));
    assert_eq!(net.engine(0).snapshot(a).unwrap().offer, OfferState::Stable);
    assert_eq!(net.engine(1).snapshot(b).unwrap().offer, OfferState::Stable);
    // Retry after the 2xx-ACK exchanges settle.
    net.run_until(500, |_| false);
    net.submit(1, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("b3") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let g = net.find(0, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap().generation;
    net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: g, sdp: Some(sdp("a3")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Completed(_)))));
    net.check_event_invariants();
}

#[test]
fn digest_challenge_is_retried_a_bounded_number_of_times() {
    let mut net = Net::new();
    net.add(A, 1);
    let mut cmd = originate("10.0.0.9", Some(sdp("o")));
    if let UaCommand::Originate(o) = &mut cmd {
        o.credentials = Some(Credentials { username: "alice".into(), password: "secret".into(), realm: None });
    }
    net.submit(0, cmd).unwrap();
    let chal = [("Proxy-Authenticate", "Digest realm=\"x\", nonce=\"n1\", qop=\"auth\"")];
    for round in 0..3 {
        let invs = net.captured("INVITE");
        assert_eq!(invs.len(), round + 1);
        let inv = invs[round].msg();
        assert_eq!(inv.cseq().unwrap().0, 1 + round as u32, "CSeq increments per retry");
        if round > 0 {
            let prev = invs[round - 1].msg();
            assert_ne!(inv.top_via().unwrap().branch, prev.top_via().unwrap().branch, "new branch per retry");
            assert_eq!(inv.call_id(), prev.call_id());
            assert_eq!(inv.from_tag(), prev.from_tag());
            let auth = inv.header("Proxy-Authorization").unwrap();
            assert!(auth.contains("username=\"alice\"") && !auth.contains("secret"));
        }
        net.inject(0, P, &respond(&inv, 407, Some("t"), &chal, None));
    }
    // Two retries (max_auth_attempts = 2), then the leg fails.
    net.run_until(100, |_| false);
    assert_eq!(net.captured("INVITE").len(), 3);
    assert_eq!(net.captured("ACK").len(), 3);
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!(f.cause.kind, CauseKind::AuthFailed);
    assert_eq!(f.cause.sip.unwrap().code, 407);
    assert!(net.settle(60_000));
}

#[test]
fn missing_ack_ends_the_call_with_bye() {
    let mut net = two();
    net.rule = Box::new(|p| usize::from(!p.first_line().starts_with("ACK")));
    let (_a, b) = establish(&mut net, Some(sdp("o")));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(40_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert!(net.has(1, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::NoAck)));
    assert!(net.has(0, |e| matches!(e, UaEvent::RemoteBye(_))));
    // T1, 2T1, 4T1, then T2 capped retransmissions over 64·T1.
    let oks = net.sent("SIP/2.0 200").iter().filter(|p| p.msg().cseq().unwrap().1 == Method::Invite).count();
    assert!((9..=12).contains(&oks), "{oks} 2xx sent");
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn simultaneous_bye_is_idempotent() {
    let (mut net, a, b) = confirmed();
    net.submit(0, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    net.submit(1, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    // A second hangup is accepted and does nothing.
    net.submit(1, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert_eq!(net.sent("BYE").len(), 2);
    assert_eq!(net.count(0, is_terminated), 1);
    assert!(net.settle(60_000));
    assert_eq!(net.submit(0, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap_err(), CommandError::UnknownLeg);
    net.check_event_invariants();
}

#[test]
fn unanswered_invite_times_out_with_408() {
    let mut net = Net::new();
    net.add(A, 1);
    net.rule = Box::new(|_| 0);
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    assert!(net.run_until(40_000, |n| n.has(0, is_terminated)));
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!((f.cause.kind, f.cause.sip.unwrap().code, f.cause.q850), (CauseKind::Timeout, 408, 102));
    assert!(net.now >= 32_000);
    assert!(net.settle(60_000));
}

#[test]
fn no_answer_timeout_cancels() {
    let mut net = two();
    let mut cmd = originate("10.0.0.2", Some(sdp("o")));
    if let UaCommand::Originate(o) = &mut cmd {
        o.no_answer_timeout_ms = Some(3_000);
    }
    net.submit(0, cmd).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, is_incoming)));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Provisional(ProvisionalRequest { leg: b, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(10_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert_eq!(term_kind(&net, 0), CauseKind::Timeout);
    assert!(net.has(1, |e| matches!(e, UaEvent::Cancelled)));
    assert!(net.sent("CANCEL")[0].msg().header("Reason").is_some());
    assert!(net.settle(60_000));
}

#[test]
fn overload_drain_and_event_backpressure() {
    // max_legs = 1: the second call gets 503.
    let mut net = Net::new();
    net.add(A, 1);
    net.add_with(B, 2, |c| UaConfig { max_legs: 1, ..c });
    establish(&mut net, Some(sdp("o")));
    net.submit(0, originate("10.0.0.2", Some(sdp("o")))).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Failed(f) if f.cause.sip.as_ref().is_some_and(|s| s.code == 503)))));
    assert_eq!(net.count(1, is_incoming), 1);
    assert_eq!(net.engine(1).stats().rejected_overload, 1);

    // Drain: new calls refused, the established one continues.
    let (mut net, a, b) = confirmed();
    net.engine(1).drain();
    net.submit(0, originate("10.0.0.2", None)).unwrap();
    assert!(net.run_until(1_000, |n| n.count(0, is_terminated) == 1));
    assert_eq!(net.submit(1, originate("10.0.0.1", None)).unwrap_err(), CommandError::Draining);
    net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::Update, sdp: sdp("u") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    net.submit(1, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.count(0, is_terminated) == 2));
    assert!(net.settle(60_000));

    // The application stops reading events: new legs are failed explicitly
    // (503 + Failed/Terminated), never silently dropped.
    let mut net = Net::new();
    net.add(A, 1);
    net.add_with(B, 2, |c| UaConfig { max_pending_events: 0, ..c });
    net.submit(0, originate("10.0.0.2", Some(sdp("o")))).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, is_terminated)));
    assert!(!net.has(1, is_incoming));
    assert!(net.has(1, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::Overload)));
    assert_eq!(term_kind(&net, 1), CauseKind::Overload);
    assert_eq!(net.engine(1).stats().events_shed, 1);
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn uas_rejects_bad_requests_statelessly_enough() {
    let mut net = Net::new();
    net.add(A, 1);
    // In-dialog request for an unknown dialog: 481.
    let mut bye = SipMessage::request(Method::Bye, "sip:a@10.0.0.1");
    bye.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKx1");
    bye.push_header("From", "<sip:p@x>;tag=1");
    bye.push_header("To", "<sip:a@x>;tag=2");
    bye.push_header("Call-ID", "nope");
    bye.push_header("CSeq", "1 BYE");
    net.inject(0, P, &bye.to_bytes());
    // Retransmission is answered from the transaction.
    net.inject(0, P, &bye.to_bytes());
    assert_eq!(net.captured("SIP/2.0 481").len(), 2);
    // INVITE requiring an extension we lack: 420.
    let mut inv = SipMessage::request(Method::Invite, "sip:a@10.0.0.1");
    inv.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKx2");
    inv.push_header("From", "<sip:p@x>;tag=1");
    inv.push_header("To", "<sip:a@x>");
    inv.push_header("Call-ID", "c2");
    inv.push_header("CSeq", "1 INVITE");
    inv.push_header("Contact", "<sip:p@10.0.0.9>");
    inv.push_header("Require", "100rel, x-unknown-ext");
    net.inject(0, P, &inv.to_bytes());
    let r = net.captured("SIP/2.0 420")[0].msg();
    assert_eq!(r.header("Unsupported"), Some("x-unknown-ext"), "only the unknown one");
    // Garbage is counted, not answered.
    net.inject(0, P, b"NOT SIP AT ALL\r\n\r\n");
    assert_eq!(net.engine(0).stats().malformed, 1);
    // OPTIONS out of dialog: 200 with Allow.
    let mut opt = SipMessage::request(Method::Options, "sip:a@10.0.0.1");
    opt.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKx3");
    opt.push_header("From", "<sip:p@x>;tag=1");
    opt.push_header("To", "<sip:a@x>");
    opt.push_header("Call-ID", "c3");
    opt.push_header("CSeq", "1 OPTIONS");
    net.inject(0, P, &opt.to_bytes());
    assert!(net.captured("SIP/2.0 200")[0].msg().header("Allow").unwrap().contains("INVITE"));
    assert!(net.events(0).is_empty());
    assert!(net.settle(60_000));
}

#[test]
fn info_is_delivered_and_completed() {
    let (mut net, a, _b) = confirmed();
    let op = net
        .submit(
            0,
            UaCommand::SendInfo(InfoRequest {
                leg: a,
                content_type: "application/dtmf-relay".into(),
                body: b"Signal=5\r\nDuration=160\r\n".to_vec(),
                headers: vec![],
            }),
        )
        .unwrap()
        .op;
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Completed(_)))));
    assert_eq!(net.find(0, |e| matches!(e, UaEvent::Completed(_))).unwrap().op, Some(op));
    let UaEvent::Info(i) = net.find(1, |e| matches!(e, UaEvent::Info(_))).unwrap().event else { panic!() };
    assert_eq!(i.content_type.as_deref(), Some("application/dtmf-relay"));
    assert_eq!(i.body, b"Signal=5\r\nDuration=160\r\n");
    // Reserved headers are refused.
    let bad = InfoRequest { leg: a, content_type: "text/plain".into(), body: vec![], headers: vec![Header::new("Call-ID", "x")] };
    assert!(matches!(net.submit(0, UaCommand::SendInfo(bad)), Err(CommandError::InvalidArgument(_))));
    let bad = InfoRequest { leg: a, content_type: "text/plain".into(), body: vec![], headers: vec![Header::new("X-A", "1\r\nInjected: 1")] };
    assert!(matches!(net.submit(0, UaCommand::SendInfo(bad)), Err(CommandError::InvalidArgument(_))));
}

#[test]
fn uas_answer_timeout_rejects_with_480() {
    let mut net = Net::new();
    net.add(A, 1);
    net.add_with(B, 2, |c| UaConfig { uas_answer_timeout_ms: 2_000, ..c });
    net.submit(0, originate("10.0.0.2", Some(sdp("o")))).unwrap();
    assert!(net.run_until(5_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!((f.cause.sip.unwrap().code, f.cause.q850), (480, 18));
    assert!(net.settle(60_000));
}

#[test]
fn bye_before_ack_from_uas_waits_for_the_ack() {
    let mut net = two();
    // Hold every ACK for a while by dropping the first one.
    let mut dropped = false;
    net.rule = Box::new(move |p| {
        if p.first_line().starts_with("ACK") && !dropped {
            dropped = true;
            return 0;
        }
        1
    });
    let (_a, b) = establish(&mut net, Some(sdp("o")));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    net.submit(1, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    net.run_until(100, |_| false);
    assert!(net.sent("BYE").is_empty(), "no BYE before the ACK (RFC 3261 §15)");
    assert!(net.run_until(5_000, |n| n.has(0, is_terminated) && n.has(1, is_terminated)));
    assert_eq!(net.sent("BYE").len(), 1);
    assert!(net.settle(60_000));
    net.check_event_invariants();
}

#[test]
fn transport_failure_fails_the_leg_with_its_cause() {
    let mut e = UaEngine::with_entropy(config(addr(A)), Box::new(SeededEntropy::new(9)), IdAllocator::new());
    let mut o = OriginateRequest { request_uri: "sip:bob@10.0.0.9".into(), from: "<sip:alice@x>".into(), ..Default::default() };
    o.sdp = Some(sdp("o"));
    let acc = e.submit(UaCommand::Originate(Box::new(o)), 0).unwrap();
    let t = e.poll_transmit().unwrap();
    e.handle_send_error(t.txn.unwrap(), 1);
    let evs: Vec<UaEvent> = std::iter::from_fn(|| e.poll_event()).map(|x| x.event).collect();
    assert!(matches!(&evs[..], [UaEvent::Failed(f), UaEvent::Terminated(_)] if f.cause.kind == CauseKind::Transport && f.cause.q850 == 38), "{evs:?}");
    assert!(e.snapshot(acc.leg).is_none());
    assert!(e.is_idle());
}

#[test]
fn early_dialogs_per_leg_are_bounded() {
    let mut net = Net::new();
    net.add_with(A, 1, |c| UaConfig { max_early_dialogs: 4, ..c });
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    for i in 0..10 {
        net.inject(0, P, &respond(&inv, 180, Some(&format!("fork{i}")), &[("Contact", "<sip:x@10.0.0.9>")], None));
    }
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Provisional(_))), 4);
    assert_eq!(net.engine(0).stats().early_dialogs_dropped, 6);
    // A known fork keeps working.
    net.inject(0, P, &respond(&inv, 183, Some("fork1"), &[("Contact", "<sip:x@10.0.0.9>")], None));
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Provisional(_))), 5);
    // Two forks answer: one wins, one is counted as terminated.
    net.inject(0, P, &respond(&inv, 200, Some("fork0"), &[("Contact", "<sip:x@10.0.0.9>")], Some(&sdp("a"))));
    net.inject(0, P, &respond(&inv, 200, Some("fork9"), &[("Contact", "<sip:x@10.0.0.9>")], Some(&sdp("b"))));
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Accepted(_))), 1);
    assert_eq!(net.engine(0).stats().forks_terminated, 1);
}

#[test]
fn branch_changing_clients_are_strict_by_default_and_lenient_on_request() {
    for lenient in [false, true] {
        let mut net = Net::new();
        net.add_with(A, 1, |c| UaConfig { lenient_matching: lenient, ..c });
        let inv = |branch: &str, method: Method| {
            let mut m = SipMessage::request(method.clone(), "sip:a@10.0.0.1");
            m.push_header("Via", format!("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK{branch};rport"));
            m.push_header("From", "<sip:p@x>;tag=pt");
            m.push_header("To", "<sip:a@x>");
            m.push_header("Call-ID", "len");
            m.push_header("CSeq", format!("1 {method}"));
            m.push_header("Contact", "<sip:p@10.0.0.9>");
            if method == Method::Invite {
                m.push_header("Content-Type", "application/sdp");
                m.body = sdp("o");
            }
            m.to_bytes()
        };
        net.inject(0, P, &inv("first", Method::Invite));
        let leg = net.incoming_leg(0).unwrap();
        net.submit(0, UaCommand::Provisional(ProvisionalRequest { leg, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
        net.inject(0, P, &inv("second", Method::Invite));
        net.inject(0, P, &inv("third", Method::Cancel));
        let lines: Vec<String> = net.captured.iter().map(Packet::first_line).collect();
        if lenient {
            assert_eq!(lines, ["SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 180 Ringing", "SIP/2.0 200 OK", "SIP/2.0 487 Request Terminated"]);
            assert!(net.has(0, |e| matches!(e, UaEvent::Cancelled)));
        } else {
            assert_eq!(lines, ["SIP/2.0 100 Trying", "SIP/2.0 180 Ringing", "SIP/2.0 482 Loop Detected", "SIP/2.0 481 Call/Transaction Does Not Exist"]);
        }
        assert_eq!(net.count(0, |e| matches!(e, UaEvent::IncomingInvite(_))), 1);
        net.submit(0, UaCommand::Hangup(HangupRequest { leg, reason: None, code: None })).ok();
        assert!(net.settle(60_000), "lenient={lenient}");
    }
}
