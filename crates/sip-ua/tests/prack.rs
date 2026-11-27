//! RFC 3262 reliable provisionals (100rel / PRACK) and early UPDATE.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
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
const P: &str = "10.0.0.9:5060";

fn two() -> Net {
    let mut n = Net::new();
    n.add(A, 1);
    n.add(B, 2);
    n
}

fn incoming(net: &mut Net, offer: Option<Vec<u8>>) -> (UaLegId, UaLegId) {
    let a = net.submit(0, originate("10.0.0.2", offer)).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    (a, net.incoming_leg(1).unwrap())
}

fn provisional(leg: UaLegId, code: u16, sdp: Option<Vec<u8>>) -> UaCommand {
    UaCommand::Provisional(ProvisionalRequest { leg, code, reason: None, sdp, headers: vec![] })
}

fn rseq(p: &Packet) -> u32 {
    p.msg().header("RSeq").unwrap().parse().unwrap()
}

#[test]
fn early_media_183_is_sent_reliably_and_pracked() {
    let mut net = two();
    let (_a, b) = incoming(&mut net, Some(sdp("o")));
    assert!(net.sent("INVITE")[0].msg().has_option("Supported", "100rel"));
    net.submit(1, provisional(b, 183, Some(sdp("early")))).unwrap();
    assert!(net.run_until(1_000, |n| !n.sent("SIP/2.0 200").is_empty()));
    let p183 = net.sent("SIP/2.0 183");
    assert_eq!(p183.len(), 1, "PRACKed before any retransmission");
    assert!(p183[0].msg().has_option("Require", "100rel"));
    let pr = net.sent("PRACK");
    assert_eq!(pr.len(), 1);
    assert_eq!(pr[0].msg().header("RAck").unwrap(), format!("{} 1 INVITE", rseq(&p183[0])));
    assert_eq!(pr[0].msg().cseq().unwrap(), (2, Method::Prack));
    let UaEvent::Provisional(pv) = net.find(0, |e| matches!(e, UaEvent::Provisional(_))).unwrap().event else { panic!() };
    assert_eq!(pv.sdp.as_deref(), Some(&sdp("early")[..]));
    // No retransmissions after the PRACK.
    net.run_until(5_000, |_| false);
    assert_eq!(net.sent("SIP/2.0 183").len(), 1);
    // The answer was given reliably: the 2xx needs no SDP.
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    let ok = net.sent("SIP/2.0 200").into_iter().find(|p| p.msg().cseq().unwrap().1 == Method::Invite).unwrap();
    assert!(ok.msg().body.is_empty());
    assert!(net.has(0, |e| matches!(e, UaEvent::Accepted(a) if a.sdp.is_none())));
    net.check_event_invariants();
}

#[test]
fn lost_183_and_lost_prack_recover() {
    let mut net = two();
    let (mut lost183, mut lostprack) = (false, false);
    net.rule = Box::new(move |p| {
        let l = p.first_line();
        if l.starts_with("SIP/2.0 183") && !lost183 {
            lost183 = true;
            return 0;
        }
        if l.starts_with("PRACK") && !lostprack {
            lostprack = true;
            return 0;
        }
        1
    });
    let (_a, b) = incoming(&mut net, Some(sdp("o")));
    net.submit(1, provisional(b, 183, Some(sdp("early")))).unwrap();
    net.run_until(10_000, |_| false);
    assert!(net.sent("SIP/2.0 183").len() >= 2, "183 retransmitted");
    assert!(net.sent("PRACK").len() >= 2, "PRACK retransmitted");
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Provisional(_))), 1);
    // Retransmissions stopped once the PRACK got through.
    let n = net.sent("SIP/2.0 183").len();
    net.run_until(10_000, |_| false);
    assert_eq!(net.sent("SIP/2.0 183").len(), n);
}

#[test]
fn offer_in_reliable_183_is_answered_in_the_prack() {
    let mut net = two();
    let (a, b) = incoming(&mut net, None);
    let op = net.submit(1, provisional(b, 183, Some(sdp("uasoffer")))).unwrap().op;
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let ro = net.find(0, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    let UaEvent::RemoteOffer(r) = &ro.event else { panic!() };
    assert_eq!(r.kind, OfferKind::ReliableProvisional);
    assert!(net.sent("PRACK").is_empty(), "the PRACK waits for the answer");
    // No 2xx before the PRACK answers our offer.
    assert_eq!(net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: None, headers: vec![] })).unwrap_err(), CommandError::OfferPending);
    net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: ro.generation, sdp: Some(sdp("uacanswer")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Completed(_)))));
    let done = net.find(1, |e| matches!(e, UaEvent::Completed(_))).unwrap();
    assert_eq!(done.op, Some(op));
    let UaEvent::Completed(c) = done.event else { panic!() };
    assert_eq!(c.sdp.as_deref(), Some(&sdp("uacanswer")[..]));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    assert!(net.sent("ACK")[0].msg().body.is_empty());
    let (sa, sb) = (net.engine(0).snapshot(a).unwrap(), net.engine(1).snapshot(b).unwrap());
    assert_eq!((sa.offer, sb.offer), (OfferState::Stable, OfferState::Stable));
    net.check_event_invariants();
}

#[test]
fn missing_prack_rejects_the_invite_with_504() {
    let mut net = two();
    net.rule = Box::new(|p| usize::from(!p.first_line().starts_with("PRACK")));
    let (_a, b) = incoming(&mut net, Some(sdp("o")));
    net.submit(1, provisional(b, 183, Some(sdp("early")))).unwrap();
    assert!(net.run_until(40_000, |n| n.has(0, |e| matches!(e, UaEvent::Terminated(_)))));
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!(f.cause.sip.unwrap().code, 504);
    assert!(net.has(1, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::NoAck)));
    assert!(net.settle(60_000));
}

#[test]
fn caller_requiring_100rel_gets_queued_provisionals_in_rseq_order() {
    let mut net = Net::new();
    net.add(B, 2);
    let mut inv = SipMessage::request(Method::Invite, "sip:b@10.0.0.2");
    inv.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKr1");
    inv.push_header("From", "<sip:p@x>;tag=pt");
    inv.push_header("To", "<sip:b@x>");
    inv.push_header("Call-ID", "rel");
    inv.push_header("CSeq", "7 INVITE");
    inv.push_header("Contact", "<sip:p@10.0.0.9>");
    inv.push_header("Require", "100rel");
    inv.push_header("Content-Type", "application/sdp");
    inv.body = sdp("o");
    net.inject(0, P, &inv.to_bytes());
    let b = net.incoming_leg(0).unwrap();
    net.submit(0, provisional(b, 180, None)).unwrap();
    net.submit(0, provisional(b, 182, None)).unwrap();
    let first = net.captured("SIP/2.0 18");
    assert_eq!(first.len(), 1, "the 182 waits for the 180's PRACK");
    assert!(first[0].msg().has_option("Require", "100rel"));
    let r1 = rseq(&first[0]);
    let to = first[0].msg().header("To").unwrap().to_string();
    let prack = |rs: u32, cseq: u32, branch: &str| {
        let mut m = SipMessage::request(Method::Prack, "sip:ua@10.0.0.2");
        m.push_header("Via", format!("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK{branch}"));
        m.push_header("From", "<sip:p@x>;tag=pt");
        m.push_header("To", to.as_str());
        m.push_header("Call-ID", "rel");
        m.push_header("CSeq", format!("{cseq} PRACK"));
        m.push_header("RAck", format!("{rs} 7 INVITE"));
        m.to_bytes()
    };
    // A PRACK for the wrong RSeq is not a match.
    net.inject(0, P, &prack(r1 + 5, 8, "x1"));
    assert_eq!(net.captured("SIP/2.0 481").len(), 1);
    net.inject(0, P, &prack(r1, 9, "x2"));
    let all = net.captured("SIP/2.0 18");
    let second = all.iter().find(|p| p.first_line().starts_with("SIP/2.0 182")).unwrap();
    assert_eq!(rseq(second), r1 + 1);
}

#[test]
fn early_update_both_ways_after_reliable_exchange() {
    let mut net = two();
    let (a, b) = incoming(&mut net, Some(sdp("o")));
    net.submit(1, provisional(b, 183, Some(sdp("early")))).unwrap();
    assert!(net.run_until(1_000, |n| !n.sent("PRACK").is_empty() && n.has(0, |e| matches!(e, UaEvent::Provisional(_)))));
    net.run_until(100, |_| false);
    // Callee changes early media.
    net.submit(1, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::Update, sdp: sdp("early2") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::RemoteOffer(r) if r.kind == OfferKind::Update))));
    let g = net.find(0, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap().generation;
    net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: g, sdp: Some(sdp("ans2")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Completed(_)))));
    // Caller changes too, on its single early dialog.
    net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::Update, sdp: sdp("caller3") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let g = net.find(1, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap().generation;
    net.submit(1, UaCommand::RespondToOffer(OfferResponse { leg: b, generation: g, sdp: Some(sdp("ans3")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Completed(_)))));
    // A re-INVITE is still refused before the dialog is confirmed.
    assert!(matches!(
        net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("x") })),
        Err(CommandError::InvalidState(_))
    ));
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Accepted(_)))));
    net.check_event_invariants();
}

#[test]
fn duplicate_and_out_of_order_rseq_are_ignored() {
    let mut net = Net::new();
    net.add(A, 1);
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    let rel = |rs: &str| respond(&inv, 183, Some("t"), &[("Contact", "<sip:bob@10.0.0.9>"), ("Require", "100rel"), ("RSeq", rs)], Some(&sdp("e")));
    net.inject(0, P, &rel("5"));
    net.inject(0, P, &rel("5"));
    net.inject(0, P, &rel("7"));
    let pracks: Vec<String> = net.captured("PRACK").iter().map(|p| p.msg().header("RAck").unwrap().to_string()).collect();
    assert_eq!(pracks, vec![format!("5 {} INVITE", inv.cseq().unwrap().0)]);
    net.inject(0, P, &rel("6"));
    assert_eq!(net.captured("PRACK").len(), 2);
    assert_eq!(net.captured("PRACK")[1].msg().header("RAck").unwrap(), format!("6 {} INVITE", inv.cseq().unwrap().0));
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Provisional(_))), 2);
}
