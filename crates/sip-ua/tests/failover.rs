//! RFC 3263 failover of the initial INVITE across resolved targets.

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
const DEAD: &str = "10.0.0.66:5060";

fn net_with_targets(targets: &[&'static str]) -> Net {
    let mut net = Net::new();
    net.add(A, 1);
    net.add(B, 2);
    let t: Vec<Dest> = targets.iter().map(|a| Dest::new(Proto::Udp, addr(a))).collect();
    net.resolver = Box::new(move |r| if r.host == "b.example" { Ok(t.clone()) } else { Err("NXDOMAIN".into()) });
    net
}

fn call_b_example(net: &mut Net) -> UaLegId {
    let o = OriginateRequest { request_uri: "sip:bob@b.example".into(), from: "<sip:alice@a.example>".into(), sdp: Some(sdp("o")), ..Default::default() };
    net.submit(0, UaCommand::Originate(Box::new(o))).unwrap().leg
}

#[test]
fn silent_first_target_fails_over_after_the_probe() {
    let mut net = net_with_targets(&[DEAD, B]);
    call_b_example(&mut net);
    assert!(net.run_until(10_000, |n| n.incoming_leg(1).is_some()));
    let dead: Vec<_> = net.captured.iter().filter(|p| p.to == addr(DEAD)).collect();
    assert!(!dead.is_empty(), "first target tried");
    let invs = net.sent("INVITE");
    let to_b = invs.iter().find(|p| p.to == addr(B)).unwrap().msg();
    let to_dead = invs.iter().find(|p| p.to == addr(DEAD)).unwrap().msg();
    assert_eq!(to_b.call_id(), to_dead.call_id());
    assert_eq!(to_b.from_tag(), to_dead.from_tag());
    assert_ne!(to_b.top_via().unwrap().branch, to_dead.top_via().unwrap().branch);
    assert!(net.now >= 4_000, "after the 4 s probe");
    // The abandoned target gets nothing more after the failover.
    let n_dead = net.captured.iter().filter(|p| p.to == addr(DEAD)).count();
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(2_000, |n| n.has(0, |e| matches!(e, UaEvent::Accepted(_)))));
    net.run_until(40_000, |_| false);
    assert_eq!(net.captured.iter().filter(|p| p.to == addr(DEAD)).count(), n_dead);
    assert!(!net.has(0, |e| matches!(e, UaEvent::Failed(_))));
    net.check_event_invariants();
}

#[test]
fn a_503_moves_to_the_next_target_at_once() {
    let mut net = Net::new();
    net.add(A, 1);
    net.add_with(B, 2, |c| UaConfig { max_legs: 0, ..c }); // B answers 503
    net.add("10.0.0.3:5060", 3);
    let t = vec![Dest::new(Proto::Udp, addr(B)), Dest::new(Proto::Udp, addr("10.0.0.3:5060"))];
    net.resolver = Box::new(move |_| Ok(t.clone()));
    call_b_example(&mut net);
    assert!(net.run_until(1_000, |n| n.incoming_leg(2).is_some()));
    assert!(net.now < 1_000, "no probe wait after a 503");
    assert_eq!(net.sent("SIP/2.0 503").len(), 1);
}

#[test]
fn no_failover_after_a_provisional_and_none_without_alternatives() {
    // Only one target, which rejects with 503: the caller sees the 503.
    let mut net = net_with_targets(&[B]);
    net.nodes[1].engine.drain();
    call_b_example(&mut net);
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Terminated(_)))));
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!(f.cause.sip.unwrap().code, 503);

    // Ringing at the first target: no failover when it times out the call.
    let mut net = net_with_targets(&[B, "10.0.0.3:5060"]);
    net.add("10.0.0.3:5060", 3);
    call_b_example(&mut net);
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Provisional(ProvisionalRequest { leg: b, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    net.run_until(10_000, |_| false);
    net.submit(1, UaCommand::Reject(RejectRequest { leg: b, code: 503, reason: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Terminated(_)))));
    assert!(net.incoming_leg(2).is_none());
}

#[test]
fn dns_failure_is_reported_as_dns() {
    let mut net = net_with_targets(&[]);
    call_b_example(&mut net);
    let UaEvent::Failed(f) = net.find(0, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!((f.cause.kind, f.cause.q850), (CauseKind::Dns, 38));
}
