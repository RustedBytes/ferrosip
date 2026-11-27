//! 3xx redirection of the initial INVITE: reported (default) or followed
//! with loop protection and a cap.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers outside #[test] fns"
)]

mod sim;

use sim::*;
use sip_ua::*;

const P: &str = "10.0.0.9:5060";

fn failed(net: &Net) -> Cause {
    match net.find(0, |e| matches!(e, UaEvent::Failed(_))).map(|e| e.event) {
        Some(UaEvent::Failed(f)) => f.cause,
        other => panic!("{other:?}"),
    }
}

fn redirect(inv: &SipMessage, contacts: &str) -> Vec<u8> {
    respond(inv, 302, Some("r"), &[("Contact", contacts)], None)
}

#[test]
fn by_default_the_3xx_contacts_go_to_the_application() {
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 1);
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    net.inject(0, P, &redirect(&inv, "<sip:low@10.0.0.7>;q=0.1, <sip:high@10.0.0.8>;q=0.9"));
    let c = failed(&net);
    assert_eq!(c.sip.as_ref().map(|s| s.code), Some(302));
    assert_eq!(c.contacts, vec!["sip:high@10.0.0.8", "sip:low@10.0.0.7"]);
    assert_eq!(net.captured("INVITE").len(), 1);
    assert_eq!(net.captured("ACK").len(), 1, "the 3xx is ACKed");
}

#[test]
fn followed_redirect_reaches_the_new_target() {
    let mut net = Net::new();
    net.add_with("10.0.0.1:5060", 1, |c| UaConfig { max_redirects: 3, ..c });
    net.add("10.0.0.2:5060", 2);
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    net.inject(0, P, &redirect(&inv, "<sip:bob@10.0.0.2>"));
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let UaEvent::IncomingInvite(ii) = net.find(1, |e| matches!(e, UaEvent::IncomingInvite(_))).unwrap().event else { panic!() };
    assert_eq!(ii.request_uri, "sip:bob@10.0.0.2");
    let second = net.sent("INVITE").into_iter().find(|p| p.to == addr("10.0.0.2:5060")).unwrap().msg();
    assert_eq!((second.call_id(), second.from_tag(), second.cseq().unwrap().0), (inv.call_id(), inv.from_tag(), 2));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(0, |e| matches!(e, UaEvent::Accepted(_)))));
    assert!(!net.has(0, |e| matches!(e, UaEvent::Failed(_))));
    net.check_event_invariants();
}

#[test]
fn redirect_loops_and_chains_are_bounded() {
    // A loop: 10.0.0.9 → 10.0.0.8 → back to 10.0.0.9: not tried again.
    let mut net = Net::new();
    net.add_with("10.0.0.1:5060", 1, |c| UaConfig { max_redirects: 5, ..c });
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    net.inject(0, P, &redirect(&inv, "<sip:x@10.0.0.8>"));
    let inv2 = net.captured("INVITE")[1].msg();
    assert_eq!(inv2.uri(), Some("sip:x@10.0.0.8"));
    net.inject(0, "10.0.0.8:5060", &redirect(&inv2, "<sip:bob@10.0.0.9>, <SIP:X@10.0.0.8>"));
    assert_eq!(net.captured("INVITE").len(), 2, "no URI tried twice");
    assert_eq!(failed(&net).sip.unwrap().code, 302);

    // A chain longer than the cap.
    let mut net = Net::new();
    net.add_with("10.0.0.1:5060", 1, |c| UaConfig { max_redirects: 1, ..c });
    net.submit(0, originate("10.0.0.9", Some(sdp("o")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    net.inject(0, P, &redirect(&inv, "<sip:x@10.0.0.8>"));
    let inv2 = net.captured("INVITE")[1].msg();
    net.inject(0, "10.0.0.8:5060", &redirect(&inv2, "<sip:y@10.0.0.7>"));
    assert_eq!(net.captured("INVITE").len(), 2);
    assert_eq!(failed(&net).contacts, vec!["sip:y@10.0.0.7"]);
    assert!(net.settle(60_000));
}
