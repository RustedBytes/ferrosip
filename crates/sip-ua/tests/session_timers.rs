//! RFC 4028 session timers between engines and against scripted peers.

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

fn se(secs: u32) -> impl FnOnce(UaConfig) -> UaConfig {
    move |c| UaConfig { session_expires: Some(secs), ..c }
}

fn establish(net: &mut Net) -> (UaLegId, UaLegId) {
    let a = net.submit(0, originate("10.0.0.2", Some(sdp("o")))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.incoming_leg(1).is_some()));
    let b = net.incoming_leg(1).unwrap();
    net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(1, |e| matches!(e, UaEvent::Ack(_)))));
    (a, b)
}

fn failed_kind(net: &Net, n: usize) -> Option<CauseKind> {
    net.find(n, |e| matches!(e, UaEvent::Failed(_))).map(|e| if let UaEvent::Failed(f) = e.event { f.cause.kind } else { unreachable!() })
}

#[test]
fn caller_refreshes_with_update_and_the_call_stays_up() {
    let mut net = Net::new();
    net.add_with(A, 1, se(90));
    net.add_with(B, 2, se(90));
    let (a, b) = establish(&mut net);
    // The INVITE asked for 90 s without choosing; the UAC supports timer, so it refreshes.
    let inv = net.sent("INVITE")[0].msg();
    assert_eq!(inv.header("Session-Expires"), Some("90"));
    assert!(inv.has_option("Supported", "timer"));
    let ok = net.sent("SIP/2.0 200")[0].msg();
    assert_eq!(ok.header("Session-Expires"), Some("90;refresher=uac"));
    assert!(ok.has_option("Require", "timer"));
    assert_eq!(net.engine(0).snapshot(a).unwrap().session_timer, Some((90, true)));
    assert_eq!(net.engine(1).snapshot(b).unwrap().session_timer, Some((90, false)));
    net.run_until(300_000, |_| false);
    let updates = net.sent("UPDATE");
    assert!((6..=7).contains(&updates.len()), "{} refreshes in 300 s", updates.len());
    assert!(updates.iter().all(|u| u.msg().body.is_empty() && u.msg().header("Session-Expires") == Some("90;refresher=uac")));
    assert_eq!(net.engine(0).snapshot(a).unwrap().phase, Phase::Confirmed);
    assert_eq!(net.engine(1).snapshot(b).unwrap().phase, Phase::Confirmed);
    assert!(failed_kind(&net, 0).is_none() && failed_kind(&net, 1).is_none());
    net.check_event_invariants();
}

#[test]
fn lost_refreshes_expire_the_session() {
    let mut net = Net::new();
    net.add_with(A, 1, se(90));
    net.add_with(B, 2, se(90));
    establish(&mut net);
    net.rule = Box::new(|p| usize::from(!p.first_line().starts_with("UPDATE")));
    assert!(net.run_until(200_000, |n| n.has(1, |e| matches!(e, UaEvent::Terminated(_))) && n.has(0, |e| matches!(e, UaEvent::Terminated(_)))));
    assert_eq!(failed_kind(&net, 1), Some(CauseKind::SessionExpired));
    // §10: BYE at interval − min(32 s, interval/3) = 60 s.
    let bye = net.sent("BYE");
    assert_eq!(bye.len(), 1);
    assert!(net.has(0, |e| matches!(e, UaEvent::RemoteBye(_))));
    assert!(net.settle(100_000));
    net.check_event_invariants();
}

#[test]
fn bye_comes_at_sixty_seconds_without_refresh() {
    let mut net = Net::new();
    net.add_with(A, 1, se(90));
    net.add_with(B, 2, se(90));
    establish(&mut net);
    let t0 = net.now;
    net.rule = Box::new(|p| usize::from(!p.first_line().starts_with("UPDATE")));
    assert!(net.run_until(200_000, |n| !n.sent("BYE").is_empty()));
    let at = net.now - t0;
    assert!((59_000..=61_000).contains(&at), "BYE after {at} ms");
}

#[test]
fn min_se_422_is_renegotiated() {
    let mut net = Net::new();
    net.add_with(A, 1, se(90));
    net.add_with(B, 2, |c| UaConfig { min_se: 120, ..c });
    let (a, b) = establish(&mut net);
    assert_eq!(net.sent("SIP/2.0 422").len(), 1);
    let invs = net.sent("INVITE");
    assert_eq!(invs.len(), 2);
    let retry = invs[1].msg();
    assert_eq!((retry.header("Session-Expires"), retry.cseq().unwrap().0), (Some("120"), 2));
    assert_eq!(net.engine(0).snapshot(a).unwrap().session_timer, Some((120, true)));
    assert_eq!(net.engine(1).snapshot(b).unwrap().session_timer, Some((120, false)));
    assert!(net.has(0, |e| matches!(e, UaEvent::Accepted(_))));
    // An in-dialog refresh below our Min-SE gets 422 too.
    assert!(!net.has(0, |e| matches!(e, UaEvent::Failed(_))));
}

#[test]
fn peer_without_update_is_refreshed_by_reinvite_with_our_sdp() {
    let mut net = Net::new();
    net.add_with(A, 1, se(90));
    net.submit(0, originate("10.0.0.9", Some(sdp("mine")))).unwrap();
    let inv = net.captured("INVITE")[0].msg();
    let ok = respond(
        &inv,
        200,
        Some("p"),
        &[("Contact", "<sip:bob@10.0.0.9>"), ("Session-Expires", "90;refresher=uac"), ("Allow", "INVITE, ACK, BYE, CANCEL")],
        Some(&sdp("theirs")),
    );
    net.inject(0, P, &ok);
    assert!(net.has(0, |e| matches!(e, UaEvent::Accepted(_))));
    net.run_until(46_000, |n| n.captured("INVITE").len() == 2);
    let invs = net.captured("INVITE");
    assert_eq!(invs.len(), 2, "re-INVITE refresh at 45 s");
    let re = invs[1].msg();
    assert_eq!(re.body, sdp("mine"), "the refresh repeats our last SDP");
    assert_eq!(re.header("Session-Expires"), Some("90;refresher=uac"));
    assert_eq!(re.to_tag().as_deref(), Some("p"));
    net.inject(0, P, &respond(&re, 200, None, &[("Session-Expires", "90;refresher=uac"), ("Contact", "<sip:bob@10.0.0.9>")], Some(&sdp("theirs"))));
    // ACKed, and no event reached the application for an internal refresh.
    assert_eq!(net.captured("ACK").len(), 2);
    assert_eq!(net.events(0).len(), 1, "{:?}", net.events(0));
    // The application can renegotiate right after.
    let leg = net.events(0)[0].leg;
    assert!(net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg, method: NegotiateMethod::ReInvite, sdp: sdp("new") })).is_ok());
}

#[test]
fn uas_refreshes_for_a_caller_without_timer_support() {
    let mut net = Net::new();
    net.add_with(B, 2, se(90));
    let mut inv = SipMessage::request(Method::Invite, "sip:b@10.0.0.2");
    inv.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKold1");
    inv.push_header("From", "<sip:p@x>;tag=pt");
    inv.push_header("To", "<sip:b@x>");
    inv.push_header("Call-ID", "legacy");
    inv.push_header("CSeq", "1 INVITE");
    inv.push_header("Contact", "<sip:p@10.0.0.9>");
    inv.push_header("Allow", "INVITE, ACK, BYE, UPDATE");
    inv.push_header("Content-Type", "application/sdp");
    inv.body = sdp("o");
    net.inject(0, P, &inv.to_bytes());
    let b = net.incoming_leg(0).unwrap();
    net.submit(0, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    let ok = net.captured("SIP/2.0 200")[0].msg();
    assert_eq!(ok.header("Session-Expires"), Some("90;refresher=uas"));
    assert!(!ok.has_option("Require", "timer"), "the caller doesn't support timer");
    let mut ack = SipMessage::request(Method::Ack, "sip:ua@10.0.0.2");
    ack.push_header("Via", "SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKold2");
    ack.push_header("From", "<sip:p@x>;tag=pt");
    ack.push_header("To", ok.header("To").unwrap());
    ack.push_header("Call-ID", "legacy");
    ack.push_header("CSeq", "1 ACK");
    net.inject(0, P, &ack.to_bytes());
    net.run_until(46_000, |n| !n.captured("UPDATE").is_empty());
    let up = net.captured("UPDATE");
    assert_eq!(up.len(), 1);
    assert_eq!(up[0].msg().header("Session-Expires"), Some("90;refresher=uac"));
}
