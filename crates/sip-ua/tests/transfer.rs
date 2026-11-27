//! RFC 3515 REFER (blind transfer) and RFC 3891 Replaces (attended
//! transfer) across three engines.

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
use sip_ua::refer::{Replaces, refer_to_with_replaces};
use sip_ua::*;

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;

fn three() -> Net {
    let mut n = Net::new();
    n.add("10.0.0.1:5060", 31);
    n.add("10.0.0.2:5060", 32);
    n.add("10.0.0.3:5060", 33);
    n
}

/// `from` calls `to` (host) and `to_node` answers. Returns (caller leg, callee leg).
fn call(net: &mut Net, from: usize, to_host: &str, to_node: usize, replaces: Option<Replaces>) -> (UaLegId, UaLegId) {
    let before = net.count(to_node, |e| matches!(e, UaEvent::IncomingInvite(_)));
    let mut o = OriginateRequest { request_uri: format!("sip:x@{to_host}"), from: "<sip:me@example.com>".into(), sdp: Some(sdp("o")), ..Default::default() };
    o.replaces = replaces;
    let a = net.submit(from, UaCommand::Originate(Box::new(o))).unwrap().leg;
    assert!(net.run_until(1_000, |n| n.count(to_node, |e| matches!(e, UaEvent::IncomingInvite(_))) > before));
    let b = net.events(to_node).iter().rev().find(|e| matches!(e.event, UaEvent::IncomingInvite(_))).unwrap().leg;
    net.submit(to_node, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.events(from).iter().any(|e| e.leg == a && matches!(e.event, UaEvent::Accepted(_)))));
    net.run_until(100, |_| false);
    (a, b)
}

fn progress(net: &Net, n: usize) -> Vec<(u16, bool)> {
    net.events(n).iter().filter_map(|e| if let UaEvent::ReferProgress(p) = &e.event { Some((p.status.code, p.last)) } else { None }).collect()
}

#[test]
fn blind_transfer_with_notify_lifecycle() {
    let mut net = three();
    let (ab, ba) = call(&mut net, A, "10.0.0.2", B, None);
    // B transfers A to C.
    let op = net
        .submit(
            B,
            UaCommand::Refer(ReferRequest { leg: ba, refer_to: "sip:carol@10.0.0.3".into(), referred_by: Some("sip:bob@example.com".into()), headers: vec![] }),
        )
        .unwrap()
        .op;
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::ReferRequested(_)))));
    let rq = net.find(A, |e| matches!(e, UaEvent::ReferRequested(_))).unwrap();
    assert_eq!(rq.leg, ab);
    let UaEvent::ReferRequested(r) = &rq.event else { panic!() };
    assert_eq!((r.target.as_str(), r.replaces.is_none()), ("sip:carol@10.0.0.3", true));
    assert_eq!(r.referred_by.as_deref(), Some("<sip:bob@example.com>"));
    net.submit(A, UaCommand::RespondToRefer(ReferResponse { leg: ab, accept: true })).unwrap();
    assert!(net.run_until(1_000, |n| progress(n, B) == vec![(100, false)]));
    let done = net.find(B, |e| matches!(e, UaEvent::Completed(_))).unwrap();
    assert_eq!(done.op, Some(op));
    let UaEvent::Completed(c) = done.event else { panic!() };
    assert_eq!(c.status.code, 202);
    // A calls the target and reports progress.
    let (ac, _ca) = call(&mut net, A, "10.0.0.3", C, None);
    net.submit(A, UaCommand::NotifyRefer(ReferNotify { leg: ab, code: 200, reason: None, last: true })).unwrap();
    assert!(net.run_until(1_000, |n| progress(n, B).len() == 2));
    assert_eq!(progress(&net, B), vec![(100, false), (200, true)]);
    assert!(net.events(B).iter().filter(|e| matches!(e.event, UaEvent::ReferProgress(_))).all(|e| e.op == Some(op)));
    let notify = net.sent("NOTIFY").last().unwrap().msg();
    assert_eq!(notify.header("Event"), Some("refer"));
    assert_eq!(notify.header("Subscription-State"), Some("terminated;reason=noresource"));
    assert_eq!(notify.content_type(), Some("message/sipfrag;version=2.0"));
    assert_eq!(notify.body, b"SIP/2.0 200 OK\r\n");
    // No more NOTIFYs once terminated.
    assert!(matches!(net.submit(A, UaCommand::NotifyRefer(ReferNotify { leg: ab, code: 200, reason: None, last: true })), Err(CommandError::InvalidState(_))));
    // The transferor hangs up; A's call with C stays.
    net.submit(B, UaCommand::Hangup(HangupRequest { leg: ba, reason: None, code: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.events(A).iter().any(|e| e.leg == ab && matches!(e.event, UaEvent::Terminated(_)))));
    assert_eq!(net.engine(A).snapshot(ac).unwrap().phase, Phase::Confirmed);
    net.check_event_invariants();
}

#[test]
fn attended_transfer_replaces_the_consultation_dialog() {
    let mut net = three();
    let (ab, ba) = call(&mut net, A, "10.0.0.2", B, None);
    // B consults C.
    let (bc, cb) = call(&mut net, B, "10.0.0.3", C, None);
    let consult = net.engine(B).snapshot(bc).unwrap().dialog.unwrap();
    let refer_to = refer_to_with_replaces("sip:carol@10.0.0.3", &Replaces::for_peer_of(&consult));
    net.submit(B, UaCommand::Refer(ReferRequest { leg: ba, refer_to, referred_by: None, headers: vec![] })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::ReferRequested(_)))));
    let UaEvent::ReferRequested(r) = net.find(A, |e| matches!(e, UaEvent::ReferRequested(_))).unwrap().event else { panic!() };
    let replaces = r.replaces.clone().unwrap();
    net.submit(A, UaCommand::RespondToRefer(ReferResponse { leg: ab, accept: true })).unwrap();
    // A calls C replacing the B–C dialog.
    let (ac, ca) = call(&mut net, A, "10.0.0.3", C, Some(replaces));
    let inv = net.events(C).iter().find(|e| e.leg == ca).unwrap().clone();
    let UaEvent::IncomingInvite(ii) = &inv.event else { panic!() };
    assert_eq!(ii.replaces, Some(cb), "C maps the Replaces to its leg with B");
    assert!(ii.headers.iter().any(|h| h.name == "Require" && h.value == "replaces"));
    // C ends the replaced dialog; A reports success and B hangs up.
    net.submit(C, UaCommand::Hangup(HangupRequest { leg: cb, reason: None, code: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.events(B).iter().any(|e| e.leg == bc && matches!(e.event, UaEvent::RemoteBye(_)))));
    net.submit(A, UaCommand::NotifyRefer(ReferNotify { leg: ab, code: 200, reason: None, last: true })).unwrap();
    assert!(net.run_until(1_000, |n| progress(n, B).last() == Some(&(200, true))));
    net.submit(B, UaCommand::Hangup(HangupRequest { leg: ba, reason: None, code: None })).unwrap();
    assert!(net.run_until(1_000, |n| n.nodes[B].engine.legs().is_empty()));
    assert_eq!(net.engine(A).snapshot(ac).unwrap().phase, Phase::Confirmed);
    assert_eq!(net.engine(C).legs(), vec![ca]);
    net.check_event_invariants();
}

#[test]
fn replaces_is_validated() {
    let mut net = three();
    let (_bc, cb) = call(&mut net, B, "10.0.0.3", C, None);
    let d = net.engine(C).snapshot(cb).unwrap().dialog.unwrap();
    let inv = |replaces: &str, branch: &str| {
        let mut m = SipMessage::request(Method::Invite, "sip:c@10.0.0.3");
        m.push_header("Via", format!("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK{branch}"));
        m.push_header("From", "<sip:p@x>;tag=pt");
        m.push_header("To", "<sip:c@x>");
        m.push_header("Call-ID", format!("r-{branch}"));
        m.push_header("CSeq", "1 INVITE");
        m.push_header("Contact", "<sip:p@10.0.0.9>");
        m.push_header("Replaces", replaces);
        m.to_bytes()
    };
    // From C's point of view: to-tag = its local tag, from-tag = remote.
    net.inject(C, "10.0.0.9:5060", &inv(&format!("{};to-tag={};from-tag={};early-only", d.call_id, d.local_tag, d.remote_tag), "e1"));
    net.inject(C, "10.0.0.9:5060", &inv(&format!("{};to-tag={};from-tag={}", d.call_id, d.remote_tag, d.local_tag), "e2"));
    net.inject(C, "10.0.0.9:5060", &inv("only-a-call-id", "e3"));
    let codes: Vec<String> = net.captured.iter().map(|p| p.first_line()).filter(|l| !l.contains(" 100 ")).collect();
    assert_eq!(codes, vec!["SIP/2.0 486 Busy Here", "SIP/2.0 481 Call/Transaction Does Not Exist", "SIP/2.0 400 Bad Request"]);
    assert_eq!(net.count(C, |e| matches!(e, UaEvent::IncomingInvite(_))), 1);
}

#[test]
fn refer_declined_unanswered_and_stray_notifies() {
    let mut net = three();
    let (ab, ba) = call(&mut net, A, "10.0.0.2", B, None);
    let refer = |leg| UaCommand::Refer(ReferRequest { leg, refer_to: "<sip:carol@10.0.0.3>".into(), referred_by: None, headers: vec![] });
    // Declined.
    let op = net.submit(B, refer(ba)).unwrap().op;
    assert!(matches!(net.submit(B, refer(ba)), Err(CommandError::InvalidState(_))), "one REFER at a time");
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::ReferRequested(_)))));
    net.submit(A, UaCommand::RespondToRefer(ReferResponse { leg: ab, accept: false })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Failed(_)))));
    let f = net.find(B, |e| matches!(e, UaEvent::Failed(_))).unwrap();
    assert_eq!(f.op, Some(op));
    let UaEvent::Failed(f) = f.event else { panic!() };
    assert_eq!((f.cause.sip.unwrap().code, f.leg_failed), (603, false));
    // Unanswered by the application: 603 at the deadline.
    net.submit(B, refer(ba)).unwrap();
    assert!(net.run_until(10_000, |n| n.count(B, |e| matches!(e, UaEvent::Failed(_))) == 2));
    assert!(net.has(A, |e| matches!(e, UaEvent::Failed(f) if f.cause.kind == CauseKind::AnswerTimeout && !f.leg_failed)));
    // A NOTIFY nobody subscribed to, and one for another event package.
    let notify = |event: &str, cseq: u32| {
        let ok = net.sent("SIP/2.0 200").into_iter().find(|p| p.msg().cseq().unwrap().1 == Method::Invite).unwrap().msg();
        let mut m = SipMessage::request(Method::Notify, "sip:me@10.0.0.1");
        m.push_header("Via", format!("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKn{cseq}"));
        m.push_header("From", ok.header("To").unwrap());
        m.push_header("To", ok.header("From").unwrap());
        m.push_header("Call-ID", ok.call_id().unwrap());
        m.push_header("CSeq", format!("{cseq} NOTIFY"));
        m.push_header("Event", event);
        m.push_header("Subscription-State", "active");
        m.to_bytes()
    };
    let (n1, n2) = (notify("refer", 50), notify("presence", 51));
    net.inject(A, "10.0.0.2:5060", &n1);
    net.inject(A, "10.0.0.2:5060", &n2);
    let replies: Vec<String> = net.log.iter().rev().take(2).map(Packet::first_line).collect();
    assert_eq!(replies, vec!["SIP/2.0 489 Bad Event", "SIP/2.0 481 Call/Transaction Does Not Exist"]);
    // The call itself is unaffected.
    assert_eq!(net.engine(A).snapshot(ab).unwrap().phase, Phase::Confirmed);
}
