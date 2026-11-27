//! RFC 6086 Info Packages: `Recv-Info` exchanged on INVITE / 2xx /
//! re-INVITE, INFO sent only for a package the peer listed, 469 for a
//! package we did not list, legacy INFO (no `Info-Package`) unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, reason = "test helpers")]

mod sim;

use sim::*;
use sip_ua::*;

const A: usize = 0;
const B: usize = 1;

fn pair(a: Option<&[&str]>, b: Option<&[&str]>) -> Net {
    let list = |l: Option<&[&str]>| l.map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let (la, lb) = (list(a), list(b));
    let mut net = Net::new();
    net.add_with("10.0.0.1:5060", 1, move |c| UaConfig { recv_info: la, ..c });
    net.add_with("10.0.0.2:5060", 2, move |c| UaConfig { recv_info: lb, ..c });
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

fn info(leg: UaLegId, package: Option<&str>) -> UaCommand {
    UaCommand::SendInfo(InfoRequest {
        leg,
        content_type: "application/x-test".into(),
        body: b"x".to_vec(),
        headers: vec![],
        package: package.map(str::to_string),
    })
}

fn recv_info_of(net: &Net, first_line: &str) -> Option<String> {
    net.log.iter().find(|p| p.first_line().starts_with(first_line)).and_then(|p| p.msg().header("Recv-Info").map(str::to_string))
}

#[test]
fn recv_info_is_exchanged_and_info_is_sent_only_for_listed_packages() {
    let mut net = pair(Some(&["dtmf"]), Some(&["foo", "dtmf"]));
    let (a, b) = establish(&mut net);
    assert_eq!(recv_info_of(&net, "INVITE").as_deref(), Some("dtmf"));
    assert_eq!(recv_info_of(&net, "SIP/2.0 200").as_deref(), Some("foo, dtmf"));
    assert_eq!(net.engine(A).snapshot(a).unwrap().peer_recv_info, Some(vec!["foo".to_string(), "dtmf".to_string()]));
    assert_eq!(net.engine(B).snapshot(b).unwrap().peer_recv_info, Some(vec!["dtmf".to_string()]));
    // A package B listed: delivered with its name.
    net.submit(A, info(a, Some("foo"))).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Completed(_)))));
    let ev = net.find(B, |e| matches!(e, UaEvent::Info(_))).unwrap();
    let UaEvent::Info(i) = ev.event else { panic!() };
    assert_eq!(i.package.as_deref(), Some("foo"));
    assert_eq!(net.sent("INFO").last().unwrap().msg().header("Info-Package"), Some("foo"));
    // One B did not list: refused before anything is sent.
    let infos = net.sent("INFO").len();
    assert!(matches!(net.submit(A, info(a, Some("bar"))), Err(CommandError::InvalidArgument(_))));
    assert_eq!(net.sent("INFO").len(), infos);
    // B to A: only dtmf.
    assert!(net.submit(B, info(b, Some("foo"))).is_err());
    net.submit(B, info(b, Some("DTMF"))).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Info(i) if i.package.as_deref() == Some("DTMF")))));
}

#[test]
fn an_info_for_a_package_we_did_not_list_gets_469_with_our_list() {
    let mut net = pair(Some(&["dtmf"]), Some(&["foo"]));
    let (a, _) = establish(&mut net);
    // A peer that ignores our Recv-Info: forge the INFO B would not send.
    let real = {
        net.submit(A, info(a, Some("foo"))).unwrap();
        assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Info(_)))));
        net.sent("INFO").last().unwrap().data.clone()
    };
    let text = String::from_utf8(real).unwrap();
    let forged =
        text.replace("Info-Package: foo", "Info-Package: nope").replace("CSeq: 2 INFO", "CSeq: 3 INFO").replace("branch=z9hG4bK", "branch=z9hG4bKforged");
    let infos_before = net.count(B, |e| matches!(e, UaEvent::Info(_)));
    net.inject(B, "10.0.0.1:5060", forged.as_bytes());
    net.run_until(500, |_| false);
    let reply = net.log.iter().rev().find(|p| p.first_line().starts_with("SIP/2.0 469")).expect("469");
    assert_eq!(reply.first_line(), "SIP/2.0 469 Bad Info Package");
    assert_eq!(reply.msg().header("Recv-Info"), Some("foo"));
    assert_eq!(net.count(B, |e| matches!(e, UaEvent::Info(_))), infos_before, "not delivered");
}

#[test]
fn without_the_framework_legacy_info_works_and_packages_are_refused() {
    let mut net = pair(None, None);
    let (a, b) = establish(&mut net);
    assert!(net.log.iter().all(|p| p.msg().header("Recv-Info").is_none()), "no Recv-Info anywhere");
    assert_eq!(net.engine(A).snapshot(a).unwrap().peer_recv_info, None);
    // Legacy INFO (RFC 2976 style): delivered without a package.
    net.submit(A, info(a, None)).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::Info(i) if i.package.is_none()))));
    // A package to a peer that never listed any: refused locally.
    assert!(net.submit(B, info(b, Some("dtmf"))).is_err());
}

#[test]
fn an_empty_recv_info_means_no_packages_and_a_reinvite_updates_the_list() {
    let mut net = pair(Some(&[]), Some(&["dtmf"]));
    let (a, b) = establish(&mut net);
    assert_eq!(recv_info_of(&net, "INVITE").as_deref(), Some(""));
    assert_eq!(net.engine(B).snapshot(b).unwrap().peer_recv_info, Some(vec![]));
    assert!(net.submit(B, info(b, Some("dtmf"))).is_err(), "A accepts no package");
    // A re-INVITE carries the (unchanged) list again; B's view is refreshed from it.
    net.submit(A, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("re") })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(B, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let reinvite = net.sent("INVITE").last().unwrap().msg();
    assert_eq!(reinvite.header("Recv-Info"), Some(""));
    let e = net.find(B, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    net.submit(B, UaCommand::RespondToOffer(OfferResponse { leg: b, generation: e.generation, sdp: Some(sdp("ra")) })).unwrap();
    assert!(net.run_until(1_000, |n| n.has(A, |e| matches!(e, UaEvent::Completed(_)))));
    let ok = net.log.iter().rev().find(|p| p.first_line().starts_with("SIP/2.0 200") && p.msg().cseq().is_some_and(|c| c.0 == 2)).unwrap();
    assert_eq!(ok.msg().header("Recv-Info"), Some("dtmf"), "the 2xx to the re-INVITE carries B's list");
}
