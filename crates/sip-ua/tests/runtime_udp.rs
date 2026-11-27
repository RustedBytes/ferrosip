//! The std UDP runtime over real loopback sockets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test helpers outside #[test] fns"
)]

use sip_ua::runtime::{Resolver, RuntimeConfig, spawn_udp};
use sip_ua::*;
use std::time::Duration;

struct NoDns;
impl Resolver for NoDns {
    fn resolve(&self, r: &ResolveRequest) -> Result<Vec<Dest>, String> {
        Err(format!("no DNS for {}", r.host))
    }
}

fn wait(rx: &std::sync::mpsc::Receiver<EventEnvelope>, what: &str, f: impl Fn(&UaEvent) -> bool) -> EventEnvelope {
    loop {
        let e = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| panic!("timed out waiting for {what}"));
        if f(&e.event) {
            return e;
        }
    }
}

fn sdp() -> Vec<u8> {
    b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n".to_vec()
}

#[test]
fn call_over_loopback_udp() {
    let a = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let b = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let o =
        OriginateRequest { request_uri: format!("sip:bob@{}", b.local_addr()), from: "<sip:alice@127.0.0.1>".into(), sdp: Some(sdp()), ..Default::default() };
    let acc = a.submit(UaCommand::Originate(Box::new(o))).unwrap();
    let inv = wait(b.events(), "INVITE", |e| matches!(e, UaEvent::IncomingInvite(_)));
    b.submit(UaCommand::Accept(AcceptRequest { leg: inv.leg, sdp: Some(sdp()), headers: vec![] })).unwrap();
    let ok = wait(a.events(), "2xx", |e| matches!(e, UaEvent::Accepted(_)));
    assert_eq!(ok.leg, acc.leg);
    wait(b.events(), "ACK", |e| matches!(e, UaEvent::Ack(_)));
    a.submit(UaCommand::Hangup(HangupRequest { leg: acc.leg, reason: None, code: None })).unwrap();
    wait(b.events(), "BYE", |e| matches!(e, UaEvent::RemoteBye(_)));
    wait(a.events(), "end", |e| matches!(e, UaEvent::Terminated(_)));
    // Unknown legs are refused asynchronously.
    let bad = a.submit(UaCommand::Hangup(HangupRequest { leg: UaLegId(999), reason: None, code: None })).unwrap();
    let rej = wait(a.events(), "rejection", |e| matches!(e, UaEvent::CommandRejected(_)));
    assert_eq!((rej.op, rej.seq), (Some(bad.op), 0));
    // A name needing DNS fails with a DNS cause.
    let o = OriginateRequest { request_uri: "sip:bob@unresolvable.invalid".into(), from: "<sip:alice@127.0.0.1>".into(), ..Default::default() };
    a.submit(UaCommand::Originate(Box::new(o))).unwrap();
    let f = wait(a.events(), "DNS failure", |e| matches!(e, UaEvent::Failed(_)));
    let UaEvent::Failed(f) = f.event else { panic!() };
    assert_eq!(f.cause.kind, CauseKind::Dns);
    a.shutdown();
    b.shutdown();
}
