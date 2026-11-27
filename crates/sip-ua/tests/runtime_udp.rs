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

#[test]
fn event_waker_lets_an_async_consumer_poll_without_blocking() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let a = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let b = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let wakes = Arc::new(AtomicUsize::new(0));
    let w = wakes.clone();
    b.set_event_waker(Arc::new(move || {
        w.fetch_add(1, Ordering::SeqCst);
    }));
    assert!(b.try_event().is_none(), "nothing yet, and no blocking");
    // Setting the waker wakes once (events may already wait): wakes may be spurious.
    let initial = wakes.load(Ordering::SeqCst);
    let o =
        OriginateRequest { request_uri: format!("sip:bob@{}", b.local_addr()), from: "<sip:alice@127.0.0.1>".into(), sdp: Some(sdp()), ..Default::default() };
    a.submit(UaCommand::Originate(Box::new(o))).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while wakes.load(Ordering::SeqCst) == initial && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(wakes.load(Ordering::SeqCst) > initial, "woken by the engine thread");
    let ev = b.try_event().expect("an event is ready after the wake");
    assert!(matches!(ev.event, UaEvent::IncomingInvite(_)));
    a.shutdown();
    b.shutdown();
}

#[test]
fn a_fenced_owner_puts_nothing_on_the_wire() {
    use std::sync::atomic::Ordering;
    // The peer: a raw socket that counts what reaches it.
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let fence = EgressFence::new(1);
    let rt = RuntimeConfig { epoch: 1, egress_fence: Some(fence.clone()), ..RuntimeConfig::default() };
    let a = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt).unwrap();
    let call = |to: &std::net::UdpSocket| OriginateRequest {
        request_uri: format!("sip:bob@{}", to.local_addr().unwrap()),
        from: "<sip:alice@127.0.0.1>".into(),
        sdp: Some(sdp()),
        ..Default::default()
    };
    // The owner of epoch 1 may send.
    a.submit(UaCommand::Originate(Box::new(call(&peer)))).unwrap();
    let mut buf = [0u8; 4096];
    assert!(peer.recv_from(&mut buf).is_ok(), "epoch 1 is the owner: its INVITE leaves");
    // A takeover by epoch 2: nothing more leaves, not even retransmissions.
    fence.raise(2);
    while peer.recv_from(&mut buf).is_ok() {}
    let _ = a.submit(UaCommand::Originate(Box::new(call(&peer))));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut leaked = 0;
    while std::time::Instant::now() < deadline {
        if peer.recv_from(&mut buf).is_ok() {
            leaked += 1;
        }
    }
    assert_eq!(leaked, 0, "a stale owner's transmits are dropped");
    assert!(a.stats().fenced.load(Ordering::Relaxed) >= 1);
    a.shutdown();
}

#[test]
fn sharded_engines_keep_each_call_on_one_shard() {
    use sip_ua::shard::{shard_of_call_id, shard_of_leg};
    use std::collections::{BTreeMap, BTreeSet};
    const SHARDS: u32 = 4;
    const CALLS: usize = 120;
    let rt = || RuntimeConfig { shards: SHARDS, ..RuntimeConfig::default() };
    let a = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt()).unwrap();
    let b = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt()).unwrap();
    assert_eq!((a.shards(), b.shards()), (4, 4));
    let mut a_legs = Vec::new();
    for _ in 0..CALLS {
        let o = OriginateRequest {
            request_uri: format!("sip:bob@{}", b.local_addr()),
            from: "<sip:alice@127.0.0.1>".into(),
            sdp: Some(sdp()),
            ..Default::default()
        };
        a_legs.push(a.submit(UaCommand::Originate(Box::new(o))).unwrap().leg);
    }
    // B answers four in five; A cancels the rest while they ring.
    let mut b_seen = 0;
    let mut checked = 0;
    let check = |e: &EventEnvelope, checked: &mut usize| {
        if let Some(d) = &e.dialog {
            assert_eq!(shard_of_leg(e.leg, SHARDS), shard_of_call_id(&d.call_id, SHARDS), "{e:?}");
            *checked += 1;
        }
    };
    while b_seen < CALLS {
        let e = b.events().recv_timeout(Duration::from_secs(5)).expect("B events");
        check(&e, &mut checked);
        if let UaEvent::IncomingInvite(i) = &e.event {
            assert_eq!(shard_of_leg(e.leg, SHARDS), shard_of_call_id(&i.call_id, SHARDS), "inbound leg on the Call-ID's shard");
            b_seen += 1;
            if b_seen % 5 == 0 {
                b.submit(UaCommand::Provisional(ProvisionalRequest { leg: e.leg, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
            } else {
                b.submit(UaCommand::Accept(AcceptRequest { leg: e.leg, sdp: Some(sdp()), headers: vec![] })).unwrap();
            }
        }
    }
    // A: hang up answered calls, cancel ringing ones (by Call-ID through the dialog in its events).
    let mut answered = BTreeSet::new();
    let mut ringing: BTreeMap<UaLegId, ()> = BTreeMap::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while answered.len() + ringing.len() < CALLS && std::time::Instant::now() < deadline {
        let Ok(e) = a.events().recv_timeout(Duration::from_secs(5)) else { break };
        check(&e, &mut checked);
        match &e.event {
            UaEvent::Accepted(_) => {
                answered.insert(e.leg);
                a.submit(UaCommand::Hangup(HangupRequest { leg: e.leg, reason: None, code: None })).unwrap();
            }
            // B rings only the calls it will not answer.
            UaEvent::Provisional(_) if ringing.insert(e.leg, ()).is_none() => {
                a.submit(UaCommand::Cancel(CancelRequest { leg: e.leg, reason: None })).unwrap();
            }
            _ => {}
        }
    }
    assert_eq!((answered.len(), ringing.len()), (CALLS * 4 / 5, CALLS / 5));
    // Every call ends on both sides, cancelled ones with Cancelled at B.
    let mut b_ended = 0;
    let mut b_cancelled = 0;
    while b_ended < CALLS {
        let e = b.events().recv_timeout(Duration::from_secs(5)).expect("B teardown");
        check(&e, &mut checked);
        match e.event {
            UaEvent::Terminated(_) => b_ended += 1,
            UaEvent::Cancelled => b_cancelled += 1,
            _ => {}
        }
    }
    assert_eq!(b_cancelled, CALLS / 5);
    let shards_used: BTreeSet<u32> = a_legs.iter().map(|l| shard_of_leg(*l, SHARDS)).collect();
    assert_eq!(shards_used.len(), 4, "new calls spread over the shards");
    assert!(checked > CALLS * 2);
    a.shutdown();
    b.shutdown();
}

#[test]
fn the_threaded_runtime_refuses_durable_mode() {
    let r = spawn_udp(UaConfig { durable: true, ..UaConfig::default() }, "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default());
    assert!(r.is_err());
}

#[test]
fn replaces_finds_a_dialog_on_another_shard_and_the_new_dialog_works() {
    use sip_ua::shard::shard_of_call_id;
    const SHARDS: u32 = 4;
    let one = || spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig::default()).unwrap();
    let (a, c) = (one(), one());
    let b =
        spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), RuntimeConfig { shards: SHARDS, ..RuntimeConfig::default() }).unwrap();
    let to_b = format!("sip:bob@{}", b.local_addr());
    let mut cross = 0;
    for _ in 0..8 {
        // A calls B; B answers.
        let o = OriginateRequest { request_uri: to_b.clone(), from: "<sip:alice@127.0.0.1>".into(), sdp: Some(sdp()), ..Default::default() };
        a.submit(UaCommand::Originate(Box::new(o))).unwrap();
        let inv = wait(b.events(), "INVITE at B", |e| matches!(e, UaEvent::IncomingInvite(_)));
        b.submit(UaCommand::Accept(AcceptRequest { leg: inv.leg, sdp: Some(sdp()), headers: vec![] })).unwrap();
        let ack = wait(b.events(), "ACK at B", |e| matches!(e, UaEvent::Ack(_)));
        let x = ack.dialog.clone().expect("B's dialog");
        wait(a.events(), "A answered", |e| matches!(e, UaEvent::Accepted(_)));
        // C replaces it (attended transfer): its own Call-ID, B's dialog in Replaces.
        let r = Replaces { call_id: x.call_id.clone(), to_tag: x.local_tag.clone(), from_tag: x.remote_tag.clone(), early_only: false };
        let o = OriginateRequest { request_uri: to_b.clone(), from: "<sip:carol@127.0.0.1>".into(), sdp: Some(sdp()), replaces: Some(r), ..Default::default() };
        let c_leg = c.submit(UaCommand::Originate(Box::new(o))).unwrap().leg;
        let inv2 = wait(b.events(), "INVITE with Replaces at B", |e| matches!(e, UaEvent::IncomingInvite(_)));
        let UaEvent::IncomingInvite(i2) = &inv2.event else { panic!("not an INVITE") };
        assert_eq!(i2.replaces, Some(inv.leg), "the replaced leg, wherever its shard");
        if shard_of_call_id(&i2.call_id, SHARDS) != shard_of_call_id(&x.call_id, SHARDS) {
            cross += 1;
        }
        // B takes C's call and ends A's.
        b.submit(UaCommand::Accept(AcceptRequest { leg: inv2.leg, sdp: Some(sdp()), headers: vec![] })).unwrap();
        b.submit(UaCommand::Hangup(HangupRequest { leg: inv.leg, reason: None, code: None })).unwrap();
        wait(a.events(), "A hung up", |e| matches!(e, UaEvent::RemoteBye(_)));
        wait(c.events(), "C answered", |e| matches!(e, UaEvent::Accepted(_)));
        // The new dialog's own requests reach the shard that holds it.
        c.submit(UaCommand::Hangup(HangupRequest { leg: c_leg, reason: None, code: None })).unwrap();
        // (A shard without the dialog would answer 481 and emit nothing.)
        wait(b.events(), "B saw C's BYE in the new dialog", |e| matches!(e, UaEvent::RemoteBye(_)));
        wait(c.events(), "C ended", |e| matches!(e, UaEvent::Terminated(_)));
    }
    assert!(cross >= 2, "most Replaces cross shards: {cross} of 8");
    a.shutdown();
    b.shutdown();
    c.shutdown();
}

#[test]
fn the_runtime_halts_when_its_lease_lapses_and_renewals_keep_it_alive() {
    use std::time::Instant;
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    let rt = RuntimeConfig { lease_until: Some(Instant::now() + Duration::from_millis(600)), ..RuntimeConfig::default() };
    let a = spawn_udp(UaConfig::default(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt).unwrap();
    let options = |n: u32| {
        format!(
            "OPTIONS sip:a@{} SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bKlease{n}\r\nMax-Forwards: 70\r\nFrom: <sip:p@x>;tag=p\r\nTo: <sip:a@x>\r\nCall-ID: lease-{n}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
            a.local_addr(),
            peer.local_addr().unwrap()
        )
    };
    let ask = |n: u32| {
        peer.send_to(options(n).as_bytes(), a.local_addr()).unwrap();
        let mut buf = [0u8; 2048];
        peer.recv_from(&mut buf).is_ok()
    };
    assert!(ask(1), "answered within the lease");
    // Renewed: still answering past the first deadline.
    a.renew_lease(Instant::now() + Duration::from_millis(800)).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    assert!(ask(2), "answered past the first deadline after a renewal");
    // Not renewed: past the lease, nothing comes back.
    std::thread::sleep(Duration::from_millis(500));
    assert!(!ask(3), "silent once the lease lapsed");
    a.shutdown();
}
