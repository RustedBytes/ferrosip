//! The example B2BUA's bridge logic, driven through the simulator:
//! caller (A) → B2BUA (X) → callee (B), each an independent engine.

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

#[path = "../examples/b2bua/bridge.rs"]
#[allow(dead_code, reason = "the example's API is wider than what the test uses")]
mod bridge;

use bridge::{Bridge, Passthrough};
use sim::*;
use sip_ua::*;

const CALLER: usize = 0;
const B2B: usize = 1;
const CALLEE: usize = 2;

struct World {
    net: Net,
    bridge: Bridge<Passthrough>,
    seen: usize,
}

impl World {
    fn new() -> Self {
        let mut net = Net::new();
        net.add("10.0.0.1:5060", 11);
        net.add("10.0.0.5:5060", 12);
        net.add("10.0.0.2:5060", 13);
        Self { net, bridge: Bridge::new(Passthrough::default(), "10.0.0.2:5060"), seen: 0 }
    }

    /// Feed new B2BUA events to the bridge until `cond` or `limit` ms.
    fn run(&mut self, limit: u64, cond: impl Fn(&Net) -> bool) -> bool {
        let end = self.net.now + limit;
        loop {
            while self.seen < self.net.events(B2B).len() {
                let ev = self.net.events(B2B)[self.seen].clone();
                self.seen += 1;
                let net = &mut self.net;
                self.bridge.on_event(&ev, &mut |c| net.submit(B2B, c));
            }
            if cond(&self.net) {
                return true;
            }
            if self.net.now > end || !self.net.step_capped(self.net.now + 20) {
                return cond(&self.net);
            }
        }
    }

    fn settle(&mut self) -> bool {
        self.run(120_000, |n| n.nodes.iter().all(|x| x.engine.is_idle()))
    }
}

fn callee_leg(n: &Net) -> Option<UaLegId> {
    n.incoming_leg(CALLEE)
}

fn answer(w: &mut World, offer: Option<Vec<u8>>) -> (UaLegId, UaLegId) {
    let a = w.net.submit(CALLER, originate("10.0.0.5", offer)).unwrap().leg;
    assert!(w.run(2_000, |n| callee_leg(n).is_some()));
    let b = callee_leg(&w.net).unwrap();
    w.net.submit(CALLEE, UaCommand::Provisional(ProvisionalRequest { leg: b, code: 180, reason: None, sdp: None, headers: vec![] })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLER, |e| matches!(e, UaEvent::Provisional(_)))));
    (a, b)
}

#[test]
fn bridged_call_relays_ringing_answer_reinvite_and_bye() {
    let mut w = World::new();
    let (a, b) = answer(&mut w, Some(sdp("caller")));
    let UaEvent::IncomingInvite(ii) = w.net.find(CALLEE, |e| matches!(e, UaEvent::IncomingInvite(_))).unwrap().event else { panic!() };
    assert_eq!(ii.sdp.as_deref(), Some(&sdp("caller")[..]));
    assert_eq!(ii.request_uri, "sip:bob@10.0.0.2:5060");
    w.net.submit(CALLEE, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("callee")), headers: vec![] })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLER, |e| matches!(e, UaEvent::Accepted(_)))));
    let UaEvent::Accepted(acc) = w.net.find(CALLER, |e| matches!(e, UaEvent::Accepted(_))).unwrap().event else { panic!() };
    assert_eq!(acc.sdp.as_deref(), Some(&sdp("callee")[..]));

    // Two independent dialogs: no Call-ID or tag is shared across legs.
    let ca = w.net.engine(CALLER).snapshot(a).unwrap().dialog.unwrap();
    let cb = w.net.engine(CALLEE).snapshot(b).unwrap().dialog.unwrap();
    assert_ne!(ca.call_id, cb.call_id);
    assert!(![&cb.local_tag, &cb.remote_tag].contains(&&ca.local_tag));

    // The callee puts the call on hold: relayed as a re-INVITE to the caller.
    w.net.submit(CALLEE, UaCommand::Negotiate(NegotiateRequest { leg: b, method: NegotiateMethod::ReInvite, sdp: sdp("hold") })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let ro = w.net.find(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    let UaEvent::RemoteOffer(r) = &ro.event else { panic!() };
    assert_eq!((r.kind, r.sdp.as_deref()), (OfferKind::ReInvite, Some(&sdp("hold")[..])));
    w.net.submit(CALLER, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: ro.generation, sdp: Some(sdp("held")) })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLEE, |e| matches!(e, UaEvent::Completed(_)))));
    let UaEvent::Completed(c) = w.net.find(CALLEE, |e| matches!(e, UaEvent::Completed(_))).unwrap().event else { panic!() };
    assert_eq!(c.sdp.as_deref(), Some(&sdp("held")[..]));

    w.net.submit(CALLER, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLEE, |e| matches!(e, UaEvent::RemoteBye(_)))));
    assert!(w.settle());
    assert_eq!(w.bridge.active_calls(), 0);
    assert_eq!(w.bridge.media.released, vec![1]);
    w.net.check_event_invariants();
}

#[test]
fn bridged_delayed_offer_reaches_the_ack() {
    let mut w = World::new();
    let (_a, b) = answer(&mut w, None);
    w.net.submit(CALLEE, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("calleeoffer")), headers: vec![] })).unwrap();
    // The caller gets the callee's offer in the 2xx and answers in its ACK.
    assert!(w.run(2_000, |n| n.has(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let ro = w.net.find(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    let leg = ro.leg;
    w.net.submit(CALLER, UaCommand::RespondToOffer(OfferResponse { leg, generation: ro.generation, sdp: Some(sdp("callerans")) })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLEE, |e| matches!(e, UaEvent::Ack(a) if a.sdp.is_some()))));
    let UaEvent::Ack(ack) = w.net.find(CALLEE, |e| matches!(e, UaEvent::Ack(_))).unwrap().event else { panic!() };
    assert_eq!(ack.sdp.as_deref(), Some(&sdp("callerans")[..]));
    w.net.submit(CALLEE, UaCommand::Hangup(HangupRequest { leg: b, reason: None, code: None })).unwrap();
    assert!(w.settle());
    w.net.check_event_invariants();
}

#[test]
fn bridged_busy_and_cancel_propagate() {
    // Busy: the caller sees the callee's 486.
    let mut w = World::new();
    let (_a, b) = answer(&mut w, Some(sdp("o")));
    w.net.submit(CALLEE, UaCommand::Reject(RejectRequest { leg: b, code: 486, reason: None, headers: vec![] })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLER, |e| matches!(e, UaEvent::Terminated(_)))));
    let UaEvent::Failed(f) = w.net.find(CALLER, |e| matches!(e, UaEvent::Failed(_))).unwrap().event else { panic!() };
    assert_eq!((f.cause.sip.unwrap().code, f.cause.q850), (486, 17));
    assert!(w.settle());

    // Caller cancels: the callee's leg is cancelled too.
    let mut w = World::new();
    let (a, _b) = answer(&mut w, Some(sdp("o")));
    w.net.submit(CALLER, UaCommand::Cancel(CancelRequest { leg: a, reason: None })).unwrap();
    assert!(w.run(2_000, |n| n.has(CALLEE, |e| matches!(e, UaEvent::Cancelled))));
    assert!(w.settle());
    assert_eq!(w.bridge.active_calls(), 0);
    w.net.check_event_invariants();
}
