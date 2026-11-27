//! Randomized event orders: packet loss, duplication and reordering with
//! random application behaviour. Whatever happens, every leg ends exactly
//! once, events have no gaps, nothing is delivered to the application
//! twice, and no state is left behind.

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

struct Rng(SeededEntropy);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0.next_u64() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

fn run_seed(seed: u64) {
    let mut net = Net::new();
    net.add("10.0.0.1:5060", seed.wrapping_mul(3) + 1);
    net.add("10.0.0.2:5060", seed.wrapping_mul(5) + 2);
    net.jitter = Some((SeededEntropy::new(seed ^ 0xabc), 40));
    let mut wire = Rng(SeededEntropy::new(seed ^ 0x77));
    let (loss, dup) = (wire.below(25), wire.below(15));
    net.rule = Box::new(move |_| {
        if wire.chance(loss) {
            0
        } else if wire.chance(dup) {
            2
        } else {
            1
        }
    });
    let mut app = Rng(SeededEntropy::new(seed ^ 0x1234));
    let delayed = app.chance(30);
    let offer = if delayed { None } else { Some(sdp("o")) };
    let Ok(acc) = net.submit(0, originate("10.0.0.2", offer)) else { panic!("originate") };
    let a = acc.leg;

    // B's behaviour, A's behaviour, at random times.
    let mut b: Option<UaLegId> = None;
    let mut b_done = false;
    let mut a_cancel_at = if app.chance(25) { Some(net.now + app.below(3_000)) } else { None };
    let answer_at = net.now + app.below(4_000);
    let reject = app.chance(20);
    let renegotiate = app.chance(50);
    let mut renegotiated = false;
    let mut retried = false;
    let mut answered_offers = 0usize;
    let end = net.now + 60_000;
    while net.now < end {
        // Tick at most 20 ms so scheduled application actions happen on time.
        let cap = net.now + 20;
        if !net.step_capped(cap) {
            break;
        }
        if b.is_none() {
            b = net.incoming_leg(1);
            if let Some(l) = b {
                let _ = net.submit(1, UaCommand::Provisional(ProvisionalRequest { leg: l, code: 180, reason: None, sdp: None, headers: vec![] }));
            }
        }
        if let (Some(l), false) = (b, b_done)
            && net.now >= answer_at
        {
            b_done = true;
            let cmd = if reject {
                UaCommand::Reject(RejectRequest { leg: l, code: 486, reason: None, headers: vec![] })
            } else {
                UaCommand::Accept(AcceptRequest { leg: l, sdp: Some(sdp("ans")), headers: vec![] })
            };
            let _ = net.submit(1, cmd);
        }
        if let Some(t) = a_cancel_at
            && net.now >= t
        {
            a_cancel_at = None;
            let _ = net.submit(0, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None }));
        }
        // Answer every remote offer on either side.
        for n in 0..2 {
            let offers: Vec<EventEnvelope> = net.events(n).iter().filter(|e| matches!(e.event, UaEvent::RemoteOffer(_))).cloned().collect();
            if n == 0 && offers.len() > answered_offers {
                answered_offers = offers.len();
                let e = offers.last().unwrap();
                let _ = net.submit(0, UaCommand::RespondToOffer(OfferResponse { leg: e.leg, generation: e.generation, sdp: Some(sdp("r")) }));
            }
            if n == 1
                && let Some(e) = offers.last()
                && net.engine(1).snapshot(e.leg).is_some_and(|s| s.offer == OfferState::RemoteOffer && s.generation == e.generation)
            {
                let _ = net.submit(1, UaCommand::RespondToOffer(OfferResponse { leg: e.leg, generation: e.generation, sdp: Some(sdp("r")) }));
            }
        }
        if renegotiate && !renegotiated && net.engine(0).snapshot(a).is_some_and(|s| s.phase == Phase::Confirmed && s.offer == OfferState::Stable) {
            renegotiated = true;
            let _ = net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::ReInvite, sdp: sdp("re") }));
        }
        // A 500 + Retry-After (our re-INVITE overtook the ACK): retry once.
        if renegotiated
            && !retried
            && net.has(0, |e| matches!(e, UaEvent::Failed(f) if f.cause.sip.as_ref().is_some_and(|s| s.code == 500)))
            && net.engine(0).snapshot(a).is_some_and(|s| s.phase == Phase::Confirmed && s.offer == OfferState::Stable)
        {
            retried = true;
            let _ = net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::Update, sdp: sdp("re2") }));
        }
        if net.now > 20_000 {
            break;
        }
    }
    // Both applications hang up whatever is still alive, then everything settles.
    for (n, leg) in [(0, Some(a)), (1, b)] {
        if let Some(l) = leg {
            let _ = net.submit(n, UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None }));
        }
    }
    let settled = net.settle(400_000);
    let stats = (net.engine(0).stats(), net.engine(1).stats());
    assert!(settled, "seed {seed}: not idle: {stats:?}");
    net.check_event_invariants();
    assert_eq!(net.count(0, |e| matches!(e, UaEvent::Terminated(_))), 1, "seed {seed}: A legs");
    assert!(net.count(1, |e| matches!(e, UaEvent::IncomingInvite(_))) <= 1, "seed {seed}: duplicate IncomingInvite");
    assert_eq!(net.count(1, |e| matches!(e, UaEvent::Terminated(_))), usize::from(b.is_some()), "seed {seed}: B legs");
    assert!(net.count(0, |e| matches!(e, UaEvent::Accepted(_))) <= 1, "seed {seed}: duplicate Accepted");
    assert!(net.count(1, |e| matches!(e, UaEvent::Ack(_))) <= 2, "seed {seed}: duplicate Ack");
    // B never sends an offer of its own, so A never sees glare; and a
    // hangup the application asked for is never reported as a failure.
    for n in 0..2 {
        for e in net.events(n) {
            if let UaEvent::Failed(f) = &e.event {
                assert_ne!(f.cause.sip.as_ref().map(|s| s.code), Some(491), "seed {seed}: spurious glare");
                assert_ne!(f.cause.kind, CauseKind::Local, "seed {seed}: local hangup reported as failure");
            }
        }
    }
    // Engine-level 2xx/ACK bookkeeping matches the applications' view.
    if net.has(0, |e| matches!(e, UaEvent::Accepted(_))) {
        assert!(b.is_some(), "seed {seed}: accepted without an inbound leg");
    }
}

#[test]
fn random_loss_duplication_and_reordering() {
    let seeds: u64 = std::env::var("SIP_UA_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let start: u64 = std::env::var("SIP_UA_SEED0").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    for seed in start..start.saturating_add(seeds) {
        run_seed(seed);
    }
}
