//! Random crashes (random boundary, random downtime) during random calls
//! over a lossy, reordering network, both sides durable. Whatever happens:
//! state drains (engines and journals), no CSeq is reused by two requests
//! of a dialog, one keyed Originate is one call, and per-leg event
//! sequences are consistent once replay duplicates are removed.

#![cfg(feature = "recovery")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects, reason = "test helpers")]

mod sim;

use sim::*;
use sip_ua::*;
use std::collections::{BTreeMap, BTreeSet};

struct Rng(SeededEntropy);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0.next_u64() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

const BOUNDARIES: [Boundary; 3] = [Boundary::PreCommit, Boundary::PostCommit, Boundary::PostSend];

fn run_seed(seed: u64) -> u64 {
    let mut net = Net::new();
    net.add_durable("10.0.0.1:5060", seed * 3 + 1, |c| UaConfig { session_expires: Some(90), ..c });
    net.add_durable("10.0.0.2:5060", seed * 5 + 2, |c| UaConfig { session_expires: Some(90), ..c });
    net.jitter = Some((SeededEntropy::new(seed ^ 0xabc), 30));
    let mut wire = Rng(SeededEntropy::new(seed ^ 0x77));
    let loss = wire.below(15);
    net.rule = Box::new(move |_| usize::from(!wire.chance(loss)));
    let mut r = Rng(SeededEntropy::new(seed ^ 0x5151));

    let key = format!("call-{seed}");
    let mut a_leg = None;
    let mut b_leg: Option<UaLegId> = None;
    let mut b_answered = false;
    let answer_at = r.below(3_000);
    let hangup_at = 3_000 + r.below(8_000);
    let hangup_side = r.below(2);
    let renegotiate_at = 2_000 + r.below(4_000);
    let mut renegotiated = false;
    let mut crashes = 0;
    let end = 15_000;
    while net.now < end {
        // Inject a crash now and then.
        if crashes < 4 && r.chance(2) {
            crashes += 1;
            let n = usize::try_from(r.below(2)).unwrap();
            if r.chance(50) {
                net.nodes[n].crash_at = Some(BOUNDARIES[usize::try_from(r.below(3)).unwrap()]);
            } else {
                net.crash_and_restore(n, r.below(5_000));
            }
        }
        // The caller (re)submits its keyed Originate until it has a leg.
        if a_leg.is_none() || (net.now > 200 && net.now < 400) {
            let now = net.now;
            if let Ok(acc) = net.nodes[0].engine.submit_keyed(&key, originate("10.0.0.2", Some(sdp("o"))), now) {
                a_leg = Some(acc.leg);
            }
            net.flush();
        }
        if b_leg.is_none() {
            b_leg = net.incoming_leg(1);
        }
        if let Some(b) = b_leg
            && !b_answered
            && net.now >= answer_at
        {
            b_answered =
                net.submit(1, UaCommand::Accept(AcceptRequest { leg: b, sdp: Some(sdp("a")), headers: vec![] })).is_ok() || net.engine(1).snapshot(b).is_none();
        }
        if let Some(a) = a_leg
            && !renegotiated
            && net.now >= renegotiate_at
            && net.engine(0).snapshot(a).is_some_and(|s| s.phase == Phase::Confirmed && s.offer == OfferState::Stable)
        {
            renegotiated = true;
            let _ = net.submit(0, UaCommand::Negotiate(NegotiateRequest { leg: a, method: NegotiateMethod::Update, sdp: sdp("u") }));
        }
        // Answer remote offers on B.
        let offers: Vec<EventEnvelope> = net.events(1).iter().filter(|e| matches!(e.event, UaEvent::RemoteOffer(_))).cloned().collect();
        if let Some(e) = offers.last()
            && net.engine(1).snapshot(e.leg).is_some_and(|s| s.offer == OfferState::RemoteOffer && s.generation == e.generation)
        {
            let _ = net.submit(1, UaCommand::RespondToOffer(OfferResponse { leg: e.leg, generation: e.generation, sdp: Some(sdp("r")) }));
        }
        if net.now >= hangup_at {
            let (n, leg) = if hangup_side == 0 { (0, a_leg) } else { (1, b_leg) };
            if let Some(l) = leg {
                let _ = net.submit(n, UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None }));
            }
        }
        let cap = net.now + 20;
        if !net.step_capped(cap) {
            break;
        }
    }
    // Both hang up whatever is left; everything must drain.
    for (n, leg) in [(0, a_leg), (1, b_leg)] {
        if let Some(l) = leg {
            let _ = net.submit(n, UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None }));
        }
    }
    let settled = net.settle(400_000);
    assert!(settled, "seed {seed}: not idle: {:?} / {:?}", net.engine(0).stats(), net.engine(1).stats());
    for (n, node) in net.nodes.iter().enumerate() {
        let st = node.journal.as_ref().unwrap().state().unwrap();
        assert_eq!((st.leg_count(), st.transaction_count()), (0, 0), "seed {seed}: node {n} journal not drained");
    }
    // One logical call for the key.
    // (A replayed IncomingInvite has the same leg and seq: count legs and Call-IDs.)
    let calls: BTreeSet<(UaLegId, String)> =
        net.events(1).iter().filter_map(|e| if let UaEvent::IncomingInvite(i) = &e.event { Some((e.leg, i.call_id.clone())) } else { None }).collect();
    assert!(calls.len() <= 1, "seed {seed}: duplicate call: {calls:?}");
    // No CSeq reused by two different requests of a dialog.
    let mut by_cseq: BTreeMap<(String, String, u32), BTreeSet<String>> = BTreeMap::new();
    for p in net.log.iter().filter(|p| !p.first_line().starts_with("SIP/2.0") && !p.first_line().starts_with("ACK") && !p.first_line().starts_with("CANCEL")) {
        let m = p.msg();
        let from = m.from_tag().unwrap_or_default();
        by_cseq.entry((m.call_id().unwrap().to_string(), from, m.cseq().unwrap().0)).or_default().insert(m.top_via().unwrap().branch.unwrap_or_default());
    }
    for (k, branches) in &by_cseq {
        assert_eq!(branches.len(), 1, "seed {seed}: CSeq {k:?} used by {} requests", branches.len());
    }
    // Events: dedupe replays by (leg, seq), then sequences are 1.. with one
    // Terminated last.
    for n in 0..2 {
        let mut seen = BTreeMap::new();
        for e in net.events(n) {
            seen.entry((e.leg, e.seq)).or_insert_with(|| e.clone());
        }
        let mut per_leg: BTreeMap<UaLegId, Vec<EventEnvelope>> = BTreeMap::new();
        for ((l, _), e) in seen {
            per_leg.entry(l).or_default().push(e);
        }
        for (l, evs) in per_leg {
            for (i, e) in evs.iter().enumerate() {
                assert_eq!(e.seq, i as u64 + 1, "seed {seed}: node {n} {l}: gap in {evs:#?}");
            }
            let terms = evs.iter().filter(|e| matches!(e.event, UaEvent::Terminated(_))).count();
            assert!(terms <= 1 && (terms == 0 || matches!(evs.last().unwrap().event, UaEvent::Terminated(_))), "seed {seed}: node {n} {l}");
        }
    }
    net.nodes[0].restarts + net.nodes[1].restarts
}

#[test]
fn random_crashes_during_random_calls() {
    let seeds: u64 = std::env::var("SIP_UA_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    let start: u64 = std::env::var("SIP_UA_SEED0").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut restarts = 0;
    for seed in start..start.saturating_add(seeds) {
        restarts += run_seed(seed);
    }
    // The point is to crash: most seeds must have restarted something.
    assert!(restarts >= seeds, "only {restarts} restarts in {seeds} seeds");
    eprintln!("{restarts} restarts in {seeds} seeds");
}
