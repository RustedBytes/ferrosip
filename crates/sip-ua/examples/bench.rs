//! In-process engine benchmark: two engines exchange messages directly
//! (no sockets, no media), so this measures SIP engine work only: parsing,
//! transactions, dialogs and serialization. It is not complete-call CPS
//! over a network; see `docs/sip-ua.md` (Benchmarks) for the methodology.
//!
//! ```text
//! cargo run --release -p sip-ua --example bench -- [calls] [concurrent]
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects, reason = "a benchmark tool")]
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "reporting floats")]

use sip_ua::*;
use std::time::Instant;

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n";

struct Pair {
    a: UaEngine,
    b: UaEngine,
    a_addr: Dest,
    b_addr: Dest,
    now: u64,
    lat_ns: Vec<u64>,
    msgs: u64,
}

impl Pair {
    fn new() -> Self {
        let a_addr = Dest::new(Proto::Udp, "10.0.0.1:5060".parse().unwrap());
        let b_addr = Dest::new(Proto::Udp, "10.0.0.2:5060".parse().unwrap());
        let cfg = |d: Dest| UaConfig { local: vec![(Proto::Udp, d.addr)], max_legs: 1_000_000, max_pending_events: 1_000_000, ..UaConfig::default() };
        Self { a: UaEngine::new(cfg(a_addr)), b: UaEngine::new(cfg(b_addr)), a_addr, b_addr, now: 0, lat_ns: Vec::new(), msgs: 0 }
    }

    /// Deliver every queued message both ways until quiet; B answers calls.
    fn pump(&mut self, b_events: &mut Vec<EventEnvelope>, a_events: &mut Vec<EventEnvelope>) {
        loop {
            let mut moved = false;
            while let Some(t) = self.a.poll_transmit() {
                moved = true;
                let s = Instant::now();
                self.b.handle_message(&t.data, self.a_addr, self.now);
                self.lat_ns.push(s.elapsed().as_nanos() as u64);
                self.msgs += 1;
            }
            while let Some(t) = self.b.poll_transmit() {
                moved = true;
                let s = Instant::now();
                self.a.handle_message(&t.data, self.b_addr, self.now);
                self.lat_ns.push(s.elapsed().as_nanos() as u64);
                self.msgs += 1;
            }
            while let Some(e) = self.b.poll_event() {
                moved = true;
                b_events.push(e);
            }
            while let Some(e) = self.a.poll_event() {
                moved = true;
                a_events.push(e);
            }
            if !moved {
                return;
            }
        }
    }

    /// Originate `n` calls, ring + answer them on B; returns A's legs.
    fn establish(&mut self, n: usize) -> (Vec<UaLegId>, Vec<UaLegId>) {
        let mut legs = Vec::with_capacity(n);
        for _ in 0..n {
            let o = OriginateRequest {
                request_uri: "sip:bob@10.0.0.2".into(),
                from: "<sip:alice@example.com>".into(),
                sdp: Some(SDP.to_vec()),
                ..Default::default()
            };
            legs.push(self.a.submit(UaCommand::Originate(Box::new(o)), self.now).unwrap().leg);
        }
        let (mut be, mut ae) = (Vec::new(), Vec::new());
        self.pump(&mut be, &mut ae);
        let inbound: Vec<UaLegId> = be.iter().filter(|e| matches!(e.event, UaEvent::IncomingInvite(_))).map(|e| e.leg).collect();
        for &l in &inbound {
            self.b.submit(UaCommand::Provisional(ProvisionalRequest { leg: l, code: 180, reason: None, sdp: None, headers: vec![] }), self.now).unwrap();
            self.b.submit(UaCommand::Accept(AcceptRequest { leg: l, sdp: Some(SDP.to_vec()), headers: vec![] }), self.now).unwrap();
        }
        self.pump(&mut be, &mut ae);
        assert_eq!(ae.iter().filter(|e| matches!(e.event, UaEvent::Accepted(_))).count(), n, "all calls answered");
        (legs, inbound)
    }

    fn hangup(&mut self, legs: &[UaLegId]) {
        for &l in legs {
            self.a.submit(UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None }), self.now).unwrap();
        }
        let (mut be, mut ae) = (Vec::new(), Vec::new());
        self.pump(&mut be, &mut ae);
    }

    /// Let every transaction timer run out.
    fn expire(&mut self) {
        self.now += 64_000;
        self.a.handle_timeout(self.now);
        self.b.handle_timeout(self.now);
        let (mut be, mut ae) = (Vec::new(), Vec::new());
        self.pump(&mut be, &mut ae);
    }
}

fn rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

fn pct(v: &mut [u64], p: f64) -> u64 {
    v.sort_unstable();
    v[((v.len() as f64 - 1.0) * p) as usize]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let calls: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(50_000);
    let concurrent: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);

    // 1. Throughput: complete calls (INVITE/100/180/200/ACK, BYE/200) in batches of 1000.
    let mut p = Pair::new();
    let start = Instant::now();
    let mut done = 0;
    while done < calls {
        let n = 1_000.min(calls - done);
        let (legs, _) = p.establish(n);
        p.hangup(&legs);
        p.expire();
        done += n;
    }
    let secs = start.elapsed().as_secs_f64();
    assert!(p.a.is_idle() && p.b.is_idle(), "no state left: {:?} {:?}", p.a.stats(), p.b.stats());
    let msgs = p.msgs;
    let mut lat = std::mem::take(&mut p.lat_ns);
    println!("calls                 {calls}");
    println!("engine call rate      {:.0} calls/s (both UAC and UAS sides, one thread)", calls as f64 / secs);
    println!("messages handled      {msgs} ({:.0}/s)", msgs as f64 / secs);
    println!("handle_message p50    {} ns", pct(&mut lat, 0.50));
    println!("handle_message p95    {} ns", pct(&mut lat, 0.95));
    println!("handle_message p99    {} ns", pct(&mut lat, 0.99));

    // 2. Memory: `concurrent` established calls, set up in batches of 1000
    // (transactions expired after each) so transient queues don't count.
    let mut p = Pair::new();
    let (warm, _) = p.establish(1_000);
    p.hangup(&warm);
    p.expire();
    let before = rss_bytes();
    let mut legs = Vec::with_capacity(concurrent);
    while legs.len() < concurrent {
        let (l, _) = p.establish(1_000.min(concurrent - legs.len()));
        legs.extend(l);
        p.expire();
    }
    let after = rss_bytes();
    println!("concurrent calls      {concurrent} ({} legs on each engine)", p.a.stats().legs);
    if let (Some(b), Some(a)) = (before, after) {
        println!(
            "RSS growth            {:.1} MiB, ~{} bytes per call (one UAC + one UAS leg, incl. allocator overhead)",
            (a.saturating_sub(b)) as f64 / 1048576.0,
            a.saturating_sub(b) / concurrent as u64
        );
    }
    p.hangup(&legs);
    p.expire();
    assert!(p.a.is_idle() && p.b.is_idle());
}
