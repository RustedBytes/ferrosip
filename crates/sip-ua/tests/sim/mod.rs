//! Deterministic network simulation: engines on fake addresses, a fake
//! clock, per-packet loss/duplication rules and captured traffic to
//! addresses that no engine owns (hand-scripted peers).

#![allow(dead_code, reason = "shared by several test files, each using a subset")]

use sip_ua::*;
use std::collections::VecDeque;
use std::net::SocketAddr;

pub const LATENCY: u64 = 10;

pub struct Node {
    pub addr: SocketAddr,
    pub engine: UaEngine,
    pub events: Vec<EventEnvelope>,
}

/// A datagram on the wire.
#[derive(Clone, Debug)]
pub struct Packet {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn msg(&self) -> SipMessage {
        SipMessage::parse(&self.data, &Limits::default()).expect("valid SIP on the wire")
    }
    pub fn first_line(&self) -> String {
        String::from_utf8_lossy(&self.data).lines().next().unwrap_or_default().to_string()
    }
}

/// Decide a packet's fate: how many copies to deliver (0 = lost).
pub type Rule = Box<dyn FnMut(&Packet) -> usize>;

pub struct Net {
    pub now: u64,
    pub nodes: Vec<Node>,
    inflight: VecDeque<(u64, Packet)>,
    /// Packets to addresses no node owns.
    pub captured: Vec<Packet>,
    /// Every packet an engine sent (before loss/duplication).
    pub log: Vec<Packet>,
    pub rule: Rule,
    /// Extra random delay per packet (reordering): (rng, max ms).
    pub jitter: Option<(SeededEntropy, u64)>,
}

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub fn config(a: SocketAddr) -> UaConfig {
    UaConfig { local: vec![(Proto::Udp, a)], ..UaConfig::default() }
}

pub fn sdp(tag: &str) -> Vec<u8> {
    format!("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns={tag}\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n").into_bytes()
}

impl Net {
    pub fn new() -> Self {
        Self { now: 0, nodes: Vec::new(), inflight: VecDeque::new(), captured: Vec::new(), log: Vec::new(), rule: Box::new(|_| 1), jitter: None }
    }

    pub fn add(&mut self, a: &str, seed: u64) -> usize {
        self.add_with(a, seed, |c| c)
    }

    pub fn add_with(&mut self, a: &str, seed: u64, f: impl FnOnce(UaConfig) -> UaConfig) -> usize {
        let a = addr(a);
        let engine = UaEngine::with_entropy(f(config(a)), Box::new(SeededEntropy::new(seed)), IdAllocator::new());
        self.nodes.push(Node { addr: a, engine, events: Vec::new() });
        self.nodes.len() - 1
    }

    pub fn engine(&mut self, n: usize) -> &mut UaEngine {
        &mut self.nodes[n].engine
    }

    pub fn submit(&mut self, n: usize, cmd: UaCommand) -> Result<Accepted, CommandError> {
        let now = self.now;
        let r = self.nodes[n].engine.submit(cmd, now);
        self.flush();
        r
    }

    /// Hand a raw message to node `n` as if sent from `from`.
    pub fn inject(&mut self, n: usize, from: &str, data: &[u8]) {
        let now = self.now;
        self.nodes[n].engine.handle_message(data, Dest::new(Proto::Udp, addr(from)), now);
        self.flush();
    }

    /// Move outputs of every engine onto the wire and collect events.
    pub fn flush(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                let from = self.nodes[i].addr;
                while let Some(t) = self.nodes[i].engine.poll_transmit() {
                    moved = true;
                    let p = Packet { from, to: t.dest.addr, data: t.data.to_vec() };
                    let copies = (self.rule)(&p);
                    self.log.push(p.clone());
                    for _ in 0..copies {
                        if self.nodes.iter().any(|n| n.addr == p.to) {
                            let extra = self.jitter.as_mut().map_or(0, |(r, max)| r.next_u64() % (*max + 1));
                            self.inflight.push_back((self.now + LATENCY + extra, p.clone()));
                        } else {
                            self.captured.push(p.clone());
                        }
                    }
                }
                while let Some(r) = self.nodes[i].engine.poll_resolve() {
                    // Tests only use IP targets; resolution "fails".
                    let now = self.now;
                    self.nodes[i].engine.resolved(r.id, Err(format!("no DNS in tests: {}", r.host)), now);
                    moved = true;
                }
                while let Some(e) = self.nodes[i].engine.poll_event() {
                    self.nodes[i].events.push(e);
                }
            }
            if !moved {
                break;
            }
        }
    }

    /// Advance to the next packet delivery or timer; false when nothing is pending.
    pub fn step(&mut self) -> bool {
        self.step_capped(u64::MAX)
    }

    /// `step`, but never advance the clock past `cap` (application actions
    /// scheduled at a time must not be skipped over).
    pub fn step_capped(&mut self, cap: u64) -> bool {
        self.flush();
        let next_pkt = self.inflight.iter().map(|(t, _)| *t).min();
        let next_timer = self.nodes.iter().filter_map(|n| n.engine.next_timeout()).min();
        let Some(next) = [next_pkt, next_timer].into_iter().flatten().min() else { return false };
        if next > cap {
            self.now = self.now.max(cap);
            return true;
        }
        self.now = self.now.max(next);
        let now = self.now;
        // Deliver every due packet (in arrival order), then timers.
        let mut due = Vec::new();
        self.inflight.retain(|(t, p)| {
            if *t <= now {
                due.push((*t, p.clone()));
                false
            } else {
                true
            }
        });
        due.sort_by_key(|(t, _)| *t);
        for (_, p) in due {
            if let Some(n) = self.nodes.iter_mut().find(|n| n.addr == p.to) {
                n.engine.handle_message(&p.data, Dest::new(Proto::Udp, p.from), now);
            }
            self.flush();
        }
        for n in &mut self.nodes {
            n.engine.handle_timeout(now);
        }
        self.flush();
        true
    }

    /// Step until `cond` holds or `limit` ms of simulated time pass.
    pub fn run_until(&mut self, limit: u64, mut cond: impl FnMut(&Net) -> bool) -> bool {
        let end = self.now + limit;
        self.flush();
        while !cond(self) {
            if self.now > end || !self.step() {
                return cond(self);
            }
        }
        true
    }

    /// Run until every engine is idle (all timers out) or `limit` passes.
    pub fn settle(&mut self, limit: u64) -> bool {
        self.run_until(limit, |n| n.nodes.iter().all(|x| x.engine.is_idle()) && n.inflight.is_empty())
    }

    pub fn events(&self, n: usize) -> &[EventEnvelope] {
        &self.nodes[n].events
    }

    pub fn count(&self, n: usize, f: impl Fn(&UaEvent) -> bool) -> usize {
        self.nodes[n].events.iter().filter(|e| f(&e.event)).count()
    }

    pub fn has(&self, n: usize, f: impl Fn(&UaEvent) -> bool) -> bool {
        self.count(n, f) > 0
    }

    pub fn find(&self, n: usize, f: impl Fn(&UaEvent) -> bool) -> Option<EventEnvelope> {
        self.nodes[n].events.iter().find(|e| f(&e.event)).cloned()
    }

    pub fn incoming_leg(&self, n: usize) -> Option<UaLegId> {
        self.find(n, |e| matches!(e, UaEvent::IncomingInvite(_))).map(|e| e.leg)
    }

    /// Packets whose first line starts with `prefix`.
    pub fn sent(&self, prefix: &str) -> Vec<Packet> {
        self.log.iter().filter(|p| p.first_line().starts_with(prefix)).cloned().collect()
    }

    pub fn captured(&self, prefix: &str) -> Vec<Packet> {
        self.captured.iter().filter(|p| p.first_line().starts_with(prefix)).cloned().collect()
    }

    /// Every leg's events: sequence numbers are 1, 2, 3… and `Terminated`
    /// is last and unique.
    pub fn check_event_invariants(&self) {
        for n in &self.nodes {
            let mut legs: Vec<UaLegId> = n.events.iter().map(|e| e.leg).collect();
            legs.sort();
            legs.dedup();
            for l in legs {
                let evs: Vec<&EventEnvelope> = n.events.iter().filter(|e| e.leg == l).collect();
                for (i, e) in evs.iter().enumerate() {
                    assert_eq!(e.seq, i as u64 + 1, "{l}: sequence gap in {evs:#?}");
                }
                let terms = evs.iter().filter(|e| matches!(e.event, UaEvent::Terminated(_))).count();
                assert!(terms <= 1, "{l}: {terms} Terminated events");
                if terms == 1 {
                    assert!(matches!(evs.last().unwrap().event, UaEvent::Terminated(_)), "{l}: events after Terminated: {evs:#?}");
                }
            }
        }
    }
}

pub fn originate(to: &str, sdp: Option<Vec<u8>>) -> UaCommand {
    UaCommand::Originate(Box::new(OriginateRequest {
        request_uri: format!("sip:bob@{to}"),
        from: "\"Alice\" <sip:alice@example.com>".into(),
        sdp,
        ..Default::default()
    }))
}

/// A response to `req` (as a scripted peer would send it).
pub fn respond(req: &SipMessage, code: u16, to_tag: Option<&str>, extra: &[(&str, &str)], body: Option<&[u8]>) -> Vec<u8> {
    let mut r = SipMessage::response(code, "Scripted");
    for v in req.header_lines("Via") {
        r.push_header("Via", v);
    }
    r.push_header("From", req.header("From").unwrap());
    let to = req.header("To").unwrap();
    match to_tag {
        Some(t) => r.push_header("To", format!("{to};tag={t}")),
        None => r.push_header("To", to),
    }
    r.push_header("Call-ID", req.call_id().unwrap());
    r.push_header("CSeq", req.header("CSeq").unwrap());
    for (n, v) in extra {
        r.push_header(*n, *v);
    }
    if let Some(b) = body {
        r.push_header("Content-Type", "application/sdp");
        r.body = b.to_vec();
    }
    r.to_bytes()
}
