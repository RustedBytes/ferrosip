//! Deterministic network simulation: engines on fake addresses, a fake
//! clock, per-packet loss/duplication rules and captured traffic to
//! addresses that no engine owns (hand-scripted peers).

#![allow(dead_code, reason = "shared by several test files, each using a subset")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "test helpers outside #[test] fns"
)]

use sip_ua::*;
use std::collections::VecDeque;
use std::net::SocketAddr;

pub const LATENCY: u64 = 10;

pub struct Node {
    pub addr: SocketAddr,
    pub engine: UaEngine,
    pub events: Vec<EventEnvelope>,
    pub cfg: UaConfig,
    /// Durable mode: the node's journal (feature `recovery`).
    #[cfg(feature = "recovery")]
    pub journal: Option<sip_ua::recovery::MemoryJournal>,
    /// Crash at this boundary on the next committed transition.
    #[cfg(feature = "recovery")]
    pub crash_at: Option<Boundary>,
    /// Restores done (each picks a new entropy seed).
    pub restarts: u64,
    /// A stale incarnation of this node (an old owner still running after
    /// a takeover: paused process, partition). It shares the node's
    /// address and journal.
    #[cfg(feature = "recovery")]
    pub stale: Option<Stale>,
}

/// An old owner that has not noticed it lost ownership.
#[cfg(feature = "recovery")]
pub struct Stale {
    pub engine: UaEngine,
    /// It gets a copy of every packet sent to the node's address (an
    /// address both can be reached at during a failover).
    pub hears: bool,
    /// It can reach the store (false: partitioned from it; every append
    /// and admission check fails).
    pub reaches_store: bool,
    /// Its timers run.
    pub running: bool,
    pub events: Vec<EventEnvelope>,
}

/// Where a durable node dies in its commit-then-dispatch cycle.
#[cfg(feature = "recovery")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    /// The transition was computed but never persisted.
    PreCommit,
    /// Persisted, nothing dispatched.
    PostCommit,
    /// Persisted and dispatched, but the dispatch was not recorded.
    PostSend,
}

/// A datagram on the wire.
#[derive(Clone, Debug)]
pub struct Packet {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub data: Vec<u8>,
    /// Owner epoch of the engine that sent it.
    pub epoch: u64,
    /// Simulated time it was sent.
    pub at: u64,
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

/// Answers the engines' DNS requests (default: every lookup fails).
pub type Resolve = Box<dyn FnMut(&ResolveRequest) -> Result<Vec<Dest>, String>>;

pub struct Net {
    pub now: u64,
    pub nodes: Vec<Node>,
    inflight: VecDeque<(u64, Packet)>,
    /// Packets to addresses no node owns.
    pub captured: Vec<Packet>,
    /// Every packet an engine sent (before loss/duplication).
    pub log: Vec<Packet>,
    pub rule: Rule,
    pub resolver: Resolve,
    /// Wall clock = engine clock + this (restores jump it forward).
    pub wall_offset: u64,
    /// Extra random delay per packet (reordering): (rng, max ms).
    pub jitter: Option<(SeededEntropy, u64)>,
    /// The egress point of one node's address: drops its transmits of
    /// fenced epochs.
    pub egress: Option<(SocketAddr, EgressFence)>,
    /// Transmits the egress fence dropped.
    pub egress_dropped: Vec<Packet>,
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
        Self {
            now: 0,
            nodes: Vec::new(),
            inflight: VecDeque::new(),
            captured: Vec::new(),
            log: Vec::new(),
            rule: Box::new(|_| 1),
            resolver: Box::new(|r| Err(format!("no DNS in tests: {}", r.host))),
            wall_offset: 1_800_000_000_000,
            jitter: None,
            egress: None,
            egress_dropped: Vec::new(),
        }
    }

    pub fn add(&mut self, a: &str, seed: u64) -> usize {
        self.add_with(a, seed, |c| c)
    }

    pub fn add_with(&mut self, a: &str, seed: u64, f: impl FnOnce(UaConfig) -> UaConfig) -> usize {
        let a = addr(a);
        let cfg = f(config(a));
        let engine = UaEngine::with_entropy(cfg.clone(), Box::new(SeededEntropy::new(seed)), IdAllocator::new());
        self.nodes.push(Node {
            addr: a,
            engine,
            events: Vec::new(),
            cfg,
            #[cfg(feature = "recovery")]
            journal: None,
            #[cfg(feature = "recovery")]
            crash_at: None,
            restarts: 0,
            #[cfg(feature = "recovery")]
            stale: None,
        });
        self.nodes.len() - 1
    }

    /// A node in durable mode, journaling into memory.
    #[cfg(feature = "recovery")]
    pub fn add_durable(&mut self, a: &str, seed: u64, f: impl FnOnce(UaConfig) -> UaConfig) -> usize {
        let n = self.add_with(a, seed, |c| f(UaConfig { durable: true, ..c }));
        self.nodes[n].journal = Some(sip_ua::recovery::MemoryJournal::new(10_000));
        n
    }

    /// The simulated wall clock (Unix ms): the engine clock plus `wall_offset`.
    pub fn wall(&self) -> u64 {
        self.now + self.wall_offset
    }

    /// Kill node `n` and restart it from its journal after `downtime_ms`
    /// (the wall clock moves on; the engine clock is the simulation's).
    /// Replayed effects are dispatched as a restarting driver would.
    /// Packets in flight to it are lost.
    #[cfg(feature = "recovery")]
    pub fn crash_and_restore(&mut self, n: usize, downtime_ms: u64) -> sip_ua::recovery::RestoreReport {
        use sip_ua::recovery::RestoreOptions;
        self.wall_offset += downtime_ms;
        let to = self.nodes[n].addr;
        self.inflight.retain(|(_, p)| p.to != to);
        let state = self.nodes[n].journal.as_ref().expect("durable node").state().expect("state");
        let restarts = self.nodes[n].restarts + 1;
        let (engine, report) = UaEngine::restore(
            self.nodes[n].cfg.clone(),
            Box::new(SeededEntropy::new(0xdead_0000 + restarts * 7919)),
            IdAllocator::new(),
            &state,
            &RestoreOptions { epoch: self.nodes[n].engine.epoch(), ..RestoreOptions::default() },
            self.now,
            self.wall(),
        )
        .expect("restore");
        self.nodes[n].engine = engine;
        self.nodes[n].restarts = restarts;
        let from = self.nodes[n].addr;
        for t in report.replay_transmits.clone() {
            let p = Packet { from, to: t.dest.addr, data: t.data.to_vec(), epoch: t.epoch, at: self.now };
            self.put_on_wire(p);
        }
        self.nodes[n].events.extend(report.replay_events.clone());
        if let Some(j) = self.nodes[n].journal.as_mut() {
            j.dispatched(report.replay_up_to);
        }
        self.flush();
        report
    }

    pub fn put_on_wire(&mut self, p: Packet) {
        if self.egress.as_ref().is_some_and(|(a, f)| *a == p.from && !f.admits(p.epoch)) {
            self.egress_dropped.push(p);
            return;
        }
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

    /// One durable node's transitions: commit, then dispatch (with the
    /// failpoint applied). Returns whether anything moved.
    #[cfg(feature = "recovery")]
    fn flush_durable(&mut self, i: usize) -> bool {
        let mut moved = false;
        let (now, wall) = (self.now, self.wall());
        while let Some(t) = self.nodes[i].engine.take_transition(now, wall) {
            moved = true;
            let from = self.nodes[i].addr;
            if t.needs_commit {
                if self.nodes[i].crash_at == Some(Boundary::PreCommit) {
                    self.nodes[i].crash_at = None;
                    self.crash_and_restore(i, 0);
                    return true;
                }
                let r = self.nodes[i].journal.as_mut().expect("durable").append(&t.record);
                if r.is_err() {
                    // Fail closed: no effects past a commit that failed.
                    self.nodes[i].engine.halt();
                    return true;
                }
                if self.nodes[i].crash_at == Some(Boundary::PostCommit) {
                    self.nodes[i].crash_at = None;
                    self.crash_and_restore(i, 0);
                    return true;
                }
            }
            if !t.needs_commit && self.nodes[i].journal.as_ref().expect("durable").admit(t.record.epoch).is_err() {
                // Even a stateless reply waits for the ownership check.
                self.nodes[i].engine.halt();
                return true;
            }
            for tx in &t.record.transmits {
                let p = Packet { from, to: tx.dest.addr, data: tx.data.to_vec(), epoch: tx.epoch, at: self.now };
                self.put_on_wire(p);
            }
            self.nodes[i].events.extend(t.record.events.iter().cloned());
            if t.needs_commit {
                if self.nodes[i].crash_at == Some(Boundary::PostSend) {
                    self.nodes[i].crash_at = None;
                    self.crash_and_restore(i, 0);
                    return true;
                }
                if let Some(j) = self.nodes[i].journal.as_mut() {
                    j.dispatched(t.record.seq);
                }
            }
        }
        moved
    }

    /// The stale incarnation's transitions: it tries the store exactly as
    /// a live owner would; a refused (fenced) or unreachable store halts it.
    #[cfg(feature = "recovery")]
    fn flush_stale(&mut self, i: usize) -> bool {
        let (now, wall) = (self.now, self.wall());
        let mut moved = false;
        loop {
            let node = &mut self.nodes[i];
            let Some(st) = node.stale.as_mut() else { return moved };
            let Some(t) = st.engine.take_transition(now, wall) else { return moved };
            moved = true;
            let journal = node.journal.as_mut().expect("durable");
            let ok = st.reaches_store && if t.needs_commit { journal.append(&t.record).is_ok() } else { journal.admit(t.record.epoch).is_ok() };
            if !ok {
                st.engine.halt();
                continue;
            }
            st.events.extend(t.record.events.iter().cloned());
            let from = node.addr;
            for tx in &t.record.transmits {
                let p = Packet { from, to: tx.dest.addr, data: tx.data.to_vec(), epoch: tx.epoch, at: now };
                self.put_on_wire(p);
            }
            if t.needs_commit {
                self.nodes[i].journal.as_mut().expect("durable").dispatched(t.record.seq);
            }
        }
    }

    /// A takeover of node `n` by a new owner of `epoch`: restore from the
    /// journal (refusing a non-newer epoch), fence the store and the
    /// egress, and keep the old engine running as the stale incarnation.
    /// Replayed effects are dispatched by the new owner.
    #[cfg(feature = "recovery")]
    pub fn take_over(&mut self, n: usize, epoch: u64, hears: bool, reaches_store: bool) -> sip_ua::recovery::RestoreReport {
        use sip_ua::recovery::RestoreOptions;
        let state = self.nodes[n].journal.as_ref().expect("durable node").state().expect("state");
        let restarts = self.nodes[n].restarts + 1;
        let (engine, report) = UaEngine::restore(
            self.nodes[n].cfg.clone(),
            Box::new(SeededEntropy::new(0xbeef_0000 + restarts * 7919)),
            IdAllocator::new(),
            &state,
            &RestoreOptions { epoch, require_newer_epoch: true, credentials: None },
            self.now,
            self.wall(),
        )
        .expect("takeover");
        self.nodes[n].journal.as_mut().expect("durable").fence(epoch);
        if let Some((_, f)) = self.egress.as_ref().filter(|(a, _)| *a == self.nodes[n].addr) {
            f.raise(epoch);
        }
        let old = std::mem::replace(&mut self.nodes[n].engine, engine);
        self.nodes[n].stale = Some(Stale { engine: old, hears, reaches_store, running: true, events: Vec::new() });
        self.nodes[n].restarts = restarts;
        let from = self.nodes[n].addr;
        for t in report.replay_transmits.clone() {
            let p = Packet { from, to: t.dest.addr, data: t.data.to_vec(), epoch: t.epoch, at: self.now };
            self.put_on_wire(p);
        }
        self.nodes[n].events.extend(report.replay_events.clone());
        if let Some(j) = self.nodes[n].journal.as_mut() {
            j.dispatched(report.replay_up_to);
        }
        self.flush();
        report
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
                #[cfg(feature = "recovery")]
                if self.nodes[i].journal.is_some() && self.flush_durable(i) {
                    moved = true;
                }
                #[cfg(feature = "recovery")]
                if self.flush_stale(i) {
                    moved = true;
                }
                let from = self.nodes[i].addr;
                while let Some(t) = self.nodes[i].engine.poll_transmit() {
                    moved = true;
                    let p = Packet { from, to: t.dest.addr, data: t.data.to_vec(), epoch: t.epoch, at: self.now };
                    if self.egress.as_ref().is_some_and(|(a, f)| *a == p.from && !f.admits(p.epoch)) {
                        self.egress_dropped.push(p);
                        continue;
                    }
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
                    let now = self.now;
                    let res = (self.resolver)(&r);
                    self.nodes[i].engine.resolved(r.id, res, now);
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
        #[cfg(feature = "recovery")]
        let next_timer = next_timer
            .into_iter()
            .chain(self.nodes.iter().filter_map(|n| n.stale.as_ref().filter(|st| st.running).and_then(|st| st.engine.next_timeout())))
            .min();
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
                #[cfg(feature = "recovery")]
                if let Some(st) = n.stale.as_mut().filter(|st| st.hears) {
                    st.engine.handle_message(&p.data, Dest::new(Proto::Udp, p.from), now);
                }
            }
            self.flush();
        }
        for n in &mut self.nodes {
            n.engine.handle_timeout(now);
            #[cfg(feature = "recovery")]
            if let Some(st) = n.stale.as_mut().filter(|st| st.running) {
                st.engine.handle_timeout(now);
            }
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
