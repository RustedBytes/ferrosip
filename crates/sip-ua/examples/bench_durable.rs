//! The cost of durable mode (feature `recovery`): the in-process engine
//! benchmark of `examples/bench.rs` (two engines, no sockets) run three
//! ways —
//!
//! - `memory`: in-memory mode (`poll_transmit` / `poll_event`);
//! - `durable-encode`: durable mode, every transition encoded to its JSON
//!   record (what a store would receive) and dropped: the engine's own
//!   cost of durability (change tracking, record building, encoding);
//! - `durable-fsync`: durable mode into a `FileJournal` per engine (one
//!   `fdatasync` per transition), the end-to-end cost on the given disk.
//!
//! ```text
//! cargo run --release -p sip-ua --features recovery --example bench_durable -- [calls] [fsync-calls] [batch] [dir]
//! ```
//!
//! `batch`: calls set up together (default 1000). Every input's changes
//! that are pending when the driver takes a transition go into one
//! record, so a large batch is group commit (few, large records) and a
//! batch of 1 is one call at a time (a record per protocol step).
//!
//! Reports call rate, transitions and journal bytes per call, and
//! per-transition commit latency (fsync mode). Engineering numbers for one
//! machine and disk, not a capacity claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    reason = "a benchmark tool"
)]
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "reporting floats")]

use sip_ua::recovery::FileJournal;
use sip_ua::*;
use std::time::Instant;

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Memory,
    DurableEncode,
    DurableFsync,
}

struct Side {
    ua: UaEngine,
    addr: Dest,
    journal: Option<FileJournal>,
}

struct Pair {
    sides: [Side; 2],
    mode: Mode,
    now: u64,
    committed: u64,
    bytes: u64,
    commit_ns: Vec<u64>,
}

impl Pair {
    fn new(mode: Mode, dir: &std::path::Path) -> Self {
        let mk = |a: &str, n: u64| {
            let addr = Dest::new(Proto::Udp, a.parse().unwrap());
            let cfg = UaConfig {
                local: vec![(Proto::Udp, addr.addr)],
                max_legs: 1_000_000,
                max_pending_events: 1_000_000,
                durable: mode != Mode::Memory,
                ..UaConfig::default()
            };
            let journal = (mode == Mode::DurableFsync).then(|| {
                let d = dir.join(format!("engine-{n}"));
                let _ = std::fs::remove_dir_all(&d);
                FileJournal::open(&d).unwrap()
            });
            Side { ua: UaEngine::with_entropy(cfg, Box::new(SystemEntropy::default()), IdAllocator::new()), addr, journal }
        };
        Self { sides: [mk("10.0.0.1:5060", 1), mk("10.0.0.2:5060", 2)], mode, now: 0, committed: 0, bytes: 0, commit_ns: Vec::new() }
    }

    /// One side's output: (transmits, events).
    fn drain(&mut self, i: usize) -> (Vec<Transmit>, Vec<EventEnvelope>) {
        let (mut tx, mut ev) = (Vec::new(), Vec::new());
        if self.mode == Mode::Memory {
            while let Some(t) = self.sides[i].ua.poll_transmit() {
                tx.push(t);
            }
            while let Some(e) = self.sides[i].ua.poll_event() {
                ev.push(e);
            }
            return (tx, ev);
        }
        let now = self.now;
        while let Some(t) = self.sides[i].ua.take_transition(now, 1_800_000_000_000 + now) {
            if t.needs_commit {
                self.committed += 1;
                let s = Instant::now();
                match self.sides[i].journal.as_mut() {
                    Some(j) => {
                        j.append(&t.record).unwrap();
                        j.dispatched(t.record.seq).unwrap();
                    }
                    None => self.bytes += t.record.to_json().unwrap().len() as u64,
                }
                self.commit_ns.push(s.elapsed().as_nanos() as u64);
            }
            tx.extend(t.record.transmits);
            ev.extend(t.record.events);
        }
        (tx, ev)
    }

    fn pump(&mut self, evs: &mut [Vec<EventEnvelope>; 2]) {
        loop {
            let mut moved = false;
            for i in 0..2 {
                let (tx, ev) = self.drain(i);
                moved |= !tx.is_empty() || !ev.is_empty();
                evs[i].extend(ev);
                let from = self.sides[i].addr;
                for t in tx {
                    self.sides[1 - i].ua.handle_message(&t.data, from, self.now);
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn call_batch(&mut self, n: usize) {
        let mut evs = [Vec::new(), Vec::new()];
        let mut legs = Vec::with_capacity(n);
        for _ in 0..n {
            let o = OriginateRequest {
                request_uri: "sip:bob@10.0.0.2".into(),
                from: "<sip:alice@example.com>".into(),
                sdp: Some(SDP.to_vec()),
                ..Default::default()
            };
            legs.push(self.sides[0].ua.submit(UaCommand::Originate(Box::new(o)), self.now).unwrap().leg);
        }
        self.pump(&mut evs);
        let inbound: Vec<UaLegId> = evs[1].iter().filter(|e| matches!(e.event, UaEvent::IncomingInvite(_))).map(|e| e.leg).collect();
        for &l in &inbound {
            let b = &mut self.sides[1].ua;
            b.submit(UaCommand::Provisional(ProvisionalRequest { leg: l, code: 180, reason: None, sdp: None, headers: vec![] }), self.now).unwrap();
            b.submit(UaCommand::Accept(AcceptRequest { leg: l, sdp: Some(SDP.to_vec()), headers: vec![] }), self.now).unwrap();
        }
        self.pump(&mut evs);
        assert_eq!(evs[0].iter().filter(|e| matches!(e.event, UaEvent::Accepted(_))).count(), n, "all answered");
        for &l in &legs {
            self.sides[0].ua.submit(UaCommand::Hangup(HangupRequest { leg: l, reason: None, code: None }), self.now).unwrap();
        }
        self.pump(&mut evs);
        self.now += 64_000;
        for s in &mut self.sides {
            s.ua.handle_timeout(self.now);
        }
        self.pump(&mut evs);
    }
}

fn pct(v: &mut [u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() as f64 - 1.0) * p) as usize]
}

fn run(mode: Mode, calls: usize, batch: usize, dir: &std::path::Path) {
    let mut p = Pair::new(mode, dir);
    let start = Instant::now();
    let mut done = 0;
    while done < calls {
        let n = batch.min(calls - done);
        p.call_batch(n);
        done += n;
    }
    let secs = start.elapsed().as_secs_f64();
    assert!(p.sides.iter().all(|s| s.ua.is_idle()), "engines idle");
    let journal_bytes: u64 = (0..2).map(|i| std::fs::metadata(dir.join(format!("engine-{}/journal.log", i + 1))).map_or(0, |m| m.len())).sum();
    let bytes = if mode == Mode::DurableFsync { journal_bytes } else { p.bytes };
    println!(
        "{:<14} batch {batch:>4} {:>6} calls {:>7.0} calls/s  {:>6.2} commits/call  {:>6.0} B/call  {:>7.0} B/commit  commit p50 {:.1} µs p99 {:.1} µs",
        format!("{mode:?}"),
        calls,
        calls as f64 / secs,
        p.committed as f64 / calls as f64,
        bytes as f64 / calls as f64,
        bytes as f64 / p.committed.max(1) as f64,
        pct(&mut p.commit_ns, 0.5) as f64 / 1000.0,
        pct(&mut p.commit_ns, 0.99) as f64 / 1000.0,
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let calls: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let fsync_calls: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000);
    let batch: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000).max(1);
    let dir = std::path::PathBuf::from(args.next().unwrap_or_else(|| std::env::temp_dir().join("sip-ua-bench-durable").display().to_string()));
    std::fs::create_dir_all(&dir).unwrap();
    run(Mode::Memory, calls, batch, &dir);
    run(Mode::DurableEncode, calls, batch, &dir);
    run(Mode::DurableFsync, fsync_calls, batch, &dir);
    if std::env::var_os("BENCH_KEEP").is_none() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}
