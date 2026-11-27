//! Sharding over real UDP on loopback: two runtimes (caller A, callee B),
//! each with `shards` engine threads behind one socket, complete calls
//! (INVITE/100/200/ACK, BYE/200) with a bounded number in flight. Both
//! UAs, their reader threads and the two application threads share the
//! machine, so this shows how the engines scale with threads, not a
//! capacity figure.
//!
//! ```text
//! cargo run --release -p sip-ua --example bench_shards -- [calls] [in-flight] [shards...]
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout, clippy::arithmetic_side_effects, reason = "a benchmark tool")]
#![allow(clippy::cast_precision_loss, reason = "reporting floats")]

use sip_ua::runtime::{Resolver, RuntimeConfig, spawn_udp};
use sip_ua::*;
use std::time::{Duration, Instant};

struct NoDns;
impl Resolver for NoDns {
    fn resolve(&self, r: &ResolveRequest) -> Result<Vec<Dest>, String> {
        Err(format!("no DNS for {}", r.host))
    }
}

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 0\r\n";

fn run(calls: usize, window: usize, shards: u32) -> f64 {
    let rt = RuntimeConfig { shards, input_capacity: 65_536, event_capacity: 65_536, ..RuntimeConfig::default() };
    let cfg = UaConfig { session_expires: None, max_legs: 1_000_000, ..UaConfig::default() };
    let a = spawn_udp(cfg.clone(), "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt.clone()).unwrap();
    let b = spawn_udp(cfg, "127.0.0.1:0".parse().unwrap(), Box::new(NoDns), rt).unwrap();
    let to = format!("sip:bob@{}", b.local_addr());
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callee = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let Ok(e) = b.events().recv_timeout(Duration::from_millis(50)) else { continue };
                if let UaEvent::IncomingInvite(_) = e.event {
                    let _ = b.submit(UaCommand::Accept(AcceptRequest { leg: e.leg, sdp: Some(SDP.to_vec()), headers: vec![] }));
                }
            }
            b.shutdown();
        })
    };
    let start = Instant::now();
    let (mut started, mut done, mut failed) = (0usize, 0usize, 0usize);
    while done + failed < calls {
        while started < calls && started - done - failed < window {
            let o = OriginateRequest { request_uri: to.clone(), from: "<sip:alice@127.0.0.1>".into(), sdp: Some(SDP.to_vec()), ..Default::default() };
            if a.submit(UaCommand::Originate(Box::new(o))).is_err() {
                break;
            }
            started += 1;
        }
        let Ok(e) = a.events().recv_timeout(Duration::from_secs(10)) else { break };
        match e.event {
            UaEvent::Accepted(_) => {
                let _ = a.submit(UaCommand::Hangup(HangupRequest { leg: e.leg, reason: None, code: None }));
            }
            UaEvent::Terminated(t) => {
                if t.cause.kind == CauseKind::NormalClearing || t.cause.kind == CauseKind::Local {
                    done += 1;
                } else {
                    failed += 1;
                }
            }
            _ => {}
        }
    }
    let secs = start.elapsed().as_secs_f64();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    callee.join().unwrap();
    a.shutdown();
    let rate = done as f64 / secs;
    println!("shards {shards}: {done} calls ({failed} failed) in {secs:.2} s = {rate:.0} calls/s");
    rate
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let calls: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let window: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(500);
    let shards: Vec<u32> = if args.len() > 2 { args.get(2..).unwrap_or_default().iter().filter_map(|s| s.parse().ok()).collect() } else { vec![1, 2, 4] };
    for s in shards {
        run(calls, window, s);
    }
}
