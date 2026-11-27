//! A durable UA process for crash tests (feature `recovery`): one engine
//! on a UDP socket, journaled to a directory with `FileJournal` (fsync per
//! transition), restored from it on start.
//!
//! ```text
//! recoverable_ua --listen 127.0.0.1:5470 --dir /tmp/ua [--epoch N [--takeover]]
//!                [--call sip:bob@127.0.0.1:5480 --key call-1] [--checkpoint-every N]
//! ```
//!
//! Ownership: `--takeover` opens the journal as the owner of `--epoch`
//! (which must be newer than the state's): the journal's fence rises, so an
//! older incarnation still running on the same directory can no longer
//! commit, record a dispatch, checkpoint, or send even a stateless reply.
//! The socket is bound with `SO_REUSEPORT`, so a new owner can bind the
//! address while the old one still holds it (as during a failover). A
//! halted process (`HALT`) exits with status 3. Every message sent is
//! printed: `SENT <epoch> <first line>`.
//!
//! Lease: `--lease-ms N --lease-file F` holds an ownership lease of N ms,
//! renewed (every N/3) only while the file F exists — the stand-in for an
//! authority this process can reach. Remove F (a partition) and the engine
//! halts by itself within N ms (`HALT lease`, status 3).
//!
//! Inbound calls are answered at once (200 with SDP); remote offers are
//! answered; a `--call` is originated under `--key` (a retry after a
//! restart finds it instead of calling again). Events go to stdout, one per
//! line: `EVENT <leg> <seq> <kind>`; `READY` once restored and listening.
//!
//! Failpoint: `RECOVERY_CRASH=<boundary>:<prefix>` aborts the process at
//! `pre-commit`, `post-commit` or `post-send` of the first transition that
//! sends a message starting with `<prefix>` (e.g. `post-commit:SIP/2.0 200`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "a test tool"
)]

use sip_ua::recovery::{FileJournal, RestoreOptions};
use sip_ua::*;
use std::io::Write as _;
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SDP: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).cloned()
}

fn wall() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn say(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
}

fn main() {
    let listen: std::net::SocketAddr = arg("--listen").expect("--listen").parse().expect("address");
    let dir = std::path::PathBuf::from(arg("--dir").expect("--dir"));
    let epoch: u64 = arg("--epoch").map_or(0, |e| e.parse().expect("epoch"));
    let checkpoint_every: u64 = arg("--checkpoint-every").map_or(0, |e| e.parse().expect("number"));
    let crash = std::env::var("RECOVERY_CRASH").ok().and_then(|v| v.split_once(':').map(|(b, p)| (b.to_string(), p.to_string())));

    let sock = bind_reuseport(listen);
    sock.set_read_timeout(Some(Duration::from_millis(5))).expect("timeout");
    let cfg = UaConfig { local: vec![(Proto::Udp, listen)], durable: true, session_expires: Some(90), ..UaConfig::default() };
    let takeover = std::env::args().any(|a| a == "--takeover");
    let mut journal = match FileJournal::open_as(&dir, takeover.then_some(epoch)) {
        Ok(j) => j,
        Err(e) => {
            say(&format!("REFUSED {e}"));
            std::process::exit(4);
        }
    };
    let start = Instant::now();
    let now = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (mut ua, report) = UaEngine::restore(
        cfg,
        Box::new(SystemEntropy::default()),
        IdAllocator::new(),
        journal.state(),
        &RestoreOptions {
            epoch: if takeover { epoch } else { epoch.max(journal.owner()).max(journal.state().epoch) },
            require_newer_epoch: takeover,
            credentials: None,
        },
        now(),
        wall(),
    )
    .unwrap_or_else(|e| {
        say(&format!("REFUSED {e:?}"));
        std::process::exit(4)
    });
    for l in &report.legs {
        say(&format!("RESTORED {l:?}"));
    }
    // Committed effects whose dispatch wasn't recorded: send them now.
    for t in &report.replay_transmits {
        sent(&sock, t);
    }
    for e in &report.replay_events {
        say(&format!("EVENT {} {} {} replay", e.leg.0, e.seq, kind(&e.event)));
    }
    journal.dispatched(report.replay_up_to).expect("journal");
    // Reconciliation: an inbound call we had been told about but never
    // answered durably is answered now (no new IncomingInvite will come).
    for leg in report.restored() {
        if let Some(sn) = ua.snapshot(leg)
            && sn.role == Role::Uas
            && matches!(sn.phase, Phase::Calling | Phase::Early)
        {
            let _ = ua.submit(UaCommand::Accept(AcceptRequest { leg, sdp: Some(SDP.to_vec()), headers: vec![] }), now());
            say(&format!("RECONCILE answer {}", leg.0));
        }
    }
    let lease_ms: Option<u64> = arg("--lease-ms").map(|v| v.parse().expect("ms"));
    let lease_file = arg("--lease-file").map(std::path::PathBuf::from);
    let mut renewed_at = now();
    if let Some(l) = lease_ms {
        ua.set_lease(Some(now() + l));
    }
    say("READY");

    if let (Some(uri), Some(key)) = (arg("--call"), arg("--key")) {
        let o = OriginateRequest { request_uri: uri, from: format!("<sip:ua@{listen}>"), sdp: Some(SDP.to_vec()), ..Default::default() };
        match ua.submit_keyed(&key, UaCommand::Originate(Box::new(o)), now()) {
            Ok(k) => say(&format!("KEYED {} {} replayed={}", k.op.0, k.leg.0, k.replayed)),
            Err(e) => say(&format!("KEYED error {e}")),
        }
    }

    let mut buf = vec![0u8; 65_535];
    let mut since_checkpoint = 0u64;
    loop {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            ua.handle_message(buf.get(..n).unwrap_or_default(), Dest::new(Proto::Udp, from), now());
        }
        if let Some(l) = lease_ms
            && now() - renewed_at >= l / 3
            && lease_file.as_ref().is_some_and(|f| f.exists())
        {
            // Computed before asking (here: the file check), never after.
            renewed_at = now();
            ua.set_lease(Some(renewed_at + l));
        }
        ua.handle_timeout(now());
        if ua.is_halted() && ua.stats().lease_lapsed {
            say("HALT lease");
            std::process::exit(3);
        }
        while let Some(t) = ua.take_transition(now(), wall()) {
            let hits = |p: &str| t.record.transmits.iter().any(|x| x.data.starts_with(p.as_bytes()));
            let fail = |b: &str| crash.as_ref().is_some_and(|(cb, p)| cb == b && hits(p));
            if t.needs_commit {
                if fail("pre-commit") {
                    std::process::abort();
                }
                if let Err(e) = journal.append(&t.record) {
                    halt(&mut ua, &e);
                }
                if fail("post-commit") {
                    std::process::abort();
                }
            }
            if !t.needs_commit
                && let Err(e) = journal.admit(t.record.epoch)
            {
                // No commit, but still only the owner may answer.
                halt(&mut ua, &e);
            }
            for x in &t.record.transmits {
                sent(&sock, x);
            }
            let mut react = Vec::new();
            for e in &t.record.events {
                say(&format!("EVENT {} {} {}", e.leg.0, e.seq, kind(&e.event)));
                react.push(e.clone());
            }
            if t.needs_commit {
                if fail("post-send") {
                    std::process::abort();
                }
                if let Err(e) = journal.dispatched(t.record.seq) {
                    halt(&mut ua, &e);
                }
                since_checkpoint += 1;
            }
            // The "application": answer calls and offers.
            for e in react {
                let cmd = match &e.event {
                    UaEvent::IncomingInvite(_) => Some(UaCommand::Accept(AcceptRequest { leg: e.leg, sdp: Some(SDP.to_vec()), headers: vec![] })),
                    UaEvent::RemoteOffer(_) => Some(UaCommand::RespondToOffer(OfferResponse { leg: e.leg, generation: e.generation, sdp: Some(SDP.to_vec()) })),
                    _ => None,
                };
                if let Some(c) = cmd {
                    let _ = ua.submit(c, now());
                }
            }
        }
        if checkpoint_every > 0 && since_checkpoint >= checkpoint_every {
            since_checkpoint = 0;
            if let Err(e) = journal.checkpoint() {
                halt(&mut ua, &e);
            }
            say("CHECKPOINT");
        }
    }
}

fn bind_reuseport(listen: std::net::SocketAddr) -> UdpSocket {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(listen), Type::DGRAM, Some(Protocol::UDP)).expect("socket");
    s.set_reuse_port(true).expect("SO_REUSEPORT");
    s.bind(&listen.into()).expect("bind");
    s.into()
}

fn sent(sock: &UdpSocket, t: &Transmit) {
    let line = String::from_utf8_lossy(&t.data).lines().next().unwrap_or_default().to_string();
    say(&format!("SENT {} {line}", t.epoch));
    let _ = sock.send_to(&t.data, t.dest.addr);
}

/// Ownership lost or the store failed: stop (fail closed).
fn halt(ua: &mut UaEngine, e: &sip_ua::recovery::JournalError) -> ! {
    ua.halt();
    say(&format!("HALT {e}"));
    std::process::exit(3);
}

fn kind(e: &UaEvent) -> &'static str {
    match e {
        UaEvent::IncomingInvite(_) => "IncomingInvite",
        UaEvent::Provisional(_) => "Provisional",
        UaEvent::Accepted(_) => "Accepted",
        UaEvent::Ack(_) => "Ack",
        UaEvent::Cancelled => "Cancelled",
        UaEvent::RemoteOffer(_) => "RemoteOffer",
        UaEvent::RemoteBye(_) => "RemoteBye",
        UaEvent::Info(_) => "Info",
        UaEvent::ReferRequested(_) => "ReferRequested",
        UaEvent::ReferProgress(_) => "ReferProgress",
        UaEvent::Completed(_) => "Completed",
        UaEvent::Failed(_) => "Failed",
        UaEvent::Terminated(_) => "Terminated",
        UaEvent::CommandRejected(_) => "CommandRejected",
    }
}
