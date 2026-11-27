//! Cross-repo: the example B2BUA anchoring media in a real rtpflux (ng
//! protocol), with real RTP through the relay. Skipped when there is no
//! rtpflux binary ($RTPFLUX, else ../rtpflux/target/release/rtpflux).

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
#[path = "../examples/b2bua/rtpflux.rs"]
mod rtpflux;

use bridge::Bridge;
use rtpflux::Rtpflux;
use sim::*;
use sip_ua::*;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const CALLER: usize = 0;
const B2B: usize = 1;
const CALLEE: usize = 2;
const PORT_MIN: u16 = 41_000;
const PORT_MAX: u16 = 41_099;

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_rtpflux() -> Option<(Relay, std::net::SocketAddr)> {
    let bin = std::env::var("RTPFLUX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../rtpflux/target/release/rtpflux"));
    if !bin.exists() {
        eprintln!("SKIP: no rtpflux binary at {} (set RTPFLUX)", bin.display());
        return None;
    }
    let ng_port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("sip-ua-rtpflux-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("rtpflux.toml");
    std::fs::write(
        &cfg,
        format!(
            "[control]\nlisten = [\"127.0.0.1:{ng_port}\"]\n\n[[interface]]\nname = \"default\"\naddress = \"127.0.0.1\"\n\n[ports]\nmin = {PORT_MIN}\nmax = {PORT_MAX}\n\n[sessions]\nmax = 20\ntimeout = 30\n\n[runtime]\nworkers = 1\n"
        ),
    )
    .unwrap();
    let child = Command::new(&bin).arg("-c").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let relay = Relay(child);
    let ng: std::net::SocketAddr = format!("127.0.0.1:{ng_port}").parse().unwrap();
    // Wait until it answers ping.
    for _ in 0..50 {
        if Rtpflux::new(ng).unwrap().ping().is_ok() {
            return Some((relay, ng));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("rtpflux did not answer ping");
}

fn media_sdp(port: u16) -> Vec<u8> {
    format!("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n")
        .into_bytes()
}

fn audio_port(sdp: &[u8]) -> u16 {
    let s = String::from_utf8_lossy(sdp);
    let m = s.lines().find(|l| l.starts_with("m=audio ")).unwrap();
    m.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn rtp(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    p.extend(std::iter::repeat_n(0xffu8, 160));
    p
}

/// Send RTP from `from` to the relay port until something arrives at `to`.
fn flows(from: &UdpSocket, relay_port: u16, to: &UdpSocket) -> bool {
    to.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut buf = [0u8; 2048];
    for seq in 0..30 {
        from.send_to(&rtp(seq), ("127.0.0.1", relay_port)).unwrap();
        if let Ok(n) = to.recv(&mut buf)
            && n >= 12
        {
            return true;
        }
    }
    false
}

#[test]
fn bridged_call_with_media_through_rtpflux() {
    let Some((_relay, ng)) = start_rtpflux() else { return };
    let mut net = Net::new();
    net.add("10.0.0.1:5060", 21);
    net.add("10.0.0.5:5060", 22);
    net.add("10.0.0.2:5060", 23);
    let mut bridge = Bridge::new(Rtpflux::new(ng).unwrap(), "10.0.0.2:5060");
    let mut seen = 0;
    let mut run = |net: &mut Net, bridge: &mut Bridge<Rtpflux>, cond: &dyn Fn(&Net) -> bool| {
        for _ in 0..10_000 {
            while seen < net.events(B2B).len() {
                let ev = net.events(B2B)[seen].clone();
                seen += 1;
                bridge.on_event(&ev, &mut |c| net.submit(B2B, c));
            }
            if cond(net) {
                return true;
            }
            if !net.step_capped(net.now + 20) {
                return cond(net);
            }
        }
        false
    };
    // Real media endpoints for both parties.
    let caller_rtp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let callee_rtp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let a = net.submit(CALLER, originate("10.0.0.5", Some(media_sdp(caller_rtp.local_addr().unwrap().port())))).unwrap().leg;
    assert!(run(&mut net, &mut bridge, &|n| n.incoming_leg(CALLEE).is_some()));
    let inv = net.find(CALLEE, |e| matches!(e, UaEvent::IncomingInvite(_))).unwrap();
    let UaEvent::IncomingInvite(ii) = &inv.event else { panic!() };
    let to_callee = audio_port(ii.sdp.as_deref().unwrap());
    assert!((PORT_MIN..=PORT_MAX).contains(&to_callee), "callee sees the relay, not the caller: {to_callee}");
    net.submit(CALLEE, UaCommand::Accept(AcceptRequest { leg: inv.leg, sdp: Some(media_sdp(callee_rtp.local_addr().unwrap().port())), headers: vec![] }))
        .unwrap();
    assert!(run(&mut net, &mut bridge, &|n| n.has(CALLER, |e| matches!(e, UaEvent::Accepted(_)))));
    let UaEvent::Accepted(acc) = net.find(CALLER, |e| matches!(e, UaEvent::Accepted(_))).unwrap().event else { panic!() };
    let to_caller = audio_port(acc.sdp.as_deref().unwrap());
    assert!((PORT_MIN..=PORT_MAX).contains(&to_caller), "caller sees the relay: {to_caller}");
    assert_ne!(to_caller, to_callee);
    // RTP both ways through the relay.
    assert!(flows(&caller_rtp, to_caller, &callee_rtp), "caller → callee media");
    assert!(flows(&callee_rtp, to_callee, &caller_rtp), "callee → caller media");
    assert_eq!(bridge.media.list().unwrap(), vec!["b2b-1".to_string()]);
    // The callee (the first answerer) puts the call on hold: a re-offer
    // through the relay, which keeps the ports both sides already use.
    let hold = String::from_utf8(media_sdp(callee_rtp.local_addr().unwrap().port())).unwrap().replace("a=sendrecv", "a=sendonly");
    net.submit(CALLEE, UaCommand::Negotiate(NegotiateRequest { leg: inv.leg, method: NegotiateMethod::ReInvite, sdp: hold.into_bytes() })).unwrap();
    assert!(run(&mut net, &mut bridge, &|n| n.has(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_)))));
    let ro = net.find(CALLER, |e| matches!(e, UaEvent::RemoteOffer(_))).unwrap();
    let UaEvent::RemoteOffer(r) = &ro.event else { panic!() };
    let offered = r.sdp.clone().unwrap();
    assert_eq!(audio_port(&offered), to_caller, "same relay port after the re-offer");
    assert!(String::from_utf8_lossy(&offered).contains("a=sendonly"));
    let held = String::from_utf8(media_sdp(caller_rtp.local_addr().unwrap().port())).unwrap().replace("a=sendrecv", "a=recvonly");
    net.submit(CALLER, UaCommand::RespondToOffer(OfferResponse { leg: a, generation: ro.generation, sdp: Some(held.into_bytes()) })).unwrap();
    assert!(run(&mut net, &mut bridge, &|n| n.has(CALLEE, |e| matches!(e, UaEvent::Completed(_)))));
    let UaEvent::Completed(c) = net.find(CALLEE, |e| matches!(e, UaEvent::Completed(_))).unwrap().event else { panic!() };
    assert_eq!(audio_port(c.sdp.as_deref().unwrap()), to_callee);
    assert!(String::from_utf8_lossy(c.sdp.as_deref().unwrap()).contains("a=recvonly"));
    // Hang up: both legs end, the media session is deleted.
    net.submit(CALLER, UaCommand::Hangup(HangupRequest { leg: a, reason: None, code: None })).unwrap();
    assert!(run(&mut net, &mut bridge, &|n| n.has(CALLEE, |e| matches!(e, UaEvent::Terminated(_)))));
    run(&mut net, &mut bridge, &|n| n.nodes.iter().all(|x| x.engine.is_idle()));
    assert_eq!(bridge.active_calls(), 0);
    assert!(bridge.media.list().unwrap().is_empty(), "media session released");
    net.check_event_invariants();
}
