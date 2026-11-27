//! Example two-leg B2BUA on ferrosip's transport layer.
//!
//! ```text
//! cargo run -p sip-ua --example b2bua -- LISTEN TARGET [--rtpflux NG_ADDR] [--tls-cert F --tls-key F]
//! cargo run -p sip-ua --example b2bua -- 127.0.0.1:5070 127.0.0.1:5080
//! cargo run -p sip-ua --example b2bua -- tcp:127.0.0.1:5070 127.0.0.1:5080 --rtpflux 127.0.0.1:2223
//! ```
//!
//! Every INVITE received on LISTEN (`[udp|tcp|tls|ws|wss:]ip:port`, may be
//! repeated as a comma-separated list) is originated as an independent
//! call to TARGET (`host:port`, a `;transport=` may follow). Media is
//! passed through unchanged, or anchored in rtpflux with `--rtpflux`.

mod bridge;
mod rtpflux;

use bridge::{Bridge, MediaAdapter, Passthrough};
use sip_transport::{Config, Listen, TcpOpts, TlsFiles};
use sip_ua::runtime::{RuntimeConfig, SystemResolver, spawn_transport};
use sip_ua::*;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(listen), Some(target)) = (args.first(), args.get(1)) else {
        eprintln!("usage: b2bua LISTEN TARGET [--rtpflux NG_ADDR] [--tls-cert F --tls-key F]");
        std::process::exit(2);
    };
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i.saturating_add(1))).cloned();
    let listen = listen.split(',').map(Listen::parse).collect::<Result<Vec<_>, _>>()?;
    let tls = TlsFiles { cert: opt("--tls-cert").map(Into::into), key: opt("--tls-key").map(Into::into), ..TlsFiles::default() };
    let tcfg = Config { listen, udp_workers: 1, tcp: TcpOpts::default(), tls, advertise_ip: None };
    let ua = spawn_transport(UaConfig::default(), &tcfg, Box::new(SystemResolver), RuntimeConfig::default())?;
    let media: Box<dyn MediaAdapter> = match opt("--rtpflux") {
        Some(ng) => {
            let mut r = rtpflux::Rtpflux::new(ng.parse()?)?;
            r.ping()?;
            eprintln!("b2bua: media anchored in rtpflux at {ng}");
            Box::new(r)
        }
        None => Box::new(Passthrough::default()),
    };
    eprintln!(
        "b2bua: listening on {} → {target}",
        tcfg.listen.iter().map(|l| format!("{}:{}", l.proto.via_name().to_lowercase(), l.addr)).collect::<Vec<_>>().join(", ")
    );
    let mut bridge = Bridge::new(media, target.clone());
    loop {
        match ua.events().recv_timeout(Duration::from_secs(1)) {
            Ok(ev) => {
                eprintln!("{} #{} {:?}", ev.leg, ev.seq, std::mem::discriminant(&ev.event));
                bridge.on_event(&ev, &mut |c| ua.submit(c));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if bridge.active_calls() > 0 {
                    eprintln!("b2bua: {} active call(s)", bridge.active_calls());
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}
