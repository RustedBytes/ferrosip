//! Example two-leg B2BUA on the std UDP runtime.
//!
//! ```text
//! cargo run -p sip-ua --example b2bua -- 127.0.0.1:5070 127.0.0.1:5080
//! ```
//!
//! Every INVITE received on the first address is originated as an
//! independent call to the second, with media passed through unchanged.

mod bridge;

use bridge::{Bridge, Passthrough};
use sip_ua::runtime::{RuntimeConfig, SystemResolver, spawn_udp};
use sip_ua::*;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(listen), Some(target)) = (args.next(), args.next()) else {
        eprintln!("usage: b2bua <listen ip:port> <target ip:port>");
        std::process::exit(2);
    };
    let ua = spawn_udp(UaConfig::default(), listen.parse()?, Box::new(SystemResolver), RuntimeConfig::default())?;
    eprintln!("b2bua: listening on udp:{} → {target}", ua.local_addr());
    let mut bridge = Bridge::new(Passthrough::default(), target);
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
