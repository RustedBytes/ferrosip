//! Helpers for the unit tests: a parsed message in a `Ctx`, and a network
//! that only advertises addresses (nothing is sent).

use bumpalo::Bump;
use sip_core::{Ctx, Dest, Lumps, Outbound, Proto};
use sip_parser::Msg;
use std::net::SocketAddr;

/// Advertises `addrs` for every protocol (first one wins); sends nothing.
pub struct FakeNet(pub Vec<SocketAddr>);

impl Outbound for FakeNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        self.0.first().copied()
    }
}

pub fn udp(addr: &str) -> Dest {
    Dest::new(Proto::Udp, addr.parse().unwrap())
}

/// Runs `f` on a context for `raw` (CRLF line ends added), received from `src`.
pub fn with_ctx<R>(raw: &str, src: Dest, net: &dyn Outbound, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let raw = raw.replace("\r\n", "\n").replace('\n', "\r\n");
    let arena = Bump::new();
    let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, src, 0);
    f(&mut ctx)
}

/// The message with the context's edits applied.
pub fn rendered(ctx: &mut Ctx<'_, '_>) -> String {
    let mut out = Vec::new();
    ctx.lumps.apply(ctx.msg.buf, &mut out);
    String::from_utf8(out).unwrap()
}

/// A request with the given R-URI and extra header lines.
pub fn request(method: &str, ruri: &str, extra: &str) -> String {
    format!(
        "{method} {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKt\nFrom: <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>\nCall-ID: cid-1\nCSeq: 1 {method}\nMax-Forwards: 70\n{extra}Content-Length: 0\n\n"
    )
}
