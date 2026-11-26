//! Helpers for the unit tests: a parsed request in a `Ctx`, and the
//! reply the code under test sent.

use sip_core::{Ctx, Dest, Lumps, Outbound, Proto};
use std::net::SocketAddr;

/// Sends nothing, advertises nothing.
pub struct NoNet;

impl Outbound for NoNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        None
    }
}

/// Runs `f` on a context for `raw` (`\n` line ends become CRLF; the body
/// after the blank line is kept as is), received over UDP from 192.0.2.9.
pub fn with_msg<R>(raw: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let raw = format!("{}\r\n\r\n{body}", head.replace('\n', "\r\n"));
    let arena = bumpalo::Bump::new();
    let mut m = sip_parser::Msg::parse(raw.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let src = Dest::new(Proto::Udp, SocketAddr::from(([192, 0, 2, 9], 5060)));
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, src, 0);
    f(&mut ctx)
}

/// A request: the start line, the usual headers, `extra` header lines
/// (each ending in `\n`) and `body`.
pub fn request(method: &str, ruri: &str, to_tag: Option<&str>, extra: &str, body: &str) -> String {
    let tt = to_tag.map(|t| format!(";tag={t}")).unwrap_or_default();
    format!(
        "{method} {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:watcher@ex.com>;tag=ft\nTo: <{ruri}>{tt}\n\
         Call-ID: cid-1\nCSeq: 2 {method}\nContact: <sip:watcher@192.0.2.9>\n{extra}Content-Length: {}\n\n{body}",
        body.len()
    )
}

/// The status code and header section of the reply in `ctx.out`.
pub fn reply(ctx: &Ctx<'_, '_>) -> (u16, String) {
    let s = String::from_utf8_lossy(ctx.out).into_owned();
    let code = s.get(8..11).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, s)
}

/// The value of header `name` in `msg` (a reply as text).
pub fn hdr(msg: &str, name: &str) -> Option<String> {
    msg.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}
