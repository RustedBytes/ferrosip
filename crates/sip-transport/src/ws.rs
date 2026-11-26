//! WebSocket codec (RFC 6455) and the SIP-over-WebSocket handshake rules of
//! RFC 7118 — the equivalent of Kamailio's `websocket` module (ws_handshake.c,
//! ws_frame.c). Pure functions, no I/O: the TCP layer feeds bytes in.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use memchr::memmem;
use ring::digest;
use std::cell::RefCell;

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest HTTP upgrade request we accept.
pub const MAX_HANDSHAKE: usize = 8 * 1024;

pub mod op {
    pub const CONT: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xA;
}

/// Close status codes (RFC 6455 §7.4.1).
pub mod close {
    pub const NORMAL: u16 = 1000;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const INVALID_DATA: u16 = 1007;
    pub const TOO_BIG: u16 = 1009;
}

/// Server-side WebSocket options.
#[derive(Clone, Debug, Default)]
pub struct WsOpts {
    /// If non-empty, browsers (requests carrying `Origin`) must match one of
    /// these, else 403. Requests without `Origin` (non-browser) are allowed.
    pub allowed_origins: Vec<String>,
    /// Accept permessage-deflate (RFC 7692) when the client offers it.
    pub deflate: bool,
}

/// Negotiated permessage-deflate parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deflate {
    /// Client resets its compressor per message, so we may reset our inflater.
    pub client_no_context_takeover: bool,
}

pub fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(b.len().div_ceil(3).saturating_mul(4));
    for c in b.chunks(3) {
        let mut group = [0u8; 4];
        group.iter_mut().skip(1).zip(c).for_each(|(g, &b)| *g = b);
        let n = u32::from_be_bytes(group);
        // A group of k bytes gives k + 1 characters, padded with '=' to 4.
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= c.len() {
                #[allow(clippy::indexing_slicing, reason = "the index is masked to 0..64, the length of T")]
                s.push(char::from(T[usize::try_from(n >> shift & 63).unwrap_or_default()]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}{GUID}").as_bytes());
    base64(d.as_ref())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Handshake {
    Incomplete,
    /// Upgrade accepted: consume `len` bytes and send `response`.
    Accept {
        len: usize,
        response: String,
        deflate: Option<Deflate>,
    },
    /// Send `response`, then close.
    Reject {
        response: &'static str,
    },
}

const BAD_REQUEST: &str = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const NO_SIP: &str = "HTTP/1.1 400 Bad Request\r\nX-Reason: Sec-WebSocket-Protocol must include sip (RFC 7118)\r\n\
Content-Length: 0\r\nConnection: close\r\n\r\n";
const FORBIDDEN: &str = "HTTP/1.1 403 Forbidden\r\nX-Reason: Origin not allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const UPGRADE_REQUIRED: &str = "HTTP/1.1 426 Upgrade Required\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Picks the first acceptable permessage-deflate offer (RFC 7692 §5, §7).
/// We always answer `server_no_context_takeover`: every outgoing message is
/// compressed from scratch, so any thread can compress (thread-local state)
/// and nothing per connection is kept for sending.
pub fn negotiate_deflate(offers: &str) -> Option<(Deflate, String)> {
    'offer: for offer in offers.split(',') {
        let mut parts = offer.split(';').map(str::trim);
        if !parts.next().is_some_and(|n| n.eq_ignore_ascii_case("permessage-deflate")) {
            continue;
        }
        let (mut cnct, mut smwb, mut seen) = (false, false, Vec::new());
        for p in parts.filter(|p| !p.is_empty()) {
            let (k, v) = p.split_once('=').map_or((p, None), |(k, v)| (k.trim(), Some(v.trim().trim_matches('"'))));
            let k = k.to_ascii_lowercase();
            if seen.contains(&k) {
                continue 'offer; // duplicate parameter → invalid offer
            }
            seen.push(k.clone());
            match (k.as_str(), v) {
                ("server_no_context_takeover", None) => {}
                ("client_no_context_takeover", None) => cnct = true,
                // We compress with a 32 KiB window; a smaller one can't be honoured.
                ("server_max_window_bits", Some("15")) => smwb = true,
                // Client may limit its own window; we can inflate any size.
                ("client_max_window_bits", None) => {}
                ("client_max_window_bits", Some(b)) if matches!(b.parse::<u8>(), Ok(8..=15)) => {}
                _ => continue 'offer,
            }
        }
        let mut resp = String::from("permessage-deflate; server_no_context_takeover");
        if cnct {
            resp.push_str("; client_no_context_takeover");
        }
        if smwb {
            resp.push_str("; server_max_window_bits=15");
        }
        return Some((Deflate { client_no_context_takeover: cnct }, resp));
    }
    None
}

/// An HTTP head: the bytes before the first blank line, and the length of
/// the head with that blank line.
fn http_head(buf: &[u8]) -> Option<(&[u8], usize)> {
    let end = memmem::find(buf, b"\r\n\r\n")?;
    Some((buf.get(..end)?, end.checked_add(4)?))
}

/// Server side of the opening handshake.
pub fn server_handshake(buf: &[u8], opts: &WsOpts) -> Handshake {
    let Some((head, head_len)) = http_head(buf) else {
        return if buf.len() > MAX_HANDSHAKE { Handshake::Reject { response: BAD_REQUEST } } else { Handshake::Incomplete };
    };
    let reject = |response| Handshake::Reject { response };
    let Ok(head) = std::str::from_utf8(head) else { return reject(BAD_REQUEST) };
    let mut lines = head.split("\r\n");
    let rl = lines.next().unwrap_or("");
    if !rl.starts_with("GET ") || !rl.ends_with(" HTTP/1.1") {
        return reject(BAD_REQUEST);
    }
    let (mut upgrade, mut conn_upgrade, mut key, mut version, mut sip) = (false, false, None, None, false);
    let (mut origin, mut extensions) = (None, String::new());
    for l in lines {
        let Some((name, value)) = l.split_once(':') else { return reject(BAD_REQUEST) };
        let (name, value) = (name.trim(), value.trim());
        let tokens = || value.split(',').map(str::trim);
        if name.eq_ignore_ascii_case("upgrade") {
            upgrade = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("connection") {
            conn_upgrade = tokens().any(|t| t.eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(value);
        } else if name.eq_ignore_ascii_case("sec-websocket-version") {
            version = Some(value);
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            sip |= tokens().any(|t| t.eq_ignore_ascii_case("sip"));
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value);
        } else if name.eq_ignore_ascii_case("sec-websocket-extensions") {
            if !extensions.is_empty() {
                extensions.push(',');
            }
            extensions.push_str(value);
        }
    }
    let Some(key) = key.filter(|_| upgrade && conn_upgrade) else { return reject(BAD_REQUEST) };
    if version != Some("13") {
        return reject(UPGRADE_REQUIRED);
    }
    if !sip {
        return reject(NO_SIP);
    }
    if let Some(o) = origin
        && !opts.allowed_origins.is_empty()
        && !opts.allowed_origins.iter().any(|a| a.eq_ignore_ascii_case(o))
    {
        return reject(FORBIDDEN);
    }
    let deflate = if opts.deflate { negotiate_deflate(&extensions) } else { None };
    let ext = deflate.as_ref().map_or(String::new(), |(_, r)| format!("Sec-WebSocket-Extensions: {r}\r\n"));
    Handshake::Accept {
        len: head_len,
        response: format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n{ext}\r\n",
            accept_key(key)
        ),
        deflate: deflate.map(|(d, _)| d),
    }
}

/// 403 for an upgrade refused by `event_route[websocket:handshake]`.
pub const HOOK_FORBIDDEN: &str = "HTTP/1.1 403 Forbidden\r\nX-Reason: refused by policy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Client side: the opening request we send (`Sec-WebSocket-Protocol: sip`).
pub fn client_request(host: &str, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\nUser-Agent: ferrosip\r\n\r\n"
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClientHandshake {
    Incomplete,
    /// 101 with the right `Sec-WebSocket-Accept`: consume `len` bytes.
    Open {
        len: usize,
    },
    Failed(String),
}

/// Client side: check the server's answer to `client_request`.
pub fn client_handshake(buf: &[u8], key: &str) -> ClientHandshake {
    let Some((head, head_len)) = http_head(buf) else {
        return if buf.len() > MAX_HANDSHAKE { ClientHandshake::Failed("handshake too long".into()) } else { ClientHandshake::Incomplete };
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    if !status.starts_with("HTTP/1.1 101") {
        return ClientHandshake::Failed(format!("server answered {status:?}"));
    }
    let want = accept_key(key);
    let (mut accept, mut sip) = (false, false);
    for l in lines {
        let Some((n, v)) = l.split_once(':') else { continue };
        let (n, v) = (n.trim(), v.trim());
        if n.eq_ignore_ascii_case("sec-websocket-accept") {
            accept = v == want;
        } else if n.eq_ignore_ascii_case("sec-websocket-protocol") {
            sip = v.split(',').any(|t| t.trim().eq_ignore_ascii_case("sip"));
        }
    }
    match (accept, sip) {
        (true, true) => ClientHandshake::Open { len: head_len },
        (false, _) => ClientHandshake::Failed("bad Sec-WebSocket-Accept".into()),
        (_, false) => ClientHandshake::Failed("server did not accept Sec-WebSocket-Protocol: sip".into()),
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct FrameHdr {
    pub fin: bool,
    /// RSV1: first frame of a compressed message (permessage-deflate).
    pub rsv1: bool,
    pub opcode: u8,
    /// Header bytes (incl. masking key); the payload starts here.
    pub hdr_len: usize,
    pub len: usize,
}

impl FrameHdr {
    /// Header and payload: the bytes this frame takes in the buffer.
    pub fn frame_len(&self) -> usize {
        // Can't saturate: `parse_frame` found both in the buffer.
        self.hdr_len.saturating_add(self.len)
    }

    /// The payload, in the buffer `parse_frame` read the frame from.
    pub fn payload<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        buf.get(self.hdr_len..self.frame_len()).unwrap_or_default()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Incomplete,
    Frame(FrameHdr),
    /// Protocol violation: close with this status code.
    Error(u16, &'static str),
}

/// Parses one frame at the start of `buf`. If it is complete and masked, the
/// payload is unmasked **in place**, so the caller can hand the bytes straight
/// to the SIP parser without copying.
/// `allow_rsv1` is true when permessage-deflate was negotiated.
pub fn parse_frame(buf: &mut [u8], max_len: usize, expect_masked: bool, allow_rsv1: bool) -> Parsed {
    let [b0, b1, rest @ ..] = &*buf else { return Parsed::Incomplete };
    let (b0, b1) = (*b0, *b1);
    let (fin, opcode, masked) = (b0 & 0x80 != 0, b0 & 0x0f, b1 & 0x80 != 0);
    let rsv1 = b0 & 0x40 != 0;
    if b0 & 0x30 != 0 || (rsv1 && (!allow_rsv1 || opcode == op::CONT || opcode >= 8)) {
        return Parsed::Error(close::PROTOCOL_ERROR, "reserved bits set");
    }
    if masked != expect_masked {
        return Parsed::Error(close::PROTOCOL_ERROR, if expect_masked { "unmasked client frame" } else { "masked server frame" });
    }
    let (len, rest) = match (b1 & 0x7f, rest) {
        (126, [a, b, rest @ ..]) => (u64::from(u16::from_be_bytes([*a, *b])), rest),
        (127, [a, b, c, d, e, f, g, h, rest @ ..]) => (u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]), rest),
        (126 | 127, _) => return Parsed::Incomplete,
        (n, _) => (u64::from(n), rest),
    };
    match opcode {
        op::CLOSE | op::PING | op::PONG if !fin || len > 125 => return Parsed::Error(close::PROTOCOL_ERROR, "fragmented or oversized control frame"),
        op::CONT | op::TEXT | op::BINARY | op::CLOSE | op::PING | op::PONG => {}
        _ => return Parsed::Error(close::PROTOCOL_ERROR, "unknown opcode"),
    }
    let len = match usize::try_from(len) {
        Ok(len) if len <= max_len => len,
        _ => return Parsed::Error(close::TOO_BIG, "frame too big"),
    };
    let (mask, rest) = match rest.split_first_chunk::<4>() {
        Some((m, rest)) if masked => (Some(*m), rest),
        None if masked => return Parsed::Incomplete,
        _ => (None, rest),
    };
    // The header is what precedes `rest` (a suffix of `buf`).
    let hdr_len = buf.len().saturating_sub(rest.len());
    // A length near usize::MAX (allowed by a huge `max_len`) must not wrap.
    if hdr_len.checked_add(len).is_none() {
        return Parsed::Error(close::TOO_BIG, "frame too big");
    }
    let Some(payload) = buf.get_mut(hdr_len..).and_then(|p| p.get_mut(..len)) else { return Parsed::Incomplete };
    if let Some(m) = mask {
        apply_mask(payload, m);
    }
    Parsed::Frame(FrameHdr { fin, rsv1, opcode, hdr_len, len })
}

/// XOR with the 4-byte key, 8 bytes at a time.
pub fn apply_mask(data: &mut [u8], m: [u8; 4]) {
    let k = u64::from_ne_bytes([m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3]]);
    let (chunks, rest) = data.as_chunks_mut::<8>();
    for c in chunks {
        *c = (u64::from_ne_bytes(*c) ^ k).to_ne_bytes();
    }
    for (b, k) in rest.iter_mut().zip(m.iter().cycle()) {
        *b ^= k;
    }
}

/// An encoded frame header (2 to 14 bytes).
#[derive(Clone, Copy, Debug)]
pub struct FrameHeader {
    bytes: [u8; 14],
    len: usize,
}

impl FrameHeader {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&self.bytes)
    }

    /// With RSV1 set: the first frame of a compressed message (RFC 7692).
    #[must_use]
    pub fn compressed(mut self) -> Self {
        if let Some(b0) = self.bytes.first_mut() {
            *b0 |= 0x40;
        }
        self
    }
}

/// Frame header for a payload of `len` bytes.
pub fn frame_header(fin: bool, opcode: u8, len: usize, mask: Option<[u8; 4]>) -> FrameHeader {
    let b0 = if fin { 0x80 } else { 0 } | opcode;
    let mbit = if mask.is_some() { 0x80 } else { 0 };
    // 7-bit length, or 126 + 16-bit length, or 127 + 64-bit length.
    let (len7, ext, ext_len) = if let Ok(short @ 0..=125) = u8::try_from(len) {
        (short, [0; 8], 0)
    } else if let Ok(medium) = u16::try_from(len) {
        let [a, b] = medium.to_be_bytes();
        (126, [a, b, 0, 0, 0, 0, 0, 0], 2)
    } else {
        (127, u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes(), 8)
    };
    let src = [b0, mbit | len7].into_iter().chain(ext.into_iter().take(ext_len)).chain(mask.into_iter().flatten());
    let mut bytes = [0u8; 14];
    let len = bytes.iter_mut().zip(src).map(|(dst, b)| *dst = b).count();
    FrameHeader { bytes, len }
}

/// Header + (masked) payload into `out` — for clients and tests.
pub fn encode(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>, out: &mut Vec<u8>) {
    out.extend_from_slice(frame_header(fin, opcode, payload.len(), mask).as_bytes());
    let start = out.len();
    out.extend_from_slice(payload);
    if let Some(m) = mask
        && let Some(masked) = out.get_mut(start..)
    {
        apply_mask(masked, m);
    }
}

const TAIL: [u8; 4] = [0, 0, 0xff, 0xff];

/// Per-connection decompressor for client→server messages.
pub struct Inflater {
    d: Decompress,
    /// Client promised `client_no_context_takeover`: reset after each message.
    reset_each: bool,
}

impl Inflater {
    pub fn new(p: Deflate) -> Self {
        Self { d: Decompress::new(false), reset_each: p.client_no_context_takeover }
    }

    /// Decompresses one message into `out`, refusing to grow past `max`
    /// (no decompression bombs). Errors map to a close code.
    pub fn inflate(&mut self, data: &[u8], max: usize, out: &mut Vec<u8>) -> Result<(), (u16, &'static str)> {
        out.clear();
        for chunk in [data, &TAIL[..]] {
            let mut pos = 0;
            loop {
                if out.spare_capacity_mut().len() < 1024 {
                    out.reserve(4096.max(chunk.len().saturating_mul(2)));
                }
                let (in0, out0) = (self.d.total_in(), out.len());
                let input = chunk.get(pos..).unwrap_or_default();
                let status = self.d.decompress_vec(input, out, FlushDecompress::Sync).map_err(|_| (close::INVALID_DATA, "invalid deflate data"))?;
                pos = pos.saturating_add(consumed(in0, self.d.total_in()));
                if out.len() > max {
                    return Err((close::TOO_BIG, "decompressed message too big"));
                }
                if status == Status::StreamEnd {
                    // RFC 7692 §7.2.3.3: the message ended with a BFINAL
                    // block. What follows it (the appended tail) is ignored,
                    // and the next message starts a new stream.
                    self.d.reset(false);
                    return Ok(());
                }
                if pos >= chunk.len() && out.len() < out.capacity() {
                    break;
                }
                if self.d.total_in() == in0 && out.len() == out0 {
                    return Err((close::INVALID_DATA, "deflate stream stalled"));
                }
            }
        }
        if self.reset_each {
            self.d.reset(false);
        }
        Ok(())
    }
}

thread_local! {
    static DEFLATER: RefCell<(Compress, Vec<u8>)> =
        RefCell::new((Compress::new(Compression::fast(), false), Vec::new()));
}

/// Input bytes a (de)compressor step took, from its `total_in` before and after.
fn consumed(before: u64, after: u64) -> usize {
    usize::try_from(after.saturating_sub(before)).unwrap_or(usize::MAX)
}

/// Compress one outgoing message with this thread's compressor (fresh window
/// per message: server_no_context_takeover) and pass the payload to `f`.
/// `None` (and `f` not called) if the compressor fails: send uncompressed.
pub fn with_deflated<R>(data: &[u8], f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    DEFLATER.with(|cell| {
        let (c, out) = &mut *cell.borrow_mut();
        c.reset();
        out.clear();
        let mut pos = 0;
        loop {
            out.reserve((data.len() / 2).saturating_add(64));
            let in0 = c.total_in();
            c.compress_vec(data.get(pos..).unwrap_or_default(), out, FlushCompress::Sync).ok()?;
            pos = pos.saturating_add(consumed(in0, c.total_in()));
            if pos >= data.len() && out.len() < out.capacity() {
                break;
            }
        }
        if let Some(body) = out.strip_suffix(&TAIL) {
            out.truncate(body.len()); // RFC 7692 §7.2.1
        }
        Some(f(out))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn client_side() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        assert!(client_request("10.0.0.1:80", "/", key).contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        let ok = format!("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: sip\r\n\r\nX", accept_key(key));
        assert_eq!(client_handshake(ok.as_bytes(), key), ClientHandshake::Open { len: ok.len() - 1 });
        assert!(matches!(client_handshake(b"HTTP/1.1 403 Forbidden\r\n\r\n", key), ClientHandshake::Failed(_)));
        assert!(matches!(client_handshake(b"HTTP/1.1 101 x\r\nSec-WebSocket-Accept: nope\r\n\r\n", key), ClientHandshake::Failed(_)));
        assert_eq!(client_handshake(b"HTTP/1.1 101", key), ClientHandshake::Incomplete);
    }

    use super::*;

    #[test]
    fn rfc6455_accept_key() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn rfc6455_masked_hello() {
        let mut f = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        let Parsed::Frame(h) = parse_frame(&mut f, 1000, true, false) else { panic!() };
        assert_eq!((h.fin, h.opcode, h.hdr_len, h.len), (true, op::TEXT, 6, 5));
        assert_eq!(&f[6..], b"Hello");
    }

    #[test]
    fn roundtrip_lengths_and_partial() {
        for len in [0usize, 1, 125, 126, 1000, 65535, 65536, 70000] {
            let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 256).unwrap()).collect();
            let mut out = Vec::new();
            encode(true, op::BINARY, &payload, Some([1, 2, 3, 4]), &mut out);
            for cut in [1, out.len() / 2, out.len() - 1] {
                if cut < out.len() {
                    assert_eq!(parse_frame(&mut out.clone()[..cut], 1 << 20, true, false), Parsed::Incomplete, "len {len} cut {cut}");
                }
            }
            let Parsed::Frame(h) = parse_frame(&mut out, 1 << 20, true, false) else { panic!("len {len}") };
            assert_eq!(h.len, len);
            assert_eq!(&out[h.hdr_len..], &payload[..]);
        }
    }

    #[test]
    fn violations() {
        let mut out = Vec::new();
        encode(true, op::TEXT, b"x", None, &mut out);
        assert_eq!(parse_frame(&mut out, 100, true, false), Parsed::Error(close::PROTOCOL_ERROR, "unmasked client frame"));
        let mut out = Vec::new();
        encode(false, op::PING, b"x", Some([0; 4]), &mut out);
        assert!(matches!(parse_frame(&mut out, 100, true, false), Parsed::Error(1002, _)));
        let mut out = Vec::new();
        encode(true, op::TEXT, &[0; 200], Some([0; 4]), &mut out);
        assert_eq!(parse_frame(&mut out, 100, true, false), Parsed::Error(close::TOO_BIG, "frame too big"));
        // A 64-bit length beyond any buffer (or usize) is refused, not wrapped.
        let mut huge = vec![0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4];
        assert_eq!(parse_frame(&mut huge, usize::MAX, true, false), Parsed::Error(close::TOO_BIG, "frame too big"));
        // RSV1 only with permessage-deflate, and never on control frames.
        let mut out = Vec::new();
        encode(true, op::TEXT, b"x", Some([0; 4]), &mut out);
        out[0] |= 0x40;
        assert!(matches!(parse_frame(&mut out.clone(), 100, true, false), Parsed::Error(1002, _)));
        assert!(matches!(parse_frame(&mut out, 100, true, true), Parsed::Frame(FrameHdr { rsv1: true, .. })));
        let mut out = Vec::new();
        encode(true, op::PING, b"x", Some([0; 4]), &mut out);
        out[0] |= 0x40;
        assert!(matches!(parse_frame(&mut out, 100, true, true), Parsed::Error(1002, _)));
    }

    #[test]
    fn handshake() {
        let ok = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat, sip\r\n\r\n";
        let o = WsOpts::default();
        let Handshake::Accept { len, response, deflate: None } = server_handshake(ok, &o) else { panic!() };
        assert_eq!(len, ok.len());
        assert!(response.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") && response.contains("Sec-WebSocket-Protocol: sip"));
        assert_eq!(server_handshake(&ok[..ok.len() - 1], &o), Handshake::Incomplete);
        let s = String::from_utf8_lossy(ok);
        let no_sip = s.replace("chat, sip", "chat");
        assert_eq!(server_handshake(no_sip.as_bytes(), &o), Handshake::Reject { response: NO_SIP });
        let v8 = s.replace("Version: 13", "Version: 8");
        assert_eq!(server_handshake(v8.as_bytes(), &o), Handshake::Reject { response: UPGRADE_REQUIRED });
        assert_eq!(server_handshake(b"POST / HTTP/1.1\r\n\r\n", &o), Handshake::Reject { response: BAD_REQUEST });

        // Origin allow-list: browsers from other origins get 403; no Origin is fine.
        let strict = WsOpts { allowed_origins: vec!["https://app.example".into()], ..o.clone() };
        let with = |origin: &str| s.replace("Host: x\r\n", &format!("Host: x\r\nOrigin: {origin}\r\n"));
        assert_eq!(server_handshake(with("https://evil.example").as_bytes(), &strict), Handshake::Reject { response: FORBIDDEN });
        assert!(matches!(server_handshake(with("https://APP.example").as_bytes(), &strict), Handshake::Accept { .. }));
        assert!(matches!(server_handshake(ok, &strict), Handshake::Accept { .. }));

        // permessage-deflate is only accepted when enabled.
        let ext = s.replace("Host: x\r\n", "Host: x\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n");
        assert!(matches!(server_handshake(ext.as_bytes(), &o), Handshake::Accept { deflate: None, .. }));
        let on = WsOpts { deflate: true, ..o };
        let Handshake::Accept { response, deflate: Some(d), .. } = server_handshake(ext.as_bytes(), &on) else { panic!() };
        assert!(!d.client_no_context_takeover);
        assert!(response.contains("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n"));
    }

    #[test]
    fn deflate_negotiation() {
        let n = |s: &str| negotiate_deflate(s).map(|(d, r)| (d.client_no_context_takeover, r));
        assert_eq!(n("x-webkit-deflate-frame"), None);
        assert_eq!(
            n("permessage-deflate; client_no_context_takeover"),
            Some((true, "permessage-deflate; server_no_context_takeover; client_no_context_takeover".into()))
        );
        // First offer asks for a 9-bit server window (unsupported) → fall back to the second.
        assert_eq!(
            n("permessage-deflate; server_max_window_bits=9, permessage-deflate; server_max_window_bits=\"15\""),
            Some((false, "permessage-deflate; server_no_context_takeover; server_max_window_bits=15".into()))
        );
        assert_eq!(n("permessage-deflate; foo=1"), None);
        assert_eq!(n("permessage-deflate; client_no_context_takeover; client_no_context_takeover"), None);
    }

    #[test]
    fn deflate_roundtrip_with_context_takeover() {
        let msg = b"MESSAGE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/WSS x.invalid;branch=z9hG4bK1\r\n\r\n".repeat(20);
        // Server→client (fresh compressor each time) through an inflater that
        // keeps its window across messages (client context takeover).
        let mut inf = Inflater::new(Deflate { client_no_context_takeover: false });
        let mut out = Vec::new();
        for _ in 0..3 {
            let c = with_deflated(&msg, |c| c.to_vec()).unwrap();
            assert!(c.len() < msg.len() / 4, "compressed {} of {}", c.len(), msg.len());
            inf.inflate(&c, 1 << 20, &mut out).unwrap();
            assert_eq!(out, msg);
        }
        // Size limit applies to the *decompressed* size.
        let bomb = with_deflated(&vec![0u8; 1 << 20], |c| c.to_vec()).unwrap();
        assert_eq!(inf.inflate(&bomb, 64 * 1024, &mut out), Err((close::TOO_BIG, "decompressed message too big")));
        let mut inf = Inflater::new(Deflate { client_no_context_takeover: true });
        assert!(inf.inflate(b"\xff\xff\xff garbage", 1 << 20, &mut out).is_err());
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    fn frame(fin: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::new();
        encode(fin, opcode, payload, mask, &mut out);
        out
    }

    #[test]
    fn base64_rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (&[0xff, 0xfe, 0xfd], "//79"),
        ];
        for (raw, enc) in cases {
            assert_eq!(base64(raw), *enc, "{raw:?}");
        }
    }

    #[test]
    fn frame_header_bytes() {
        let m = Some([0xa, 0xb, 0xc, 0xd]);
        // (fin, opcode, payload length, mask, header bytes)
        type Case = (bool, u8, usize, Option<[u8; 4]>, &'static [u8]);
        let cases: &[Case] = &[
            (true, op::TEXT, 0, None, &[0x81, 0x00]),
            (false, op::BINARY, 125, None, &[0x02, 125]),
            (true, op::CONT, 126, None, &[0x80, 126, 0, 126]),
            (true, op::TEXT, 255, None, &[0x81, 126, 0, 255]),
            (true, op::TEXT, 65535, None, &[0x81, 126, 0xff, 0xff]),
            (true, op::TEXT, 65536, None, &[0x81, 127, 0, 0, 0, 0, 0, 1, 0, 0]),
            (true, op::PING, 3, m, &[0x89, 0x83, 0xa, 0xb, 0xc, 0xd]),
            (true, op::TEXT, 70000, m, &[0x81, 0xff, 0, 0, 0, 0, 0, 1, 0x11, 0x70, 0xa, 0xb, 0xc, 0xd]),
        ];
        for (fin, opcode, len, mask, want) in cases {
            assert_eq!(frame_header(*fin, *opcode, *len, *mask).as_bytes(), *want, "fin {fin} op {opcode} len {len}");
        }
        assert_eq!(frame_header(true, op::TEXT, 5, None).compressed().as_bytes(), [0xc1, 5], "RSV1");
    }

    #[test]
    fn masking_matches_the_bytewise_definition_and_undoes_itself() {
        let key = [0x37, 0xfa, 0x21, 0x3d];
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| u8::try_from(i * 7 % 256).unwrap()).collect();
            let mut fast = data.clone();
            apply_mask(&mut fast, key);
            let slow: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
            assert_eq!(fast, slow, "len {len}");
            apply_mask(&mut fast, key);
            assert_eq!(fast, data, "masking twice gives the data back (len {len})");
        }
    }

    #[test]
    fn control_frame_rules() {
        let m = Some([1, 2, 3, 4]);
        // (frame, expect: Ok(opcode) or Err(code))
        let cases: Vec<(&str, Vec<u8>, Result<u8, u16>)> = vec![
            ("ping 125", frame(true, op::PING, &[7; 125], m), Ok(op::PING)),
            ("ping 126", frame(true, op::PING, &[7; 126], m), Err(close::PROTOCOL_ERROR)),
            ("pong empty", frame(true, op::PONG, b"", m), Ok(op::PONG)),
            ("close with code", frame(true, op::CLOSE, &1000u16.to_be_bytes(), m), Ok(op::CLOSE)),
            ("fragmented close", frame(false, op::CLOSE, b"", m), Err(close::PROTOCOL_ERROR)),
            ("fragmented pong", frame(false, op::PONG, b"", m), Err(close::PROTOCOL_ERROR)),
            ("opcode 3", frame(true, 3, b"", m), Err(close::PROTOCOL_ERROR)),
            ("opcode 0xB", frame(true, 0xb, b"", m), Err(close::PROTOCOL_ERROR)),
            ("text fragment", frame(false, op::TEXT, b"ab", m), Ok(op::TEXT)),
            ("continuation", frame(false, op::CONT, b"ab", m), Ok(op::CONT)),
        ];
        for (what, mut f, want) in cases {
            let got = match parse_frame(&mut f, 1000, true, true) {
                Parsed::Frame(h) => Ok(h.opcode),
                Parsed::Error(code, _) => Err(code),
                Parsed::Incomplete => panic!("{what}: incomplete"),
            };
            assert_eq!(got, want, "{what}");
        }
    }

    #[test]
    fn reserved_bits() {
        for (bits, allow_rsv1, ok) in [(0x40, true, true), (0x40, false, false), (0x20, true, false), (0x10, true, false), (0x70, true, false)] {
            let mut f = frame(true, op::TEXT, b"x", Some([0; 4]));
            f[0] |= bits;
            assert_eq!(matches!(parse_frame(&mut f, 100, true, allow_rsv1), Parsed::Frame(_)), ok, "bits {bits:#x} allow {allow_rsv1}");
        }
        let mut f = frame(false, op::CONT, b"x", Some([0; 4]));
        f[0] |= 0x40;
        assert!(matches!(parse_frame(&mut f, 100, true, true), Parsed::Error(1002, _)), "RSV1 only on the first frame of a message");
    }

    #[test]
    fn masking_direction() {
        let mut from_server = frame(true, op::TEXT, b"hi", None);
        let Parsed::Frame(h) = parse_frame(&mut from_server, 100, false, false) else { panic!() };
        assert_eq!((h.hdr_len, h.payload(&from_server)), (2, &b"hi"[..]), "a client reads unmasked frames");
        let mut masked = frame(true, op::TEXT, b"hi", Some([9; 4]));
        assert_eq!(parse_frame(&mut masked, 100, false, false), Parsed::Error(close::PROTOCOL_ERROR, "masked server frame"));
    }

    #[test]
    fn incomplete_headers() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x81],
            &[0x81, 0xfe],          // 16-bit length missing
            &[0x81, 0xfe, 0x01],    // half of it
            &[0x81, 0xff, 0, 0, 0], // 64-bit length cut
            &[0x81, 0x85, 1, 2],    // mask key cut
            &[0x81, 0x85, 1, 2, 3, 4, b'a'],
        ];
        for c in cases {
            assert_eq!(parse_frame(&mut c.to_vec(), 100, true, false), Parsed::Incomplete, "{c:?}");
        }
    }

    #[test]
    fn length_limit_is_inclusive() {
        let mut f = frame(true, op::BINARY, &[1; 100], Some([0; 4]));
        assert!(matches!(parse_frame(&mut f.clone(), 100, true, false), Parsed::Frame(FrameHdr { len: 100, .. })));
        assert_eq!(parse_frame(&mut f, 99, true, false), Parsed::Error(close::TOO_BIG, "frame too big"));
    }

    #[test]
    fn back_to_back_frames_in_one_buffer() {
        let mut buf = frame(false, op::TEXT, b"INVITE ", Some([1, 2, 3, 4]));
        buf.extend(frame(true, op::CONT, b"sip:x", Some([5, 6, 7, 8])));
        buf.extend(frame(true, op::PING, b"", Some([0; 4])));
        let mut at = 0;
        let mut seen = Vec::new();
        while at < buf.len() {
            let Parsed::Frame(h) = parse_frame(&mut buf[at..], 100, true, false) else { panic!("at {at}") };
            seen.push((h.fin, h.opcode, h.payload(&buf[at..]).to_vec()));
            at += h.frame_len();
        }
        assert_eq!(seen, [(false, op::TEXT, b"INVITE ".to_vec()), (true, op::CONT, b"sip:x".to_vec()), (true, op::PING, vec![])]);
    }

    fn upgrade(extra: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sip\r\n{extra}\r\n"
        )
    }

    #[test]
    fn handshake_rejections() {
        let o = WsOpts::default();
        let ok = upgrade("");
        let cases: Vec<(&str, String, &str)> = vec![
            ("no key", ok.replace("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", ""), BAD_REQUEST),
            ("Upgrade: h2c", ok.replace("Upgrade: websocket", "Upgrade: h2c"), BAD_REQUEST),
            ("Connection: close", ok.replace("Connection: Upgrade", "Connection: close"), BAD_REQUEST),
            ("HTTP/1.0", ok.replace("HTTP/1.1", "HTTP/1.0"), BAD_REQUEST),
            ("a line without a colon", upgrade("junk\r\n"), BAD_REQUEST),
            ("no version", ok.replace("Sec-WebSocket-Version: 13\r\n", ""), UPGRADE_REQUIRED),
            ("no protocol", ok.replace("Sec-WebSocket-Protocol: sip\r\n", ""), NO_SIP),
            ("sips is not sip", ok.replace("Protocol: sip", "Protocol: sips"), NO_SIP),
        ];
        for (what, req, want) in cases {
            assert_eq!(server_handshake(req.as_bytes(), &o), Handshake::Reject { response: want }, "{what}");
        }
        let mut bad_utf8 = ok.clone().into_bytes();
        bad_utf8[6] = 0xff;
        assert_eq!(server_handshake(&bad_utf8, &o), Handshake::Reject { response: BAD_REQUEST });
    }

    #[test]
    fn handshake_header_variants_are_accepted() {
        let o = WsOpts::default();
        let cases = [
            (
                "lower-case names and values",
                upgrade("").to_ascii_lowercase().replace("dghlihnhbxbszsbub25jzq==", "dGhlIHNhbXBsZSBub25jZQ==").replace("get / http/1.1", "GET / HTTP/1.1"),
            ),
            (
                "protocol in a second header",
                upgrade("").replace("Sec-WebSocket-Protocol: sip\r\n", "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Protocol: SIP\r\n"),
            ),
            ("connection token list", upgrade("").replace("Connection: Upgrade", "Connection: keep-alive,upgrade")),
        ];
        for (what, req) in cases {
            assert!(matches!(server_handshake(req.as_bytes(), &o), Handshake::Accept { .. }), "{what}: {req}");
        }
    }

    #[test]
    fn handshake_length_and_trailing_bytes() {
        let o = WsOpts::default();
        let req = upgrade("");
        let with_frame = format!("{req}\u{81}");
        let Handshake::Accept { len, .. } = server_handshake(with_frame.as_bytes(), &o) else { panic!() };
        assert_eq!(len, req.len(), "only the HTTP head is consumed");
        assert_eq!(server_handshake(&vec![b'a'; MAX_HANDSHAKE], &o), Handshake::Incomplete);
        assert_eq!(server_handshake(&vec![b'a'; MAX_HANDSHAKE + 1], &o), Handshake::Reject { response: BAD_REQUEST });
        assert!(matches!(client_handshake(&vec![b'a'; MAX_HANDSHAKE + 1], "k"), ClientHandshake::Failed(_)));
    }

    #[test]
    fn extensions_from_several_headers_are_combined() {
        let on = WsOpts { deflate: true, ..WsOpts::default() };
        let req = upgrade("Sec-WebSocket-Extensions: x-foo\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover\r\n");
        let Handshake::Accept { response, deflate, .. } = server_handshake(req.as_bytes(), &on) else { panic!() };
        assert_eq!(deflate, Some(Deflate { client_no_context_takeover: true }));
        assert!(response.contains("Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"), "{response}");
        let Handshake::Accept { response, deflate: None, .. } = server_handshake(upgrade("").as_bytes(), &on) else { panic!() };
        assert!(!response.contains("Extensions"), "no offer, no extension");
    }

    #[test]
    fn deflate_offer_parameters() {
        let ok = |s: &str| negotiate_deflate(s).is_some();
        let cases: &[(&str, bool)] = &[
            ("", false),
            ("permessage-deflate", true),
            ("PerMessage-Deflate", true),
            ("permessage-deflate;", true),
            ("permessage-deflate; server_no_context_takeover", true),
            ("permessage-deflate; server_no_context_takeover=1", false),
            ("permessage-deflate; client_no_context_takeover=x", false),
            ("permessage-deflate; client_max_window_bits=8", true),
            ("permessage-deflate; client_max_window_bits=15", true),
            ("permessage-deflate; client_max_window_bits=7", false),
            ("permessage-deflate; client_max_window_bits=16", false),
            ("permessage-deflate; client_max_window_bits=\"10\"", true),
            ("permessage-deflate; server_max_window_bits=15", true),
            ("permessage-deflate; server_max_window_bits=14", false),
            ("permessage-deflate; server_max_window_bits", false),
            ("permessage-deflate; SERVER_NO_CONTEXT_TAKEOVER; Server_No_Context_Takeover", false),
            ("x-other, permessage-deflate", true),
            ("permessage-deflatex", false),
        ];
        for (offer, want) in cases {
            assert_eq!(ok(offer), *want, "{offer:?}");
        }
    }

    #[test]
    fn client_handshake_checks() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = accept_key(key);
        let cases: Vec<(String, bool)> = vec![
            (format!("HTTP/1.1 101 OK\r\nsec-websocket-accept: {accept}\r\nsec-websocket-protocol: SIP\r\n\r\n"), true),
            (format!("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"), false),
            (format!("HTTP/1.1 101 OK\r\nSec-WebSocket-Accept:{accept}\r\nSec-WebSocket-Protocol: chat, sip\r\n\r\n"), true),
            (format!("HTTP/1.1 200 OK\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: sip\r\n\r\n"), false),
            ("HTTP/1.1 101 OK\r\nSec-WebSocket-Protocol: sip\r\n\r\n".to_string(), false),
        ];
        for (resp, open) in cases {
            assert_eq!(matches!(client_handshake(resp.as_bytes(), key), ClientHandshake::Open { .. }), open, "{resp}");
        }
        let req = client_request("example.com:443", "/sip", key);
        assert!(req.starts_with("GET /sip HTTP/1.1\r\nHost: example.com:443\r\n") && req.ends_with("\r\n\r\n"), "{req}");
        assert!(matches!(server_handshake(req.as_bytes(), &WsOpts::default()), Handshake::Accept { .. }), "our request passes our own checks");
    }

    #[test]
    fn deflate_without_context_takeover_and_empty_messages() {
        let mut inf = Inflater::new(Deflate { client_no_context_takeover: true });
        let mut out = Vec::new();
        for msg in [&b""[..], b"x", b"OPTIONS sip:a SIP/2.0\r\n\r\n", b"OPTIONS sip:a SIP/2.0\r\n\r\n"] {
            let z = with_deflated(msg, <[u8]>::to_vec).unwrap();
            assert!(!z.ends_with(&TAIL), "the sync tail is stripped (RFC 7692 §7.2.1)");
            inf.inflate(&z, 1024, &mut out).unwrap();
            assert_eq!(out, msg);
        }
        let z = with_deflated(&[b'a'; 2000], <[u8]>::to_vec).unwrap();
        assert!(inf.inflate(&z, 2000, &mut out).is_ok(), "exactly at the limit");
        assert_eq!(inf.inflate(&z, 1999, &mut out), Err((close::TOO_BIG, "decompressed message too big")));
    }

    #[test]
    fn a_message_ending_with_a_bfinal_block_inflates() {
        // RFC 7692 §7.2.3.3: a sender may end each message with a DEFLATE
        // block that has BFINAL set; the 0x00 0x00 0xff 0xff tail the
        // receiver appends then follows the end of the stream.
        let bfinal = |msg: &[u8]| {
            let mut c = Compress::new(Compression::fast(), false);
            let mut z = Vec::with_capacity(64);
            c.compress_vec(msg, &mut z, FlushCompress::Finish).unwrap();
            z
        };
        for client_no_context_takeover in [false, true] {
            let mut inf = Inflater::new(Deflate { client_no_context_takeover });
            let mut out = Vec::new();
            for msg in [&b"OPTIONS sip:a@b SIP/2.0"[..], b"BYE sip:a@b SIP/2.0"] {
                assert_eq!(inf.inflate(&bfinal(msg), 100, &mut out), Ok(()), "each message is a stream of its own");
                assert_eq!(out, msg);
            }
            // A regular (sync-flushed) message after it.
            let z = with_deflated(b"INFO sip:a@b SIP/2.0", <[u8]>::to_vec).unwrap();
            assert_eq!(inf.inflate(&z, 100, &mut out), Ok(()));
            assert_eq!(out, b"INFO sip:a@b SIP/2.0");
        }
        // The size cap still applies.
        let mut inf = Inflater::new(Deflate { client_no_context_takeover: false });
        assert_eq!(inf.inflate(&bfinal(&[b'a'; 300]), 100, &mut Vec::new()).unwrap_err().0, close::TOO_BIG);
    }
}
