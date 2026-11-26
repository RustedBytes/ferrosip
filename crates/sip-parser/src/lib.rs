//! Zero-copy, lazy SIP parser.
//!
//! Design points borrowed from Kamailio (src/core/parser/msg_parser.c):
//! * Every parsed field is a slice into the receive buffer – nothing is copied.
//! * `parse_headers(flags)` parses only until the requested headers are found.
//!   A message that is merely relayed never has its body or tail parsed.
//! * Per-message allocations (the header index) go into a bump arena owned by
//!   the worker and reset after every message – the equivalent of Kamailio's
//!   lock-free per-process `pkg` memory.
#![forbid(unsafe_code)]

mod hdr;
pub mod uri;
pub mod util;
mod via;

pub use hdr::{HdrFlags, HdrKind, kind_of};
pub use uri::{Uri, parse_uri};
pub use via::{Via, parse_via};

use bumpalo::{Bump, collections::Vec as BVec};
use util::{first_line, split_once, trim};

/// A request method. The RFC 3261 core methods and the extensions a proxy
/// meets (RFC 3262 PRACK, 3265/6665 SUBSCRIBE/NOTIFY, 3311 UPDATE, 3428
/// MESSAGE, 3515 REFER, 3903 PUBLISH, 6086 INFO); any other name is
/// `Other` (the name itself stays in `FirstLine::Request::method_raw`).
/// Names are case-sensitive (RFC 3261 §7.1).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Register,
    Options,
    Message,
    Subscribe,
    Notify,
    Publish,
    Info,
    Update,
    Prack,
    Refer,
    Other,
}

impl Method {
    /// Every named method (not `Other`).
    pub const ALL: [Method; 14] = [
        Self::Invite,
        Self::Ack,
        Self::Bye,
        Self::Cancel,
        Self::Register,
        Self::Options,
        Self::Message,
        Self::Subscribe,
        Self::Notify,
        Self::Publish,
        Self::Info,
        Self::Update,
        Self::Prack,
        Self::Refer,
    ];

    /// The method of a name (exact, no allocation); `Other` if unknown.
    #[inline]
    pub fn from_bytes(b: &[u8]) -> Self {
        match b {
            b"INVITE" => Self::Invite,
            b"ACK" => Self::Ack,
            b"BYE" => Self::Bye,
            b"CANCEL" => Self::Cancel,
            b"REGISTER" => Self::Register,
            b"OPTIONS" => Self::Options,
            b"MESSAGE" => Self::Message,
            b"SUBSCRIBE" => Self::Subscribe,
            b"NOTIFY" => Self::Notify,
            b"PUBLISH" => Self::Publish,
            b"INFO" => Self::Info,
            b"UPDATE" => Self::Update,
            b"PRACK" => Self::Prack,
            b"REFER" => Self::Refer,
            _ => Self::Other,
        }
    }

    /// The method named in a CSeq header body (`1 INVITE`); `Other` when
    /// unknown or missing.
    pub fn from_cseq(body: &[u8]) -> Self {
        body.split(|c| c.is_ascii_whitespace()).filter(|x| !x.is_empty()).nth(1).map_or(Self::Other, Self::from_bytes)
    }

    /// The method's name; `"OTHER"` for `Other` (whose real name is only in
    /// the message).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Register => "REGISTER",
            Self::Options => "OPTIONS",
            Self::Message => "MESSAGE",
            Self::Subscribe => "SUBSCRIBE",
            Self::Notify => "NOTIFY",
            Self::Publish => "PUBLISH",
            Self::Info => "INFO",
            Self::Update => "UPDATE",
            Self::Prack => "PRACK",
            Self::Refer => "REFER",
            Self::Other => "OTHER",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FirstLine<'a> {
    Request { method: Method, method_raw: &'a [u8], uri: &'a [u8] },
    Response { code: u16, reason: &'a [u8] },
}

#[derive(Clone, Copy, Debug)]
pub struct Header<'a> {
    pub kind: HdrKind,
    pub name: &'a [u8],
    pub body: &'a [u8],
    /// Offset of the first byte of the header line in the buffer.
    pub start: usize,
    /// Offset just past the terminating CRLF.
    pub end: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    BadFirstLine,
    BadHeader(usize),
    BadVia,
}

pub struct Msg<'a> {
    pub buf: &'a [u8],
    pub first: FirstLine<'a>,
    pub first_line_end: usize,
    pub headers: BVec<'a, Header<'a>>,
    pub via1: Option<Via<'a>>,
    /// Index into `headers` of the header line carrying via1.
    pub via1_hdr: Option<usize>,
    /// Buffer offset of the 2nd Via value if it shares via1's header line.
    pub via1_next: Option<usize>,
    pub via2: Option<Via<'a>>,
    parsed: HdrFlags,
    pos: usize,
    eoh: Option<(usize, usize)>, // (offset of empty line, body start)
}

impl<'a> Msg<'a> {
    /// Parses only the first line. Headers are parsed on demand.
    pub fn parse(buf: &'a [u8], arena: &'a Bump) -> Result<Self, ParseError> {
        let line = first_line(buf).ok_or(ParseError::Truncated)?;
        let first = parse_first_line(trim(line))?;
        Ok(Msg {
            buf,
            first,
            first_line_end: line.len(),
            headers: BVec::with_capacity_in(16, arena),
            via1: None,
            via1_hdr: None,
            via1_next: None,
            via2: None,
            parsed: HdrFlags::NONE,
            pos: line.len(),
            eoh: None,
        })
    }

    #[inline]
    pub fn is_request(&self) -> bool {
        matches!(self.first, FirstLine::Request { .. })
    }
    #[inline]
    pub fn method(&self) -> Option<Method> {
        match self.first {
            FirstLine::Request { method, .. } => Some(method),
            _ => None,
        }
    }
    #[inline]
    pub fn status(&self) -> Option<u16> {
        match self.first {
            FirstLine::Response { code, .. } => Some(code),
            _ => None,
        }
    }
    pub fn ruri(&self) -> Option<&'a [u8]> {
        match self.first {
            FirstLine::Request { uri, .. } => Some(uri),
            _ => None,
        }
    }
    /// The user part of the Request-URI (`sip:alice@host` -> `alice`).
    pub fn ruri_user(&self) -> Option<&'a [u8]> {
        parse_uri(self.ruri()?)?.user
    }

    /// Parse headers until all of `want` are known (or the end of headers).
    pub fn parse_headers(&mut self, want: HdrFlags) -> Result<(), ParseError> {
        while !self.parsed.contains(want) && self.eoh.is_none() {
            self.parse_next()?;
        }
        Ok(())
    }

    pub fn get(&self, kind: HdrKind) -> Option<&Header<'a>> {
        self.headers.iter().find(|h| h.kind == kind)
    }

    /// Offset where new headers can be appended (start of the empty line).
    /// Requires `parse_headers(HdrFlags::EOH)`.
    pub fn eoh_offset(&self) -> Option<usize> {
        self.eoh.map(|e| e.0)
    }
    pub fn body(&self) -> Option<&'a [u8]> {
        self.eoh.and_then(|e| self.buf.get(e.1..))
    }

    /// Byte offset of a sub-slice of `buf`. Because every parsed value is a
    /// slice of the buffer, positions for in-place edits are free.
    ///
    /// `s` must lie inside the buffer, as every header, body and URI slice
    /// the parser hands out does. A slice from anywhere else gives the
    /// buffer length (an empty tail) instead of a wrapped offset that would
    /// make the caller slice out of bounds; debug builds assert.
    #[inline]
    pub fn offset_of(&self, s: &[u8]) -> usize {
        let inside = s.as_ptr().addr().checked_sub(self.buf.as_ptr().addr()).filter(|off| off.checked_add(s.len()).is_some_and(|end| end <= self.buf.len()));
        debug_assert!(inside.is_some(), "offset_of: the slice is not inside the message");
        inside.unwrap_or(self.buf.len())
    }

    fn parse_next(&mut self) -> Result<(), ParseError> {
        let buf = self.buf;
        let start = self.pos;
        // `pos` never passes the end of the buffer.
        let rest = buf.get(start..).unwrap_or_default();
        // An empty line (or the end of the buffer) ends the headers.
        let body = match rest {
            [] => Some(rest),
            [b'\n', body @ ..] | [b'\r', b'\n', body @ ..] => Some(body),
            _ => None,
        };
        if let Some(body) = body {
            self.eoh = Some((start, self.offset_of(body)));
            self.parsed |= HdrFlags::EOH;
            return Ok(());
        }
        // Logical line end, honouring header folding (continuation lines):
        // the first `\n` not followed by a space or tab.
        let (line, tail) = memchr::memchr_iter(b'\n', rest)
            .filter_map(|i| rest.split_at_checked(i))
            .find(|(_, tail)| !matches!(tail, [b'\n', b' ' | b'\t', ..]))
            .ok_or(ParseError::Truncated)?;
        let end = self.offset_of(tail.get(1..).unwrap_or_default());
        let (name, body) = split_once(line, b':').ok_or(ParseError::BadHeader(start))?;
        let (name, body) = (trim(name), trim(body));
        let kind = kind_of(name);

        if kind == HdrKind::Via {
            if self.via1.is_none() {
                let (v, more) = parse_via(body).ok_or(ParseError::BadVia)?;
                self.via1 = Some(v);
                self.via1_hdr = Some(self.headers.len());
                if let Some(m) = more {
                    self.via1_next = Some(self.offset_of(m));
                    self.via2 = Some(parse_via(m).ok_or(ParseError::BadVia)?.0);
                    self.parsed |= HdrFlags::VIA2;
                }
            } else if self.via2.is_none() {
                self.via2 = Some(parse_via(body).ok_or(ParseError::BadVia)?.0);
                self.parsed |= HdrFlags::VIA2;
            }
        }
        self.parsed |= HdrFlags::of(kind);
        self.headers.push(Header { kind, name, body, start, end });
        self.pos = end;
        Ok(())
    }
}

fn parse_first_line(line: &[u8]) -> Result<FirstLine<'_>, ParseError> {
    let mut parts = line.splitn(3, |&c| c == b' ');
    let a = parts.next().ok_or(ParseError::BadFirstLine)?;
    let b = parts.next().ok_or(ParseError::BadFirstLine)?;
    // The Reason-Phrase may be empty (RFC 3261 §25.1), and the trimmed line
    // then ends right after the status code.
    let c = parts.next();
    if a == b"SIP/2.0" {
        let code = util::parse_u32(b).and_then(|c| u16::try_from(c).ok()).filter(|c| (100..700).contains(c));
        let code = code.ok_or(ParseError::BadFirstLine)?;
        Ok(FirstLine::Response { code, reason: c.unwrap_or_default() })
    } else if c == Some(b"SIP/2.0") {
        Ok(FirstLine::Request { method: Method::from_bytes(a), method_raw: a, uri: b })
    } else {
        Err(ParseError::BadFirstLine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"INVITE sip:+4930123@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKaaa;rport, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bKbbb\r\n\
v: SIP/2.0/TCP [2001:db8::1]:5070;branch=z9hG4bKccc\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=1\r\n\
To: <sip:+4930123@example.com>\r\n\
Call-ID: abc@10.0.0.1\r\n\
CSeq: 1 INVITE\r\n\
Subject: folded\r\n  continuation\r\n\
Content-Length: 4\r\n\
\r\n\
v=0\n";

    #[test]
    fn lazy_parsing_stops_early() {
        let a = Bump::new();
        let mut m = Msg::parse(INVITE, &a).unwrap();
        assert_eq!(m.method(), Some(Method::Invite));
        for m in Method::ALL {
            assert_eq!(Method::from_bytes(m.as_str().as_bytes()), m);
            assert_eq!(m.to_string(), m.as_str());
        }
        assert_eq!(Method::from_bytes(b"invite"), Method::Other, "case-sensitive");
        assert_eq!(Method::from_bytes(b"PING"), Method::Other);
        assert_eq!(Method::from_cseq(b"12  UPDATE"), Method::Update);
        assert_eq!(Method::from_cseq(b"12"), Method::Other);
        m.parse_headers(HdrFlags::VIA).unwrap();
        assert_eq!(m.headers.len(), 1, "only the first header was touched");
        let v = m.via1.unwrap();
        assert_eq!(v.host, b"10.0.0.1");
        assert_eq!(v.port, Some(5060));
        assert_eq!(v.branch, Some(&b"z9hG4bKaaa"[..]));
        assert_eq!(v.rport, Some(&b""[..]));
        assert_eq!(m.via2.unwrap().branch, Some(&b"z9hG4bKbbb"[..]));
    }

    #[test]
    fn full_parse() {
        let a = Bump::new();
        let mut m = Msg::parse(INVITE, &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.get(HdrKind::CallId).unwrap().body, b"abc@10.0.0.1");
        assert_eq!(m.body(), Some(&b"v=0\n"[..]));
        assert_eq!(m.ruri_user(), Some(&b"+4930123"[..]));
        let subj = m.headers.iter().find(|h| h.name == b"Subject").unwrap();
        assert!(subj.body.ends_with(b"continuation"));
        let h = m.get(HdrKind::MaxForwards).unwrap();
        assert_eq!(&m.buf[m.offset_of(h.body)..][..2], b"70");
        assert_eq!(m.offset_of(&m.buf[m.buf.len()..]), m.buf.len(), "the empty tail");
    }

    #[test]
    fn response() {
        let a = Bump::new();
        let m = Msg::parse(b"SIP/2.0 180 Ringing\r\n\r\n", &a).unwrap();
        assert_eq!(m.status(), Some(180));
        for bad in [&b"SIP/2.0 65716 Wrapped\r\n\r\n"[..], b"SIP/2.0 99 Low\r\n\r\n", b"SIP/2.0 700 High\r\n\r\n"] {
            assert_eq!(Msg::parse(bad, &a).err(), Some(ParseError::BadFirstLine));
        }
    }

    #[test]
    fn line_ends() {
        let a = Bump::new();
        let mut m = Msg::parse(b"OPTIONS sip:x SIP/2.0\nA: 1\n\tfolded\nB:2\n\nbody", &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.headers.iter().map(|h| (h.name, h.body)).collect::<Vec<_>>(), [(&b"A"[..], &b"1\n\tfolded"[..]), (b"B", b"2")]);
        assert_eq!(m.headers.iter().map(|h| (h.start, h.end)).collect::<Vec<_>>(), [(22, 35), (35, 39)]);
        assert_eq!((m.eoh_offset(), m.body()), (Some(39), Some(&b"body"[..])));
        let mut m = Msg::parse(b"OPTIONS sip:x SIP/2.0\r\nA: 1", &a).unwrap();
        assert_eq!(m.parse_headers(HdrFlags::EOH).err(), Some(ParseError::Truncated));
        let mut m = Msg::parse(b"OPTIONS sip:x SIP/2.0\r\n", &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!((m.eoh_offset(), m.body()), (Some(23), Some(&b""[..])));
    }

    #[test]
    fn garbage() {
        let a = Bump::new();
        assert!(Msg::parse(b"hello\r\n", &a).is_err());
        let mut m = Msg::parse(b"OPTIONS sip:x SIP/2.0\r\nno-colon\r\n\r\n", &a).unwrap();
        assert!(m.parse_headers(HdrFlags::EOH).is_err());
    }
}

/// Result of looking for one SIP message at the start of a stream buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame {
    /// Need more bytes.
    Incomplete,
    /// `len` bytes of CR/LF keep-alive; `ping` = RFC 5626 double-CRLF ping
    /// that must be answered with a single CRLF pong.
    Keepalive { len: usize, ping: bool },
    /// A complete message of `len` bytes.
    Message(usize),
    /// Unrecoverable framing error: the connection must be closed.
    Error(&'static str),
}

/// Stream framing (Kamailio's tcp_read.c): on TCP/TLS the message boundary is
/// end-of-headers + Content-Length, which is mandatory there (RFC 3261 §18.3).
pub fn stream_frame(buf: &[u8], max_len: usize) -> Frame {
    let lead = buf.iter().take_while(|c| matches!(c, b'\r' | b'\n')).count();
    if lead > 0 {
        if buf.starts_with(b"\r\n\r\n") {
            return Frame::Keepalive { len: 4, ping: true };
        }
        if lead == buf.len() && lead < 4 {
            return Frame::Incomplete; // could still become a ping
        }
        return Frame::Keepalive { len: lead.min(2), ping: false };
    }
    // The headers end at an empty line: LF LF or LF CR LF (Kamailio's
    // tcp_read.c, states H_LF / H_LFCR), so `\r\n\r\n`, `\n\n`, `\r\n\n`
    // and `\n\r\n` all count. `hend` is that first LF; the body follows the
    // terminator.
    let end_of_headers = memchr::memchr_iter(b'\n', buf).find_map(|i| {
        let after = buf.get(i.saturating_add(1)..).unwrap_or_default();
        match after {
            [b'\n', ..] => Some((i, i.saturating_add(2))),
            [b'\r', b'\n', ..] => Some((i, i.saturating_add(3))),
            _ => None,
        }
    });
    let Some((lf, body_start)) = end_of_headers else {
        return if buf.len() > max_len { Frame::Error("headers too large") } else { Frame::Incomplete };
    };
    // The header block without its last line ending.
    let hend = if lf > 0 && buf.get(lf.saturating_sub(1)) == Some(&b'\r') { lf.saturating_sub(1) } else { lf };
    let mut clen = None;
    let head = buf.get(..hend).unwrap_or_default();
    for line in head.split(|&c| c == b'\n').skip(1) {
        let Some((name, value)) = split_once(line, b':') else { continue };
        if kind_of(trim(name)) == HdrKind::ContentLength {
            match util::parse_u32(trim(value)) {
                Some(n) => clen = Some(n as usize),
                None => return Frame::Error("bad Content-Length"),
            }
            break;
        }
    }
    let Some(clen) = clen else { return Frame::Error("missing Content-Length on stream transport") };
    match body_start.checked_add(clen) {
        Some(total) if total <= max_len => {
            if buf.len() < total {
                Frame::Incomplete
            } else {
                Frame::Message(total)
            }
        }
        _ => Frame::Error("message too large"),
    }
}

#[cfg(test)]
mod frame_tests {
    use super::{Frame::*, stream_frame as f};

    #[test]
    fn framing() {
        let m = b"MESSAGE sip:a SIP/2.0\r\nl: 3\r\n\r\nabcOPTIONS";
        assert_eq!(f(m, 1000), Message(m.len() - 7));
        assert_eq!(f(&m[..m.len() - 9], 1000), Incomplete); // body cut
        assert_eq!(f(b"\r\n\r\nINVITE", 1000), Keepalive { len: 4, ping: true });
        assert_eq!(f(b"\r\nINVITE", 1000), Keepalive { len: 2, ping: false });
        assert_eq!(f(b"\r\n", 1000), Incomplete);
        assert_eq!(f(b"OPTIONS sip:a SIP/2.0\r\nTo: x\r\n\r\n", 1000), Error("missing Content-Length on stream transport"));
        assert_eq!(f(&[b'A'; 2000], 1000), Error("headers too large"));
        assert_eq!(f(b"M sip:a SIP/2.0\r\nl: 999999999\r\n\r\n", usize::MAX), Incomplete, "no overflow at the size limit");
        assert_eq!(f(b"M sip:a SIP/2.0\r\nl: 1\r\n\r\nxy", 25), Error("message too large"));
    }
}

#[cfg(test)]
mod msg_tests {
    use super::*;

    fn headers(buf: &[u8]) -> Result<Vec<(String, String)>, ParseError> {
        let a = Bump::new();
        let mut m = Msg::parse(buf, &a)?;
        m.parse_headers(HdrFlags::EOH)?;
        Ok(m.headers.iter().map(|h| (String::from_utf8_lossy(h.name).into_owned(), String::from_utf8_lossy(h.body).into_owned())).collect())
    }

    /// A line starting with whitespace right after the start line has no
    /// header to continue. Kamailio is lenient there too: parse_hname2.c
    /// takes `" X-A: 1"` as a header (its name starts at the space), so
    /// the message is accepted rather than refused.
    #[test]
    fn whitespace_led_first_header_is_accepted_as_kamailio_does() {
        let h = headers(b"OPTIONS sip:a@b SIP/2.0\r\n X-A: 1\r\nCall-ID: c\r\n\r\n").unwrap();
        assert_eq!(h.len(), 2, "{h:?}");
        assert!(h[0].0.trim() == "X-A" && h[0].1 == "1", "{h:?}");
        assert_eq!(h[1], ("Call-ID".to_string(), "c".to_string()));
    }

    #[test]
    fn first_line_requests_and_responses() {
        let a = Bump::new();
        // (first line, method, method_raw, uri)
        type Request<'a> = (&'a [u8], Method, &'a [u8], &'a [u8]);
        let requests: &[Request] = &[
            (b"INVITE sip:a@h SIP/2.0\r\n", Method::Invite, b"INVITE", b"sip:a@h"),
            (b"REGISTER sip:h SIP/2.0\n", Method::Register, b"REGISTER", b"sip:h"),
            (b"FOO sip:h SIP/2.0\r\n", Method::Other, b"FOO", b"sip:h"),
            (b"invite sip:h SIP/2.0\r\n", Method::Other, b"invite", b"sip:h"),
            (b"PRACK tel:+1234 SIP/2.0\r\n", Method::Prack, b"PRACK", b"tel:+1234"),
        ];
        for &(buf, method, raw, uri) in requests {
            let m = Msg::parse(buf, &a).unwrap();
            assert!(m.is_request());
            assert_eq!(m.status(), None);
            let FirstLine::Request { method: got, method_raw, uri: got_uri } = m.first else { panic!("not a request") };
            assert_eq!((got, method_raw, got_uri), (method, raw, uri));
            assert_eq!(m.first_line_end, buf.len());
        }
        let responses: &[(&[u8], u16, &[u8])] = &[
            (b"SIP/2.0 100 Trying\r\n", 100, b"Trying"),
            (b"SIP/2.0 486 Busy Here\r\n", 486, b"Busy Here"),
            (b"SIP/2.0 699 x\r\n", 699, b"x"),
            (b"SIP/2.0 200 \r\n", 200, b""),
            (b"SIP/2.0 200\r\n", 200, b""),
        ];
        for &(buf, code, reason) in responses {
            let m = Msg::parse(buf, &a).unwrap_or_else(|e| panic!("{:?}: {e:?}", String::from_utf8_lossy(buf)));
            assert!(!m.is_request());
            assert_eq!((m.method(), m.ruri()), (None, None));
            let FirstLine::Response { code: got, reason: got_reason } = m.first else { panic!("not a response") };
            assert_eq!((got, got_reason), (code, reason), "{:?}", String::from_utf8_lossy(buf));
        }
        let bad: &[(&[u8], ParseError)] = &[
            (b"", ParseError::Truncated),
            (b"INVITE sip:a@h SIP/2.0", ParseError::Truncated),
            (b"\r\n", ParseError::BadFirstLine),
            (b"INVITE sip:a@h\r\n", ParseError::BadFirstLine),
            (b"INVITE sip:a@h SIP/1.0\r\n", ParseError::BadFirstLine),
            (b"INVITE sip:a@h sip/2.0\r\n", ParseError::BadFirstLine),
            (b"SIP/2.0 2000 OK\r\n", ParseError::BadFirstLine),
            (b"SIP/2.0 abc OK\r\n", ParseError::BadFirstLine),
            (b"SIP/2.0 -200 OK\r\n", ParseError::BadFirstLine),
            (b"SIP/2.0\r\n", ParseError::BadFirstLine),
            (b"SIP/2.0  200 OK\r\n", ParseError::BadFirstLine),
        ];
        for (buf, err) in bad {
            assert_eq!(Msg::parse(buf, &a).err().as_ref(), Some(err), "{:?}", String::from_utf8_lossy(buf));
        }
    }

    #[test]
    fn header_folding_joins_continuation_lines() {
        // (message, [(name, body)])
        type Case<'a> = (&'a [u8], &'a [(&'a str, &'a str)]);
        let cases: &[Case] = &[
            (b"OPTIONS sip:h SIP/2.0\r\nSubject: a\r\n b\r\n\r\n", &[("Subject", "a\r\n b")]),
            (b"OPTIONS sip:h SIP/2.0\r\nSubject: a\r\n\tb\r\nX: 1\r\n\r\n", &[("Subject", "a\r\n\tb"), ("X", "1")]),
            (b"OPTIONS sip:h SIP/2.0\r\nSubject: a\r\n b\r\n  c\r\n\r\n", &[("Subject", "a\r\n b\r\n  c")]),
            (b"OPTIONS sip:h SIP/2.0\r\nSubject:\r\n b\r\n\r\n", &[("Subject", "b")]),
            (b"OPTIONS sip:h SIP/2.0\nSubject: a\n b\nX: 1\n\n", &[("Subject", "a\n b"), ("X", "1")]),
            (b"OPTIONS sip:h SIP/2.0\r\nSubject: a\r\n b  \r\n\r\n", &[("Subject", "a\r\n b")]),
        ];
        for &(buf, want) in cases {
            let got = headers(buf).unwrap();
            let want: Vec<_> = want.iter().map(|&(n, b)| (n.to_owned(), b.to_owned())).collect();
            assert_eq!(got, want, "{:?}", String::from_utf8_lossy(buf));
        }
    }

    #[test]
    fn folded_via_is_parsed_as_one_value() {
        let a = Bump::new();
        let mut m = Msg::parse(b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h1;branch=z9hG4bK1,\r\n SIP/2.0/UDP h2;branch=z9hG4bK2\r\n\r\n", &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.headers.len(), 1);
        assert_eq!(m.via1.unwrap().branch, Some(&b"z9hG4bK1"[..]));
        let v2 = m.via2.unwrap();
        assert_eq!((v2.host, v2.branch), (&b"h2"[..], Some(&b"z9hG4bK2"[..])));
    }

    #[test]
    fn crlf_and_lf_line_endings_give_the_same_headers() {
        let crlf =
            b"INVITE sip:a@h SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bK1\r\nf: <sip:x@h>;tag=1\r\nt: <sip:a@h>\r\ni: c1\r\nCSeq: 1 INVITE\r\nl: 2\r\n\r\nhi";
        let lf: Vec<u8> = crlf.iter().copied().filter(|&c| c != b'\r').collect();
        let a = Bump::new();
        for buf in [&crlf[..], &lf[..]] {
            let mut m = Msg::parse(buf, &a).unwrap();
            m.parse_headers(HdrFlags::EOH).unwrap();
            assert_eq!(m.headers.len(), 6);
            assert_eq!(m.body(), Some(&b"hi"[..]));
            assert_eq!(m.get(HdrKind::CallId).unwrap().body, b"c1");
            assert_eq!(m.via1.unwrap().branch, Some(&b"z9hG4bK1"[..]));
            let eoh = m.eoh_offset().unwrap();
            assert_eq!(&buf[eoh..buf.len() - 2], if buf.len() == crlf.len() { &b"\r\n"[..] } else { b"\n" });
            let last = m.headers.last().unwrap();
            assert_eq!(last.end, eoh, "the last header ends where the empty line starts");
        }
        // Mixed endings in one message.
        let got = headers(b"OPTIONS sip:h SIP/2.0\nA: 1\r\nB: 2\n\r\nbody").unwrap();
        assert_eq!(got, [("A".to_owned(), "1".to_owned()), ("B".to_owned(), "2".to_owned())]);
    }

    #[test]
    fn compact_header_names_map_to_their_kinds() {
        let a = Bump::new();
        let buf = b"INVITE sip:a@h SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bK1\r\nf: <sip:x@h>;tag=1\r\nt: <sip:a@h>\r\ni: c1\r\nm: <sip:x@1.2.3.4>\r\nl: 0\r\nk: 100rel\r\n\r\n";
        let mut m = Msg::parse(buf, &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        let kinds: Vec<_> = m.headers.iter().map(|h| h.kind).collect();
        assert_eq!(kinds, [HdrKind::Via, HdrKind::From, HdrKind::To, HdrKind::CallId, HdrKind::Contact, HdrKind::ContentLength, HdrKind::Other]);
        assert_eq!(m.get(HdrKind::Contact).unwrap().body, b"<sip:x@1.2.3.4>");
        assert_eq!(m.get(HdrKind::ContentLength).unwrap().name, b"l", "the name is kept as written");
        assert!(m.via1.is_some());
    }

    #[test]
    fn multiple_via_values_across_lines_and_within_one_line() {
        let a = Bump::new();
        // Two Via header lines: via2 comes from the second.
        let mut m = Msg::parse(
            b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h1;branch=b1\r\nX: y\r\nVia: SIP/2.0/TCP h2;branch=b2\r\nVia: SIP/2.0/TCP h3;branch=b3\r\n\r\n",
            &a,
        )
        .unwrap();
        m.parse_headers(HdrFlags::VIA).unwrap();
        assert!(m.via2.is_none(), "VIA alone stops after the first Via line");
        m.parse_headers(HdrFlags::VIA2).unwrap();
        assert_eq!(m.headers.len(), 3);
        assert_eq!(m.via2.unwrap().branch, Some(&b"b2"[..]));
        assert_eq!((m.via1_hdr, m.via1_next), (Some(0), None));
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.via2.unwrap().host, b"h2", "a third Via does not replace via2");

        // Three values in one line, after another header.
        let buf = b"OPTIONS sip:h SIP/2.0\r\nMax-Forwards: 70\r\nVia: SIP/2.0/UDP h1;branch=b1, SIP/2.0/UDP h2;branch=b2, SIP/2.0/UDP h3\r\nVia: SIP/2.0/UDP h4\r\n\r\n";
        let mut m = Msg::parse(buf, &a).unwrap();
        m.parse_headers(HdrFlags::VIA2).unwrap();
        assert_eq!(m.headers.len(), 2);
        assert_eq!(m.via1_hdr, Some(1));
        assert_eq!(m.via1.unwrap().host, b"h1");
        assert_eq!(m.via2.unwrap().host, b"h2");
        let next = m.via1_next.unwrap();
        assert!(buf[next..].starts_with(b"SIP/2.0/UDP h2;branch=b2, SIP/2.0/UDP h3\r\n"));
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.via2.unwrap().host, b"h2");
    }

    #[test]
    fn get_returns_the_first_of_repeated_headers() {
        let a = Bump::new();
        let mut m =
            Msg::parse(b"INVITE sip:h SIP/2.0\r\nRoute: <sip:p1;lr>\r\nRoute: <sip:p2;lr>, <sip:p3;lr>\r\nContact: <sip:a@x>;q=0.5, <sip:b@y>;q=1\r\n\r\n", &a)
                .unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.get(HdrKind::Route).unwrap().body, b"<sip:p1;lr>");
        let routes: Vec<&[u8]> = m.headers.iter().filter(|h| h.kind == HdrKind::Route).flat_map(|h| uri::split_list(h.body)).collect();
        assert_eq!(routes, [&b"<sip:p1;lr>"[..], b"<sip:p2;lr>", b"<sip:p3;lr>"]);
        let qs: Vec<_> = uri::split_list(m.get(HdrKind::Contact).unwrap().body).into_iter().map(|c| uri::parse_contact(c).q).collect();
        assert_eq!(qs, [Some(500), Some(1000)]);
        assert!(m.get(HdrKind::RecordRoute).is_none());
    }

    #[test]
    fn header_offsets_cover_whole_lines() {
        let a = Bump::new();
        let buf = b"OPTIONS sip:h SIP/2.0\r\nA:1\r\nBb : two \r\n folded\r\nC:\r\n\r\nxyz";
        let mut m = Msg::parse(buf, &a).unwrap();
        m.parse_headers(HdrFlags::EOH).unwrap();
        let lines: Vec<_> = m.headers.iter().map(|h| (&buf[h.start..h.end], h.name, h.body)).collect();
        assert_eq!(lines, [(&b"A:1\r\n"[..], &b"A"[..], &b"1"[..]), (b"Bb : two \r\n folded\r\n", b"Bb", b"two \r\n folded"), (b"C:\r\n", b"C", b"")]);
        for h in m.headers.iter() {
            let off = m.offset_of(h.body);
            assert_eq!(&buf[off..off + h.body.len()], h.body);
        }
        assert_eq!(m.eoh_offset(), Some(buf.len() - 5));
        assert_eq!(m.body(), Some(&b"xyz"[..]));
    }

    #[test]
    fn parse_headers_is_lazy_and_idempotent() {
        let a = Bump::new();
        let buf = b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h\r\nFrom: <sip:a@h>\r\nCall-ID: c\r\nTo: <sip:h>\r\n\r\n";
        let mut m = Msg::parse(buf, &a).unwrap();
        m.parse_headers(HdrFlags::CALLID).unwrap();
        assert_eq!(m.headers.len(), 3);
        m.parse_headers(HdrFlags::FROM | HdrFlags::CALLID).unwrap();
        assert_eq!(m.headers.len(), 3, "already known headers parse nothing");
        assert_eq!(m.eoh_offset(), None);
        assert_eq!(m.body(), None, "no body before the end of headers");
        m.parse_headers(HdrFlags::CONTACT).unwrap();
        assert_eq!(m.headers.len(), 4, "an absent header parses to the end");
        assert!(m.get(HdrKind::Contact).is_none());
        assert_eq!(m.eoh_offset(), Some(buf.len() - 2));
        m.parse_headers(HdrFlags::EOH).unwrap();
        assert_eq!(m.headers.len(), 4);
    }

    #[test]
    fn content_length_is_not_applied_to_datagram_bodies() {
        // The parser hands out everything after the empty line; checking it
        // against Content-Length is up to the caller (and stream_frame).
        let a = Bump::new();
        for (buf, body) in [
            (&b"MESSAGE sip:h SIP/2.0\r\nContent-Length: 2\r\n\r\nabcdef"[..], &b"abcdef"[..]),
            (b"MESSAGE sip:h SIP/2.0\r\nContent-Length: 10\r\n\r\nab", b"ab"),
            (b"MESSAGE sip:h SIP/2.0\r\nContent-Length: x\r\n\r\nab", b"ab"),
        ] {
            let mut m = Msg::parse(buf, &a).unwrap();
            m.parse_headers(HdrFlags::EOH).unwrap();
            assert_eq!(m.body(), Some(body));
        }
    }

    #[test]
    fn every_truncation_of_a_valid_message_is_ok_or_truncated() {
        let buf = b"INVITE sip:bob@h SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKa, SIP/2.0/UDP [::1];branch=z9hG4bKb\r\nSubject: a\r\n b\r\nCall-ID: c\r\nContent-Length: 4\r\n\r\nbody";
        let a = Bump::new();
        for cut in 0..=buf.len() {
            let part = &buf[..cut];
            let Ok(mut m) = Msg::parse(part, &a) else {
                assert!(!part.contains(&b'\n'), "cut {cut}: only an incomplete first line fails");
                continue;
            };
            match m.parse_headers(HdrFlags::EOH) {
                Ok(()) => {
                    let body = m.body().unwrap();
                    assert!(part.ends_with(body), "cut {cut}");
                }
                Err(e) => assert_eq!(e, ParseError::Truncated, "cut {cut}"),
            }
        }
    }

    #[test]
    fn malformed_headers_report_their_offset() {
        let a = Bump::new();
        let cases: &[(&[u8], ParseError)] = &[
            (b"OPTIONS sip:h SIP/2.0\r\nA: 1\r\nno colon\r\n\r\n", ParseError::BadHeader(29)),
            (b"OPTIONS sip:h SIP/2.0\r\nVia: nonsense\r\n\r\n", ParseError::BadVia),
            (b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h, junk\r\n\r\n", ParseError::BadVia),
            (b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP h\r\nv: SIP/2.0/UDP ;branch=x\r\n\r\n", ParseError::BadVia),
            (b"OPTIONS sip:h SIP/2.0\r\nA: 1\r\nB: 2", ParseError::Truncated),
        ];
        for (buf, err) in cases {
            let mut m = Msg::parse(buf, &a).unwrap();
            assert_eq!(m.parse_headers(HdrFlags::EOH).err().as_ref(), Some(err), "{:?}", String::from_utf8_lossy(buf));
        }
        // A third malformed Via is not looked at.
        let mut m = Msg::parse(b"OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/UDP a\r\nVia: SIP/2.0/UDP b\r\nVia: junk\r\n\r\n", &a).unwrap();
        assert!(m.parse_headers(HdrFlags::EOH).is_ok());
    }

    #[test]
    fn ruri_user_reads_the_request_uri() {
        let a = Bump::new();
        let cases: &[(&[u8], Option<&[u8]>)] = &[
            (b"INVITE sip:alice@h SIP/2.0\r\n", Some(b"alice")),
            (b"INVITE sip:h SIP/2.0\r\n", None),
            (b"INVITE sip:+1;npdi@h;user=phone SIP/2.0\r\n", Some(b"+1;npdi")),
            (b"INVITE nonsense SIP/2.0\r\n", None),
            (b"SIP/2.0 200 OK\r\n", None),
        ];
        for &(buf, user) in cases {
            assert_eq!(Msg::parse(buf, &a).unwrap().ruri_user(), user, "{:?}", String::from_utf8_lossy(buf));
        }
    }
}

#[cfg(test)]
mod frame_table_tests {
    use super::{Frame, Frame::*, stream_frame};

    #[test]
    fn stream_frame_cases() {
        let cases: &[(&[u8], usize, Frame)] = &[
            // Keep-alives.
            (b"", 100, Incomplete),
            (b"\r", 100, Incomplete),
            (b"\r\n\r", 100, Incomplete),
            (b"\r\n\r\n", 100, Keepalive { len: 4, ping: true }),
            (b"\r\n\r\n\r\n", 100, Keepalive { len: 4, ping: true }),
            (b"\n", 100, Incomplete),
            (b"\nX", 100, Keepalive { len: 1, ping: false }),
            (b"\n\n\n\n", 100, Keepalive { len: 2, ping: false }),
            (b"\r\n\rX", 100, Keepalive { len: 2, ping: false }),
            // Content-Length forms.
            (b"M sip:a SIP/2.0\r\nContent-Length: 3\r\n\r\nabc", 100, Message(41)),
            (b"M sip:a SIP/2.0\r\ncontent-length:3\r\n\r\nabc", 100, Message(40)),
            (b"M sip:a SIP/2.0\r\nCONTENT-LENGTH :  3  \r\n\r\nabc", 100, Message(45)),
            (b"M sip:a SIP/2.0\r\nL: 3\r\n\r\nabc", 100, Message(28)),
            (b"M sip:a SIP/2.0\r\nl: 0\r\n\r\n", 100, Message(25)),
            (b"M sip:a SIP/2.0\r\nl: 0\r\n\r\nNEXT", 100, Message(25)),
            (b"M sip:a SIP/2.0\r\nl: 2\r\nl: 9\r\n\r\nab", 100, Message(33)),
            (b"M sip:a SIP/2.0\r\nX-Content-Length: 2\r\n\r\nab", 100, Error("missing Content-Length on stream transport")),
            (b"M sip:a SIP/2.0\r\n\r\nl: 2\r\n", 100, Error("missing Content-Length on stream transport")),
            (b"M sip:a SIP/2.0\r\nl: -1\r\n\r\n", 100, Error("bad Content-Length")),
            (b"M sip:a SIP/2.0\r\nl: 1x\r\n\r\n", 100, Error("bad Content-Length")),
            (b"M sip:a SIP/2.0\r\nl:\r\n\r\n", 100, Error("bad Content-Length")),
            // Ten digits fit a u32: valid, and bounded by max_len.
            (b"M sip:a SIP/2.0\r\nl: 1234567890\r\n\r\n", usize::MAX, Incomplete),
            (b"M sip:a SIP/2.0\r\nl: 1234567890\r\n\r\n", 65535, Error("message too large")),
            (b"M sip:a SIP/2.0\r\nl: 4294967296\r\n\r\n", usize::MAX, Error("bad Content-Length")),
            // Body not complete yet.
            (b"M sip:a SIP/2.0\r\nl: 3\r\n\r\nab", 100, Incomplete),
            (b"M sip:a SIP/2.0\r\nl: 3\r\n\r\n", 100, Incomplete),
            (b"M sip:a SIP/2.0\r\nl: 3\r\n\r", 100, Incomplete),
            // LF-only and mixed header ends (LF LF, LF CR LF), as Kamailio's
            // tcp_read.c accepts them.
            (b"M sip:a SIP/2.0\nl: 0\n\n", 100, Message(22)),
            (b"M sip:a SIP/2.0\nl: 2\n\nabX", 100, Message(24)),
            (b"M sip:a SIP/2.0\r\nl: 2\r\n\nab", 100, Message(26)),
            (b"M sip:a SIP/2.0\nl: 2\n\r\nab", 100, Message(25)),
            (b"M sip:a SIP/2.0\nl: 2\n\n", 100, Incomplete),
            // A terminator cut after LF CR could still become LF CR LF.
            (b"M sip:a SIP/2.0\nl: 0\n\r", 100, Incomplete),
        ];
        for (buf, max, want) in cases {
            assert_eq!(&stream_frame(buf, *max), want, "{:?}", String::from_utf8_lossy(buf));
        }
    }

    #[test]
    fn stream_frame_size_limits_are_inclusive() {
        let m = b"M sip:a SIP/2.0\r\nl: 4\r\n\r\nabcd";
        assert_eq!(stream_frame(m, m.len()), Message(m.len()));
        assert_eq!(stream_frame(m, m.len() - 1), Error("message too large"));
        assert_eq!(stream_frame(&m[..20], m.len()), Incomplete, "a large message is reported only once its headers are in");
        let partial = [b'A'; 50];
        assert_eq!(stream_frame(&partial, 50), Incomplete);
        assert_eq!(stream_frame(&partial, 49), Error("headers too large"));
    }

    #[test]
    fn stream_frame_splits_back_to_back_messages() {
        let one = &b"MESSAGE sip:a SIP/2.0\r\nl: 2\r\n\r\nhi"[..];
        let two = &b"OPTIONS sip:a SIP/2.0\r\nContent-Length: 0\r\n\r\n"[..];
        let stream: Vec<u8> = [one, b"\r\n\r\n", two, b"\r\n"].concat();
        let mut rest = &stream[..];
        let mut seen = Vec::new();
        loop {
            match stream_frame(rest, 1000) {
                Message(n) => {
                    seen.push(&rest[..n]);
                    rest = &rest[n..];
                }
                Keepalive { len, ping } => {
                    assert!(ping, "only the double CRLF between messages is a ping");
                    rest = &rest[len..];
                }
                Incomplete => break,
                Error(e) => panic!("{e}"),
            }
        }
        assert_eq!(seen, [one, two]);
        assert_eq!(rest, b"\r\n", "a lone CRLF waits for more bytes");
    }
}
