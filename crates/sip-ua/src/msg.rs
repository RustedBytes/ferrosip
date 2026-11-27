//! Owned SIP messages.
//!
//! `sip-parser` hands out zero-copy slices of a receive buffer that lives
//! only for one worker iteration. Everything the UA keeps (transactions,
//! dialogs) or hands to the application across a thread boundary must
//! outlive that buffer, so the engine converts each message it accepts into
//! a [`SipMessage`] once, after validating it against [`Limits`].

use bumpalo::Bump;
use sip_parser::uri::{name_addr, param, split_list};
use sip_parser::{FirstLine, HdrFlags, Msg, parse_via};
use std::fmt;

/// A SIP method (owned; unknown methods keep their name).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Info,
    Update,
    Prack,
    Refer,
    Notify,
    Subscribe,
    Message,
    Register,
    Publish,
    Other(String),
}

impl Method {
    /// The method named `s` (case-sensitive, RFC 3261 §7.1).
    pub fn parse(s: &str) -> Self {
        match s {
            "INVITE" => Self::Invite,
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "OPTIONS" => Self::Options,
            "INFO" => Self::Info,
            "UPDATE" => Self::Update,
            "PRACK" => Self::Prack,
            "REFER" => Self::Refer,
            "NOTIFY" => Self::Notify,
            "SUBSCRIBE" => Self::Subscribe,
            "MESSAGE" => Self::Message,
            "REGISTER" => Self::Register,
            "PUBLISH" => Self::Publish,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Options => "OPTIONS",
            Self::Info => "INFO",
            Self::Update => "UPDATE",
            Self::Prack => "PRACK",
            Self::Refer => "REFER",
            Self::Notify => "NOTIFY",
            Self::Subscribe => "SUBSCRIBE",
            Self::Message => "MESSAGE",
            Self::Register => "REGISTER",
            Self::Publish => "PUBLISH",
            Self::Other(s) => s,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One header line (name as written, value trimmed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self { name: name.into(), value: value.into() }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartLine {
    Request { method: Method, uri: String },
    Response { code: u16, reason: String },
}

/// Size limits applied to every received message before it is accepted.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Whole message (datagram or stream frame), bytes.
    pub max_message: usize,
    /// Header lines (Content-Length not counted: it is recomputed).
    pub max_headers: usize,
    /// One header value, bytes.
    pub max_header_len: usize,
    /// Body, bytes.
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_message: 65_535, max_headers: 128, max_header_len: 8_192, max_body: 32_768 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MsgError {
    TooLarge,
    TooManyHeaders,
    HeaderTooLong,
    BodyTooLarge,
    Parse,
    /// Header bytes are not UTF-8.
    Encoding,
    /// Content-Length is missing a body or malformed.
    ContentLength,
    /// A mandatory header (Via, From, To, Call-ID, CSeq) is missing or bad.
    Missing(&'static str),
}

impl fmt::Display for MsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("message too large"),
            Self::TooManyHeaders => f.write_str("too many headers"),
            Self::HeaderTooLong => f.write_str("header too long"),
            Self::BodyTooLarge => f.write_str("body too large"),
            Self::Parse => f.write_str("malformed message"),
            Self::Encoding => f.write_str("header is not UTF-8"),
            Self::ContentLength => f.write_str("bad Content-Length"),
            Self::Missing(h) => write!(f, "missing or malformed {h}"),
        }
    }
}

impl std::error::Error for MsgError {}

/// The top Via, owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViaInfo {
    pub transport: String,
    pub host: String,
    pub port: Option<u16>,
    pub branch: Option<String>,
    /// `;rport` is present (RFC 3581).
    pub rport: bool,
}

impl ViaInfo {
    /// `host[:port]` as written in the Via (the transaction key's sent-by).
    pub fn sent_by(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{p}", self.host),
            None => self.host.clone(),
        }
    }
}

/// An owned SIP request or response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SipMessage {
    pub start: StartLine,
    /// Every header except Content-Length (recomputed on serialization).
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// Compact header forms (RFC 3261 §7.3.3 and extensions).
fn expand(name: &str) -> &str {
    if name.len() != 1 {
        return name;
    }
    match name.as_bytes().first().map(u8::to_ascii_lowercase) {
        Some(b'v') => "via",
        Some(b'f') => "from",
        Some(b't') => "to",
        Some(b'i') => "call-id",
        Some(b'm') => "contact",
        Some(b'l') => "content-length",
        Some(b'c') => "content-type",
        Some(b'e') => "content-encoding",
        Some(b'k') => "supported",
        Some(b's') => "subject",
        Some(b'o') => "event",
        Some(b'r') => "refer-to",
        Some(b'b') => "referred-by",
        Some(b'x') => "session-expires",
        Some(b'u') => "allow-events",
        _ => name,
    }
}

/// A header value with its line folding (CRLF or LF followed by SP/HT,
/// RFC 3261 §7.3.1) replaced by one space. Any other control character
/// (a bare CR or LF, NUL…) makes the message malformed: normalising it
/// instead would change how the value tokenizes once re-serialized.
fn unfold(v: &str) -> Result<String, MsgError> {
    // Almost every value has no control character except tabs: copy it.
    if !v.chars().any(|c| c.is_control() && c != '\t') {
        return Ok(v.trim().to_string());
    }
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' if it.peek() == Some(&'\n') => {}
            '\n' if matches!(it.peek(), Some(' ' | '\t')) => {
                while matches!(it.peek(), Some(' ' | '\t')) {
                    it.next();
                }
                let trimmed = out.trim_end().len();
                out.truncate(trimmed);
                out.push(' ');
            }
            '\t' => out.push(c),
            c if c.is_control() => return Err(MsgError::Parse),
            c => out.push(c),
        }
    }
    Ok(out.trim().to_string())
}

/// Header names compare case-insensitively, compact forms included.
pub fn same_name(a: &str, b: &str) -> bool {
    expand(a).eq_ignore_ascii_case(expand(b))
}

/// `value` without its `;tag=` header parameter.
pub fn strip_tag(value: &str) -> String {
    let (uri, params) = name_addr(value.as_bytes());
    if params.is_empty() || param(params, b"tag").is_none() {
        return value.to_string();
    }
    // Keep everything up to the URI end, then the non-tag parameters.
    let Some(uri_end) = value.as_bytes().windows(uri.len().max(1)).position(|w| w == uri).and_then(|p| p.checked_add(uri.len())) else {
        return value.to_string();
    };
    let head = value.get(..uri_end).unwrap_or(value);
    let close = if value.contains('<') { ">" } else { "" };
    let mut out = head.to_string();
    out.push_str(close);
    for p in String::from_utf8_lossy(params).split(';') {
        let p = p.trim();
        if p.is_empty() || p.split('=').next().is_some_and(|k| k.trim().eq_ignore_ascii_case("tag")) {
            continue;
        }
        out.push(';');
        out.push_str(p);
    }
    out
}

/// The `tag` parameter of a From/To value.
pub fn tag_of(value: &str) -> Option<String> {
    let (_, params) = name_addr(value.as_bytes());
    let t = param(params, b"tag")?;
    (!t.is_empty()).then(|| String::from_utf8_lossy(t).into_owned())
}

/// The URI of a name-addr / addr-spec value.
pub fn uri_of(value: &str) -> String {
    String::from_utf8_lossy(name_addr(value.as_bytes()).0).into_owned()
}

/// Split a header value on top-level commas (not inside quotes or `<>`).
pub fn split_values(value: &str) -> Vec<String> {
    split_list(value.as_bytes()).into_iter().map(|v| String::from_utf8_lossy(v).trim().to_string()).filter(|v| !v.is_empty()).collect()
}

impl SipMessage {
    pub fn request(method: Method, uri: impl Into<String>) -> Self {
        Self { start: StartLine::Request { method, uri: uri.into() }, headers: Vec::new(), body: Vec::new() }
    }

    pub fn response(code: u16, reason: impl Into<String>) -> Self {
        Self { start: StartLine::Response { code, reason: reason.into() }, headers: Vec::new(), body: Vec::new() }
    }

    /// Parse and validate one complete message.
    pub fn parse(buf: &[u8], limits: &Limits) -> Result<Self, MsgError> {
        if buf.len() > limits.max_message {
            return Err(MsgError::TooLarge);
        }
        let arena = Bump::new();
        let mut m = Msg::parse(buf, &arena).map_err(|_| MsgError::Parse)?;
        m.parse_headers(HdrFlags::EOH).map_err(|_| MsgError::Parse)?;
        // Content-Length is not kept (it is recomputed), so it doesn't count.
        if m.headers.len() > limits.max_headers.saturating_add(1) {
            return Err(MsgError::TooManyHeaders);
        }
        let start = match m.first {
            FirstLine::Request { method_raw, uri, .. } => {
                let method = std::str::from_utf8(method_raw).map_err(|_| MsgError::Encoding)?;
                let uri = std::str::from_utf8(uri).map_err(|_| MsgError::Encoding)?;
                if !is_token(method) || uri.chars().any(char::is_control) {
                    return Err(MsgError::Parse);
                }
                StartLine::Request { method: Method::parse(method), uri: uri.to_string() }
            }
            FirstLine::Response { code, reason } => {
                let reason = std::str::from_utf8(reason).map_err(|_| MsgError::Encoding)?;
                if reason.chars().any(|c| c.is_control() && c != '\t') {
                    return Err(MsgError::Parse);
                }
                StartLine::Response { code, reason: reason.to_string() }
            }
        };
        let mut headers = Vec::with_capacity(m.headers.len());
        let mut clen: Option<usize> = None;
        for h in m.headers.iter() {
            if h.body.len() > limits.max_header_len {
                return Err(MsgError::HeaderTooLong);
            }
            let name = std::str::from_utf8(h.name).map_err(|_| MsgError::Encoding)?;
            let value = std::str::from_utf8(h.body).map_err(|_| MsgError::Encoding)?;
            let value = unfold(value)?;
            if !is_token(name) {
                return Err(MsgError::Parse);
            }
            if same_name(name, "content-length") {
                let n = value.trim().parse::<usize>().map_err(|_| MsgError::ContentLength)?;
                if clen.is_some_and(|c| c != n) {
                    return Err(MsgError::ContentLength);
                }
                clen = Some(n);
                continue;
            }
            if headers.len() >= limits.max_headers {
                return Err(MsgError::TooManyHeaders);
            }
            headers.push(Header { name: name.to_string(), value });
        }
        let raw_body = m.body().unwrap_or_default();
        let body = match clen {
            Some(n) => raw_body.get(..n).ok_or(MsgError::ContentLength)?,
            None => raw_body,
        };
        if body.len() > limits.max_body {
            return Err(MsgError::BodyTooLarge);
        }
        let msg = Self { start, headers, body: body.to_vec() };
        msg.validate()?;
        Ok(msg)
    }

    /// RFC 3261 §8.1.1 mandatory headers.
    fn validate(&self) -> Result<(), MsgError> {
        self.top_via().ok_or(MsgError::Missing("Via"))?;
        // Every Via value must parse, not only the first two the lazy
        // parser looks at: a later one can become the top Via of a
        // response we build (and of this message once re-serialized).
        for line in self.header_lines("Via") {
            let mut rest = Some(line.as_bytes());
            while let Some(r) = rest {
                let (_, next) = parse_via(r).ok_or(MsgError::Missing("Via"))?;
                rest = next;
            }
        }
        self.header("From").ok_or(MsgError::Missing("From"))?;
        self.header("To").ok_or(MsgError::Missing("To"))?;
        self.call_id().ok_or(MsgError::Missing("Call-ID"))?;
        let (_, cseq_method) = self.cseq().ok_or(MsgError::Missing("CSeq"))?;
        if let Some(m) = self.method() {
            // The CSeq method must match, except an ACK/CANCEL is its own method too.
            if *m != cseq_method {
                return Err(MsgError::Missing("CSeq"));
            }
        }
        Ok(())
    }

    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    pub fn method(&self) -> Option<&Method> {
        match &self.start {
            StartLine::Request { method, .. } => Some(method),
            StartLine::Response { .. } => None,
        }
    }

    pub fn uri(&self) -> Option<&str> {
        match &self.start {
            StartLine::Request { uri, .. } => Some(uri),
            StartLine::Response { .. } => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match &self.start {
            StartLine::Response { code, .. } => Some(*code),
            StartLine::Request { .. } => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match &self.start {
            StartLine::Response { reason, .. } => Some(reason),
            StartLine::Request { .. } => None,
        }
    }

    /// The first header named `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|h| same_name(&h.name, name)).map(|h| h.value.as_str())
    }

    /// Every header line named `name`, in order.
    pub fn header_lines<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers.iter().filter(move |h| same_name(&h.name, name)).map(|h| h.value.as_str())
    }

    /// Every comma-separated value of every `name` header, in order.
    pub fn values(&self, name: &str) -> Vec<String> {
        self.header_lines(name).flat_map(split_values).collect()
    }

    pub fn push_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push(Header::new(name, value));
    }

    /// Insert before every other header (Via on requests we originate).
    pub fn prepend_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(0, Header::new(name, value));
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !same_name(&h.name, name));
    }

    /// Replace every `name` header with one line.
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        match self.headers.iter().position(|h| same_name(&h.name, name)) {
            Some(i) => {
                if let Some(h) = self.headers.get_mut(i) {
                    h.value = value;
                }
                let mut seen = 0usize;
                self.headers.retain(|h| {
                    if same_name(&h.name, name) {
                        seen = seen.saturating_add(1);
                        seen == 1
                    } else {
                        true
                    }
                });
            }
            None => self.push_header(name, value),
        }
    }

    pub fn call_id(&self) -> Option<&str> {
        self.header("Call-ID").map(str::trim).filter(|c| !c.is_empty())
    }

    /// CSeq number and method.
    pub fn cseq(&self) -> Option<(u32, Method)> {
        let v = self.header("CSeq")?;
        let mut it = v.split_ascii_whitespace();
        let n = it.next()?.parse::<u32>().ok()?;
        let m = Method::parse(it.next()?);
        Some((n, m))
    }

    pub fn from_tag(&self) -> Option<String> {
        tag_of(self.header("From")?)
    }

    pub fn to_tag(&self) -> Option<String> {
        tag_of(self.header("To")?)
    }

    pub fn top_via(&self) -> Option<ViaInfo> {
        let line = self.header("Via")?;
        let (v, _) = parse_via(line.as_bytes())?;
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Some(ViaInfo { transport: s(v.transport), host: s(v.host), port: v.port, branch: v.branch.filter(|b| !b.is_empty()).map(s), rport: v.rport.is_some() })
    }

    /// The Contact URI (first value).
    pub fn contact_uri(&self) -> Option<String> {
        let v = self.values("Contact").into_iter().next()?;
        let u = uri_of(&v);
        (!u.is_empty() && u != "*").then_some(u)
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    /// The body if it is SDP (`application/sdp`) and not empty.
    pub fn sdp(&self) -> Option<&[u8]> {
        let ct = self.content_type()?;
        let mime = ct.split(';').next().unwrap_or_default().trim();
        (mime.eq_ignore_ascii_case("application/sdp") && !self.body.is_empty()).then_some(self.body.as_slice())
    }

    /// Option tag `tag` is listed in `name` (Supported, Require…). Option
    /// tags are tokens, so a plain comma split is exact (and allocates nothing).
    pub fn has_option(&self, name: &str, tag: &str) -> bool {
        self.header_lines(name).any(|l| l.split(',').any(|v| v.trim().eq_ignore_ascii_case(tag)))
    }

    /// Serialize; Content-Length is always written and always correct.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512usize.saturating_add(self.body.len()));
        match &self.start {
            StartLine::Request { method, uri } => {
                out.extend_from_slice(method.as_str().as_bytes());
                out.push(b' ');
                out.extend_from_slice(uri.as_bytes());
                out.extend_from_slice(b" SIP/2.0\r\n");
            }
            StartLine::Response { code, reason } => {
                out.extend_from_slice(format!("SIP/2.0 {code} {reason}\r\n").as_bytes());
            }
        }
        for h in &self.headers {
            out.extend_from_slice(h.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(h.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Header values must not smuggle line breaks into a message we build.
pub fn is_safe_value(v: &str) -> bool {
    !v.contains(['\r', '\n', '\0'])
}

/// Header names are RFC 3261 tokens.
pub fn is_token(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKabc;rport\r\n\
Max-Forwards: 70\r\n\
f: \"Alice\" <sip:alice@example.com>;tag=a1\r\n\
t: <sip:bob@example.com>\r\n\
i: call-1@10.0.0.1\r\n\
CSeq: 7 INVITE\r\n\
m: <sip:alice@10.0.0.1:5060>\r\n\
Record-Route: <sip:p1;lr>, <sip:p2;lr>\r\n\
Record-Route: <sip:p3;lr>\r\n\
c: application/sdp\r\n\
l: 4\r\n\
\r\n\
v=0\r\ntrailing";

    #[test]
    fn parses_owned_message() {
        let m = SipMessage::parse(INVITE, &Limits::default()).unwrap();
        assert_eq!(m.method(), Some(&Method::Invite));
        assert_eq!(m.call_id(), Some("call-1@10.0.0.1"));
        assert_eq!(m.cseq(), Some((7, Method::Invite)));
        assert_eq!(m.from_tag().as_deref(), Some("a1"));
        assert_eq!(m.to_tag(), None);
        let via = m.top_via().unwrap();
        assert_eq!((via.host.as_str(), via.port, via.branch.as_deref(), via.rport), ("10.0.0.1", Some(5060), Some("z9hG4bKabc"), true));
        assert_eq!(m.contact_uri().as_deref(), Some("sip:alice@10.0.0.1:5060"));
        assert_eq!(m.values("Record-Route"), vec!["<sip:p1;lr>", "<sip:p2;lr>", "<sip:p3;lr>"]);
        // Content-Length bounds the body (datagram trailing bytes dropped).
        assert_eq!(m.body, b"v=0\r");
        assert_eq!(m.sdp(), Some(&b"v=0\r"[..]));
    }

    #[test]
    fn roundtrip_recomputes_content_length() {
        let mut m = SipMessage::parse(INVITE, &Limits::default()).unwrap();
        m.body = b"v=0\r\n".to_vec();
        let again = SipMessage::parse(&m.to_bytes(), &Limits::default()).unwrap();
        assert_eq!(again.body, b"v=0\r\n");
        assert_eq!(again.header("Content-Length"), None);
    }

    #[test]
    fn limits_are_enforced() {
        let small = Limits { max_message: 10, ..Limits::default() };
        assert_eq!(SipMessage::parse(INVITE, &small), Err(MsgError::TooLarge));
        let few = Limits { max_headers: 3, ..Limits::default() };
        assert_eq!(SipMessage::parse(INVITE, &few), Err(MsgError::TooManyHeaders));
        let body = Limits { max_body: 2, ..Limits::default() };
        assert_eq!(SipMessage::parse(INVITE, &body), Err(MsgError::BodyTooLarge));
    }

    #[test]
    fn rejects_missing_mandatory_headers_and_bad_lengths() {
        let no_cseq = b"BYE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: x\r\n\r\n";
        assert_eq!(SipMessage::parse(no_cseq, &Limits::default()), Err(MsgError::Missing("CSeq")));
        let mismatch =
            b"BYE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\r\n";
        assert_eq!(SipMessage::parse(mismatch, &Limits::default()), Err(MsgError::Missing("CSeq")));
        let short = b"BYE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: x\r\nCSeq: 1 BYE\r\nContent-Length: 10\r\n\r\nab";
        assert_eq!(SipMessage::parse(short, &Limits::default()), Err(MsgError::ContentLength));
    }

    #[test]
    fn folding_is_unfolded_and_stray_controls_rejected() {
        let ok = b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: x\r\nCSeq: 1 OPTIONS\r\nSubject: one\r\n  two\r\n\r\n";
        let m = SipMessage::parse(ok, &Limits::default()).unwrap();
        assert_eq!(m.header("Subject"), Some("one two"));
        for bad in [&b"Subject: a\rb"[..], b"Subject: a\x00b", b"X Y: z"] {
            let mut raw =
                b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: x\r\nCSeq: 1 OPTIONS\r\n"
                    .to_vec();
            raw.extend_from_slice(bad);
            raw.extend_from_slice(b"\r\n\r\n");
            assert_eq!(SipMessage::parse(&raw, &Limits::default()), Err(MsgError::Parse), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn tag_helpers() {
        assert_eq!(tag_of("<sip:a@b>;tag=xyz;foo=1").as_deref(), Some("xyz"));
        assert_eq!(strip_tag("\"A\" <sip:a@b;transport=tcp>;tag=xyz;foo=1"), "\"A\" <sip:a@b;transport=tcp>;foo=1");
        assert_eq!(strip_tag("<sip:a@b>"), "<sip:a@b>");
        assert_eq!(uri_of("\"A\" <sip:a@b;lr>;tag=1"), "sip:a@b;lr");
    }

    #[test]
    fn set_and_remove_headers() {
        let mut m = SipMessage::request(Method::Options, "sip:x");
        m.push_header("X-A", "1");
        m.push_header("x-a", "2");
        m.set_header("X-A", "3");
        assert_eq!(m.header_lines("X-A").collect::<Vec<_>>(), vec!["3"]);
        m.remove_header("x-a");
        assert!(m.header("X-A").is_none());
        assert!(is_token("X-Custom-1") && !is_token("X A") && !is_safe_value("a\r\nb"));
    }
}
