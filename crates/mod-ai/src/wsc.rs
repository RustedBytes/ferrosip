//! A small WebSocket client (RFC 6455) over TCP or TLS, for one provider
//! connection per call. Reads use a short socket timeout so the call loop
//! can interleave them with RTP.

use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sip_transport::ws::{self, Parsed, op};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The largest message we accept from a provider (audio chunks are far smaller).
const MAX_MESSAGE: usize = 16 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query.
    pub path: String,
}

pub fn parse_url(s: &str) -> Result<Url, String> {
    let (tls, rest) = if let Some(r) = s.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(format!("{s:?}: not a ws:// or wss:// URL"));
    };
    let (hostport, path) = match rest.find(['/', '?']).map(|i| rest.split_at(i)) {
        Some((hp, p)) if p.starts_with('/') => (hp, p.to_string()),
        Some((hp, q)) => (hp, format!("/{q}")),
        None => (rest, "/".to_string()),
    };
    let default = if tls { 443 } else { 80 };
    let bad_port = || format!("{s:?}: bad port");
    // An empty port (`host:`) is the default one (RFC 3986 §3.2.3).
    let port_of = |p: &str| if p.is_empty() { Ok(default) } else { p.parse::<u16>().map_err(|_| bad_port()) };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (h, rest) = v6.split_once(']').ok_or_else(|| format!("{s:?}: unclosed '['"))?;
        (h, if rest.is_empty() { default } else { port_of(rest.strip_prefix(':').ok_or_else(bad_port)?)? })
    } else {
        match hostport.rsplit_once(':') {
            // A bare IPv6 address: no port.
            Some((h, _)) if h.contains(':') => (hostport, default),
            Some((h, p)) => (h, port_of(p)?),
            None => (hostport, default),
        }
    };
    if host.is_empty() {
        return Err(format!("{s:?}: no host"));
    }
    Ok(Url { tls, host: host.to_string(), port, path })
}

/// TLS settings for wss://: the Mozilla roots, or the CAs in `ca_file`
/// (a self-hosted gateway, a private CA).
pub fn tls_config(ca_file: Option<&str>) -> Result<Arc<ClientConfig>, String> {
    let roots = match ca_file {
        None => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
        Some(path) => {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            let mut r = RootCertStore::empty();
            for c in CertificateDer::pem_file_iter(path).map_err(|e| format!("{path}: {e}"))? {
                r.add(c.map_err(|e| format!("{path}: {e}"))?).map_err(|e| format!("{path}: {e}"))?;
            }
            if r.is_empty() {
                return Err(format!("{path}: no certificates"));
            }
            r
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Tls(s) => &s.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(b),
            Stream::Tls(s) => s.read(b),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(b),
            Stream::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A complete text or binary message.
    Message(Vec<u8>),
    Closed(String),
}

pub struct Client {
    s: Stream,
    rx: Vec<u8>,
    msg: Vec<u8>,
    in_msg: bool,
    closed: bool,
    rng: SystemRandom,
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

impl Client {
    /// Connect and upgrade. `cancelled` is polled while waiting, so a
    /// CANCEL doesn't have to wait out the timeout.
    pub fn connect(url: &str, headers: &[(&str, String)], tls: &Arc<ClientConfig>, timeout: Duration, cancelled: &dyn Fn() -> bool) -> Result<Self, String> {
        let u = parse_url(url)?;
        let deadline = Instant::now().checked_add(timeout).ok_or("connect timeout out of range")?;
        let addrs: Vec<_> = (u.host.as_str(), u.port).to_socket_addrs().map_err(|e| format!("{}: {e}", u.host))?.collect();
        let mut last = format!("{}: no address", u.host);
        let mut tcp = None;
        for a in addrs {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match TcpStream::connect_timeout(&a, left) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        let tcp = tcp.ok_or(last)?;
        let _ = tcp.set_nodelay(true);
        tcp.set_read_timeout(Some(Duration::from_millis(50))).map_err(|e| e.to_string())?;
        let mut s = if u.tls {
            let name = ServerName::try_from(u.host.clone()).map_err(|e| format!("{}: {e}", u.host))?;
            let conn = ClientConnection::new(tls.clone(), name).map_err(|e| e.to_string())?;
            Stream::Tls(Box::new(StreamOwned::new(conn, tcp)))
        } else {
            Stream::Plain(tcp)
        };
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce).map_err(|_| "no randomness")?;
        let key = ws::base64(&nonce);
        let req = handshake(&u, &key, headers);
        // Writes are small; a TLS handshake happens inside the first write.
        let wait = |s: &mut Stream| -> Result<(), String> {
            if cancelled() {
                return Err("cancelled".into());
            }
            if Instant::now() > deadline {
                return Err("timed out".into());
            }
            let _ = s;
            Ok(())
        };
        let mut rest = req.as_bytes();
        while !rest.is_empty() {
            match s.write(rest) {
                Ok(n) => rest = rest.get(n..).unwrap_or_default(),
                Err(e) if would_block(&e) => wait(&mut s)?,
                Err(e) => return Err(e.to_string()),
            }
        }
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i.saturating_add(4);
            }
            if buf.len() > 16 << 10 {
                return Err("handshake answer too long".into());
            }
            match s.read(&mut chunk) {
                Ok(0) => return Err(format!("closed during the handshake{}", snippet(&buf))),
                Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(e) if would_block(&e) => wait(&mut s)?,
                Err(e) => return Err(e.to_string()),
            }
        };
        let head = String::from_utf8_lossy(buf.get(..end).unwrap_or_default()).to_string();
        let status = head.lines().next().unwrap_or("");
        if !status.starts_with("HTTP/1.1 101") {
            // Read a little of the body: providers explain refusals there.
            let start = Instant::now();
            while buf.len().saturating_sub(end) < 300 && start.elapsed() < Duration::from_millis(300) {
                match s.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                    Err(e) if would_block(&e) => {}
                    Err(_) => break,
                }
            }
            return Err(format!("{status}{}", snippet(buf.get(end..).unwrap_or_default())));
        }
        let want = ws::accept_key(&key);
        let ok = head.lines().any(|l| l.split_once(':').is_some_and(|(n, v)| n.trim().eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == want));
        if !ok {
            return Err("bad Sec-WebSocket-Accept".into());
        }
        s.tcp().set_read_timeout(Some(Duration::from_millis(5))).map_err(|e| e.to_string())?;
        Ok(Client { s, rx: buf.get(end..).unwrap_or_default().to_vec(), msg: Vec::new(), in_msg: false, closed: false, rng })
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let mut mask = [0u8; 4];
        let _ = self.rng.fill(&mut mask);
        let mut out = Vec::with_capacity(payload.len().saturating_add(14));
        ws::encode(true, opcode, payload, Some(mask), &mut out);
        // The socket has a read timeout only; writes block until done.
        self.s.write_all(&out)?;
        self.s.flush()
    }

    pub fn send_text(&mut self, text: &str) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "closed"));
        }
        self.send_frame(op::TEXT, text.as_bytes())
    }

    /// Read what is there (waiting at most a few ms) and return complete
    /// messages. Answers pings.
    pub fn poll(&mut self, out: &mut Vec<Event>) {
        if self.closed {
            return;
        }
        let mut chunk = [0u8; 16384];
        loop {
            match self.s.read(&mut chunk) {
                Ok(0) => {
                    self.closed = true;
                    out.push(Event::Closed("connection closed".into()));
                    break;
                }
                Ok(n) => {
                    self.rx.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    if n < chunk.len() {
                        break;
                    }
                }
                Err(e) if would_block(&e) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.closed = true;
                    out.push(Event::Closed(e.to_string()));
                    break;
                }
            }
        }
        self.parse(out);
    }

    fn parse(&mut self, out: &mut Vec<Event>) {
        let mut used = 0;
        while !self.closed {
            let Some(rest) = self.rx.get_mut(used..) else { break };
            let h = match ws::parse_frame(rest, MAX_MESSAGE, false, false) {
                Parsed::Incomplete => break,
                Parsed::Error(code, why) => {
                    let _ = self.close(code);
                    out.push(Event::Closed(format!("protocol error: {why}")));
                    break;
                }
                Parsed::Frame(h) => h,
            };
            // A parsed frame is complete: header and payload are in `rest`.
            let Some(frame_len) = h.hdr_len.checked_add(h.len) else { break };
            let Some(payload) = rest.get(h.hdr_len..frame_len).map(<[u8]>::to_vec) else { break };
            used = used.saturating_add(frame_len);
            match h.opcode {
                op::PING => {
                    let _ = self.send_frame(op::PONG, &payload);
                }
                op::PONG => {}
                op::CLOSE => {
                    let code = payload.first_chunk::<2>().map_or(1005, |c| u16::from_be_bytes(*c));
                    let why = String::from_utf8_lossy(payload.get(2..).unwrap_or_default()).to_string();
                    let _ = self.close(code);
                    out.push(Event::Closed(if why.is_empty() { format!("closed ({code})") } else { format!("closed ({code}): {why}") }));
                }
                op::TEXT | op::BINARY | op::CONT => {
                    if h.opcode != op::CONT {
                        self.msg.clear();
                        self.in_msg = true;
                    } else if !self.in_msg {
                        continue;
                    }
                    if self.msg.len().saturating_add(payload.len()) > MAX_MESSAGE {
                        let _ = self.close(ws::close::TOO_BIG);
                        out.push(Event::Closed("message too big".into()));
                        break;
                    }
                    self.msg.extend_from_slice(&payload);
                    if h.fin {
                        self.in_msg = false;
                        out.push(Event::Message(std::mem::take(&mut self.msg)));
                    }
                }
                _ => {}
            }
        }
        self.rx.drain(..used);
    }

    pub fn close(&mut self, code: u16) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let r = self.send_frame(op::CLOSE, &code.to_be_bytes());
        if let Stream::Tls(s) = &mut self.s {
            s.conn.send_close_notify();
            let _ = s.conn.write_tls(&mut s.sock);
        }
        r
    }
}

/// The upgrade request (RFC 6455 §4.1). The Host header brackets an IPv6
/// literal and leaves out the scheme's default port.
fn handshake(u: &Url, key: &str, headers: &[(&str, String)]) -> String {
    let host = if u.host.contains(':') { format!("[{}]", u.host) } else { u.host.clone() };
    let host = if (u.tls && u.port == 443) || (!u.tls && u.port == 80) { host } else { format!("{host}:{}", u.port) };
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: ferrosip\r\n",
        u.path
    );
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req
}

fn snippet(b: &[u8]) -> String {
    let t = String::from_utf8_lossy(b.get(..300).unwrap_or(b)).replace(['\r', '\n'], " ");
    let t = t.trim();
    if t.is_empty() { String::new() } else { format!(": {t}") }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.close(1000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("wss://api.openai.com/v1/realtime?model=x").unwrap();
        assert_eq!(u, Url { tls: true, host: "api.openai.com".into(), port: 443, path: "/v1/realtime?model=x".into() });
        let u = parse_url("ws://127.0.0.1:9000").unwrap();
        assert_eq!((u.tls, u.port, u.path.as_str()), (false, 9000, "/"));
        let u = parse_url("ws://[::1]:9000/a").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 9000));
        assert_eq!(parse_url("ws://h?x=1").unwrap().path, "/?x=1");
        assert!(parse_url("http://h/").is_err());
        assert!(parse_url("ws:///x").is_err());
    }

    #[test]
    fn url_cases() {
        let ok = |tls: bool, host: &str, port: u16, path: &str| Ok(Url { tls, host: host.into(), port, path: path.into() });
        let cases: Vec<(&str, Result<Url, ()>)> = vec![
            ("wss://h", ok(true, "h", 443, "/")),
            ("ws://h", ok(false, "h", 80, "/")),
            ("wss://h:8443/p/q?x=1&y=:", ok(true, "h", 8443, "/p/q?x=1&y=:")),
            ("ws://h:/x", ok(false, "h", 80, "/x")),
            ("ws://h:0", ok(false, "h", 0, "/")),
            ("ws://h?a=b", ok(false, "h", 80, "/?a=b")),
            ("ws://h:81?a=b", ok(false, "h", 81, "/?a=b")),
            ("ws://[::1]", ok(false, "::1", 80, "/")),
            ("wss://[2001:db8::1]:9443/r", ok(true, "2001:db8::1", 9443, "/r")),
            ("ws://::1", ok(false, "::1", 80, "/")),
            ("ws://h:99999", Err(())),
            ("ws://h:x/", Err(())),
            ("ws://h:-1/", Err(())),
            ("ws://[::1/", Err(())),
            ("ws://[::1]x", Err(())),
            ("ws://[::1]:x", Err(())),
            ("ws://", Err(())),
            ("ws://:80", Err(())),
            ("ws://[]", Err(())),
            ("http://h", Err(())),
            ("h", Err(())),
        ];
        for (s, want) in cases {
            assert_eq!(parse_url(s).map_err(|_| ()), want, "{s}");
        }
    }

    #[test]
    fn handshake_requests_are_exact() {
        let url = |s: &str| parse_url(s).unwrap();
        let req = handshake(&url("wss://api.example/v1/rt?model=m"), "S0VZ", &[("Authorization", "Bearer k".into()), ("X-A", "1".into())]);
        assert_eq!(
            req,
            "GET /v1/rt?model=m HTTP/1.1\r\nHost: api.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: S0VZ\r\n\
             Sec-WebSocket-Version: 13\r\nUser-Agent: ferrosip\r\nAuthorization: Bearer k\r\nX-A: 1\r\n\r\n"
        );
        // (URL, Host header)
        let cases: &[(&str, &str)] = &[
            ("ws://h", "h"),
            ("ws://h:80", "h"),
            ("ws://h:443", "h:443"),
            ("wss://h:443", "h"),
            ("wss://h:80", "h:80"),
            ("ws://127.0.0.1:9000", "127.0.0.1:9000"),
            ("ws://[::1]:9000", "[::1]:9000"),
            ("wss://[2001:db8::1]", "[2001:db8::1]"),
        ];
        for &(u, host) in cases {
            let req = handshake(&url(u), "k", &[]);
            assert!(req.contains(&format!("\r\nHost: {host}\r\n")), "{u}: {req}");
        }
    }

    #[test]
    fn error_snippets() {
        assert_eq!(snippet(b""), "");
        assert_eq!(snippet(b" \r\n "), "");
        assert_eq!(snippet(b"{\"error\":\r\n\"bad key\"}"), ": {\"error\":  \"bad key\"}");
        assert_eq!(snippet(&[b'x'; 400]).len(), 2 + 300);
    }
}
