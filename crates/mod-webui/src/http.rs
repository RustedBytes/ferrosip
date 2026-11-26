//! A small HTTP/1.1 server for the web UI: GET and HEAD only, a bounded
//! number of connections (one thread each), request heads capped at 8 KiB,
//! keep-alive with an idle timeout, Basic auth on every request, and
//! security headers on every response.

use crate::api::{Api, Query};
use crate::assets::{self, Asset};
use crate::auth::{Credentials, Throttle};
use sip_core::serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const MAX_HEAD: usize = 8 * 1024;
const IDLE: Duration = Duration::from_secs(15);

pub struct Server {
    pub api: Api,
    pub creds: Credentials,
    pub realm: String,
    pub max_connections: usize,
    pub throttle: Throttle,
    active: AtomicUsize,
}

/// One parsed request.
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Query,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A response before it is written.
pub struct Response {
    pub code: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub extra: Vec<(&'static str, String)>,
}

impl Response {
    fn json(code: u16, v: &Value) -> Self {
        Response { code, ctype: "application/json", body: v.to_string().into_bytes(), extra: vec![("Cache-Control", "no-store".into())] }
    }
    fn error(code: u16, msg: &str) -> Self {
        Self::json(code, &json!({"error": msg}))
    }
}

impl Server {
    pub fn new(api: Api, creds: Credentials, realm: String, max_connections: usize) -> Self {
        Server { api, creds, realm, max_connections, throttle: Throttle::default(), active: AtomicUsize::new(0) }
    }

    /// Accept connections until the process exits.
    pub fn run(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if self.active.fetch_add(1, Ordering::AcqRel) >= self.max_connections {
                self.active.fetch_sub(1, Ordering::AcqRel);
                let _ = write_response(&mut stream, &Response::error(503, "too many connections"), false, false);
                continue;
            }
            let me = self.clone();
            let spawned = std::thread::Builder::new().name("webui-conn".into()).spawn(move || {
                sip_core::panic::expendable();
                let peer = stream.peer_addr().ok();
                let _ = me.connection(&mut stream, peer);
                me.active.fetch_sub(1, Ordering::AcqRel);
            });
            if spawned.is_err() {
                self.active.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    fn connection(&self, s: &mut TcpStream, peer: Option<SocketAddr>) -> io::Result<()> {
        s.set_read_timeout(Some(IDLE))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let _ = s.set_nodelay(true);
        let mut buf = Vec::with_capacity(1024);
        loop {
            let Some(head_len) = read_head(s, &mut buf)? else {
                if buf.len() >= MAX_HEAD {
                    write_response(s, &Response::error(431, "request head too large"), false, false)?;
                }
                return Ok(());
            };
            let head = String::from_utf8_lossy(buf.get(..head_len).unwrap_or_default()).into_owned();
            buf.drain(..head_len);
            let Some(req) = parse_head(&head) else {
                return write_response(s, &Response::error(400, "bad request"), false, false);
            };
            let keep = !req.header("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
            // A request body is never expected: refuse instead of skipping it.
            if req.header("content-length").is_some_and(|l| l.trim() != "0") || req.header("transfer-encoding").is_some() {
                return write_response(s, &Response::error(400, "request bodies are not accepted"), false, false);
            }
            let head_only = req.method == "HEAD";
            let resp = self.respond(&req, peer);
            write_response(s, &resp, keep, head_only)?;
            if !keep {
                return Ok(());
            }
        }
    }

    /// Authentication, then routing.
    pub fn respond(&self, req: &Request, peer: Option<SocketAddr>) -> Response {
        if req.method != "GET" && req.method != "HEAD" {
            let mut r = Response::error(405, "read-only: only GET and HEAD");
            r.extra.push(("Allow", "GET, HEAD".into()));
            return r;
        }
        let ip = peer.map(|p| p.ip());
        if ip.is_some_and(|ip| self.throttle.blocked(ip)) {
            let mut r = Response::error(429, "too many failed logins, try again later");
            r.extra.push(("Retry-After", "60".into()));
            return r;
        }
        let auth = req.header("authorization");
        if !self.creds.check(auth) {
            if auth.is_some()
                && let Some(ip) = ip
            {
                self.throttle.failed(ip);
            }
            let mut r = Response::error(401, "authentication required");
            r.extra.push(("WWW-Authenticate", format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm)));
            return r;
        }
        if let Some(ip) = ip {
            self.throttle.succeeded(ip);
        }
        if let Some(api_path) = req.path.strip_prefix("/api/v1/") {
            let (code, v) = self.api.handle(api_path, &req.query);
            return Response::json(code, &v);
        }
        match assets::find(&req.path) {
            Some(a) => asset_response(a, req),
            None => Response::error(404, "not found"),
        }
    }
}

fn asset_response(a: &Asset, req: &Request) -> Response {
    let mut extra = vec![("ETag", a.etag.clone()), ("Cache-Control", "no-cache".into())];
    if req.header("if-none-match").is_some_and(|inm| etag_matches(inm, &a.etag)) {
        return Response { code: 304, ctype: a.ctype, body: Vec::new(), extra };
    }
    let gzip_ok = req.header("accept-encoding").is_some_and(accepts_gzip);
    let body = if a.gzipped && !gzip_ok {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(a.bytes).read_to_end(&mut out).is_err() {
            return Response::error(500, "asset");
        }
        out
    } else {
        if a.gzipped {
            extra.push(("Content-Encoding", "gzip".into()));
        }
        a.bytes.to_vec()
    };
    extra.push(("Vary", "Accept-Encoding".into()));
    Response { code: 200, ctype: a.ctype, body, extra }
}

/// `If-None-Match` names this entity tag: `*`, or one of a comma list,
/// compared weakly (a `W/` prefix is ignored, RFC 9110 §13.1.2).
fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    if_none_match.split(',').map(str::trim).any(|t| t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag)
}

/// `Accept-Encoding` allows gzip: a `gzip` (or `*`) coding whose q-value
/// isn't 0 (RFC 9110 §12.5.3; names are case-insensitive).
fn accepts_gzip(accept: &str) -> bool {
    let q_of = |coding: &str| {
        let mut parts = coding.split(';');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parts
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("q"))
            .map_or(1.0, |(_, v)| v.trim().parse::<f32>().unwrap_or(0.0));
        (name, q)
    };
    let codings: Vec<(String, f32)> = accept.split(',').map(q_of).collect();
    match codings.iter().find(|(n, _)| n == "gzip").or_else(|| codings.iter().find(|(n, _)| n == "*")) {
        Some(&(_, q)) => q > 0.0,
        None => false,
    }
}

/// Read until the end of a request head. `Some(len)` (bytes including the
/// blank line), or `None` on EOF, idle timeout or a head over the limit.
fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Option<usize>> {
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            // The head with its blank line (p + 4 <= buf.len()).
            return Ok(Some(p.saturating_add(4)));
        }
        if buf.len() >= MAX_HEAD {
            return Ok(None);
        }
        let mut chunk = [0u8; 2048];
        match s.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
}

pub fn parse_head(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    let (method, target, version) = (rl.next()?, rl.next()?, rl.next()?);
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let (path, qs) = target.split_once('?').unwrap_or((target, ""));
    let path = percent_decode(path)?;
    if path.contains("..") {
        return None;
    }
    let query = qs
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((percent_decode(&k.replace('+', " "))?, percent_decode(&v.replace('+', " "))?))
        })
        .collect();
    let headers = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(n, v)| (n.trim().to_string(), v.trim().to_string())).collect();
    Some(Request { method: method.to_string(), path, query, headers })
}

fn percent_decode(s: &str) -> Option<String> {
    let mut rest = s.as_bytes();
    let mut out = Vec::with_capacity(rest.len());
    while let Some((&c, tail)) = rest.split_first() {
        rest = tail;
        if c == b'%' {
            let (&[hi, lo], tail) = rest.split_first_chunk::<2>()?;
            let nib = |c: u8| (c as char).to_digit(16);
            out.push(u8::try_from(nib(hi)? << 4 | nib(lo)?).ok()?);
            rest = tail;
        } else {
            out.push(c);
        }
    }
    String::from_utf8(out).ok()
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn write_response(s: &mut TcpStream, r: &Response, keep: bool, head_only: bool) -> io::Result<()> {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nServer: ferrosip-webui\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\
         Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\
         X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n",
        r.code,
        reason(r.code),
        r.ctype,
        r.body.len(),
        if keep { "keep-alive" } else { "close" }
    );
    for (n, v) in &r.extra {
        h.push_str(n);
        h.push_str(": ");
        h.push_str(v);
        h.push_str("\r\n");
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    if !head_only && r.code != 304 {
        s.write_all(&r.body)?;
    }
    s.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads() {
        let r = parse_head("GET /api/v1/dialogs?q=alice%40x&sort=-duration&limit=5 HTTP/1.1\r\nHost: x\r\nAuthorization: Basic abc\r\n\r\n").unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("GET", "/api/v1/dialogs"));
        assert_eq!(r.query["q"], "alice@x");
        assert_eq!(r.query["sort"], "-duration");
        assert_eq!(r.header("authorization"), Some("Basic abc"));
        assert!(parse_head("GET /../etc/passwd HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GET /%2e%2e/x HTTP/1.1\r\n\r\n").is_none());
        assert_eq!(percent_decode("a%41%62"), Some("aAb".into()));
        assert!(percent_decode("a%4").is_none() && percent_decode("%").is_none() && percent_decode("%zz").is_none());
        assert!(parse_head("GET x HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_head("GARBAGE\r\n\r\n").is_none());
    }

    #[test]
    fn request_targets_are_decoded_or_refused() {
        // (target, decoded path or None when refused)
        let cases: &[(&str, Option<&str>)] = &[
            ("/", Some("/")),
            ("/app.js", Some("/app.js")),
            ("/a%20b", Some("/a b")),
            ("/a+b", Some("/a+b")),
            ("/caf%C3%A9", Some("/café")),
            ("/a%2Fb", Some("/a/b")),
            ("/x?", Some("/x")),
            ("/x?y?z", Some("/x")),
            ("/..", None),
            ("/../etc/passwd", None),
            ("/a/../b", None),
            ("/%2e%2E/x", None),
            ("/.%2e/x", None),
            ("/a%2", None),
            ("/a%g0", None),
            ("/%ff", None),
            ("x", None),
            ("*", None),
            ("http://h/x", None),
        ];
        for &(target, want) in cases {
            let got = parse_head(&format!("GET {target} HTTP/1.1\r\n\r\n")).map(|r| r.path);
            assert_eq!(got.as_deref(), want, "GET {target}");
        }
    }

    #[test]
    fn query_strings_are_decoded() {
        let q = parse_head("GET /api/v1/x?a=1&b=two+words&c=%2B&d&=e&f=a=b&g=%zz&&h=%C3%A9 HTTP/1.1\r\n\r\n").unwrap().query;
        let mut got: Vec<(&str, &str)> = q.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        got.sort_unstable();
        assert_eq!(got, [("", "e"), ("a", "1"), ("b", "two words"), ("c", "+"), ("d", ""), ("f", "a=b"), ("h", "é")]);
        let q = parse_head("GET /x?k=1&k=2 HTTP/1.1\r\n\r\n").unwrap().query;
        assert_eq!(q.len(), 1, "a repeated key keeps one value");
    }

    #[test]
    fn request_lines_and_headers() {
        for bad in ["", "GET\r\n\r\n", "GET /\r\n\r\n", "GET / HTTP/2.0\r\n\r\n", "GET / FTP/1.0\r\n\r\n"] {
            assert!(parse_head(bad).is_none(), "{bad:?}");
        }
        let r = parse_head("HEAD / HTTP/1.0\r\nX-A:  1 \r\nbroken line\r\nX-B:\r\nX-A: 2\r\n\r\n").unwrap();
        assert_eq!(r.method, "HEAD");
        assert_eq!(r.headers.len(), 3);
        assert_eq!(r.header("x-a"), Some("1"), "the first of repeated headers");
        assert_eq!(r.header("X-B"), Some(""));
    }

    #[test]
    fn percent_decoder_cases() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", Some("")),
            ("abc", Some("abc")),
            ("%41", Some("A")),
            ("%4a%4A", Some("JJ")),
            ("%25", Some("%")),
            ("%2541", Some("%41")),
            ("%", None),
            ("%4", None),
            ("a%", None),
            ("%-1", None),
            ("%+1", None),
            ("%c3", None),
            ("%00", Some("\0")),
        ];
        for &(input, want) in cases {
            assert_eq!(percent_decode(input).as_deref(), want, "percent_decode({input:?})");
        }
    }

    #[test]
    fn accept_encoding_negotiation() {
        let cases: &[(&str, bool)] = &[
            ("gzip", true),
            ("GZIP", true),
            ("br, gzip;q=0.8", true),
            ("*", true),
            ("gzip;q=0", false),
            ("gzip; q=0.000", false),
            ("*;q=0", false),
            ("gzip;q=0, *", false),
            ("identity", false),
            ("gzipx", false),
            ("", false),
        ];
        for &(accept, want) in cases {
            assert_eq!(accepts_gzip(accept), want, "Accept-Encoding: {accept}");
        }
    }

    #[test]
    fn if_none_match_forms() {
        let tag = "\"abc\"";
        let cases: &[(&str, bool)] =
            &[("\"abc\"", true), ("W/\"abc\"", true), ("\"x\", \"abc\"", true), ("*", true), ("\"abd\"", false), ("abc", false), ("", false)];
        for &(inm, want) in cases {
            assert_eq!(etag_matches(inm, tag), want, "If-None-Match: {inm}");
        }
    }

    fn request(path: &str, hdrs: &str) -> Request {
        parse_head(&format!("GET {path} HTTP/1.1\r\n{hdrs}\r\n")).unwrap()
    }

    #[test]
    fn assets_are_served_with_type_etag_and_encoding() {
        for (path, ctype, gz) in [
            ("/", "text/html; charset=utf-8", false),
            ("/index.html", "text/html; charset=utf-8", false),
            ("/app.js", "text/javascript; charset=utf-8", true),
            ("/app.css", "text/css; charset=utf-8", true),
            ("/favicon.svg", "image/svg+xml", false),
        ] {
            let a = assets::find(path).unwrap_or_else(|| panic!("{path} exists"));
            assert_eq!((a.ctype, a.gzipped), (ctype, gz), "{path}");
            let z = asset_response(a, &request(path, "Accept-Encoding: gzip\r\n"));
            let plain = asset_response(a, &request(path, ""));
            assert_eq!((z.code, plain.code), (200, 200));
            assert_eq!(z.extra.iter().any(|(n, v)| *n == "Content-Encoding" && v == "gzip"), gz, "{path}");
            assert!(!plain.extra.iter().any(|(n, _)| *n == "Content-Encoding"), "{path} without gzip");
            assert_eq!(z.body, a.bytes, "{path}: the stored bytes as they are");
            if gz {
                let mut unzipped = Vec::new();
                flate2::read::GzDecoder::new(a.bytes).read_to_end(&mut unzipped).unwrap();
                assert_eq!(plain.body, unzipped, "{path} is decompressed for a client without gzip");
            } else {
                assert_eq!(plain.body, a.bytes);
            }
            let etag = &a.etag;
            assert!(etag.len() == 26 && etag.starts_with('"') && etag.ends_with('"'), "{etag}");
            let nm = asset_response(a, &request(path, &format!("If-None-Match: {etag}\r\n")));
            assert_eq!(nm.code, 304, "{path}");
            assert_eq!(asset_response(a, &request(path, "If-None-Match: \"other\"\r\n")).code, 200);
        }
        for missing in ["/index.htm", "/app.js.gz", "/APP.JS", "", "/assets/app.js", "/favicon.svg/"] {
            assert!(assets::find(missing).is_none(), "{missing:?}");
        }
    }

    fn test_server() -> Server {
        let rpc = std::sync::Arc::new(sip_core::rpc::RpcTable::default());
        rpc.add("core.uptime", "", |_| Ok(json!({"uptime": 5})));
        let hash = format!("sha256:s:{}", crate::auth::hash_password(b"s", b"pw").iter().map(|b| format!("{b:02x}")).collect::<String>());
        Server::new(Api::new(rpc, 2000), Credentials::new("u", &hash).unwrap(), "realm \"x\"".into(), 4)
    }

    #[test]
    fn respond_authenticates_before_routing() {
        let s = test_server();
        let auth = "Authorization: Basic dTpwdw==\r\n"; // u:pw
        let peer: Option<SocketAddr> = "192.0.2.1:5000".parse().ok();
        let r = s.respond(&request("/api/v1/uptime", ""), peer);
        assert_eq!(r.code, 401);
        assert!(r.extra.iter().any(|(n, v)| *n == "WWW-Authenticate" && v.starts_with("Basic realm=")));
        assert_eq!(s.respond(&request("/nope", ""), peer).code, 401, "unknown paths are not revealed");
        let ok = s.respond(&request("/api/v1/uptime", auth), peer);
        assert_eq!((ok.code, ok.ctype), (200, "application/json"));
        assert_eq!(String::from_utf8_lossy(&ok.body), r#"{"uptime":5}"#);
        assert_eq!(s.respond(&request("/api/v1/nope", auth), peer).code, 404);
        assert_eq!(s.respond(&request("/nope", auth), peer).code, 404);
        assert_eq!(s.respond(&request("/app.js", auth), peer).code, 200);
        let post = parse_head("POST /api/v1/uptime HTTP/1.1\r\n\r\n").unwrap();
        let r = s.respond(&post, peer);
        assert_eq!(r.code, 405);
        assert!(r.extra.iter().any(|(n, v)| *n == "Allow" && v == "GET, HEAD"));
        assert_eq!(String::from_utf8_lossy(&Response::error(404, "a\"b").body), r#"{"error":"a\"b"}"#);
    }

    #[test]
    fn respond_refuses_an_address_after_repeated_failures() {
        let s = test_server();
        let peer: Option<SocketAddr> = "192.0.2.9:1".parse().ok();
        let wrong = "Authorization: Basic dTp4\r\n"; // u:x
        for _ in 0..5 {
            assert_eq!(s.respond(&request("/", wrong), peer).code, 401);
        }
        let r = s.respond(&request("/", "Authorization: Basic dTpwdw==\r\n"), peer);
        assert_eq!(r.code, 429, "even the right password while blocked");
        assert!(r.extra.iter().any(|(n, v)| *n == "Retry-After" && v == "60"));
        let other: Option<SocketAddr> = "192.0.2.10:1".parse().ok();
        assert_eq!(s.respond(&request("/", "Authorization: Basic dTpwdw==\r\n"), other).code, 200);
        // Requests without credentials don't count as failures.
        for _ in 0..10 {
            assert_eq!(s.respond(&request("/", ""), other).code, 401);
        }
        assert_eq!(s.respond(&request("/", "Authorization: Basic dTpwdw==\r\n"), other).code, 200);
    }

    #[test]
    fn every_status_used_has_a_reason_phrase() {
        for code in [200, 304, 400, 401, 404, 405, 429, 431, 500, 502, 503] {
            assert!(!reason(code).is_empty(), "{code}");
        }
    }
}
