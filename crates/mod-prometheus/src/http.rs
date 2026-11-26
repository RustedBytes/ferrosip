//! The scrape endpoint: HTTP/1.1, GET and HEAD only, a bounded number of
//! connections (one thread each; the next gets 503), request heads capped
//! at 8 KiB, keep-alive with an idle timeout, optional Bearer token.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const MAX_HEAD: usize = 8 * 1024;
const IDLE: Duration = Duration::from_secs(30);

pub struct Server {
    pub path: String,
    pub token: Option<String>,
    pub max_connections: usize,
    /// The metrics page, rendered per scrape.
    pub render: Box<dyn Fn() -> String + Send + Sync>,
    active: AtomicUsize,
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub code: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub extra: Vec<(&'static str, String)>,
}

fn text(code: u16, body: &str) -> Response {
    Response { code, ctype: "text/plain; charset=utf-8", body: body.as_bytes().to_vec(), extra: Vec::new() }
}

/// Constant-time comparison (the length may leak; the content doesn't).
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Server {
    pub fn new(path: String, token: Option<String>, max_connections: usize, render: Box<dyn Fn() -> String + Send + Sync>) -> Self {
        Server { path, token, max_connections, render, active: AtomicUsize::new(0) }
    }

    pub fn run(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if self.active.fetch_add(1, Ordering::AcqRel) >= self.max_connections {
                self.active.fetch_sub(1, Ordering::AcqRel);
                let _ = write_response(&mut stream, &text(503, "too many connections\n"), false, false);
                continue;
            }
            let me = self.clone();
            let spawned = std::thread::Builder::new().name("prom-conn".into()).spawn(move || {
                sip_core::panic::expendable();
                let _ = me.connection(&mut stream);
                me.active.fetch_sub(1, Ordering::AcqRel);
            });
            if spawned.is_err() {
                self.active.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    fn connection(&self, s: &mut TcpStream) -> io::Result<()> {
        s.set_read_timeout(Some(IDLE))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let _ = s.set_nodelay(true);
        let mut buf = Vec::with_capacity(1024);
        loop {
            let Some(head_len) = read_head(s, &mut buf)? else {
                if buf.len() >= MAX_HEAD {
                    write_response(s, &text(431, "request head too large\n"), false, false)?;
                }
                return Ok(());
            };
            let head = String::from_utf8_lossy(buf.get(..head_len).unwrap_or_default()).into_owned();
            buf.drain(..head_len);
            let Some(req) = parse_head(&head) else {
                return write_response(s, &text(400, "bad request\n"), false, false);
            };
            if req.header("content-length").is_some_and(|l| l.trim() != "0") || req.header("transfer-encoding").is_some() {
                return write_response(s, &text(400, "request bodies are not accepted\n"), false, false);
            }
            let keep = !req.header("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
            let resp = self.respond(&req);
            write_response(s, &resp, keep, req.method == "HEAD")?;
            if !keep {
                return Ok(());
            }
        }
    }

    pub fn respond(&self, req: &Request) -> Response {
        if req.method != "GET" && req.method != "HEAD" {
            let mut r = text(405, "only GET and HEAD\n");
            r.extra.push(("Allow", "GET, HEAD".into()));
            return r;
        }
        if req.path == "/-/healthy" {
            return text(200, "ok\n");
        }
        if let Some(t) = &self.token {
            let given = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).map(str::trim).unwrap_or("");
            if !same(given.as_bytes(), t.as_bytes()) {
                let mut r = text(401, "a bearer token is required\n");
                r.extra.push(("WWW-Authenticate", "Bearer realm=\"ferrosip metrics\"".into()));
                return r;
            }
        }
        if req.path == "/" {
            let page = format!("<!doctype html><title>ferrosip metrics</title><p><a href=\"{0}\">{0}</a></p>\n", self.path);
            return Response { code: 200, ctype: "text/html; charset=utf-8", body: page.into_bytes(), extra: Vec::new() };
        }
        if req.path != self.path {
            return text(404, "not found\n");
        }
        let page = (self.render)();
        let mut r = Response {
            code: 200,
            ctype: "text/plain; version=0.0.4; charset=utf-8",
            body: page.into_bytes(),
            extra: vec![("Cache-Control", "no-store".into())],
        };
        if req.header("accept-encoding").is_some_and(accepts_gzip) {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            if enc.write_all(&r.body).is_ok()
                && let Ok(z) = enc.finish()
            {
                r.body = z;
                r.extra.push(("Content-Encoding", "gzip".into()));
            }
        }
        r.extra.push(("Vary", "Accept-Encoding".into()));
        r
    }
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
    // Prometheus may add query parameters (e.g. `?name[]=…`); they're ignored.
    let path = target.split('?').next().unwrap_or(target).to_string();
    let headers = lines.filter(|l| !l.is_empty()).filter_map(|l| l.split_once(':')).map(|(n, v)| (n.trim().to_string(), v.trim().to_string())).collect();
    Some(Request { method: method.to_string(), path, headers })
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn write_response(s: &mut TcpStream, r: &Response, keep: bool, head_only: bool) -> io::Result<()> {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nServer: ferrosip\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\nX-Content-Type-Options: nosniff\r\n",
        r.code,
        reason(r.code),
        r.ctype,
        r.body.len(),
        if keep { "keep-alive" } else { "close" }
    );
    for (n, v) in &r.extra {
        h.push_str(&format!("{n}: {v}\r\n"));
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    if !head_only {
        s.write_all(&r.body)?;
    }
    s.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(token: Option<&str>) -> Server {
        Server::new("/metrics".into(), token.map(String::from), 4, Box::new(|| "x 1\n".into()))
    }

    fn get(path: &str, hdrs: &str) -> Request {
        parse_head(&format!("GET {path} HTTP/1.1\r\nHost: h\r\n{hdrs}\r\n")).unwrap()
    }

    #[test]
    fn routes_and_auth() {
        let s = server(Some("s3cret"));
        assert_eq!(s.respond(&get("/metrics", "")).code, 401);
        assert_eq!(s.respond(&get("/metrics", "Authorization: Bearer nope\r\n")).code, 401);
        let ok = s.respond(&get("/metrics?x=1", "Authorization: Bearer s3cret\r\n"));
        assert_eq!((ok.code, ok.body.as_slice()), (200, &b"x 1\n"[..]));
        assert!(ok.ctype.contains("version=0.0.4"));
        assert_eq!(s.respond(&get("/-/healthy", "")).code, 200, "health needs no token");
        assert_eq!(s.respond(&get("/other", "Authorization: Bearer s3cret\r\n")).code, 404);
        let post = parse_head("POST /metrics HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(server(None).respond(&post).code, 405);
        let z = server(None).respond(&get("/metrics", "Accept-Encoding: gzip, br\r\n"));
        assert!(z.extra.iter().any(|(n, v)| *n == "Content-Encoding" && v == "gzip"));
        let mut out = String::new();
        flate2::read::GzDecoder::new(&z.body[..]).read_to_string(&mut out).unwrap();
        assert_eq!(out, "x 1\n");
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
        assert!(parse_head("GARBAGE\r\n\r\n").is_none());
    }

    #[test]
    fn gzip_is_negotiated_from_accept_encoding() {
        let cases: &[(&str, bool)] = &[
            ("gzip", true),
            ("GZip", true),
            ("deflate, gzip", true),
            ("gzip;q=0.5, identity", true),
            ("gzip; q=1.0", true),
            ("br;q=1, gzip;q=0.001", true),
            ("*", true),
            ("identity, *;q=0.1", true),
            ("gzip;q=0", false),
            ("gzip;q=0.0, deflate", false),
            ("*;q=0", false),
            ("gzip;q=0, *", false),
            ("identity", false),
            ("x-gzipped", false),
            ("gzipx", false),
            ("", false),
        ];
        for &(accept, want) in cases {
            assert_eq!(accepts_gzip(accept), want, "Accept-Encoding: {accept}");
            let r = server(None).respond(&get("/metrics", &format!("Accept-Encoding: {accept}\r\n")));
            assert_eq!(r.extra.iter().any(|(n, v)| *n == "Content-Encoding" && v == "gzip"), want, "response to {accept:?}");
            assert!(r.extra.iter().any(|(n, v)| *n == "Vary" && v == "Accept-Encoding"));
        }
    }

    #[test]
    fn request_heads_are_parsed_or_refused() {
        let r = parse_head("HEAD /metrics?name[]=up&x=%20 HTTP/1.0\r\nAccept:  text/plain \r\nX-Empty:\r\nno-colon\r\n\r\n").unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("HEAD", "/metrics"));
        assert_eq!(r.headers, [("Accept".to_string(), "text/plain".to_string()), ("X-Empty".to_string(), String::new())]);
        assert_eq!(r.header("accept"), Some("text/plain"));
        assert_eq!(r.header("missing"), None);
        for bad in
            ["", "GET\r\n\r\n", "GET /metrics\r\n\r\n", "GET metrics HTTP/1.1\r\n\r\n", "GET /metrics HTTP/2\r\n\r\n", "GET http://h/metrics HTTP/1.1\r\n\r\n"]
        {
            assert!(parse_head(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn responses_carry_the_documented_headers() {
        let open = server(None);
        let index = open.respond(&get("/", ""));
        assert_eq!((index.code, index.ctype), (200, "text/html; charset=utf-8"));
        assert!(String::from_utf8_lossy(&index.body).contains("<a href=\"/metrics\">/metrics</a>"));
        let page = open.respond(&get("/metrics", ""));
        assert_eq!(page.ctype, "text/plain; version=0.0.4; charset=utf-8");
        assert!(page.extra.iter().any(|(n, v)| *n == "Cache-Control" && v == "no-store"));
        assert!(!page.extra.iter().any(|(n, _)| *n == "Content-Encoding"));
        let head = parse_head("HEAD /metrics HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(open.respond(&head).code, 200);
        for m in ["POST", "PUT", "DELETE", "OPTIONS", "get"] {
            let r = open.respond(&parse_head(&format!("{m} /metrics HTTP/1.1\r\n\r\n")).unwrap());
            assert_eq!(r.code, 405, "{m}");
            assert!(r.extra.iter().any(|(n, v)| *n == "Allow" && v == "GET, HEAD"));
        }
        let locked = server(Some("tok"));
        let denied = locked.respond(&get("/", ""));
        assert_eq!(denied.code, 401, "the index page needs the token too");
        assert!(denied.extra.iter().any(|(n, v)| *n == "WWW-Authenticate" && v.starts_with("Bearer ")));
        for (auth, code) in
            [("Bearer tok", 200), ("Bearer  tok ", 200), ("Bearer tok2", 401), ("Bearer to", 401), ("Basic tok", 401), ("tok", 401), ("Bearer ", 401)]
        {
            assert_eq!(locked.respond(&get("/metrics", &format!("Authorization: {auth}\r\n"))).code, code, "Authorization: {auth}");
        }
        assert_eq!(locked.respond(&get("/nope", "")).code, 401, "no path probing without the token");
    }

    #[test]
    fn constant_time_compare_matches_equality() {
        let cases: &[(&[u8], &[u8])] = &[(b"", b""), (b"a", b""), (b"", b"a"), (b"abc", b"abc"), (b"abc", b"abC"), (b"\x00", b"\x80"), (b"abcd", b"abc")];
        for &(a, b) in cases {
            assert_eq!(same(a, b), a == b, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn every_status_used_has_a_reason_phrase() {
        for code in [200, 400, 401, 404, 405, 431, 503] {
            assert!(!reason(code).is_empty(), "{code}");
        }
    }
}
