//! `xhttp` — an HTTP/1.1 server for the routing script and management:
//! requests run `event_route[xhttp:request]` (the HTTP headers and body
//! are visible as `$hdr(…)` / `$rb`, the URL as `$hu`, the method as
//! `$hm`), which answers with `xhttp_reply(code, reason, ctype, body)`;
//! POST `/RPC` is JSON-RPC 2.0 (like jsonrpcs over xhttp). Kamailio serves
//! HTTP on its SIP TCP sockets; ferrosip uses its own listener:
//! `modparam("xhttp", "listen", "127.0.0.1:8080")`. `url_match` /
//! `url_skip` (regex) choose which URLs reach the script.
//!
//! `xhttp_prom` — Prometheus metrics at `xhttp_prom_path` ("/metrics"):
//! every statistic as `<xhttp_prom_beginning><group>_<name>` (default
//! prefix `kamailio_`, so existing dashboards work); `xhttp_prom_stats`
//! ("all", or a comma list of groups).

use regex::Regex;
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, RouteHub, RpcTable};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// The HTTP request an `xhttp:request` event route sees.
#[derive(Clone, Default)]
struct HttpReq {
    method: String,
    url: String,
}

/// Set by `xhttp_reply()`.
#[derive(Clone, Default)]
struct HttpResp {
    code: u16,
    reason: String,
    ctype: String,
    body: Vec<u8>,
}

/// Prometheus exposition of the statistics.
fn prometheus(prefix: &str, groups: &str) -> String {
    let mut out = String::new();
    let all = groups.trim() == "all" || groups.trim().is_empty();
    let want: Vec<&str> = groups.split(',').map(str::trim).collect();
    for (g, n, v, counter) in sip_core::stats::get_kinds("all") {
        if !all && !want.contains(&g.as_str()) {
            continue;
        }
        let name: String = format!("{prefix}{g}_{n}").chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
        // Counters are typed as such so rate()/increase() work on them.
        // Names stay as before (no `_total` suffix) for compatibility.
        let ty = if counter { "counter" } else { "gauge" };
        out.push_str(&format!("# TYPE {name} {ty}\n{name} {v}\n"));
    }
    out
}

#[derive(Default)]
pub struct Xhttp {
    listen: Mutex<Option<String>>,
    url_match: Mutex<Option<Regex>>,
    url_skip: Mutex<Option<Regex>>,
    hub: OnceLock<Arc<RouteHub>>,
    rpc: OnceLock<Arc<RpcTable>>,
    prom: OnceLock<Arc<XhttpProm>>,
}

impl Xhttp {
    fn respond(s: &mut TcpStream, code: u16, reason: &str, ctype: &str, body: &[u8], keep: bool) -> std::io::Result<()> {
        let head = format!(
            "HTTP/1.1 {code} {reason}\r\nServer: ferrosip\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
            body.len(),
            if keep { "keep-alive" } else { "close" }
        );
        s.write_all(head.as_bytes())?;
        s.write_all(body)
    }

    fn serve(self: &Arc<Self>, stream: TcpStream, net: Arc<dyn Outbound>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let Ok(mut out) = stream.try_clone() else { return };
        let mut rd = BufReader::new(stream);
        loop {
            let mut line = String::new();
            if rd.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let mut it = line.split_whitespace();
            let (Some(method), Some(url), Some(ver)) = (it.next(), it.next(), it.next()) else { return };
            let (method, url) = (method.to_string(), url.to_string());
            let mut headers = Vec::new();
            let mut clen = 0usize;
            let mut keep = ver == "HTTP/1.1";
            loop {
                let mut h = String::new();
                if rd.read_line(&mut h).unwrap_or(0) == 0 {
                    return;
                }
                let h = h.trim_end().to_string();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    let (k, v) = (k.trim(), v.trim());
                    if k.eq_ignore_ascii_case("content-length") {
                        clen = v.parse().unwrap_or(0);
                    }
                    if k.eq_ignore_ascii_case("connection") {
                        keep = !v.eq_ignore_ascii_case("close");
                    }
                    headers.push((k.to_string(), v.to_string()));
                }
            }
            let mut body = vec![0u8; clen.min(1 << 20)];
            if rd.read_exact(&mut body).is_err() {
                return;
            }
            let (code, reason, ctype, resp) = self.handle(&method, &url, &headers, &body, &*net);
            if Self::respond(&mut out, code, &reason, &ctype, &resp, keep).is_err() || !keep {
                return;
            }
        }
    }

    fn handle(&self, method: &str, url: &str, headers: &[(String, String)], body: &[u8], net: &dyn Outbound) -> (u16, String, String, Vec<u8>) {
        let path = url.split('?').next().unwrap_or(url);
        if let Some(p) = self.prom.get().filter(|p| path == lock(&p.path).as_str()) {
            let txt = prometheus(&lock(&p.prefix), &lock(&p.groups));
            return (200, "OK".into(), "text/plain; version=0.0.4".into(), txt.into_bytes());
        }
        if path == "/RPC"
            && method == "POST"
            && let Some(rpc) = self.rpc.get()
        {
            let v = rpc.handle_line(&String::from_utf8_lossy(body));
            return (200, "OK".into(), "application/json".into(), v.to_string().into_bytes());
        }
        let routed = lock(&self.url_match).as_ref().is_none_or(|r| r.is_match(url)) && !lock(&self.url_skip).as_ref().is_some_and(|r| r.is_match(url));
        let Some(hub) = self.hub.get().filter(|h| routed && h.has_event("xhttp:request")) else {
            return (404, "Not Found".into(), "text/plain".into(), b"Not Found".to_vec());
        };
        // The HTTP request as a (faked) SIP request, so $hdr and $rb work.
        let mut m = String::from(
            "OPTIONS sip:xhttp@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKxhttp\r\nFrom: <sip:xhttp@127.0.0.1>;tag=x\r\nTo: <sip:xhttp@127.0.0.1>\r\nCall-ID: xhttp\r\nCSeq: 1 OPTIONS\r\n",
        );
        for (k, v) in headers {
            if !matches!(k.to_ascii_lowercase().as_str(), "content-length" | "via" | "from" | "to" | "call-id" | "cseq") && !k.is_empty() && !v.contains('\r') {
                m.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        m.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut raw = m.into_bytes();
        raw.extend_from_slice(body);
        let resp: Arc<Mutex<Option<HttpResp>>> = Arc::new(Mutex::new(None));
        let req = HttpReq { method: method.to_string(), url: url.to_string() };
        let r2 = resp.clone();
        hub.run_event_with("xhttp:request", net, Some(&raw), move |ctx| {
            ctx.ext.push(Box::new(req));
            ctx.ext.push(Box::new(r2));
        });
        let r = lock(&resp).take();
        match r {
            Some(r) => (r.code, r.reason, r.ctype, r.body),
            None => (404, "Not Found".into(), "text/plain".into(), b"No reply from the script".to_vec()),
        }
    }
}

impl Module for Xhttp {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("listen", Ty::Str, "", "Address the HTTP server listens on, ip:port (required)"),
            p("url_match", Ty::Str, "", "Regex: only matching URLs reach the script"),
            p("url_skip", Ty::Str, "", "Regex: matching URLs do not reach the script"),
        ])
    }

    fn name(&self) -> &'static str {
        "xhttp"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let re = || Regex::new(v.str()?).map_err(|e| format!("xhttp: bad regex: {e}"));
        match name {
            "listen" => *lock(&self.listen) = Some(v.str()?.into()),
            "url_match" => *lock(&self.url_match) = Some(re()?),
            "url_skip" => *lock(&self.url_skip) = Some(re()?),
            "event_callback" => {}
            _ => return Err(format!("xhttp: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const REPLY: &[Param] = &[arg("code", Int).eg("200"), arg("reason", Str), arg("content_type", Str).eg("\"text/plain\""), arg("body", Str)];
        Some(vec![sig("xhttp_reply", "reply", REPLY, Ret::Void, "Answer the HTTP request being handled").allowed(ctx::EVENT)])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        if lock(&self.listen).is_none() {
            return Err("xhttp: modparam(\"xhttp\", \"listen\", \"ip:port\") is required".into());
        }
        let _ = self.hub.set(reg.hub.clone());
        let _ = self.rpc.set(reg.rpc.clone());
        reg.provide(self.clone());
        reg.pv("hu", PvSpec::ro(|ctx, _| ctx.ext::<HttpReq>().map_or(Val::Null, |r| Val::str(&r.url))));
        reg.pv("hm", PvSpec::ro(|ctx, _| ctx.ext::<HttpReq>().map_or(Val::Null, |r| Val::str(&r.method))));
        // ferrosip additions: the URL's path and query (`?` excluded).
        reg.pv("hp", PvSpec::ro(|ctx, _| ctx.ext::<HttpReq>().map_or(Val::Null, |r| Val::str(r.url.split_once('?').map_or(r.url.as_str(), |(p, _)| p)))));
        reg.pv("hq", PvSpec::ro(|ctx, _| ctx.ext::<HttpReq>().map_or(Val::Null, |r| Val::str(r.url.split_once('?').map_or("", |(_, q)| q)))));
        reg.export(
            "xhttp",
            "xhttp_reply",
            |a: &[Arg]| {
                let [code, reason, ctype, body] = crate::fixed_args(a)?;
                Ok([code.dyn_str()?, reason.dyn_str()?, ctype.dyn_str()?, body.dyn_str()?])
            },
            |ctx: &mut Ctx, a: &[DynStr; 4]| {
                let [code, reason, ctype, body] = a.each_ref().map(|x| x.eval(ctx).into_owned());
                let Some(slot) = ctx.ext::<Arc<Mutex<Option<HttpResp>>>>().cloned() else { return -1 };
                *lock(&slot) = Some(HttpResp { code: code.trim().parse().unwrap_or(200), reason, ctype, body: body.into_bytes() });
                1
            },
        );
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let addr = lock(&self.listen).clone().unwrap_or_default();
        let l = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("xhttp: cannot listen on {addr}: {e}"));
                return Ok(());
            }
        };
        sip_core::elog!("ferrosip: xhttp listening on http://{addr}");
        std::thread::Builder::new()
            .name("xhttp".into())
            .spawn(move || {
                for s in l.incoming().flatten() {
                    let me = self.clone();
                    let n = net.clone();
                    let spawned = std::thread::Builder::new().name("xhttp-conn".into()).spawn(move || {
                        sip_core::panic::expendable();
                        me.serve(s, n)
                    });
                    // The connection is dropped (closed).
                    if let Err(e) = spawned {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("xhttp: no thread for a connection: {e}"));
                    }
                }
            })
            .map_err(|e| format!("cannot start the xhttp thread: {e}"))?;
        Ok(())
    }
}

pub struct XhttpProm {
    path: Mutex<String>,
    prefix: Mutex<String>,
    groups: Mutex<String>,
}

impl Default for XhttpProm {
    fn default() -> Self {
        Self { path: Mutex::new("/metrics".into()), prefix: Mutex::new("kamailio_".into()), groups: Mutex::new("all".into()) }
    }
}

impl Module for XhttpProm {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("xhttp_prom_path", Ty::Str, "/metrics", "URL path the metrics are served at"),
            p("xhttp_prom_beginning", Ty::Str, "kamailio_", "Prefix of every metric name"),
            p("xhttp_prom_stats", Ty::Str, "all", "Statistics groups to export: \"all\" or a comma list"),
        ])
    }

    fn name(&self) -> &'static str {
        "xhttp_prom"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "xhttp_prom_path" => *lock(&self.path) = v.str()?.into(),
            "xhttp_prom_beginning" => *lock(&self.prefix) = v.str()?.into(),
            "xhttp_prom_stats" => *lock(&self.groups) = v.str()?.into(),
            "prom_counter" | "prom_gauge" | "prom_histogram" | "xhttp_prom_buf_size" | "xhttp_prom_timeout" | "xhttp_prom_tags" | "xhttp_prom_pkg_stats" => {}
            _ => return Err(format!("xhttp_prom: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let x = reg.api::<Xhttp>().ok_or("xhttp_prom needs xhttp loaded first")?;
        let _ = x.prom.set(self.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn prom_names() {
        let c = sip_core::stats::counter("promtest", "a-b");
        sip_core::stats::inc(c);
        let t = super::prometheus("kamailio_", "promtest");
        assert!(t.contains("kamailio_promtest_a_b 1\n"), "{t}");
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;
    use sip_core::{Dest, Proto, RouteNames, RouteRunner};

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    /// An `event_route[xhttp:request]` that answers 200 with the URL, the
    /// X-Test header and the body it saw.
    struct Echo;
    impl RouteRunner for Echo {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            let url = ctx.ext::<HttpReq>().map(|r| format!("{} {}", r.method, r.url)).unwrap_or_default();
            let _ = ctx.msg.parse_headers(sip_parser::HdrFlags::EOH);
            let xt = ctx.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"x-test")).map(|h| String::from_utf8_lossy(h.body).into_owned());
            let body = String::from_utf8_lossy(ctx.msg.body().unwrap_or_default()).into_owned();
            let Some(slot) = ctx.ext::<Arc<Mutex<Option<HttpResp>>>>().cloned() else { return true };
            *lock(&slot) = Some(HttpResp { code: 200, reason: "OK".into(), ctype: "text/plain".into(), body: format!("{url}|{xt:?}|{body}").into_bytes() });
            true
        }
    }

    fn xhttp(url_match: Option<&str>, url_skip: Option<&str>) -> Xhttp {
        let x = Xhttp::default();
        if let Some(m) = url_match {
            x.set_param("url_match", &Arg::Str(m.into())).unwrap();
        }
        if let Some(s) = url_skip {
            x.set_param("url_skip", &Arg::Str(s.into())).unwrap();
        }
        let hub = Arc::new(RouteHub::default());
        hub.set_names(RouteNames { event: vec!["xhttp:request".into()], ..RouteNames::default() });
        hub.set_runner(Arc::new(Echo));
        let _ = x.hub.set(hub);
        x
    }

    fn code(x: &Xhttp, url: &str) -> u16 {
        x.handle("GET", url, &[], b"", &NoNet).0
    }

    #[test]
    fn url_match_and_url_skip_choose_what_reaches_the_script() {
        // (url_match, url_skip, url, code)
        let cases: &[(Option<&str>, Option<&str>, &str, u16)] = &[
            (None, None, "/anything", 200),
            (Some("^/api/"), None, "/api/users", 200),
            (Some("^/api/"), None, "/other", 404),
            (Some("^/api/"), None, "/x?next=/api/", 404),
            (Some("/api/"), None, "/x?next=/api/", 200),
            (None, Some("\\.ico$"), "/favicon.ico", 404),
            (None, Some("\\.ico$"), "/index.html", 200),
            (Some("^/a/"), Some("^/a/private/"), "/a/x", 200),
            (Some("^/a/"), Some("^/a/private/"), "/a/private/1", 404),
            (Some("^/a/"), Some("^/a/private/"), "/b/x", 404),
        ];
        for &(m, s, url, want) in cases {
            assert_eq!(code(&xhttp(m, s), url), want, "match {m:?} skip {s:?} url {url:?}");
        }
    }

    #[test]
    fn bad_url_regexes_are_refused() {
        let x = Xhttp::default();
        assert!(x.set_param("url_match", &Arg::Str("(".into())).is_err());
        assert!(x.set_param("url_skip", &Arg::Str("[".into())).is_err());
    }

    #[test]
    fn without_an_event_route_every_url_is_not_found() {
        let x = Xhttp::default();
        assert_eq!(x.handle("GET", "/", &[], b"", &NoNet).0, 404);
        let _ = x.hub.set(Arc::new(RouteHub::default()));
        assert_eq!(x.handle("GET", "/", &[], b"", &NoNet).0, 404);
    }

    #[test]
    fn the_script_sees_method_url_headers_and_body() {
        let x = xhttp(None, None);
        let hdr = |k: &str, v: &str| (k.to_string(), v.to_string());
        let (code, reason, ctype, body) = x.handle("POST", "/p?q=1", &[hdr("X-Test", "yes"), hdr("Content-Length", "999")], b"payload", &NoNet);
        assert_eq!((code, reason.as_str(), ctype.as_str()), (200, "OK", "text/plain"));
        assert_eq!(String::from_utf8(body).unwrap(), "POST /p?q=1|Some(\"yes\")|payload", "the real body length wins");
        let (_, _, _, body) = x.handle("GET", "/", &[hdr("X-Test", "a\r\nVia: x")], b"", &NoNet);
        assert_eq!(String::from_utf8(body).unwrap(), "GET /|None|", "a value with CR is dropped");
    }

    #[test]
    fn metrics_path_bypasses_url_match() {
        let x = xhttp(Some("^/api/"), None);
        let _ = x.prom.set(Arc::new(XhttpProm::default()));
        let (status, _, ctype, _) = x.handle("GET", "/metrics?x=1", &[], b"", &NoNet);
        assert_eq!((status, ctype.as_str()), (200, "text/plain; version=0.0.4"));
        assert_eq!(code(&x, "/metricsx"), 404);
    }
}

#[cfg(test)]
mod serve_tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, registry, with_ctx};
    use sip_core::{RouteNames, RouteRunner};
    use std::net::Shutdown;

    /// Sends `input` (then end of stream) to `x.serve()` over a loopback
    /// connection; returns everything it answered.
    fn exchange(x: &Arc<Xhttp>, input: &[u8]) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        c.write_all(input).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        x.serve(s, Arc::new(FakeNet(None)));
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        out
    }

    fn with_rpc_and_metrics() -> Arc<Xhttp> {
        let x = Arc::new(Xhttp::default());
        let rpc = Arc::new(RpcTable::default());
        rpc.add("echo", "", |p| Ok(sip_core::serde_json::Value::Array(p.to_vec())));
        let _ = x.rpc.set(rpc);
        let _ = x.prom.set(Arc::new(XhttpProm::default()));
        x
    }

    #[test]
    fn keep_alive_serves_requests_until_http_1_0_or_close() {
        let x = with_rpc_and_metrics();
        let body = r#"{"jsonrpc":"2.0","id":7,"method":"echo","params":[1]}"#;
        let req = format!(
            "GET /metrics HTTP/1.1\r\nHost: h\r\nno colon here\r\n\r\nPOST /RPC HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}GET /x HTTP/1.0\r\n\r\nGET /never HTTP/1.1\r\n\r\n",
            body.len()
        );
        let out = exchange(&x, req.as_bytes());
        assert_eq!(out.matches("HTTP/1.1 ").count(), 3, "{out}");
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n") && out.contains("Content-Type: text/plain; version=0.0.4\r\n"));
        assert!(out.contains("Content-Type: application/json\r\n") && out.contains(r#""result":[1]"#) && out.contains(r#""id":7"#), "{out}");
        assert!(out.ends_with("Connection: close\r\n\r\nNot Found"), "HTTP/1.0: closed after the reply: {out}");
        let out = exchange(&x, b"GET /a HTTP/1.1\r\nConnection: close\r\n\r\nGET /b HTTP/1.1\r\n\r\n");
        assert_eq!(out.matches("HTTP/1.1 ").count(), 1, "{out}");
    }

    #[test]
    fn broken_requests_close_the_connection_unanswered() {
        let x = with_rpc_and_metrics();
        let cases: &[&[u8]] = &[b"", b"GARBAGE\r\n\r\n", b"GET /metrics HTTP/1.1\r\nHost: h\r\n", b"POST /RPC HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"];
        for input in cases {
            assert_eq!(exchange(&x, input), "", "{:?}", String::from_utf8_lossy(input));
        }
    }

    /// An `event_route[xhttp:request]` that never calls xhttp_reply().
    struct Silent;
    impl RouteRunner for Silent {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
    }

    #[test]
    fn a_script_without_a_reply_answers_404() {
        let x = Xhttp::default();
        let hub = Arc::new(RouteHub::default());
        hub.set_names(RouteNames { event: vec!["xhttp:request".into()], ..RouteNames::default() });
        hub.set_runner(Arc::new(Silent));
        let _ = x.hub.set(hub);
        let (code, _, _, body) = x.handle("GET", "/", &[], b"", &FakeNet(None));
        assert_eq!((code, body.as_slice()), (404, &b"No reply from the script"[..]));
    }

    #[test]
    fn parameters_and_registration() {
        let x = Xhttp::default();
        assert!(x.set_param("event_callback", &Arg::Str("ksr_xhttp".into())).is_ok());
        assert!(x.set_param("nope", &Arg::Str("x".into())).is_err());
        let err = Arc::new(Xhttp::default()).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("listen"), "{err}");
        let p = XhttpProm::default();
        for ok in ["xhttp_prom_path", "xhttp_prom_beginning", "xhttp_prom_stats", "prom_counter", "xhttp_prom_timeout"] {
            assert!(p.set_param(ok, &Arg::Str("x".into())).is_ok(), "{ok}");
        }
        assert!(p.set_param("nope", &Arg::Str("x".into())).is_err());
        assert!(Arc::new(XhttpProm::default()).register(&mut Registry::default()).err().unwrap().contains("xhttp"));
    }

    #[test]
    fn xhttp_reply_fills_the_response_of_the_request_being_handled() {
        let x = Arc::new(Xhttp::default());
        x.set_param("listen", &Arg::Str("127.0.0.1:0".into())).unwrap();
        let reg = registry(vec![x.clone(), Arc::new(XhttpProm::default())]);
        assert!(x.prom.get().is_some(), "xhttp_prom attached itself");
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "xhttp_reply", &["200", "OK", "text/plain", "hi"]).unwrap(), -1, "no HTTP request here");
            let slot: Arc<Mutex<Option<HttpResp>>> = Arc::default();
            ctx.ext.push(Box::new(slot.clone()));
            assert_eq!(call(&reg, ctx, "xhttp_reply", &["oops", "Fine", "text/html", "<p>"]).unwrap(), 1);
            let r = lock(&slot).clone().unwrap();
            assert_eq!((r.code, r.reason.as_str(), r.ctype.as_str(), r.body.as_slice()), (200, "Fine", "text/html", &b"<p>"[..]), "a bad code: 200");
        });
        assert!(fixup(&reg, "xhttp_reply", &[Arg::Int(200)]).is_err());
    }

    #[test]
    fn spawn_without_a_usable_address_only_logs() {
        let x = Xhttp::default();
        x.set_param("listen", &Arg::Str("not-an-address".into())).unwrap();
        assert!(Arc::new(x).spawn(Arc::new(FakeNet(None))).is_ok());
    }

    #[test]
    fn prometheus_keeps_only_the_wanted_groups() {
        sip_core::stats::inc(sip_core::stats::counter("promsel1", "x"));
        sip_core::stats::inc(sip_core::stats::counter("promsel2", "y"));
        let t = prometheus("p_", "promsel1, promsel2");
        assert!(t.contains("p_promsel1_x 1\n") && t.contains("p_promsel2_y 1\n"), "{t}");
        let t = prometheus("p_", "promsel2");
        assert!(!t.contains("promsel1") && t.contains("# TYPE p_promsel2_y counter\n"), "{t}");
        assert!(prometheus("p_", "all").contains("p_promsel1_x"));
    }
}
