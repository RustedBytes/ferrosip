//! `http_async_client`: HTTP(S) queries off the SIP workers. The request is
//! described with `$http_req(key) = value` (method, body, hdr — appends —,
//! timeout ms, username, password, all = reset), then
//! `http_async_query(url, route)` suspends the transaction; the query runs
//! on this module's pool and `route[route]` continues the request with the
//! response in `$http_*`.

use crate::{Pool, resume_with, route_idx};
use mod_txn::Tm;
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Continuation, Ctx, Module, Registry};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// The request being built with `$http_req(...)`.
#[derive(Clone, Default)]
pub struct HttpReq {
    pub method: Option<String>,
    pub body: String,
    pub hdrs: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// What the continuation route sees.
#[derive(Clone, Default, Debug)]
pub struct HttpReply {
    pub ok: bool,
    pub err: String,
    pub status: u16,
    pub reason: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
    pub ms: u64,
}

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut o = String::new();
    for c in b.chunks(3) {
        let [b0, b1, b2] = [0, 1, 2].map(|i| c.get(i).map_or(0, |&x| u32::from(x)));
        let n = b0 << 16 | b1 << 8 | b2;
        // The first c.len() + 1 sextets carry data, the rest is padding.
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            match T.get((n >> shift & 63) as usize) {
                Some(&x) if i <= c.len() => o.push(char::from(x)),
                _ => o.push('='),
            }
        }
    }
    o
}

/// Perform one HTTP request (blocking). Used by `http_client` too.
pub fn perform(url: &str, r: &HttpReq, default_timeout: Duration) -> HttpReply {
    let started = Instant::now();
    let elapsed = || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let failed = |err: String| HttpReply { ok: false, err, ms: elapsed(), ..Default::default() };
    let timeout = r.timeout_ms.map(Duration::from_millis).unwrap_or(default_timeout);
    // 4xx/5xx are replies like any other: the script reads $http_rs.
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).max_redirects(3).http_status_as_error(false).build().into();
    let method = r.method.clone().unwrap_or_else(|| if r.body.is_empty() { "GET".into() } else { "POST".into() }).to_ascii_uppercase();
    let mut req = ureq::http::Request::builder().method(method.as_str()).uri(url);
    for h in &r.hdrs {
        if let Some((n, v)) = h.split_once(':') {
            req = req.header(n.trim(), v.trim());
        }
    }
    if let Some(u) = &r.user {
        req = req.header("Authorization", format!("Basic {}", b64(&format!("{u}:{}", r.pass.as_deref().unwrap_or("")))));
    }
    let res = if r.body.is_empty() && matches!(method.as_str(), "GET" | "HEAD" | "DELETE") {
        req.body(()).map_err(|e| e.to_string()).and_then(|q| agent.run(q).map_err(|e| e.to_string()))
    } else {
        req.body(r.body.as_str()).map_err(|e| e.to_string()).and_then(|q| agent.run(q).map_err(|e| e.to_string()))
    };
    let mut resp = match res {
        Ok(resp) => resp,
        Err(e) => return failed(e),
    };
    let status = resp.status();
    // The wire's reason phrase isn't kept by the client: the standard one.
    let reason = status.canonical_reason().unwrap_or_default().to_string();
    let headers = resp.headers().iter().filter_map(|(n, v)| v.to_str().ok().map(|v| (n.as_str().to_string(), v.to_string()))).collect();
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    HttpReply { ok: true, err: String::new(), status: status.as_u16(), reason, body, headers, ms: elapsed() }
}

/// `$http_req(key)` setter shared with `http_client`.
pub fn set_req(r: &mut HttpReq, key: &str, v: Val) -> Result<(), String> {
    let s = || v.as_str().to_string();
    match key {
        "all" => *r = HttpReq::default(),
        "method" => r.method = Some(s()),
        "body" => r.body = s(),
        "hdr" => {
            if !matches!(v, Val::Null) {
                r.hdrs.push(s())
            }
        }
        "timeout" => r.timeout_ms = v.as_int().map(|t| u64::try_from(t).unwrap_or(0).max(1)),
        "username" => r.user = Some(s()),
        "password" => r.pass = Some(s()),
        "suspend" | "tls_client_cert" | "tls_client_key" | "tls_ca_path" | "tls_verify_host" | "tls_verify_peer" | "authmethod" | "follow_redirect" => {}
        k => return Err(format!("$http_req({k}): unknown key")),
    }
    Ok(())
}

/// What `await http.get(…)` gives.
pub static HTTP_RESPONSE: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy {
    name: "HttpResponse",
    fields: &[
        ("ok", "$http_ok", sip_core::sig::FieldTy::Bool),
        ("status", "$http_rs", sip_core::sig::FieldTy::Int),
        ("reason", "$http_rr", sip_core::sig::FieldTy::Str),
        ("body", "$http_rb", sip_core::sig::FieldTy::Str),
        ("error", "$http_err", sip_core::sig::FieldTy::Str),
        ("ms", "$http_time", sip_core::sig::FieldTy::Int),
    ],
};

type Q = (Option<DynStr>, Option<DynStr>, Option<DynStr>, Option<DynStr>, Option<DynStr>, Option<sip_core::module::DynInt>);

pub struct HttpAsync {
    workers: AtomicUsize,
    timeout_ms: AtomicU64,
    pool: OnceLock<Arc<Pool>>,
}

impl Default for HttpAsync {
    fn default() -> Self {
        Self { workers: AtomicUsize::new(1), timeout_ms: AtomicU64::new(5000), pool: OnceLock::new() }
    }
}

impl Module for HttpAsync {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("workers", Ty::Int { min: 1, max: 256 }, "1", "Threads that run the HTTP queries"),
            p("connection_timeout", Ty::Duration(Unit::Ms), "5s", "Timeout of a query (unless $http_req(timeout) says otherwise)"),
        ])
    }

    fn name(&self) -> &'static str {
        "http_async_client"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "workers" => self.workers.store(usize::try_from(v.int()?.clamp(1, 256)).unwrap_or(1), Ordering::Relaxed),
            "connection_timeout" => self.timeout_ms.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "hash_size"
            | "tls_version"
            | "tls_verify_host"
            | "tls_verify_peer"
            | "curl_verbose"
            | "curl_follow_redirect"
            | "memory_manager"
            | "tls_client_cert"
            | "tls_client_key"
            | "tls_ca_path"
            | "tcp_keepalive"
            | "tcp_ka_idle"
            | "tcp_ka_interval" => {}
            _ => return Err(format!("http_async_client: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, opt, opt_or, sig};
        const GET: &[sip_core::sig::Param] = &[arg("url", Str), opt_or("headers", Str, ""), opt("timeout", Duration(sip_core::schema::Unit::Ms))];
        const POST: &[sip_core::sig::Param] = &[
            arg("url", Str),
            arg("body", Str),
            opt_or("content_type", Str, "application/json"),
            opt_or("headers", Str, ""),
            opt("timeout", Duration(sip_core::schema::Unit::Ms)),
        ];
        const REQ: &[sip_core::sig::Param] =
            &[arg("method", Str), arg("url", Str), opt_or("body", Str, ""), opt_or("headers", Str, ""), opt("timeout", Duration(sip_core::schema::Unit::Ms))];
        Some(vec![
            sip_core::sig::hidden("http_async_query", "takes a route to resume in; .fsr uses `await http.get(…)`"),
            sig(
                "http_async_get",
                "get",
                GET,
                Ret::Await(&HTTP_RESPONSE),
                "GET a URL without blocking: `let r = await http.get(url)`; headers are `Name: value` lines",
            ),
            sig("http_async_post", "post", POST, Ret::Await(&HTTP_RESPONSE), "POST a body without blocking (JSON unless content_type says otherwise)"),
            sig("http_async_request", "request", REQ, Ret::Await(&HTTP_RESPONSE), "Any method without blocking"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let tm = reg.api::<Tm>().ok_or("http_async_client needs tm (load it first)")?;
        reg.pv(
            "http_req",
            PvSpec::rw(
                |_, _| Val::Null,
                |c, p, v| {
                    let mut r = c.ext::<HttpReq>().cloned().unwrap_or_default();
                    set_req(&mut r, &p.name, v)?;
                    *c.ext_mut::<HttpReq>() = r;
                    Ok(())
                },
            )
            .with_param(),
        );
        let get = |f: fn(&HttpReply) -> Val| PvSpec::ro(move |c, _| c.ext::<HttpReply>().map_or(Val::Null, f));
        reg.pv("http_ok", get(|r| Val::Int(i64::from(r.ok))));
        reg.pv("http_err", get(|r| if r.err.is_empty() { Val::Null } else { Val::Str(r.err.clone()) }));
        reg.pv("http_rs", get(|r| if r.ok { Val::Int(i64::from(r.status)) } else { Val::Null }));
        reg.pv("http_rr", get(|r| Val::Str(r.reason.clone())));
        reg.pv("http_rb", get(|r| Val::Str(r.body.clone())));
        reg.pv("http_bs", get(|r| Val::Int(i64::try_from(r.body.len()).unwrap_or(i64::MAX))));
        reg.pv("http_time", get(|r| Val::Int(i64::try_from(r.ms).unwrap_or(i64::MAX))));
        reg.pv(
            "http_hdr",
            PvSpec::ro(|c, p| {
                c.ext::<HttpReply>()
                    .and_then(|r| r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(&p.name)).map(|(_, v)| Val::Str(v.clone())))
                    .unwrap_or(Val::Null)
            })
            .with_param(),
        );
        // .fsr's `await http.get/post/request(…)`: the same query, then the
        // script continues after the call (its result in $http_*).
        // Arguments: get (url, headers, timeout), post (url, body,
        // content_type, headers, timeout), request (method, url, body,
        // headers, timeout).
        for (name, shape) in [("http_async_get", 0u8), ("http_async_post", 1), ("http_async_request", 2)] {
            let (me, tm) = (self.clone(), tm.clone());
            reg.export(
                "http_async_client",
                name,
                move |a: &[Arg]| {
                    let s = |i: usize| a.get(i).map(Arg::dyn_str).transpose();
                    let n = |i: usize| a.get(i).map(Arg::dyn_int).transpose();
                    let lit = |v: &str| Some(DynStr::Static(v.into()));
                    // (method, url, body, content type, headers, timeout ms)
                    Ok(match shape {
                        0 => (lit("GET"), s(0)?, None, None, s(1)?, n(2)?),
                        1 => (lit("POST"), s(0)?, s(1)?, s(2)?, s(3)?, n(4)?),
                        _ => (s(0)?, s(1)?, s(2)?, None, s(3)?, n(4)?),
                    })
                },
                move |ctx: &mut Ctx, (method, url, body, ctype, hdrs, ms): &Q| {
                    let ev = |d: &Option<DynStr>, ctx: &mut Ctx| d.as_ref().map(|d| d.eval(ctx).into_owned()).unwrap_or_default();
                    let url = ev(url, ctx);
                    let mut req = HttpReq { method: Some(ev(method, ctx)).filter(|m| !m.is_empty()), body: ev(body, ctx), ..Default::default() };
                    let ct = ev(ctype, ctx);
                    if !ct.is_empty() && !req.body.is_empty() {
                        req.hdrs.push(format!("Content-Type: {ct}"));
                    }
                    req.hdrs.extend(ev(hdrs, ctx).lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string));
                    req.timeout_ms = ms.as_ref().and_then(|m| m.eval(ctx)).and_then(|m| u64::try_from(m).ok()).filter(|m| *m > 0);
                    let Some(pool) = crate::lazy(&me.pool, || Pool::new("http-async", me.workers.load(Ordering::Relaxed))).cloned() else {
                        return sip_core::module::RC_ERR;
                    };
                    let id = match tm.suspend(ctx) {
                        Ok(id) => id,
                        Err(rc) => {
                            // Not here (after the final, or a retransmission):
                            // the result says so.
                            ctx.ext.retain(|e| !e.is::<HttpReply>());
                            ctx.ext.push(Box::new(HttpReply { err: "can't wait here".into(), ..Default::default() }));
                            return if rc == 0 { 0 } else { -1 };
                        }
                    };
                    let (tm, timeout) = (tm.clone(), Duration::from_millis(me.timeout_ms.load(Ordering::Relaxed)));
                    ctx.ext.push(Box::new(sip_core::AsyncPending(Box::new(move |cont| {
                        pool.exec(move || {
                            let reply = perform(&url, &req, timeout);
                            resume_with(&tm, &id, &cont, move |c| {
                                c.ext.retain(|e| !e.is::<HttpReply>());
                                c.ext.push(Box::new(reply));
                            });
                        });
                    }))));
                    0
                },
            );
        }
        let (me, hub) = (self.clone(), reg.hub.clone());
        reg.export(
            "http_async_client",
            "http_async_query",
            |a: &[Arg]| {
                let [url, route] = crate::fixed_args(a)?;
                Ok((url.dyn_str()?, route.str()?.to_string()))
            },
            move |ctx: &mut Ctx, (url, route): &(DynStr, String)| {
                let Some(idx) = route_idx(&hub, route) else { return -1 };
                let url = url.eval(ctx).into_owned();
                let req = ctx.ext::<HttpReq>().cloned().unwrap_or_default();
                let Some(pool) = crate::lazy(&me.pool, || Pool::new("http-async", me.workers.load(Ordering::Relaxed))) else {
                    return sip_core::module::RC_ERR;
                };
                let id = match tm.suspend(ctx) {
                    Ok(id) => id,
                    Err(rc) => return rc,
                };
                let tm = tm.clone();
                let timeout = Duration::from_millis(me.timeout_ms.load(Ordering::Relaxed));
                pool.exec(move || {
                    let reply = perform(&url, &req, timeout);
                    resume_with(&tm, &id, &Continuation::route(idx), move |c| {
                        c.ext.retain(|e| !e.is::<HttpReply>());
                        c.ext.push(Box::new(reply));
                    });
                });
                0
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(super::b64("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(super::b64("a"), "YQ==");
    }

    /// RFC 4648 decoding, for the round-trip test.
    fn unb64(s: &str) -> Vec<u8> {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits: Vec<u8> = Vec::new();
        for c in s.bytes().filter(|&c| c != b'=') {
            let v = u8::try_from(T.iter().position(|&x| x == c).unwrap()).unwrap();
            bits.extend((0..6).rev().map(|i| v >> i & 1));
        }
        bits.as_chunks::<8>().0.iter().map(|b| b.iter().fold(0u8, |acc, &x| acc << 1 | x)).collect()
    }

    #[test]
    fn base64_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("é", "w6k="),
            ("\u{0}\u{7f}", "AH8="),
            ("?>?", "Pz4/"),
            ("~~~", "fn5+"),
            ("Aladdin:open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ];
        for (input, want) in cases {
            assert_eq!(b64(input), want, "{input:?}");
        }
    }

    #[test]
    fn base64_round_trips() {
        let mut s = String::new();
        for c in (0u32..300).filter_map(char::from_u32) {
            s.push(c);
            let e = b64(&s);
            assert_eq!(e.len() % 4, 0);
            assert_eq!(unb64(&e), s.as_bytes(), "{s:?}");
        }
    }

    #[test]
    fn http_req_setters() {
        let mut r = HttpReq::default();
        set_req(&mut r, "method", Val::str("put")).unwrap();
        set_req(&mut r, "body", Val::str("{}")).unwrap();
        set_req(&mut r, "hdr", Val::str("X-A: 1")).unwrap();
        set_req(&mut r, "hdr", Val::str("X-B: 2")).unwrap();
        set_req(&mut r, "hdr", Val::Null).unwrap();
        set_req(&mut r, "username", Val::str("u")).unwrap();
        set_req(&mut r, "password", Val::Int(7)).unwrap();
        set_req(&mut r, "tls_verify_peer", Val::Int(0)).unwrap();
        assert_eq!(r.method.as_deref(), Some("put"));
        assert_eq!(r.body, "{}");
        assert_eq!(r.hdrs, ["X-A: 1", "X-B: 2"], "hdr appends; $null adds nothing");
        assert_eq!((r.user.as_deref(), r.pass.as_deref()), (Some("u"), Some("7")));
        assert!(set_req(&mut r, "nope", Val::Int(1)).is_err());
        set_req(&mut r, "all", Val::Null).unwrap();
        assert!(r.method.is_none() && r.body.is_empty() && r.hdrs.is_empty() && r.user.is_none(), "all resets");
    }

    #[test]
    fn http_req_timeout() {
        let cases: &[(Val, Option<u64>)] = &[
            (Val::Int(1500), Some(1500)),
            (Val::str("250"), Some(250)),
            (Val::Int(0), Some(1)),
            (Val::Int(-5), Some(1)),
            (Val::str("x"), None),
            (Val::Null, None),
        ];
        for (v, want) in cases {
            let mut r = HttpReq { timeout_ms: Some(99), ..Default::default() };
            set_req(&mut r, "timeout", v.clone()).unwrap();
            assert_eq!(r.timeout_ms, *want, "{v:?}");
        }
    }

    #[test]
    fn http_client_params() {
        let c = HttpClient::default();
        c.set_param("httpcon", &Arg::Str(" api => http://127.0.0.1:1/v1/ ".into())).unwrap();
        assert_eq!(lock(&c.cons).get("api").map(String::as_str), Some("http://127.0.0.1:1/v1"));
        assert!(c.set_param("httpcon", &Arg::Str("api".into())).is_err());
        c.set_param("connection_timeout", &Arg::Int(3)).unwrap();
        assert_eq!(c.timeout_ms.load(Ordering::Relaxed), 3000, "seconds");
        c.set_param("connection_timeout", &Arg::Int(0)).unwrap();
        assert_eq!(c.timeout_ms.load(Ordering::Relaxed), 1000);
        c.set_param("query_result", &Arg::Int(0)).unwrap();
        assert!(!c.first_line.load(Ordering::Relaxed));
        let h = HttpAsync::default();
        h.set_param("connection_timeout", &Arg::Int(0)).unwrap();
        assert_eq!(h.timeout_ms.load(Ordering::Relaxed), 1);
        h.set_param("workers", &Arg::Int(999)).unwrap();
        assert_eq!(h.workers.load(Ordering::Relaxed), 256);
        assert!(h.set_param("nope", &Arg::Int(1)).is_err());
    }
}

// ------------------------------------------------------------- http_client --

/// Kamailio `http_client`: blocking HTTP(S) queries from the script.
/// `http_client_query(url, [post, [hdrs,]] $res)` returns the status code
/// (negative on transport errors, then `$curlerror(error)`);
/// `http_connect(con, path, [content_type, data,] $res)` uses a named
/// connection (`httpcon` "name=>base_url"). With `query_result` 1 (the
/// default, as in Kamailio) only the first line of the body is returned.
pub struct HttpClient {
    cons: std::sync::Mutex<std::collections::HashMap<String, String>>,
    timeout_ms: AtomicU64,
    first_line: std::sync::atomic::AtomicBool,
    agent: std::sync::Mutex<String>,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self {
            cons: Default::default(),
            timeout_ms: AtomicU64::new(4000),
            first_line: std::sync::atomic::AtomicBool::new(true),
            agent: std::sync::Mutex::new("ferrosip (http_client)".into()),
        }
    }
}

/// Last http_client error of this message (`$curlerror(error)`).
#[derive(Default)]
struct CurlError(String);

impl HttpClient {
    fn run(&self, ctx: &mut Ctx<'_, '_>, url: &str, req: HttpReq, dst: &sip_core::pv::PvRef) -> i32 {
        let mut req = req;
        req.hdrs.push(format!("User-Agent: {}", lock(&self.agent)));
        let r = perform(url, &req, Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed)));
        if !r.ok {
            ctx.ext_mut::<CurlError>().0 = r.err;
            return -1;
        }
        ctx.ext_mut::<CurlError>().0.clear();
        let body = if self.first_line.load(Ordering::Relaxed) { r.body.lines().next().unwrap_or("").to_string() } else { r.body };
        let _ = dst.set(ctx, Val::Str(body));
        i32::from(r.status)
    }
}

impl Module for HttpClient {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("httpcon", Ty::List(&Ty::Str), "", "Named connections, \"name=>url\""),
            p("connection_timeout", Ty::Duration(Unit::Sec), "4s", "Timeout of a query"),
            p("query_result", Ty::Bool, "true", "Return only the first line of the response body"),
            p("useragent", Ty::Str, "ferrosip (http_client)", "User-Agent of the requests"),
        ])
    }

    fn name(&self) -> &'static str {
        "http_client"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "httpcon" => {
                let s = v.str()?;
                let (n, u) = s.split_once("=>").ok_or_else(|| format!("http_client httpcon {s:?}: expected name=>url"))?;
                lock(&self.cons).insert(n.trim().to_string(), u.trim().trim_end_matches('/').to_string());
            }
            "connection_timeout" => self.timeout_ms.store(u64::try_from(v.int()?).unwrap_or(0).max(1).saturating_mul(1000), Ordering::Relaxed),
            "query_result" => self.first_line.store(v.int()? == 1, Ordering::Relaxed),
            "useragent" => *lock(&self.agent) = v.str()?.into(),
            "keep_connections" | "tlsverifyserver" | "tlsverifyhost" | "maxdatasize" | "httpredirect" | "httpproxy" | "httpproxyport" | "tlsversion"
            | "authmethod" | "config_file" | "query_maxdatasize" | "timeout_mode" | "cipher_suites" | "netinterface" => {}
            _ => return Err(format!("http_client: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, hidden, sig};
        const GET: &[Param] = &[arg("url", Str), arg("result", Var)];
        const POST: &[Param] = &[arg("url", Str), arg("body", Str), arg("result", Var)];
        const QUERY: &[Param] = &[arg("url", Str), arg("body", Str), arg("headers", Str), arg("result", Var)];
        const CONNECT: &[Param] = &[arg("connection", Str).lit(), arg("path", Str), arg("result", Var)];
        const CONNECT_POST: &[Param] = &[arg("connection", Str).lit(), arg("path", Str), arg("content_type", Str), arg("data", Str), arg("result", Var)];
        Some(vec![
            sig("http_client_query", "get", GET, Ret::Bool, "GET `url` (blocking); the body (its first line with query_result) goes into `result`")
                .allowed(ctx::ANY),
            sig("http_client_query", "post", POST, Ret::Bool, "POST `body` to `url` (blocking; an empty body GETs), as application/x-www-form-urlencoded (`query` sets other headers); the response body into `result`")
                .allowed(ctx::ANY),
            sig(
                "http_client_query",
                "query",
                QUERY,
                Ret::Bool,
                "GET or POST (with a body) `url` with extra headers (CRLF-separated); the response body into `result`",
            )
            .allowed(ctx::ANY),
            sig("http_connect", "connect", CONNECT, Ret::Bool, "GET `path` on an `httpcon` connection; the response body into `result`").allowed(ctx::ANY),
            sig("http_connect", "connect_post", CONNECT_POST, Ret::Bool, "POST `data` to `path` on an `httpcon` connection; the response body into `result`")
                .allowed(ctx::ANY),
            hidden("http_query", "the old name of http_client_query: use http_client.get / post / query"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        use crate::json::out_pv;
        reg.pv("curlerror", PvSpec::ro(|c, _| c.ext::<CurlError>().filter(|e| !e.0.is_empty()).map_or(Val::Null, |e| Val::Str(e.0.clone()))).with_param());
        type Q = (DynStr, Option<DynStr>, Option<DynStr>, sip_core::pv::PvRef);
        let fix = |a: &[Arg]| -> Result<Q, String> {
            match a {
                [url, dst] => Ok((url.dyn_str()?, None, None, out_pv(dst)?)),
                [url, post, dst] => Ok((url.dyn_str()?, Some(post.dyn_str()?), None, out_pv(dst)?)),
                [url, post, hdrs, dst] => Ok((url.dyn_str()?, Some(post.dyn_str()?), Some(hdrs.dyn_str()?), out_pv(dst)?)),
                _ => Err("expected url[, post[, hdrs]], $result".into()),
            }
        };
        for name in ["http_client_query", "http_query"] {
            let me = self.clone();
            reg.export("http_client", name, fix, move |ctx: &mut Ctx, (url, post, hdrs, dst): &Q| {
                let url = url.eval(ctx).into_owned();
                let mut req = HttpReq::default();
                if let Some(p) = post {
                    req.body = p.eval(ctx).into_owned();
                    if !req.body.is_empty() {
                        req.method = Some("POST".into());
                    }
                }
                if let Some(h) = hdrs {
                    req.hdrs.extend(h.eval(ctx).split("\r\n").filter(|l| !l.is_empty()).map(String::from));
                }
                // A POST without a Content-Type gets libcurl's default, as in
                // Kamailio (pass headers to say otherwise).
                if req.method.is_some() && !req.hdrs.iter().any(|h| h.split(':').next().is_some_and(|n| n.trim().eq_ignore_ascii_case("content-type"))) {
                    req.hdrs.push("Content-Type: application/x-www-form-urlencoded".into());
                }
                me.run(ctx, &url, req, dst)
            });
        }
        type C = (String, DynStr, Option<(DynStr, DynStr)>, sip_core::pv::PvRef);
        let me = self.clone();
        reg.export(
            "http_client",
            "http_connect",
            |a: &[Arg]| -> Result<C, String> {
                match a {
                    [conn, url, dst] => Ok((conn.str()?.to_string(), url.dyn_str()?, None, out_pv(dst)?)),
                    [conn, url, ctype, data, dst] => Ok((conn.str()?.to_string(), url.dyn_str()?, Some((ctype.dyn_str()?, data.dyn_str()?)), out_pv(dst)?)),
                    _ => Err("expected connection, url[, content_type, data], $result".into()),
                }
            },
            move |ctx: &mut Ctx, (con, path, post, dst): &C| {
                let Some(base) = lock(&me.cons).get(con).cloned() else { return -1 };
                let path = path.eval(ctx).into_owned();
                let url = if path.is_empty() { base } else { format!("{base}/{}", path.trim_start_matches('/')) };
                let mut req = HttpReq::default();
                if let Some((ct, data)) = post {
                    req.method = Some("POST".into());
                    req.hdrs.push(format!("Content-Type: {}", ct.eval(ctx)));
                    req.body = data.eval(ctx).into_owned();
                }
                me.run(ctx, &url, req, dst)
            },
        );
        Ok(())
    }
}
