//! `sl`, `siputils` and `sanity`.

use crate::{args, dyn_arr, headers, pv_arg};
use sip_core::module::{DynInt, DynStr, rc};
use sip_core::pv::{PvRef, Val};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::{Arg, Ctx, Module, Registry, want_args};
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::{HdrFlags, HdrKind, Method, parse_uri};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ------------------------------------------------------------------ sl ---

pub struct Sl;

impl Module for Sl {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "sl"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const REPLY: &[Param] = &[arg("code", Int).eg("404"), arg("reason", Str)];
        Some(vec![
            // Kamailio exports sl_send_reply / sl_reply_error for REQUEST_ROUTE
            // only (sl.c:103-111).
            sig("sl_send_reply", "reply", REPLY, Ret::Action, "Answer the request statelessly").allowed(ctx::REQUEST),
            sig("send_reply", "send_reply", REPLY, Ret::Action, "Answer the request: through its transaction in a failure context, else statelessly"),
            sig(
                "send_reply_error",
                "reply_error",
                &[],
                Ret::Action,
                "Answer with the error of the last failed function: through the transaction in a failure context; nothing while tm owes a failed relay its reply",
            ),
            sig("send_reply_error", "reply_error_and_continue", &[], Ret::Bool, "Like reply_error(), but the route goes on after it (true: sent)"),
            sig("sl_forward_reply", "forward_reply", &[], Ret::Bool, "Forward the reply statelessly (not supported: always false)").allowed(ctx::REPLY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let fix = |a: &[Arg]| -> Result<(DynInt, DynStr), String> {
            let [code, reason] = args(a)?;
            let c = code.dyn_int()?;
            if let DynInt::Static(c) = c
                && !(100..700).contains(&c)
            {
                return Err(format!("bad status code {c}"));
            }
            Ok((c, reason.dyn_str()?))
        };
        let send = |ctx: &mut Ctx, (c, r): &(DynInt, DynStr)| -> i32 {
            let Some(code) = c.eval(ctx).filter(|c| (100..700).contains(c)).and_then(|c| u16::try_from(c).ok()) else { return -1 };
            let reason = r.eval(ctx).into_owned();
            rc(ctx.reply(code, &reason).is_ok())
        };
        reg.export("sl", "sl_send_reply", fix, send);
        // send_reply(): through tm while the request has a transaction that
        // tm answers for it (a failure route; a request route whose relay
        // failed), else stateless (Kamailio sl.c:272-313: tm's t_reply when
        // t_gett() finds one). Other transactions take a stateless reply as
        // theirs (t_newtran's ReplyHook, a resumed request's ReplyCapture).
        reg.export("sl", "send_reply", fix, |ctx: &mut Ctx, (c, r): &(DynInt, DynStr)| -> i32 {
            let Some(code) = c.eval(ctx).filter(|c| (100..700).contains(c)).and_then(|c| u16::try_from(c).ok()) else { return -1 };
            let reason = r.eval(ctx).into_owned();
            rc(matches!(ctx.send_reply(code, &reason), Ok(true)))
        });
        // send_reply_error() (Kamailio sl.c:347-367): nothing after sl's own
        // final (-2) or while tm's error reply waits for the script's end
        // (-3); else tm's t_reply_error() where tm answers for the request
        // (the error with tm's signature, tm.c:1661-1684), and sl_reply_error()
        // if there is none or it already has its final.
        reg.export(
            "sl",
            "send_reply_error",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if ctx.answered() {
                    return -2;
                }
                if ctx.ext::<sip_core::module::DelayedReply>().is_some() {
                    return -3;
                }
                if ctx.in_txn() {
                    let (code, reason) = sip_core::error::reply_error(ctx.last_error, "TM");
                    if let Ok(true) = ctx.send_reply(code, &reason) {
                        return 1;
                    }
                }
                let (code, reason) = sip_core::error::reply_error(ctx.last_error, "SL");
                rc(ctx.reply(code, &reason).is_ok())
            },
        );
        reg.export("sl", "sl_forward_reply", |a: &[Arg]| want_args(a, 0), |_: &mut Ctx, _: &()| -1);
        Ok(())
    }
}

// ------------------------------------------------------------ siputils ---

pub struct SipUtils;

fn hdr_body(ctx: &mut Ctx<'_, '_>, k: HdrKind) -> Option<Vec<u8>> {
    let _ = ctx.msg.parse_headers(HdrFlags::of(k));
    ctx.msg.get(k).map(|h| h.body.to_vec())
}

fn is_e164(s: &str) -> bool {
    let d = s.strip_prefix('+').unwrap_or("");
    (2..=15).contains(&d.len()) && d.bytes().all(|c| c.is_ascii_digit())
}

/// RFC 3261 §19.1.4 URI comparison (simplified: scheme, user, host
/// case-insensitive, port, transport/user/ttl/method/maddr params).
fn uri_eq(a: &[u8], b: &[u8]) -> bool {
    let (Some(x), Some(y)) = (parse_uri(a), parse_uri(b)) else { return false };
    let p = |u: &sip_parser::Uri<'_>, n: &[u8]| u.param(n).map(|v| v.to_ascii_lowercase());
    x.scheme.eq_ignore_ascii_case(y.scheme)
        && x.user == y.user
        && x.host.eq_ignore_ascii_case(y.host)
        && x.port == y.port
        && [&b"transport"[..], b"user", b"ttl", b"method", b"maddr"].iter().all(|n| p(&x, n) == p(&y, n))
}

impl Module for SipUtils {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "siputils"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const S: &[Param] = &[arg("s", Str)];
        const USER: &[Param] = &[arg("user", Str)];
        const URI: &[Param] = &[arg("uri", Uri)];
        const PARAM: &[Param] = &[arg("name", Str).lit(), opt("value", Str).lit()];
        const ADD_PARAM: &[Param] = &[arg("param", Str).eg("\"user=phone\"")];
        const TWO_URIS: &[Param] = &[arg("a", Uri), arg("b", Uri)];
        const OPTION: &[Param] = &[arg("option", Str).lit().eg("\"timer\"")];
        const TEL: &[Param] = &[arg("uri", Uri).eg("\"tel:+4930123\""), arg("host", Str).eg("\"example.com\""), arg("result", Var)];
        Some(vec![
            sig("is_first_hop", "is_first_hop", &[], Ret::Bool, "The request came straight from the UA (a reply: answers our first-hop request)")
                .allowed(ctx::ANY),
            sig("has_totag", "has_totag", &[], Ret::Bool, "The To header has a tag (an in-dialog request)").allowed(ctx::ANY),
            sig("is_user", "is_user", USER, Ret::Bool, "The R-URI's user part is this"),
            sig("is_e164", "is_e164", S, Ret::Bool, "The string is an E.164 number (`+` and 2 to 15 digits)").allowed(ctx::ANY),
            sig("is_uri_user_e164", "is_uri_user_e164", URI, Ret::Bool, "The URI's user part is an E.164 number").allowed(ctx::ANY),
            sig("is_alphanum", "is_alphanum", S, Ret::Bool, "The string is non-empty and only ASCII letters and digits").allowed(ctx::ANY),
            sig("is_numeric", "is_numeric", S, Ret::Bool, "The string is non-empty and only digits").allowed(ctx::ANY),
            sig("uri_param", "has_uri_param", PARAM, Ret::Bool, "The R-URI has this parameter (with this value)"),
            sig("add_uri_param", "add_uri_param", ADD_PARAM, Ret::Bool, "Append `;param` to the R-URI"),
            sig("cmp_uri", "same_uri", TWO_URIS, Ret::Bool, "The two URIs are equal by RFC 3261 rules").allowed(ctx::ANY),
            sig("cmp_aor", "same_aor", TWO_URIS, Ret::Bool, "The two URIs have the same user and host").allowed(ctx::ANY),
            sig("is_request", "is_request", &[], Ret::Bool, "The message is a request").allowed(ctx::ANY),
            sig("is_reply", "is_reply", &[], Ret::Bool, "The message is a reply").allowed(ctx::ANY),
            sig("is_supported", "is_supported", OPTION, Ret::Bool, "The Supported header lists this option tag").allowed(ctx::ANY),
            sig("options_reply", "options_reply", &[], Ret::Bool, "Answer an OPTIONS request addressed to the proxy (no user part) with 200")
                .allowed(ctx::REQUEST),
            sig("tel2sip", "tel_to_sip", TEL, Ret::Bool, "Convert a tel: URI to sip:number@host;user=phone into `result`").allowed(ctx::ANY),
            // Core functions (always there), grouped with the other SIP helpers.
            sig("force_rport", "force_rport", &[], Ret::Void, "Send this request's replies to its source port, as if its Via had ;rport"),
            sig(
                "set_reply_no_connect",
                "reply_no_connect",
                &[],
                Ret::Void,
                "Send replies to this request only over the connection it came on (never a new one)",
            )
            .allowed(ctx::ANY),
            sig("set_forward_no_connect", "forward_no_connect", &[], Ret::Void, "Forward this request only over an open connection (never a new one)"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "siputils";
        // is_first_hop(): the request came straight from the UA (one Via
        // value), or a reply is for a request we sent first (two).
        reg.export(
            m,
            "is_first_hop",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                let vias: usize = ctx
                    .msg
                    .headers
                    .iter()
                    .filter(|h| h.kind == HdrKind::Via)
                    .map(|h| {
                        let mut quoted = false;
                        let commas = h.body.iter().filter(|&&c| {
                            quoted ^= c == b'"';
                            c == b',' && !quoted
                        });
                        commas.count().saturating_add(1)
                    })
                    .sum();
                rc(vias == if ctx.msg.is_request() { 1 } else { 2 })
            },
        );
        reg.export(
            m,
            "has_totag",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                let to = hdr_body(ctx, HdrKind::To).unwrap_or_default();
                rc(sip_parser::uri::param(name_addr(&to).1, b"tag").is_some_and(|t| !t.is_empty()))
            },
        );
        reg.export(
            m,
            "is_user",
            |a: &[Arg]| {
                let [u] = args(a)?;
                u.dyn_str()
            },
            |ctx: &mut Ctx, u: &DynStr| {
                let u = u.eval(ctx).into_owned();
                let user = parse_uri(ctx.ruri()).and_then(|x| x.user).map(<[u8]>::to_vec);
                rc(user.as_deref() == Some(u.as_bytes()))
            },
        );
        reg.export(
            m,
            "is_e164",
            |a: &[Arg]| {
                let [s] = args(a)?;
                s.dyn_str()
            },
            |ctx: &mut Ctx, s: &DynStr| rc(is_e164(&s.eval(ctx))),
        );
        reg.export(
            m,
            "is_uri_user_e164",
            |a: &[Arg]| {
                let [s] = args(a)?;
                s.dyn_str()
            },
            |ctx: &mut Ctx, s: &DynStr| {
                let uri = s.eval(ctx).into_owned();
                rc(parse_uri(uri.as_bytes()).and_then(|u| u.user).is_some_and(|u| is_e164(&String::from_utf8_lossy(u))))
            },
        );
        reg.export(
            m,
            "is_alphanum",
            |a: &[Arg]| {
                let [s] = args(a)?;
                s.dyn_str()
            },
            |ctx: &mut Ctx, s: &DynStr| {
                let s = s.eval(ctx);
                rc(!s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric()))
            },
        );
        reg.export(
            m,
            "is_numeric",
            |a: &[Arg]| {
                let [s] = args(a)?;
                s.dyn_str()
            },
            |ctx: &mut Ctx, s: &DynStr| {
                let s = s.eval(ctx);
                rc(!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            },
        );
        // uri_param(name[, value]) on the R-URI.
        reg.export(
            m,
            "uri_param",
            |a: &[Arg]| {
                let (name, value) = match a {
                    [name] => (name, None),
                    [name, value] => (name, Some(value)),
                    _ => return Err("uri_param(name[, value])".into()),
                };
                Ok((name.str()?.to_string(), value.map(|v| v.str().map(str::to_string)).transpose()?))
            },
            |ctx: &mut Ctx, (n, v): &(String, Option<String>)| {
                let Some(u) = parse_uri(ctx.ruri()) else { return -1 };
                match (u.param(n.as_bytes()), v) {
                    (Some(_), None) => 1,
                    (Some(x), Some(v)) => rc(x == v.as_bytes()),
                    _ => -1,
                }
            },
        );
        reg.export(
            m,
            "add_uri_param",
            |a: &[Arg]| {
                let [p] = args(a)?;
                p.dyn_str()
            },
            |ctx: &mut Ctx, p: &DynStr| {
                let p = p.eval(ctx).into_owned();
                let mut u = ctx.ruri().to_vec();
                u.push(b';');
                u.extend_from_slice(p.as_bytes());
                ctx.new_ruri = Some(u);
                1
            },
        );
        for (name, aor) in [("cmp_uri", false), ("cmp_aor", true)] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [x, y] = dyn_arr(a)?;
                    Ok((x, y))
                },
                move |ctx: &mut Ctx, (x, y): &(DynStr, DynStr)| {
                    let (x, y) = (x.eval(ctx).into_owned(), y.eval(ctx).into_owned());
                    if aor {
                        let p = |s: &str| parse_uri(s.as_bytes()).map(|u| (u.user.map(<[u8]>::to_vec), u.host.to_ascii_lowercase()));
                        rc(p(&x).is_some() && p(&x) == p(&y))
                    } else {
                        rc(uri_eq(x.as_bytes(), y.as_bytes()))
                    }
                },
            );
        }
        reg.export(m, "is_request", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(ctx.msg.is_request()));
        reg.export(m, "is_reply", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(!ctx.msg.is_request()));
        reg.export(
            m,
            "is_supported",
            |a: &[Arg]| {
                let [opt] = args(a)?;
                Ok(opt.str()?.to_ascii_lowercase())
            },
            |ctx: &mut Ctx, opt: &String| {
                let found = headers(ctx)
                    .iter()
                    .filter(|h| h.2.eq_ignore_ascii_case(b"supported") || h.2.eq_ignore_ascii_case(b"k"))
                    .any(|h| String::from_utf8_lossy(&h.3).split(',').any(|t| t.trim().eq_ignore_ascii_case(opt)));
                rc(found)
            },
        );
        // options_reply(): answer OPTIONS addressed to us (no user part).
        reg.export(m, "options_reply", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| {
            if ctx.msg.method() != Some(Method::Options) || parse_uri(ctx.ruri()).and_then(|u| u.user).is_some() {
                return -1;
            }
            let extra = b"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\nAccept: */*\r\nAccept-Encoding: identity\r\nAccept-Language: en\r\nSupported: \r\n";
            rc(ctx.reply_with(200, "OK", extra).is_ok())
        });
        // tel2sip(uri, hostpart, $result): tel:+123;p=1 → sip:+123;p=1@host;user=phone
        reg.export(
            m,
            "tel2sip",
            |a: &[Arg]| {
                let [u, h, out] = args(a)?;
                Ok((u.dyn_str()?, h.dyn_str()?, pv_arg(out)?))
            },
            |ctx: &mut Ctx, (u, h, out): &(DynStr, DynStr, PvRef)| {
                let (u, h) = (u.eval(ctx).into_owned(), h.eval(ctx).into_owned());
                let Some(rest) = u.strip_prefix("tel:").or_else(|| u.strip_prefix("TEL:")) else { return -1 };
                let host = h.strip_prefix("sip:").unwrap_or(&h);
                let (num, params) = rest.split_once(';').map_or((rest, ""), |(a, b)| (a, b));
                let num: String = num.chars().filter(|c| !matches!(c, '-' | '.' | '(' | ')')).collect();
                let user = if params.is_empty() { num } else { format!("{num};{params}") };
                rc(out.set(ctx, Val::Str(format!("sip:{user}@{host};user=phone"))).is_ok())
            },
        );
        Ok(())
    }
}

// -------------------------------------------------------------- sanity ---

/// Kamailio sanity check bits.
mod bit {
    pub const RURI_SIP_VERSION: u32 = 1;
    pub const RURI_SCHEME: u32 = 2;
    pub const REQUIRED_HEADERS: u32 = 4;
    pub const VIA_SIP_VERSION: u32 = 8;
    pub const VIA_PROTOCOL: u32 = 16;
    pub const CSEQ_METHOD: u32 = 32;
    pub const CSEQ_VALUE: u32 = 64;
    pub const CL: u32 = 128;
    pub const EXPIRES_VALUE: u32 = 256;
    pub const PROXY_REQUIRE: u32 = 512;
    pub const PARSE_URIS: u32 = 1024;
    pub const DIGEST: u32 = 2048;
    pub const DUPTAGS: u32 = 4096;
}

pub struct Sanity {
    default_checks: AtomicU32,
    uri_checks: AtomicU32,
    autodrop: AtomicBool,
    noreply: AtomicBool,
}

impl Default for Sanity {
    fn default() -> Self {
        Self { default_checks: AtomicU32::new(3047), uri_checks: AtomicU32::new(7), autodrop: AtomicBool::new(true), noreply: AtomicBool::new(false) }
    }
}

/// None = passed; Some((code, reason, extra header)) = failed.
fn sanity(ctx: &mut Ctx<'_, '_>, checks: u32, uri_checks: u32) -> Option<(u16, &'static str, String)> {
    let fail = |c, r| Some((c, r, String::new()));
    if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return fail(400, "Bad Header");
    }
    let hs = headers(ctx);
    let get = |k: HdrKind| hs.iter().find(|h| h.4 == k).map(|h| h.3.clone());
    let is_req = ctx.msg.is_request();
    let method = match ctx.msg.first {
        sip_parser::FirstLine::Request { method_raw, .. } => Some(method_raw.to_vec()),
        _ => None,
    };
    if is_req && checks & bit::RURI_SCHEME != 0 {
        let ok = parse_uri(ctx.ruri()).is_some_and(|u| [&b"sip"[..], b"sips", b"tel", b"tels", b"urn"].iter().any(|s| u.scheme.eq_ignore_ascii_case(s)));
        if !ok {
            return fail(416, "Unsupported URI Scheme in Request URI");
        }
    }
    if checks & bit::REQUIRED_HEADERS != 0 {
        for k in [HdrKind::From, HdrKind::To, HdrKind::CallId, HdrKind::CSeq, HdrKind::Via] {
            if get(k).is_none() {
                return fail(400, "Missing Required Header in Request");
            }
        }
    }
    if checks & (bit::VIA_SIP_VERSION | bit::VIA_PROTOCOL) != 0
        && let Some(v) = ctx.msg.via1
    {
        let raw = String::from_utf8_lossy(v.raw).to_ascii_uppercase();
        if checks & bit::VIA_SIP_VERSION != 0 && !raw.starts_with("SIP/2.0/") {
            return fail(400, "Version Not Supported (Via)");
        }
        let t = String::from_utf8_lossy(v.transport).to_ascii_uppercase();
        if checks & bit::VIA_PROTOCOL != 0 && !["UDP", "TCP", "TLS", "SCTP", "WS", "WSS"].contains(&t.as_str()) {
            return fail(400, "Transport Mismatch (Via)");
        }
    }
    if checks & (bit::CSEQ_METHOD | bit::CSEQ_VALUE) != 0
        && let Some(cs) = get(HdrKind::CSeq)
    {
        let cs = String::from_utf8_lossy(&cs).into_owned();
        let mut it = cs.split_whitespace();
        let (n, m) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        if checks & bit::CSEQ_VALUE != 0 && n.parse::<u32>().is_err() {
            return fail(400, "CSeq number is illegal");
        }
        if checks & bit::CSEQ_METHOD != 0 && is_req && method.as_deref() != Some(m.as_bytes()) {
            return fail(400, "CSeq method does not match request method");
        }
    }
    if checks & bit::CL != 0
        && ctx.src.proto == sip_core::Proto::Udp
        && let Some(cl) = get(HdrKind::ContentLength)
    {
        let n: usize = String::from_utf8_lossy(&cl).trim().parse().unwrap_or(usize::MAX);
        if n != ctx.msg.body().map_or(0, <[u8]>::len) {
            return fail(400, "Content-Length mis-match");
        }
    }
    if checks & bit::EXPIRES_VALUE != 0
        && let Some(e) = hs.iter().find(|h| h.2.eq_ignore_ascii_case(b"expires"))
        && String::from_utf8_lossy(&e.3).trim().parse::<u32>().is_err()
    {
        return fail(400, "Expires value is illegal");
    }
    if is_req
        && checks & bit::PROXY_REQUIRE != 0
        && let Some(pr) = hs.iter().find(|h| h.2.eq_ignore_ascii_case(b"proxy-require"))
    {
        // We support no extensions requiring proxy support.
        let list = String::from_utf8_lossy(&pr.3).trim().to_string();
        if !list.is_empty() {
            return Some((420, "Bad Extension", format!("Unsupported: {list}\r\n")));
        }
    }
    if checks & bit::PARSE_URIS != 0 {
        if is_req && uri_checks & 1 != 0 && parse_uri(ctx.ruri()).is_none() {
            return fail(400, "Bad Request URI");
        }
        for (bitv, k) in [(2, HdrKind::From), (4, HdrKind::To)] {
            if uri_checks & bitv != 0
                && let Some(b) = get(k)
                && parse_uri(name_addr(&b).0).is_none()
            {
                return fail(400, if k == HdrKind::From { "Bad From URI" } else { "Bad To URI" });
            }
        }
        if uri_checks & 8 != 0 {
            for c in hs.iter().filter(|h| h.4 == HdrKind::Contact) {
                for item in split_list(&c.3) {
                    let s = parse_contact(item);
                    if !s.star && parse_uri(s.uri).is_none() {
                        return fail(400, "Bad Contact URI");
                    }
                }
            }
        }
    }
    if checks & bit::DIGEST != 0 {
        for h in hs.iter().filter(|h| h.2.eq_ignore_ascii_case(b"authorization") || h.2.eq_ignore_ascii_case(b"proxy-authorization")) {
            let b = String::from_utf8_lossy(&h.3);
            if b.trim_start().to_ascii_lowercase().starts_with("digest") && !(b.contains("username") && b.contains("response")) {
                return fail(400, "Bad Credentials");
            }
        }
    }
    if checks & bit::DUPTAGS != 0 {
        for k in [HdrKind::From, HdrKind::To] {
            if let Some(b) = get(k) {
                let params = String::from_utf8_lossy(name_addr(&b).1).to_ascii_lowercase();
                if params.split(';').filter(|p| p.trim().starts_with("tag=")).count() > 1 {
                    return fail(400, "Multiple tags");
                }
            }
        }
    }
    let _ = bit::RURI_SIP_VERSION; // enforced by the parser
    None
}

impl Module for Sanity {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("default_checks", Ty::Int { min: 0, max: i64::from(u32::MAX) }, "3047", "Bitmask of checks sanity_check() runs without arguments"),
            p("uri_checks", Ty::Int { min: 0, max: i64::from(u32::MAX) }, "7", "Bitmask of URI checks sanity_check() runs without arguments"),
            p("autodrop", Ty::Bool, "true", "Stop the script when a check fails"),
            p("noreply", Ty::Bool, "false", "Don't send an error reply when a check fails"),
        ])
    }

    fn name(&self) -> &'static str {
        "sanity"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, ctx, opt, sig};
        const CHECKS: &[Param] = &[opt("checks", Int).lit(), opt("uri_checks", Int).lit()];
        // Replies too (Kamailio: request and onreply routes); a reply is never answered.
        Some(vec![
            sig(
                "sanity_check",
                "check",
                CHECKS,
                Ret::Bool,
                "Check the message is well-formed (bitmasks; default: the module settings); a failure answers a request with an error",
            )
            .allowed(ctx::ROUTE | ctx::REPLY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = || v.int().and_then(|i| u32::try_from(i).map_err(|_| format!("{name}: out of range")));
        match name {
            "default_checks" => self.default_checks.store(n()?, Ordering::Relaxed),
            "uri_checks" => self.uri_checks.store(n()?, Ordering::Relaxed),
            "autodrop" => self.autodrop.store(n()? != 0, Ordering::Relaxed),
            "noreply" => self.noreply.store(n()? != 0, Ordering::Relaxed),
            _ => return Err(format!("sanity: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        reg.export(
            "sanity",
            "sanity_check",
            |a: &[Arg]| {
                if a.len() > 2 {
                    return Err("sanity_check([checks[, uri_checks]])".into());
                }
                let n = |x: &Arg| x.int().and_then(|i| u32::try_from(i).map_err(|_| "out of range".to_string()));
                Ok((a.first().map(n).transpose()?, a.get(1).map(n).transpose()?))
            },
            move |ctx: &mut Ctx, (c, u): &(Option<u32>, Option<u32>)| {
                let checks = c.unwrap_or(me.default_checks.load(Ordering::Relaxed));
                let uri_checks = u.unwrap_or(me.uri_checks.load(Ordering::Relaxed));
                let Some((code, reason, extra)) = sanity(ctx, checks, uri_checks) else { return 1 };
                sip_core::log::log(sip_core::log::L_NOTICE, &format!("sanity: {reason} from {}", ctx.src));
                sip_core::stats::inc(sip_core::stats::counter("sanity", "failed"));
                // ACKs and replies are never answered.
                if ctx.msg.is_request() && ctx.msg.method() != Some(Method::Ack) && !me.noreply.load(Ordering::Relaxed) {
                    let _ = ctx.reply_with(code, reason, extra.as_bytes());
                }
                if me.autodrop.load(Ordering::Relaxed) { 0 } else { -1 }
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn helpers() {
        assert!(super::is_e164("+4930123456"));
        assert!(!super::is_e164("4930123456"));
        assert!(!super::is_e164("+1"));
        assert!(super::uri_eq(b"sip:Bob@EXAMPLE.com;transport=TCP", b"sip:Bob@example.com;transport=tcp"));
        assert!(!super::uri_eq(b"sip:bob@example.com", b"sip:Bob@example.com"), "user part is case-sensitive");
    }
}
