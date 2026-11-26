//! `rr` (Record-Route, loose routing — RFC 3261 §16.6/§16.12) and `path`
//! (RFC 3327 Path for REGISTERs through edge proxies).
//!
//! `record_route()` only *requests* the header: tm renders it per branch
//! once the outgoing transport is known (`sip_core::rr`), so double
//! Record-Route (`enable_double_rr`, one entry per interface, `;r2=on`) is
//! right when a call crosses from UDP to TCP/TLS/WS or between interfaces.

use crate::{ListItem, args, list_items, unescape, uri_dest, uri_is_myself};
use regex::Regex;
use sip_core::module::{DynStr, rc};
use sip_core::pv::PvSpec;
use sip_core::rr::{PendingParams, RecordRoute, RrEntry, RrKind};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::{Arg, Ctx, Module, Registry, Val, want_args};
use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// What `loose_route()` consumed: our Route URI and its parameters.
#[derive(Clone, Debug, Default)]
struct RouteInfo {
    uri: String,
    params: String,
}

pub struct Rr {
    double: AtomicBool,
    append_fromtag: AtomicBool,
    full_lr: AtomicBool,
}

impl Default for Rr {
    fn default() -> Self {
        Self { double: AtomicBool::new(true), append_fromtag: AtomicBool::new(true), full_lr: AtomicBool::new(false) }
    }
}

fn from_tag(ctx: &mut Ctx<'_, '_>) -> Option<String> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let h = ctx.msg.get(HdrKind::From)?;
    param(name_addr(h.body).1, b"tag").map(|t| String::from_utf8_lossy(t).into_owned())
}

fn split_params(s: &str) -> Vec<String> {
    s.split(';').map(str::trim).filter(|p| !p.is_empty()).map(String::from).collect()
}

impl Rr {
    fn add(&self, ctx: &mut Ctx<'_, '_>, kind: RrKind, extra: &str) -> i32 {
        if !ctx.msg.is_request() {
            return -1;
        }
        let mut params = Vec::new();
        if self.append_fromtag.load(Ordering::Relaxed)
            && let Some(t) = from_tag(ctx)
        {
            params.push(format!("ftag={t}"));
        }
        params.extend(split_params(extra));
        if let Some(p) = ctx.ext_get_mut::<PendingParams>() {
            params.append(&mut p.0);
        }
        let full_lr = self.full_lr.load(Ordering::Relaxed);
        // RFC 5626: an edge proxy names the client's flow in its RR user part.
        let user = if matches!(kind, RrKind::Auto { .. }) && sip_core::flow::wanted(ctx) {
            params.push("ob".into());
            sip_core::flow::encode(&ctx.src)
        } else {
            None
        };
        ctx.ext_mut::<RecordRoute>().0.push(RrEntry { header: "Record-Route", kind, params, full_lr, user });
        1
    }

    /// Route processing (RFC 3261 §16.4 / §16.12): drop our own Route
    /// entries (two with `;r2=on`), then the next hop is the next Route, or
    /// the R-URI when none is left.
    fn loose_route(ctx: &mut Ctx<'_, '_>) -> i32 {
        let routes = list_items(ctx, HdrKind::Route, b"");
        let Some(first) = routes.first() else { return -1 };
        if !uri_is_myself(ctx.net, &first.uri) {
            // Pre-loaded Route to someone else: send there.
            match uri_dest(&first.uri) {
                Some(d) => ctx.dst = Some(d),
                None => return -1,
            }
            return 1;
        }
        let r2 = parse_uri(&first.uri).is_some_and(|u| u.param(b"r2").is_some());
        let used = match routes.get(1) {
            Some(second) if r2 && uri_is_myself(ctx.net, &second.uri) => 2,
            _ => 1,
        };
        // uri_is_myself() already parsed it.
        let Some(u) = parse_uri(&first.uri) else { return -1 };
        let received = u.param(b"received").map(unescape);
        // RFC 5626: our own Path/RR with a flow token → that flow (unless
        // the request comes from it).
        let flow = u.user.and_then(|t| sip_core::flow::decode(&String::from_utf8_lossy(t))).filter(|f| f.addr != ctx.src.addr);
        let info = RouteInfo { uri: String::from_utf8_lossy(&first.uri).into_owned(), params: String::from_utf8_lossy(u.params).into_owned() };
        remove_items(ctx, &routes, used);
        let rest = routes.get(used..).unwrap_or_default();
        *ctx.ext_mut::<RouteInfo>() = info;
        if let Some(next) = rest.first() {
            if let Some(d) = uri_dest(&next.uri) {
                ctx.dst = Some(d);
            }
        } else if let Some(f) = flow {
            ctx.dst = Some(f);
        } else if let Some(d) = received.as_deref().and_then(uri_dest) {
            // path's add_path_received(): the client behind NAT.
            ctx.dst = Some(d);
        }
        1
    }

    fn is_direction(ctx: &mut Ctx<'_, '_>, downstream: bool) -> i32 {
        let Some(ri) = ctx.ext::<RouteInfo>() else { return -1 };
        let Some(ftag) = param(ri.params.as_bytes(), b"ftag").map(<[u8]>::to_vec) else { return -1 };
        let Some(tag) = from_tag(ctx) else { return -1 };
        // From tag == ftag: same direction as the initial request.
        rc((tag.as_bytes() == ftag.as_slice()) == downstream)
    }
}

/// Remove the first `n` Route entries: delete every Route line and put the
/// remaining entries back as one header where the first one was.
fn remove_items(ctx: &mut Ctx<'_, '_>, items: &[ListItem], n: usize) {
    let mut lines: Vec<usize> = items.iter().map(|i| i.hdr).collect();
    lines.dedup();
    let Some(at) = lines.first().and_then(|&first| ctx.msg.headers.get(first)).map(|h| h.start) else { return };
    for h in lines.iter().filter_map(|&l| ctx.msg.headers.get(l)) {
        ctx.lumps.delete(h.start, h.end.saturating_sub(h.start));
    }
    let rest = items.get(n..).unwrap_or_default();
    if !rest.is_empty() {
        let mut v = b"Route: ".to_vec();
        for (i, it) in rest.iter().enumerate() {
            if i > 0 {
                v.push(b',');
            }
            v.extend_from_slice(&it.text);
        }
        v.extend_from_slice(b"\r\n");
        ctx.lumps.insert(at, v);
    }
}

impl Module for Rr {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("enable_double_rr", Ty::Bool, "true", "Two Record-Route headers when changing transport or interface"),
            p("append_fromtag", Ty::Bool, "true", "ftag parameter in Record-Route"),
            p("enable_full_lr", Ty::Bool, "false", "Write lr=on instead of lr"),
        ])
    }

    fn name(&self) -> &'static str {
        "rr"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const PARAMS: &[Param] = &[opt("params", Str).eg("\";p=1\"")];
        const PRESET: &[Param] = &[arg("address", Str).eg("\"127.0.0.1:5060\""), opt("second", Str).eg("\"10.0.0.1:5060\"")];
        const ADDRESS: &[Param] = &[arg("address", Str).eg("\"127.0.0.1:5060\"")];
        const PARAM: &[Param] = &[arg("params", Str).eg("\";p=1\"")];
        const REGEX: &[Param] = &[arg("regex", Str).lit().eg("\"p=1\"")];
        const DIRECTION: &[Param] = &[arg("direction", Enum(&["downstream", "upstream"])).lit()];
        Some(vec![
            sig("record_route", "record", PARAMS, Ret::Void, "Add a Record-Route header (twice when changing transport or interface), with extra `;params`"),
            sig("record_route_preset", "record_preset", PRESET, Ret::Void, "Add a Record-Route with this address (two given: one per interface, with r2)"),
            sig("record_route_advertised_address", "record_advertised", ADDRESS, Ret::Void, "Add a Record-Route with this advertised address"),
            sig("add_rr_param", "add_param", PARAM, Ret::Void, "Add `;params` to the Record-Route this request gets"),
            sig("remove_record_route", "remove_record", &[], Ret::Void, "Drop the Record-Route headers added so far"),
            sig("loose_route", "follow", &[], Ret::Bool, "Route by the Route headers (in-dialog or preloaded); false when there are none for us")
                .allowed(ctx::REQUEST),
            sig("loose_route_preloaded", "follow_preloaded", &[], Ret::Bool, "Follow a preloaded Route set (only initial requests, without a To tag)")
                .allowed(ctx::REQUEST),
            sig("check_route_param", "has_param", REGEX, Ret::Bool, "The parameters of our Route header match this regex (after `follow`)")
                .allowed(ctx::REQUEST),
            sig("is_direction", "is_direction", DIRECTION, Ret::Bool, "The in-dialog request goes downstream (caller to callee) or upstream (needs ftag)")
                .allowed(ctx::REQUEST),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let b = v.int()? != 0;
        match name {
            "enable_double_rr" => self.double.store(b, Ordering::Relaxed),
            "append_fromtag" => self.append_fromtag.store(b, Ordering::Relaxed),
            "enable_full_lr" => self.full_lr.store(b, Ordering::Relaxed),
            _ => return Err(format!("rr: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "rr";
        let me = self.clone();
        reg.export(
            m,
            "record_route",
            |a: &[Arg]| -> Result<Option<DynStr>, String> {
                match a {
                    [] => Ok(None),
                    [params] => Ok(Some(params.dyn_str()?)),
                    _ => Err("expected at most 1 argument".into()),
                }
            },
            move |ctx: &mut Ctx, p: &Option<DynStr>| {
                let extra = p.as_ref().map(|p| p.eval(ctx).into_owned()).unwrap_or_default();
                let double = me.double.load(Ordering::Relaxed);
                me.add(ctx, RrKind::Auto { double }, &extra)
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "record_route_preset",
            |a: &[Arg]| -> Result<Vec<DynStr>, String> {
                if a.is_empty() || a.len() > 2 {
                    return Err("expected 1 or 2 arguments".into());
                }
                a.iter().map(Arg::dyn_str).collect()
            },
            move |ctx: &mut Ctx, p: &Vec<DynStr>| {
                let v: Vec<String> = p.iter().map(|d| d.eval(ctx).into_owned()).collect();
                // With two values the second one gets the r2 flag (and so
                // does the first), as Kamailio does.
                let v = if v.len() == 2 { v.into_iter().map(|s| format!("{s};r2=on")).collect() } else { v };
                me.add(ctx, RrKind::Preset(v), "")
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "record_route_advertised_address",
            |a: &[Arg]| {
                let [p] = args(a)?;
                p.dyn_str()
            },
            move |ctx: &mut Ctx, p: &DynStr| {
                let v = p.eval(ctx).into_owned();
                me.add(ctx, RrKind::Preset(vec![v]), "")
            },
        );
        reg.export(
            m,
            "add_rr_param",
            |a: &[Arg]| {
                let [p] = args(a)?;
                p.dyn_str()
            },
            |ctx: &mut Ctx, p: &DynStr| {
                let ps = split_params(&p.eval(ctx));
                sip_core::rr::add_params(ctx, ps);
                1
            },
        );
        reg.export(
            m,
            "remove_record_route",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if let Some(rr) = ctx.ext_get_mut::<RecordRoute>() {
                    rr.0.clear();
                }
                1
            },
        );
        reg.export(m, "loose_route", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| Rr::loose_route(ctx));
        // loose_route_preloaded(): only for initial requests (no To tag).
        reg.export(
            m,
            "loose_route_preloaded",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                let has_totag =
                    ctx.msg.parse_headers(HdrFlags::EOH).is_ok() && ctx.msg.get(HdrKind::To).is_some_and(|h| param(name_addr(h.body).1, b"tag").is_some());
                if has_totag { -1 } else { Rr::loose_route(ctx) }
            },
        );
        reg.export(
            m,
            "check_route_param",
            |a: &[Arg]| {
                let [re] = args(a)?;
                Regex::new(re.str()?).map_err(|e| format!("bad regex: {e}"))
            },
            |ctx: &mut Ctx, re: &Regex| rc(ctx.ext::<RouteInfo>().is_some_and(|r| re.is_match(&r.params))),
        );
        reg.export(
            m,
            "is_direction",
            |a: &[Arg]| {
                let [direction] = args(a)?;
                match direction.str()? {
                    "downstream" => Ok(true),
                    "upstream" => Ok(false),
                    d => Err(format!("is_direction: {d:?} is not downstream|upstream")),
                }
            },
            |ctx: &mut Ctx, &down: &bool| Rr::is_direction(ctx, down),
        );
        reg.pv("route_uri", PvSpec::ro(|ctx, _| ctx.ext::<RouteInfo>().map_or(Val::Null, |r| Val::str(&r.uri))));
        Ok(())
    }
}

// ------------------------------------------------------------------ path ---

#[derive(Default)]
pub struct PathMod {
    use_received: AtomicBool,
}

impl PathMod {
    fn add(ctx: &mut Ctx<'_, '_>, user: Option<String>, received: bool) -> i32 {
        if !ctx.msg.is_request() {
            return -1;
        }
        let mut params = Vec::new();
        let user = match user {
            None if sip_core::flow::wanted(ctx) => {
                params.push("ob".into());
                sip_core::flow::encode(&ctx.src)
            }
            u => u,
        };
        if received {
            // Escaped, so the value survives as one URI parameter.
            let mut r = sip_core::pvcore::dest_to_uri(&ctx.src);
            r = r.replace(';', "%3B").replace('=', "%3D");
            params.push(format!("received={r}"));
        }
        ctx.ext_mut::<RecordRoute>().0.push(RrEntry { header: "Path", kind: RrKind::Auto { double: false }, params, full_lr: false, user });
        1
    }
}

impl Module for PathMod {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "path"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, ctx, opt, sig};
        const USER: &[Param] = &[opt("user", Str)];
        Some(vec![
            sig("add_path", "add", USER, Ret::Bool, "Add a Path header for this proxy to a REGISTER (with this user part)").allowed(ctx::REQUEST),
            sig("add_path_received", "add_received", USER, Ret::Bool, "Add a Path header with the source address as `;received`").allowed(ctx::REQUEST),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            // loose_route() always honours `;received` on our own Route.
            "use_received" => self.use_received.store(v.int()? != 0, Ordering::Relaxed),
            "enable_r2" | "sockname_mode" => {}
            _ => return Err(format!("path: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let user_fix = |a: &[Arg]| -> Result<Option<DynStr>, String> {
            match a {
                [] => Ok(None),
                [user] => Ok(Some(user.dyn_str()?)),
                _ => Err("expected at most 1 argument".into()),
            }
        };
        reg.export("path", "add_path", user_fix, |ctx: &mut Ctx, u: &Option<DynStr>| {
            let user = u.as_ref().map(|u| u.eval(ctx).into_owned());
            PathMod::add(ctx, user, false)
        });
        reg.export("path", "add_path_received", user_fix, |ctx: &mut Ctx, u: &Option<DynStr>| {
            let user = u.as_ref().map(|u| u.eval(ctx).into_owned());
            PathMod::add(ctx, user, true)
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeNet, rendered, request, udp, with_ctx};
    use sip_core::{Dest, Proto};

    /// We listen on 192.0.2.10:5060.
    fn us() -> FakeNet {
        FakeNet(vec!["192.0.2.10:5060".parse().unwrap()])
    }

    /// loose_route() on a BYE with `routes` (header lines); returns the
    /// code, the next hop, the Route lines left and the consumed params.
    fn route(routes: &str) -> (i32, Option<Dest>, Vec<String>, Option<String>) {
        let net = us();
        let m = request("BYE", "sip:bob@198.51.100.20:5062", routes);
        with_ctx(&m, udp("203.0.113.1:5060"), &net, |ctx| {
            let rc = Rr::loose_route(ctx);
            let out = rendered(ctx);
            let left = out.lines().filter(|l| l.starts_with("Route:")).map(String::from).collect();
            (rc, ctx.dst, left, ctx.ext::<RouteInfo>().map(|r| r.params.clone()))
        })
    }

    fn addr(d: Option<Dest>) -> Option<(Proto, String)> {
        d.map(|d| (d.proto, d.addr.to_string()))
    }

    #[test]
    fn loose_route_without_route_headers_is_minus_one() {
        assert_eq!(route(""), (-1, None, vec![], None));
    }

    #[test]
    fn loose_route_follows_a_foreign_top_route_untouched() {
        let (rc, dst, left, info) = route("Route: <sip:198.51.100.1:5070;lr>\n");
        assert_eq!((rc, addr(dst)), (1, Some((Proto::Udp, "198.51.100.1:5070".into()))));
        assert_eq!(left, ["Route: <sip:198.51.100.1:5070;lr>"], "not ours: not removed");
        assert_eq!(info, None);
        // Our IP on a port we don't listen on is not us either.
        let (rc, dst, left, _) = route("Route: <sip:192.0.2.10:5070;lr>\n");
        assert_eq!((rc, addr(dst), left.len()), (1, Some((Proto::Udp, "192.0.2.10:5070".into())), 1));
    }

    #[test]
    fn loose_route_removes_our_entry_and_sends_to_the_next() {
        let (rc, dst, left, info) = route("Route: <sip:192.0.2.10;lr;ftag=ft>, <sip:198.51.100.1:5080;transport=tcp;lr>\n");
        assert_eq!((rc, addr(dst)), (1, Some((Proto::Tcp, "198.51.100.1:5080".into()))));
        assert_eq!(left, ["Route: <sip:198.51.100.1:5080;transport=tcp;lr>"]);
        assert_eq!(info.as_deref(), Some("lr;ftag=ft"));
    }

    #[test]
    fn loose_route_removes_both_entries_of_an_r2_pair() {
        let (rc, dst, left, _) = route(
            "Route: <sip:192.0.2.10;r2=on;lr>\nRoute: <sip:192.0.2.10:5060;transport=tcp;r2=on;lr>\nRoute: <sip:198.51.100.1;lr>, <sip:198.51.100.2;lr>\n",
        );
        assert_eq!((rc, addr(dst)), (1, Some((Proto::Udp, "198.51.100.1:5060".into()))));
        assert_eq!(left, ["Route: <sip:198.51.100.1;lr>,<sip:198.51.100.2;lr>"], "the rest as one header");
        // r2, but the second entry is someone else's: only ours goes.
        let (_, dst, left, _) = route("Route: <sip:192.0.2.10;r2=on;lr>, <sip:198.51.100.1;r2=on;lr>\n");
        assert_eq!(addr(dst), Some((Proto::Udp, "198.51.100.1:5060".into())));
        assert_eq!(left, ["Route: <sip:198.51.100.1;r2=on;lr>"]);
    }

    #[test]
    fn loose_route_last_own_entry_leaves_the_ruri_or_received() {
        let (rc, dst, left, _) = route("Route: <sip:192.0.2.10;lr>\n");
        assert_eq!((rc, dst.is_none(), left.len()), (1, true, 0), "next hop: the R-URI");
        let (rc, dst, left, _) = route("Route: <sip:192.0.2.10;lr;received=sip:203.0.113.7:40000%3Btransport%3Dtcp>\n");
        assert_eq!((rc, addr(dst), left.len()), (1, Some((Proto::Tcp, "203.0.113.7:40000".into())), 0));
    }

    #[test]
    fn is_direction_compares_the_from_tag_with_ftag() {
        let net = us();
        let run = |from_tag: &str, down: bool| {
            let m = request("BYE", "sip:bob@198.51.100.20", "Route: <sip:192.0.2.10;lr;ftag=ft>\n").replace("tag=ft", &format!("tag={from_tag}"));
            with_ctx(&m, udp("203.0.113.1:5060"), &net, |ctx| {
                assert_eq!(Rr::is_direction(ctx, down), -1, "before loose_route()");
                Rr::loose_route(ctx);
                Rr::is_direction(ctx, down)
            })
        };
        // request() puts tag=ft in From; the Route's ftag=ft stays as is
        // only when from_tag is "ft".
        assert_eq!(run("ft", true), 1);
        assert_eq!(run("ft", false), -1);
        let m = request("BYE", "sip:bob@198.51.100.20", "Route: <sip:192.0.2.10;lr;ftag=xx>\n");
        with_ctx(&m, udp("203.0.113.1:5060"), &net, |ctx| {
            Rr::loose_route(ctx);
            assert_eq!((Rr::is_direction(ctx, false), Rr::is_direction(ctx, true)), (1, -1), "the callee's request: upstream");
        });
        let m = request("BYE", "sip:bob@198.51.100.20", "Route: <sip:192.0.2.10;lr>\n");
        with_ctx(&m, udp("203.0.113.1:5060"), &net, |ctx| {
            Rr::loose_route(ctx);
            assert_eq!(Rr::is_direction(ctx, true), -1, "no ftag");
        });
    }

    #[test]
    fn record_route_parameters_in_order() {
        let net = us();
        let rr = Rr::default();
        with_ctx(&request("INVITE", "sip:bob@b.example", ""), udp("203.0.113.1:5060"), &net, |ctx| {
            ctx.ext_mut::<PendingParams>().0.push("did=d1".into());
            assert_eq!(rr.add(ctx, RrKind::Auto { double: true }, " ;a=1;; b "), 1);
            let e = &ctx.ext::<RecordRoute>().unwrap().0;
            assert_eq!(e.len(), 1);
            assert_eq!(e[0].params, ["ftag=ft", "a=1", "b", "did=d1"]);
            assert!(!e[0].full_lr && e[0].user.is_none() && e[0].header == "Record-Route");
            assert!(ctx.ext::<PendingParams>().unwrap().0.is_empty(), "pending params are taken");
        });
        rr.set_param("append_fromtag", &Arg::Int(0)).unwrap();
        rr.set_param("enable_full_lr", &Arg::Int(1)).unwrap();
        with_ctx(&request("INVITE", "sip:bob@b.example", ""), udp("203.0.113.1:5060"), &net, |ctx| {
            rr.add(ctx, RrKind::Preset(vec!["10.0.0.1".into()]), "");
            let e = &ctx.ext::<RecordRoute>().unwrap().0[0];
            assert!(e.params.is_empty() && e.full_lr);
        });
        let reply = "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>;tag=2\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n";
        with_ctx(reply, udp("203.0.113.1:5060"), &net, |ctx| {
            assert_eq!(rr.add(ctx, RrKind::Auto { double: false }, ""), -1, "not on a reply");
            assert_eq!(PathMod::add(ctx, None, false), -1);
        });
        assert!(rr.set_param("bogus", &Arg::Int(1)).is_err());
    }

    #[test]
    fn add_path_received_escapes_the_source_uri() {
        let net = us();
        let m = request("REGISTER", "sip:b.example", "");
        with_ctx(&m, Dest::new(Proto::Tcp, "203.0.113.7:40000".parse().unwrap()), &net, |ctx| {
            assert_eq!(PathMod::add(ctx, Some("edge".into()), true), 1);
            assert_eq!(PathMod::add(ctx, None, false), 1);
            let e = &ctx.ext::<RecordRoute>().unwrap().0;
            assert_eq!(e[0].header, "Path");
            assert_eq!(e[0].user.as_deref(), Some("edge"));
            assert_eq!(e[0].params, ["received=sip:203.0.113.7:40000%3Btransport%3Dtcp"]);
            assert!(e[1].params.is_empty() && e[1].user.is_none());
            assert!(matches!(e[0].kind, RrKind::Auto { double: false }));
        });
    }
}
