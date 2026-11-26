//! `tmx` — transaction helpers on top of tm: `t_is_failure_route()`,
//! `t_is_branch_route()`, `t_is_reply_route()`, `t_is_request_route()`,
//! `t_precheck_trans()` (1 if the request already has a transaction —
//! a retransmission), `t_flush_flags()` (flags are always carried, 1),
//! `$T_req(pv)` (evaluate on the transaction's request) and `$T_rpl(pv)`
//! (on the winning reply in failure_route, the reply in reply routes).
//!
//! `uac_redirect` — `get_redirects(max[, reason])` in a failure_route:
//! the Contacts of the 3xx (by q) become new branches; `accept_filter` /
//! `deny_filter` regexes (`default_filter` "accept"|"deny"). Returns how
//! many were added (-1 if none).

use bumpalo::Bump;
use mod_txn::Tm;
use regex::Regex;
use sip_core::module::{FailureReply, rc};
use sip_core::pv::{PvRef, PvSpec, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Branch, Ctx, Lumps, Module, Registry};
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::{HdrFlags, HdrKind, Msg};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Default)]
pub struct Tmx {
    tm: OnceLock<Arc<Tm>>,
}

/// Evaluate `pv` on `raw` (a reply) in a throwaway context.
fn eval_on(ctx: &Ctx<'_, '_>, raw: &[u8], pv: &PvRef) -> Val {
    let arena = Bump::new();
    let Ok(mut m) = Msg::parse(raw, &arena) else { return Val::Null };
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let mut c = Ctx::new(&mut m, &mut lumps, &mut out, ctx.net, None, ctx.src, ctx.worker);
    pv.get(&mut c)
}

impl Module for Tmx {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "tmx"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{Ret, ctx, hidden, sig};
        Some(vec![
            sig("t_is_failure_route", "in_failure_route", &[], Ret::Bool, "Running for a failed transaction (failure route, or after an `await`)")
                .allowed(ctx::ANY),
            sig("t_is_branch_route", "in_branch_route", &[], Ret::Bool, "Running in a branch route").allowed(ctx::ANY),
            sig("t_is_reply_route", "in_reply_route", &[], Ret::Bool, "Running for a reply").allowed(ctx::ANY),
            sig("t_is_request_route", "in_request_route", &[], Ret::Bool, "Running in the main request route").allowed(ctx::ANY),
            sig("t_precheck_trans", "is_retransmission", &[], Ret::Bool, "The request already has a transaction (a retransmission)").allowed(ctx::REQUEST),
            hidden("t_flush_flags", "message flags are always carried into the transaction: nothing to flush"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let tm = reg.api::<Tm>().ok_or("tmx needs tm loaded first")?;
        let _ = self.tm.set(tm);
        let m = "tmx";
        let none = |a: &[Arg]| sip_core::want_args(a, 0);
        reg.export(m, "t_is_failure_route", none, |ctx: &mut Ctx, _: &()| rc(Tm::in_failure_route(ctx)));
        reg.export(m, "t_is_branch_route", none, |ctx: &mut Ctx, _: &()| rc(Tm::in_branch_route(ctx)));
        reg.export(m, "t_is_reply_route", none, |ctx: &mut Ctx, _: &()| rc(!ctx.msg.is_request()));
        reg.export(m, "t_is_request_route", none, |ctx: &mut Ctx, _: &()| {
            rc(ctx.msg.is_request() && !Tm::in_failure_route(ctx) && !Tm::in_branch_route(ctx) && ctx.ext::<sip_core::module::FakedMsg>().is_none())
        });
        reg.export(m, "t_flush_flags", none, |_: &mut Ctx, _: &()| 1);
        let me = self.clone();
        reg.export(m, "t_precheck_trans", none, move |ctx: &mut Ctx, _: &()| rc(me.tm.get().and_then(|t| t.txn_of(ctx)).is_some()));
        // $T_req(pv) / $T_rpl(pv): the inner variable is parsed at startup.
        let inner = |p: &mut sip_core::pv::PvParam, t: &sip_core::pv::PvTable| -> Result<(), String> {
            p.fixed = Some(Arc::new(parse_pv(p.name.trim(), t)?));
            Ok(())
        };
        reg.pv("T_req", PvSpec::ro(|ctx, p| p.fixed::<PvRef>().map_or(Val::Null, |pv| pv.get(ctx))).with_param().with_fix(inner));
        reg.pv(
            "T_rpl",
            PvSpec::ro(|ctx, p| {
                let Some(pv) = p.fixed::<PvRef>() else { return Val::Null };
                if !ctx.msg.is_request() {
                    return pv.get(ctx);
                }
                match ctx.ext::<FailureReply>().map(|r| r.0.clone()).filter(|r| !r.is_empty()) {
                    Some(raw) => eval_on(ctx, &raw, pv),
                    None => Val::Null,
                }
            })
            .with_param()
            .with_fix(inner),
        );
        Ok(())
    }
}

// ----------------------------------------------------------- uac_redirect --

pub struct UacRedirect {
    accept: Mutex<Vec<Regex>>,
    deny: Mutex<Vec<Regex>>,
    default_accept: std::sync::atomic::AtomicBool,
}

impl Default for UacRedirect {
    fn default() -> Self {
        Self { accept: Mutex::new(vec![]), deny: Mutex::new(vec![]), default_accept: std::sync::atomic::AtomicBool::new(true) }
    }
}

impl UacRedirect {
    fn allowed(&self, uri: &str) -> bool {
        if lock(&self.deny).iter().any(|r| r.is_match(uri)) {
            return false;
        }
        lock(&self.accept).iter().any(|r| r.is_match(uri)) || self.default_accept.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn get_redirects(&self, ctx: &mut Ctx<'_, '_>, max: usize) -> i32 {
        let Some(FailureReply(raw)) = ctx.ext::<FailureReply>().cloned() else { return -1 };
        let arena = Bump::new();
        let Ok(mut m) = Msg::parse(&raw, &arena) else { return -1 };
        if !m.status().is_some_and(|c| (300..400).contains(&c)) || m.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let mut targets: Vec<(u16, Vec<u8>)> = m
            .headers
            .iter()
            .filter(|h| h.kind == HdrKind::Contact)
            .flat_map(|h| split_list(h.body))
            .map(|c| {
                let cs = parse_contact(c);
                (cs.q.unwrap_or(1000), name_addr(c).0.to_vec())
            })
            .filter(|(_, u)| sip_parser::parse_uri(u).is_some() && self.allowed(&String::from_utf8_lossy(u)))
            .collect();
        targets.sort_by_key(|t| std::cmp::Reverse(t.0));
        if max > 0 {
            targets.truncate(max);
        }
        let n = targets.len();
        for (q, uri) in targets {
            ctx.branches.push(Branch { uri, dst: None, q: Some(q), path: None, ..Default::default() });
        }
        // t_relay() in the failure route forks to the branches, not the R-URI.
        if n > 0 {
            let first = ctx.branches.remove(0);
            ctx.new_ruri = Some(first.uri);
            ctx.dst = None;
            ctx.ruri_q = first.q;
            i32::try_from(n).unwrap_or(i32::MAX)
        } else {
            -1
        }
    }
}

impl Module for UacRedirect {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("accept_filter", Ty::List(&Ty::Str), "", "Regexes of redirect Contacts to accept"),
            p("deny_filter", Ty::List(&Ty::Str), "", "Regexes of redirect Contacts to refuse (checked first)"),
            p("default_filter", Ty::Enum(&[("accept", "accept"), ("deny", "deny")]), "accept", "What happens to Contacts no filter matches"),
        ])
    }

    fn name(&self) -> &'static str {
        "uac_redirect"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let re = || Regex::new(v.str()?).map_err(|e| format!("uac_redirect: bad regex: {e}"));
        match name {
            "accept_filter" => lock(&self.accept).push(re()?),
            "deny_filter" => lock(&self.deny).push(re()?),
            "default_filter" => self.default_accept.store(v.str()? != "deny", std::sync::atomic::Ordering::Relaxed),
            "acc_function" | "acc_db_table" | "bflags" | "flags_hdr_mode" | "q_value" => {}
            _ => return Err(format!("uac_redirect: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, ctx, opt, opt_or, sig};
        const GET: &[Param] = &[opt_or("max", Int, "0"), opt("reason", Str)];
        Some(vec![
            sig("get_redirects", "add_branches", GET, Ret::Bool, "Turn the Contacts of the 3xx reply (by q, at most `max`, 0: all) into new branches")
                .allowed(ctx::FAILURE),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        reg.export(
            "uac_redirect",
            "get_redirects",
            |a: &[Arg]| -> Result<usize, String> {
                match a {
                    [max] | [max, _] => {
                        let s = match max {
                            Arg::Int(i) => i.to_string(),
                            x => x.str()?.to_string(),
                        };
                        // "max" or "max_total:max_branch"
                        Ok(s.split(':').next_back().and_then(|x| x.trim().parse().ok()).unwrap_or(0))
                    }
                    _ => Err("expected max[, reason]".into()),
                }
            },
            move |ctx: &mut Ctx, &max: &usize| me.get_redirects(ctx, max),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, pv, registry, with_ctx};

    fn tmx() -> Registry {
        let mut reg = registry(vec![]);
        reg.provide(Arc::new(Tm::default()));
        reg.load(Arc::new(Tmx::default())).unwrap();
        reg
    }

    #[test]
    fn tmx_needs_tm() {
        assert!(Arc::new(Tmx::default()).register(&mut Registry::default()).err().unwrap().contains("tm"));
    }

    #[test]
    fn route_kind_checks() {
        let reg = tmx();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            let got: Vec<i32> = ["t_is_request_route", "t_is_reply_route", "t_is_failure_route", "t_is_branch_route", "t_precheck_trans", "t_flush_flags"]
                .iter()
                .map(|f| call(&reg, ctx, f, &[]).unwrap())
                .collect();
            assert_eq!(got, [1, -1, -1, -1, -1, 1]);
            ctx.ext.push(Box::new(sip_core::module::FakedMsg));
            assert_eq!(call(&reg, ctx, "t_is_request_route", &[]).unwrap(), -1, "a faked request (event route)");
        });
        with_ctx("SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKx\nCall-ID: c\nCSeq: 1 INVITE\n\n", &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "t_is_reply_route", &[]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "t_is_request_route", &[]).unwrap(), -1);
        });
        assert!(fixup(&reg, "t_is_reply_route", &[Arg::Int(1)]).is_err());
    }

    #[test]
    fn t_req_and_t_rpl_evaluate_on_the_request_and_reply() {
        let reg = tmx();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(pv(&reg, ctx, "$T_req($ci)"), Val::str("cid-1"));
            assert_eq!(pv(&reg, ctx, "$T_rpl($rs)"), Val::Null, "no reply in a request route");
            ctx.ext.push(Box::new(FailureReply(Vec::new())));
            assert_eq!(pv(&reg, ctx, "$T_rpl($rs)"), Val::Null, "an empty reply");
            ctx.ext.retain(|e| !e.is::<FailureReply>());
            ctx.ext.push(Box::new(FailureReply(b"SIP/2.0 486 Busy Here\r\nCall-ID: c\r\n\r\n".to_vec())));
            assert_eq!(pv(&reg, ctx, "$T_rpl($rr)"), Val::str("Busy Here"));
            ctx.ext.retain(|e| !e.is::<FailureReply>());
            ctx.ext.push(Box::new(FailureReply(b"\x00garbage".to_vec())));
            assert_eq!(pv(&reg, ctx, "$T_rpl($rr)"), Val::Null, "unparsable");
        });
        with_ctx("SIP/2.0 180 Ringing\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKx\nCall-ID: c\nCSeq: 1 INVITE\n\n", &FakeNet(None), |ctx| {
            assert_eq!(pv(&reg, ctx, "$T_rpl($rr)"), Val::str("Ringing"), "a reply route: the reply itself");
        });
    }

    fn redirect(filters: &[(&str, &str)]) -> Registry {
        let r = UacRedirect::default();
        for (k, v) in filters {
            r.set_param(k, &Arg::Str(v.to_string())).unwrap();
        }
        registry(vec![Arc::new(r)])
    }

    const MOVED: &[u8] = b"SIP/2.0 302 Moved\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKx\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\n\
Contact: <sip:low@x>;q=0.1, <sip:high@x>;q=0.9\r\nContact: <sip:mid@y>;q=0.5, <sip:none@deny.example>, <nonsense>\r\n\r\n";

    /// get_redirects(args) on a request whose failure reply is `reply`:
    /// (return code, new R-URI, branch URIs).
    fn redirects(reg: &Registry, reply: &[u8], args: &[&str]) -> (i32, Option<String>, Vec<String>) {
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            ctx.ext.push(Box::new(FailureReply(reply.to_vec())));
            let rc = call(reg, ctx, "get_redirects", args).unwrap();
            let s = |u: &[u8]| String::from_utf8_lossy(u).into_owned();
            (rc, ctx.new_ruri.as_deref().map(s), ctx.branches.iter().map(|b| s(&b.uri)).collect())
        })
    }

    #[test]
    fn get_redirects_orders_by_q_and_applies_max_and_filters() {
        let reg = redirect(&[("deny_filter", "deny\\.example")]);
        let (rc, ruri, br) = redirects(&reg, MOVED, &["0"]);
        assert_eq!((rc, ruri.as_deref(), br), (3, Some("sip:high@x"), vec!["sip:mid@y".to_string(), "sip:low@x".to_string()]));
        let (rc, ruri, br) = redirects(&reg, MOVED, &["2", "reason"]);
        assert_eq!((rc, ruri.as_deref(), br.len()), (2, Some("sip:high@x"), 1), "max 2");
        assert_eq!(redirects(&reg, MOVED, &["5:1"]).0, 1, "max_total:max_branch: the last number");
        let reg = redirect(&[("default_filter", "deny"), ("accept_filter", "@y$")]);
        assert_eq!(redirects(&reg, MOVED, &["0"]).0, 1, "only the accepted Contact");
        let reg = redirect(&[("default_filter", "deny")]);
        assert_eq!(redirects(&reg, MOVED, &["0"]), (-1, None, vec![]), "every Contact denied");
    }

    #[test]
    fn get_redirects_needs_a_3xx_failure_reply() {
        let reg = redirect(&[]);
        let busy = b"SIP/2.0 486 Busy\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKx\r\nContact: <sip:a@b>\r\n\r\n";
        assert_eq!(redirects(&reg, busy, &["0"]).0, -1);
        assert_eq!(redirects(&reg, b"garbage", &["0"]).0, -1);
        with_ctx(&invite(""), &FakeNet(None), |ctx| assert_eq!(call(&reg, ctx, "get_redirects", &["0"]).unwrap(), -1, "no failure reply"));
        assert!(fixup(&reg, "get_redirects", &[]).is_err());
        assert!(fixup(&reg, "get_redirects", &[Arg::Int(1), Arg::Int(2), Arg::Int(3)]).is_err());
        assert!(fixup(&reg, "get_redirects", &[Arg::Int(1)]).is_ok());
    }

    #[test]
    fn uac_redirect_parameters() {
        let r = UacRedirect::default();
        assert!(r.set_param("acc_function", &Arg::Str("x".into())).is_ok());
        assert!(r.set_param("q_value", &Arg::Int(10)).is_ok());
        assert!(r.set_param("nope", &Arg::Int(1)).is_err());
        assert!(r.set_param("accept_filter", &Arg::Str("(".into())).is_err());
    }
}
