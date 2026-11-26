//! `ims_icscf`: the I-CSCF asks the HSS which S-CSCF serves a user and
//! forwards there.
//!
//! * `I_perform_user_authorization_request(route, capabilities)` — Cx UAR
//!   for a REGISTER (type 0 registration, 1 de-registration when Expires is
//!   0, 2 when `capabilities` is "1"); `$avp(uaa_return_code)` and the
//!   return value: 1 ok, -1 error, -2 user unknown, -3 identities don't
//!   match, -4 roaming not allowed.
//! * `I_perform_location_information_request(route, orig)` — Cx LIR for
//!   other requests (R-URI, or the originating identity when `orig` is
//!   "1"); `$avp(lia_return_code)`: 1 ok, -2 user unknown, -3 not
//!   registered (unregistered service), -1 error.
//! * `I_scscf_select(initial)` — `$du` = the S-CSCF from the answer
//!   (Server-Name), or the best `scscf_entry` for the returned capabilities;
//!   "1" takes the next candidate (failure_route). `I_scscf_drop()`.
//!
//! UAR and LIR don't block a worker: the transaction is suspended until
//! the HSS answers (retransmissions are absorbed meanwhile), then the
//! script goes on in the named reply route when it exists (Kamailio), else
//! right after the call. Parameters: `cxdx_dest_realm`, `cxdx_forced_peer`,
//! `scscf_entry` ("uri" or "uri;caps=1,2", repeatable; Kamailio keeps these
//! in the `s_cscf` tables).

use crate::scscf::{CxCfg, identities};
use crate::{cdp, impu_of};
use sip_core::pv::Val;
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry, TxnVars};
use sip_diameter::codes::*;
use sip_diameter::{Avp, DiameterError, Msg, Peers};
use sip_parser::uri::name_addr;
use sip_parser::{HdrFlags, HdrKind, Method};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const XAVP: &str = "icscf_list";

/// `await ims_icscf.authorize()` / `.locate()`: the answer's code.
static UAA: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy { name: "UarResult", fields: &[("code", "$avp(uaa_return_code)", sip_core::sig::FieldTy::Int)] };
static LIA: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy { name: "LirResult", fields: &[("code", "$avp(lia_return_code)", sip_core::sig::FieldTy::Int)] };

#[derive(Default)]
pub struct Icscf {
    cx: CxCfg,
    /// (S-CSCF URI, capabilities).
    entries: Mutex<Vec<(String, Vec<u32>)>>,
    peers: OnceLock<Arc<Peers>>,
    tm: OnceLock<Arc<mod_txn::Tm>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

/// Which Cx request, for the shared send / answer handling.
#[derive(Clone, Copy)]
enum Ask {
    Uar,
    Lir,
}

/// Server-Name, or capabilities, from a UAA/LIA.
fn selection(a: &Msg) -> (Option<String>, Vec<u32>, Vec<u32>) {
    let name = a.get(SERVER_NAME, V).map(|x| x.as_str().to_string()).filter(|s| !s.is_empty());
    let (mut man, mut opt) = (Vec::new(), Vec::new());
    if let Some(c) = a.get(SERVER_CAPABILITIES, V) {
        for x in c.group_avps() {
            match x.code {
                MANDATORY_CAPABILITY => man.extend(x.as_u32()),
                OPTIONAL_CAPABILITY => opt.extend(x.as_u32()),
                _ => {}
            }
        }
    }
    (name, man, opt)
}

fn set_avp(ctx: &mut Ctx<'_, '_>, name: &str, v: i64) {
    ctx.ext_mut::<TxnVars>().avps.insert(name.to_string(), vec![Val::Int(v)]);
}

impl Icscf {
    /// Candidate S-CSCFs, best first: the named one, else entries holding
    /// every mandatory capability, by optional matches.
    fn candidates(&self, name: Option<String>, man: &[u32], opt: &[u32]) -> Vec<String> {
        if let Some(n) = name {
            return vec![n];
        }
        let mut c: Vec<(usize, String)> = lock(&self.entries)
            .iter()
            .filter(|(_, caps)| man.iter().all(|m| caps.contains(m)))
            .map(|(u, caps)| (opt.iter().filter(|o| caps.contains(o)).count(), u.clone()))
            .collect();
        c.sort_by_key(|x| std::cmp::Reverse(x.0));
        c.into_iter().map(|x| x.1).collect()
    }

    fn store(&self, ctx: &mut Ctx<'_, '_>, list: Vec<String>) {
        let items = list.into_iter().map(|u| HashMap::from([("uri".to_string(), Val::Str(u))])).collect();
        ctx.ext_mut::<TxnVars>().xavps.insert(XAVP.into(), items);
    }

    /// The UAR for a REGISTER (None: not a REGISTER, or no identities).
    fn uar_msg(&self, peers: &Peers, ctx: &mut Ctx<'_, '_>, caps: bool) -> Option<Msg> {
        if ctx.msg.method() != Some(Method::Register) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return None;
        }
        let (impi, impu) = identities(ctx, b"Authorization")?;
        let m = &*ctx.msg;
        let hexp =
            m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"expires")).and_then(|h| std::str::from_utf8(h.body).ok()?.trim().parse::<u64>().ok());
        let cexp = m.get(HdrKind::Contact).and_then(|h| sip_parser::uri::parse_contact(h.body).expires);
        let dereg = cexp.map(u64::from).or(hexp) == Some(0);
        let visited = m
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"p-visited-network-id"))
            .map(|h| String::from_utf8_lossy(h.body).trim().trim_matches('"').to_string())
            .unwrap_or_else(|| peers.cfg.realm.clone());
        let mut uar = self.cx.base(peers, CMD_UAR);
        uar.add(Avp::str(USER_NAME, None, &impi)).add(Avp::str(PUBLIC_IDENTITY, V, &impu)).add(Avp::str(VISITED_NETWORK_IDENTIFIER, V, &visited)).add(
            Avp::u32(
                USER_AUTHORIZATION_TYPE,
                V,
                if dereg {
                    1
                } else if caps {
                    2
                } else {
                    0
                },
            ),
        );
        Some(uar)
    }

    /// The LIR for the R-URI, or the caller with `orig`.
    fn lir_msg(&self, peers: &Peers, ctx: &mut Ctx<'_, '_>, orig: bool) -> Option<Msg> {
        ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
        let impu = if orig {
            ctx.msg
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case(b"p-asserted-identity"))
                .or_else(|| ctx.msg.get(HdrKind::From))
                .and_then(|h| impu_of(name_addr(h.body).0))
        } else {
            impu_of(ctx.ruri())
        };
        let mut lir = self.cx.base(peers, CMD_LIR);
        lir.add(Avp::str(PUBLIC_IDENTITY, V, &impu?));
        Some(lir)
    }

    /// The answer (or why there is none) → the return code, candidates in
    /// the `icscf_list` xavp and `$avp(uaa_return_code)` /
    /// `$avp(lia_return_code)`.
    fn apply(&self, ask: Ask, res: Result<Msg, DiameterError>, ctx: &mut Ctx<'_, '_>) -> i32 {
        let rc = match (ask, res) {
            (_, Err(e)) => {
                let what = if matches!(ask, Ask::Uar) { "UAR" } else { "LIR" };
                if e.is_timeout() {
                    // Kamailio's ims_icscf counters.
                    sip_core::stats::inc(sip_core::stats::counter("ims_icscf", if matches!(ask, Ask::Uar) { "uar_timeouts" } else { "lir_timeouts" }));
                }
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_icscf: {what}: {e}"));
                -1
            }
            (Ask::Uar, Ok(a)) => match a.result() {
                Some(DIAMETER_FIRST_REGISTRATION | DIAMETER_SUBSEQUENT_REGISTRATION | DIAMETER_SERVER_SELECTION) => {
                    let (n, man, opt) = selection(&a);
                    let list = self.candidates(n, &man, &opt);
                    self.store(ctx, list);
                    1
                }
                Some(DIAMETER_ERROR_USER_UNKNOWN) => -2,
                Some(DIAMETER_ERROR_IDENTITIES_DONT_MATCH) => -3,
                Some(DIAMETER_ERROR_ROAMING_NOT_ALLOWED) => -4,
                _ => -1,
            },
            (Ask::Lir, Ok(a)) => match a.result() {
                Some(DIAMETER_SUCCESS) | Some(DIAMETER_UNREGISTERED_SERVICE) => {
                    let (n, man, opt) = selection(&a);
                    let list = self.candidates(n, &man, &opt);
                    if list.is_empty() {
                        -1
                    } else {
                        self.store(ctx, list);
                        1
                    }
                }
                Some(DIAMETER_ERROR_USER_UNKNOWN) => -2,
                Some(DIAMETER_ERROR_IDENTITY_NOT_REGISTERED) => -3,
                _ => -1,
            },
        };
        set_avp(ctx, if matches!(ask, Ask::Uar) { "uaa_return_code" } else { "lia_return_code" }, i64::from(rc));
        rc
    }

    /// UAR / LIR: suspended while the HSS answers when the request can be
    /// (see `cx_async`), else synchronously.
    fn ask(self: &Arc<Self>, ctx: &mut Ctx<'_, '_>, ask: Ask, route: &str, flag: bool) -> i32 {
        let Some(peers) = self.peers.get() else { return -1 };
        let m = match ask {
            Ask::Uar => self.uar_msg(peers, ctx, flag),
            Ask::Lir => self.lir_msg(peers, ctx, flag),
        };
        let Some(m) = m else {
            set_avp(ctx, if matches!(ask, Ask::Uar) { "uaa_return_code" } else { "lia_return_code" }, -1);
            return -1;
        };
        if let (Some(tm), Some(hub)) = (self.tm.get(), self.hub.get()) {
            let (me, me2, p) = (self.clone(), self.clone(), peers.clone());
            let m2 = m.clone();
            let sent = crate::cx_async::run(
                tm,
                hub,
                ctx,
                route,
                peers.cfg.timeout,
                move |done| me.cx.send_async(&p, m2, done),
                Box::new(move |res, c| {
                    me2.apply(ask, res, c);
                }),
            );
            if let Some(rc) = sent {
                return rc;
            }
        }
        let res = self.cx.send(peers, m);
        self.apply(ask, res, ctx)
    }

    /// `$du` = the next candidate (dropping it from the list).
    fn select(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some(items) = ctx.ext_get_mut::<TxnVars>().and_then(|v| v.xavps.get_mut(XAVP)) else { return -1 };
        while !items.is_empty() {
            let item = items.remove(0);
            let Some(Val::Str(u)) = item.get("uri") else { continue };
            if let Some(d) = sip_core::pvcore::dest_from_uri(u.as_bytes()) {
                ctx.dst = Some(d);
                return 1;
            }
        }
        -1
    }
}

impl Module for Icscf {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("cxdx_dest_realm", Ty::Str, "", "Destination realm of Cx requests (default: the cdp realm)"),
            p("cxdx_forced_peer", Ty::Str, "", "Send Cx requests to this Diameter peer"),
            p("cxdx_dest_host", Ty::Str, "", "Alias of cxdx_forced_peer"),
            p("scscf_entry", Ty::List(&Ty::Str), "", "An S-CSCF to choose from: \"uri\" or \"uri;caps=1,2\""),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_icscf"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, opt_or, sig};
        const CAPS: &[Param] = &[opt_or("capabilities", Bool, "0").lit()];
        const ORIG: &[Param] = &[opt_or("originating", Bool, "0").lit()];
        // The transaction is suspended while the HSS answers; `await`
        // continues with the result. (A Kamailio-style call continues in
        // its named reply route when the script has it.)
        Some(vec![
            sig(
                "I_perform_user_authorization_request",
                "authorize",
                CAPS,
                Ret::Await(&UAA),
                "Cx UAR for a REGISTER: `let r = await ims_icscf.authorize()`; r.code 1 ok, -2 user unknown, -3 identities don't match, -4 roaming not allowed, -1 error",
            )
            .fixed(&[""]),
            sig(
                "I_perform_location_information_request",
                "locate",
                ORIG,
                Ret::Await(&LIA),
                "Cx LIR for the R-URI (or the caller with originating): r.code 1 ok, -2 user unknown, -3 not registered, -1 error",
            )
            .fixed(&[""]),
            sig("I_scscf_select", "select_scscf", &[], Ret::Bool, "Send to the next candidate S-CSCF (from the last UAR/LIR); false: none left").fixed(&["0"]),
            sig("I_scscf_drop", "drop_scscfs", &[], Ret::Void, "Forget the remaining candidate S-CSCFs"),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        if self.cx.set(name, v)? {
            return Ok(());
        }
        match name {
            "scscf_entry" => {
                let s = v.str()?;
                let (uri, caps) = match s.split_once(";caps=") {
                    Some((u, c)) => (u, c.split(',').filter_map(|x| x.trim().parse().ok()).collect()),
                    None => (s, Vec::new()),
                };
                lock(&self.entries).push((uri.trim().to_string(), caps));
            }
            "db_url"
            | "route_lir_user_unknown"
            | "route_uar_user_unknown"
            | "scscf_entry_expiry"
            | "use_preferred_scscf_uri"
            | "preferred_scscf_uri"
            | "cxdx_dest_host" => {}
            _ => return Err(format!("ims_icscf: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.peers.set(cdp(reg, "ims_icscf")?);
        if let Some(tm) = reg.api::<mod_txn::Tm>() {
            let _ = self.tm.set(tm);
        }
        let _ = self.hub.set(reg.hub.clone());
        let m = "ims_icscf";
        // (reply route, capabilities / originating)
        let two = |a: &[Arg]| -> Result<(String, bool), String> {
            let [route, flag] = crate::args(a)?;
            Ok((route.str().unwrap_or("").to_string(), flag.int().unwrap_or(0) == 1 || flag.str().is_ok_and(|s| s == "1")))
        };
        let me = self.clone();
        reg.export(m, "I_perform_user_authorization_request", two, move |ctx: &mut Ctx, (route, caps): &(String, bool)| me.ask(ctx, Ask::Uar, route, *caps));
        let me = self.clone();
        reg.export(m, "I_perform_location_information_request", two, move |ctx: &mut Ctx, (route, orig): &(String, bool)| me.ask(ctx, Ask::Lir, route, *orig));
        let me = self.clone();
        reg.export(m, "I_scscf_select", |a: &[Arg]| sip_core::want_args(a, 1), move |ctx: &mut Ctx, _: &()| me.select(ctx));
        reg.export(
            m,
            "I_scscf_drop",
            |a: &[Arg]| sip_core::want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if let Some(v) = ctx.ext_get_mut::<TxnVars>() {
                    v.xavps.remove(XAVP);
                }
                1
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{peers, request, with_msg};

    fn icscf(entries: &[&str]) -> Icscf {
        let i = Icscf::default();
        for e in entries {
            i.set_param("scscf_entry", &Arg::Str((*e).into())).unwrap();
        }
        i
    }

    /// An answer with this Result-Code (base) or Experimental-Result-Code
    /// (3GPP), and the given selection AVPs.
    fn answer(code: u32, experimental: bool, extra: Vec<Avp>) -> Msg {
        let mut a = Msg::request(CMD_UAR, APP_CX).answer();
        if experimental {
            a.add(Avp::group(EXPERIMENTAL_RESULT, None, vec![Avp::u32(VENDOR_ID, None, 10415), Avp::u32(EXPERIMENTAL_RESULT_CODE, None, code)]));
        } else {
            a.add(Avp::u32(RESULT_CODE, None, code));
        }
        a.avps.extend(extra);
        a
    }

    fn caps(man: &[u32], opt: &[u32]) -> Avp {
        let mut v: Vec<Avp> = man.iter().map(|&c| Avp::u32(MANDATORY_CAPABILITY, V, c)).collect();
        v.extend(opt.iter().map(|&c| Avp::u32(OPTIONAL_CAPABILITY, V, c)));
        Avp::group(SERVER_CAPABILITIES, V, v)
    }

    /// (return code, the AVP the script reads, the candidate list).
    fn run(i: &Icscf, ask: Ask, res: Result<Msg, DiameterError>) -> (i32, Option<i64>, Vec<String>) {
        with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| {
            let rc = i.apply(ask, res, ctx);
            let name = if matches!(ask, Ask::Uar) { "uaa_return_code" } else { "lia_return_code" };
            let v = ctx.ext::<TxnVars>().unwrap();
            let avp = v.avps.get(name).and_then(|x| x.first()).and_then(|x| if let Val::Int(n) = x { Some(*n) } else { None });
            let list = v
                .xavps
                .get(XAVP)
                .map(|l| l.iter().filter_map(|m| if let Some(Val::Str(u)) = m.get("uri") { Some(u.clone()) } else { None }).collect())
                .unwrap_or_default();
            (rc, avp, list)
        })
    }

    #[test]
    fn uaa_result_codes() {
        let i = icscf(&["sip:scscf1.ims.test"]);
        let named = || vec![Avp::str(SERVER_NAME, V, "sip:named.ims.test")];
        // (code, experimental, return)
        let cases = [
            (2001, true, 1),
            (2002, true, 1),
            (2003, true, 1),
            (2001, false, 1),
            (5001, true, -2),
            (5002, true, -3),
            (5004, true, -4),
            (5003, false, -1),
            (5012, false, -1),
            (3002, false, -1),
        ];
        for (code, exp, want) in cases {
            let (rc, avp, list) = run(&i, Ask::Uar, Ok(answer(code, exp, named())));
            assert_eq!((rc, avp), (want, Some(i64::from(want))), "UAA {code}");
            assert_eq!(list.is_empty(), want != 1, "UAA {code}: {list:?}");
        }
        let (rc, _, list) = run(&i, Ask::Uar, Ok(answer(2001, true, named())));
        assert_eq!((rc, list), (1, vec!["sip:named.ims.test".to_string()]));
        // No answer at all.
        let (rc, avp, _) = run(&i, Ask::Uar, Err(DiameterError::Timeout { peer: None }));
        assert_eq!((rc, avp), (-1, Some(-1)));
        let (rc, _, _) = run(&i, Ask::Uar, Err(DiameterError::NoRoute { realm: "ims.test".into() }));
        assert_eq!(rc, -1);
    }

    #[test]
    fn lia_result_codes() {
        let i = icscf(&[]);
        let named = || vec![Avp::str(SERVER_NAME, V, "sip:scscf.ims.test")];
        let cases = [(2001, false, 1), (2003, true, 1), (5001, true, -2), (5003, true, -3), (5002, true, -1), (4001, false, -1)];
        for (code, exp, want) in cases {
            let (rc, avp, _) = run(&i, Ask::Lir, Ok(answer(code, exp, named())));
            assert_eq!((rc, avp), (want, Some(i64::from(want))), "LIA {code}");
        }
        // A success that names no S-CSCF, with no entry to pick: an error.
        let (rc, avp, list) = run(&i, Ask::Lir, Ok(answer(2001, false, vec![caps(&[1], &[])])));
        assert_eq!((rc, avp, list.len()), (-1, Some(-1), 0));
        // An empty Server-Name is no name.
        let (rc, _, _) = run(&i, Ask::Lir, Ok(answer(2001, false, vec![Avp::str(SERVER_NAME, V, "")])));
        assert_eq!(rc, -1);
    }

    #[test]
    fn candidates_by_capabilities() {
        let i = icscf(&["sip:a.ims;caps=1,2", "sip:b.ims;caps=1,2,3,4", "sip:c.ims;caps=2,3", "sip:d.ims", "sip:e.ims;caps= 1 , x ,3"]);
        assert_eq!(lock(&i.entries)[4], ("sip:e.ims".to_string(), vec![1, 3]));
        // (mandatory, optional, expected order)
        let cases: &[(&[u32], &[u32], &[&str])] = &[
            (&[1], &[], &["sip:a.ims", "sip:b.ims", "sip:e.ims"]),
            (&[1], &[3, 4], &["sip:b.ims", "sip:e.ims", "sip:a.ims"]),
            (&[2, 3], &[], &["sip:b.ims", "sip:c.ims"]),
            (&[], &[], &["sip:a.ims", "sip:b.ims", "sip:c.ims", "sip:d.ims", "sip:e.ims"]),
            (&[9], &[], &[]),
        ];
        for (man, opt, want) in cases {
            assert_eq!(i.candidates(None, man, opt), *want, "{man:?} {opt:?}");
        }
        assert_eq!(i.candidates(Some("sip:x".into()), &[9], &[]), ["sip:x"], "a name wins");
        let (rc, _, list) = run(&i, Ask::Uar, Ok(answer(2001, true, vec![caps(&[2], &[4])])));
        assert_eq!((rc, list), (1, vec!["sip:b.ims".to_string(), "sip:a.ims".to_string(), "sip:c.ims".to_string()]));
    }

    #[test]
    fn select_pops_candidates_in_order() {
        let i = icscf(&[]);
        with_msg(&request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", ""), |ctx| {
            assert_eq!(i.select(ctx), -1, "no list");
            i.store(ctx, vec!["not a uri".into(), "sip:192.0.2.1:6060".into(), "sip:192.0.2.2".into()]);
            assert_eq!(i.select(ctx), 1, "the bad one is skipped");
            assert_eq!(ctx.dst.map(|d| d.addr), Some("192.0.2.1:6060".parse().unwrap()));
            assert_eq!(i.select(ctx), 1);
            assert_eq!(ctx.dst.map(|d| d.addr), Some("192.0.2.2:5060".parse().unwrap()));
            assert_eq!(i.select(ctx), -1, "list used up");
        });
    }

    fn uar_avps(extra: &str, caps: bool) -> Option<(String, String, String, u32)> {
        let p = peers();
        let i = icscf(&[]);
        with_msg(&request("REGISTER", "sip:ims.test", "sip:Alice@IMS.test", extra, ""), |ctx| {
            let m = i.uar_msg(&p, ctx, caps)?;
            assert_eq!((m.cmd, m.app), (CMD_UAR, APP_CX));
            Some((
                m.get(USER_NAME, None)?.as_str(),
                m.get(PUBLIC_IDENTITY, V)?.as_str(),
                m.get(VISITED_NETWORK_IDENTIFIER, V)?.as_str(),
                m.get(USER_AUTHORIZATION_TYPE, V)?.as_u32()?,
            ))
        })
    }

    #[test]
    fn uar_authorization_type_and_identities() {
        let auth = "Authorization: Digest username=\"alice@ims.test\", realm=\"ims.test\", nonce=\"\", uri=\"sip:ims.test\", response=\"\"\n";
        let s = |x: &str| x.to_string();
        assert_eq!(uar_avps(auth, false), Some((s("alice@ims.test"), s("sip:Alice@ims.test"), s("ims.test"), 0)));
        assert_eq!(uar_avps(auth, true).map(|x| x.3), Some(2), "capabilities");
        assert_eq!(uar_avps(&format!("{auth}Expires: 0\n"), true).map(|x| x.3), Some(1), "de-registration wins");
        assert_eq!(uar_avps("Expires: 3600\n", false).map(|x| (x.0, x.3)), Some((s("Alice@ims.test"), 0)), "IMPI from the IMPU");
        let visited = uar_avps("P-Visited-Network-ID: \"other.net\"\n", false).map(|x| x.2);
        assert_eq!(visited.as_deref(), Some("other.net"));
        // Not a REGISTER: no UAR.
        let p = peers();
        assert!(with_msg(&request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", ""), |ctx| icscf(&[]).uar_msg(&p, ctx, false)).is_none());
    }

    #[test]
    fn lir_asks_for_the_callee_or_the_caller() {
        let p = peers();
        let i = icscf(&[]);
        let impu = |extra: &str, orig: bool| {
            with_msg(&request("INVITE", "sip:Bob@IMS.test;user=phone", "sip:bob@ims.test", extra, ""), |ctx| {
                i.lir_msg(&p, ctx, orig).and_then(|m| m.get(PUBLIC_IDENTITY, V).map(Avp::as_str))
            })
        };
        assert_eq!(impu("", false).as_deref(), Some("sip:Bob@ims.test"));
        assert_eq!(impu("", true).as_deref(), Some("sip:alice@ims.test"));
        assert_eq!(impu("P-Asserted-Identity: <sip:pai@ims.test>\n", true).as_deref(), Some("sip:pai@ims.test"));
        let tel = with_msg(&request("INVITE", "tel:+4930111", "tel:+4930111", "", ""), |ctx| {
            i.lir_msg(&p, ctx, false).map(|m| m.get(PUBLIC_IDENTITY, V).unwrap().as_str())
        });
        assert_eq!(tel.as_deref(), Some("tel:+4930111"));
    }

    #[test]
    fn unknown_capability_avps_are_ignored() {
        let a = answer(
            2001,
            true,
            vec![Avp::group(
                SERVER_CAPABILITIES,
                V,
                vec![Avp::u32(MANDATORY_CAPABILITY, V, 1), Avp::str(SERVER_NAME, V, "sip:x"), Avp::u32(OPTIONAL_CAPABILITY, V, 2)],
            )],
        );
        assert_eq!(selection(&a), (None, vec![1], vec![2]));
    }

    #[test]
    fn ask_without_a_request_to_send_or_an_answer() {
        let i = Arc::new(icscf(&[]));
        let reg_msg = request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", "");
        let code = |ctx: &Ctx<'_, '_>, n: &str| crate::testutil::avp_int(ctx, n);
        // Not registered with cdp.
        assert_eq!(with_msg(&reg_msg, |ctx| i.ask(ctx, Ask::Uar, "", false)), -1);
        let _ = i.peers.set(peers());
        // A UAR is for REGISTERs only; an LIR needs an IMPU.
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&invite, |ctx| (i.ask(ctx, Ask::Uar, "", false), code(ctx, "uaa_return_code"))), (-1, Some(-1)));
        let no_user = request("INVITE", "sip:ims.test", "sip:ims.test", "", "");
        assert_eq!(with_msg(&no_user, |ctx| (i.ask(ctx, Ask::Lir, "", false), code(ctx, "lia_return_code"))), (-1, Some(-1)));
        // No tm: sent and waited for; no HSS peer, so -1.
        assert_eq!(with_msg(&reg_msg, |ctx| (i.ask(ctx, Ask::Uar, "", false), code(ctx, "uaa_return_code"))), (-1, Some(-1)));
        assert_eq!(with_msg(&invite, |ctx| (i.ask(ctx, Ask::Lir, "", true), code(ctx, "lia_return_code"))), (-1, Some(-1)));
    }

    #[test]
    fn exports_and_parameters() {
        use crate::testutil::{call, fixup_err, registry, s, script};
        let i = Icscf::default();
        for ignored in ["db_url", "route_lir_user_unknown", "preferred_scscf_uri"] {
            i.set_param(ignored, &s("x")).unwrap();
        }
        i.set_param("cxdx_dest_host", &s("hss.ims.test")).unwrap();
        assert!(i.set_param("nope", &s("x")).unwrap_err().contains("unknown parameter"));
        let mut reg = registry(true);
        script(&reg.hub, &[], &["UAR_REPLY"], Box::new(|_, _| true));
        reg.load(Arc::new(icscf(&[]))).unwrap();
        assert!(fixup_err(&reg, "I_perform_user_authorization_request", &[s("")]).is_some());
        assert!(fixup_err(&reg, "I_scscf_drop", &[s("x")]).is_some());
        // With tm the request is suspended (the HSS answer resumes it).
        let reg_msg = request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", "");
        assert_eq!(with_msg(&reg_msg, |ctx| call(&reg, ctx, "I_perform_user_authorization_request", &[s("UAR_REPLY"), Arg::Int(1)])), 0);
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "I_perform_location_information_request", &[s(""), s("1")])), 0);
        // I_scscf_drop forgets the candidates.
        let picked = with_msg(&invite, |ctx| {
            assert_eq!(call(&reg, ctx, "I_scscf_drop", &[]), 1, "nothing to drop");
            Icscf::default().store(ctx, vec!["sip:192.0.2.1".into()]);
            assert_eq!(call(&reg, ctx, "I_scscf_drop", &[]), 1);
            call(&reg, ctx, "I_scscf_select", &[s("0")])
        });
        assert_eq!(picked, -1);
    }
}
