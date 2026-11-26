//! `ims_isc` — the ISC interface: evaluate the served user's initial
//! filter criteria and route the request to the matching application
//! server, with a Route back to us that remembers where to continue.
//!
//! `isc_match_filter(direction, "location")` (direction `orig` / `term`):
//! the served user is the P-Asserted-Identity / From (orig) or the R-URI
//! (term) in ims_usrloc_scscf; the first iFC (by priority, after the one
//! the request came back from) whose trigger point matches gets the
//! request: `Route: <AS;lr>, <sip:us;lr;s=N;d=direction>` and `$du` = AS.
//! 1 when routed (then `t_relay()`), -1 when nothing (more) matches.
//! `isc_from_as(direction)` is 1 for a request coming back from an AS.

use crate::impu_of;
use crate::scscf::UsrlocScscf;
use crate::subscription::Request;
use sip_core::module::rc;
use sip_core::schema::ParamSpec;
use sip_core::{Arg, Ctx, Module, Registry};
use sip_parser::uri::{name_addr, param, split_list};
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::sync::{Arc, OnceLock};

#[derive(Default)]
pub struct Isc {
    ul: OnceLock<Arc<UsrlocScscf>>,
}

/// `(s, d)` of our own Route URI at the top, if the request came back from an AS.
fn our_mark(ctx: &mut Ctx<'_, '_>) -> Option<(usize, String)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let routes: Vec<Vec<u8>> =
        ctx.msg.headers.iter().filter(|h| h.kind == HdrKind::Route).flat_map(|h| split_list(h.body)).map(|r| name_addr(r).0.to_vec()).collect();
    for r in routes {
        let u = parse_uri(&r)?;
        if !sip_core::net::is_myself(ctx.net, &String::from_utf8_lossy(u.host)) {
            continue;
        }
        let s = u.param(b"s").and_then(|s| std::str::from_utf8(s).ok()?.parse().ok())?;
        let d = u.param(b"d").map(|d| String::from_utf8_lossy(d).into_owned()).unwrap_or_default();
        return Some((s, d));
    }
    None
}

impl Isc {
    fn served_user(ctx: &mut Ctx<'_, '_>, orig: bool) -> Option<String> {
        ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
        if !orig {
            return impu_of(ctx.ruri());
        }
        let pai = ctx
            .msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"p-asserted-identity"))
            .and_then(|h| impu_of(name_addr(split_list(h.body).first().copied().unwrap_or(b"")).0));
        pai.or_else(|| ctx.msg.get(HdrKind::From).and_then(|h| impu_of(name_addr(h.body).0)))
    }

    fn match_filter(&self, ctx: &mut Ctx<'_, '_>, dir: &str) -> i32 {
        let orig = dir.starts_with("orig");
        let Some(ul) = self.ul.get() else { return -1 };
        let Some(user) = Self::served_user(ctx, orig) else { return -1 };
        let Some(rec) = ul.get(&user) else { return -1 };
        let skip = our_mark(ctx).filter(|(_, d)| d == dir).map_or(0, |(s, _)| s);
        let session_case = match (orig, rec.registered) {
            (true, true) => 0,
            (true, false) => 3,
            (false, true) => 1,
            (false, false) => 2,
        };
        let method = match ctx.msg.first {
            sip_parser::FirstLine::Request { method_raw, .. } => String::from_utf8_lossy(method_raw).into_owned(),
            _ => return -1,
        };
        let ruri = String::from_utf8_lossy(ctx.ruri()).into_owned();
        let headers: Vec<(String, String)> =
            ctx.msg.headers.iter().map(|h| (String::from_utf8_lossy(h.name).into_owned(), String::from_utf8_lossy(h.body).into_owned())).collect();
        let body = String::from_utf8_lossy(&ctx.body()).into_owned();
        let req = Request { method: &method, ruri: &ruri, headers: &headers, body: &body, session_case };
        let Some((idx, ifc)) = rec.sub.ifcs.iter().enumerate().skip(skip).find(|(_, f)| f.matches(&req)) else { return -1 };
        let Some(as_dest) = sip_core::pvcore::dest_from_uri(ifc.server.as_bytes()) else { return -1 };
        let me = ctx.advertise(ctx.src.proto);
        let route = format!("Route: <{};lr>, <sip:{me};lr;s={};d={dir}>\r\n", ifc.server.trim_end_matches(";lr"), idx.saturating_add(1));
        let at = ctx.msg.first_line_end;
        ctx.lumps.insert(at, route.into_bytes());
        ctx.dst = Some(as_dest);
        1
    }
}

impl Module for Isc {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "ims_isc"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, sig};
        const DIR: &[Param] = &[arg("direction", Enum(&["orig", "term"])).lit()];
        Some(vec![
            sig("isc_match_filter", "match_filter", DIR, Ret::Bool, "Route to the next application server whose initial filter criteria match"),
            sig("isc_from_as", "from_as", DIR, Ret::Bool, "The request came back from an application server for this direction"),
        ])
    }

    fn set_param(&self, _name: &str, _v: &Arg) -> Result<(), String> {
        Ok(()) // isc_my_uri, expires_grace, add_p_served_user …
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.ul.set(reg.api::<UsrlocScscf>().ok_or("ims_isc needs ims_usrloc_scscf loaded first")?);
        let me = self.clone();
        reg.export(
            "ims_isc",
            "isc_match_filter",
            |a: &[Arg]| match a {
                [dir] | [dir, _] => Ok(dir.str()?.to_string()),
                _ => Err("expected direction[, \"location\"]".to_string()),
            },
            move |ctx: &mut Ctx, dir: &String| me.match_filter(ctx, dir),
        );
        reg.export(
            "ims_isc",
            "isc_from_as",
            |a: &[Arg]| {
                let [dir] = crate::args(a)?;
                Ok(dir.str()?.to_string())
            },
            |ctx: &mut Ctx, dir: &String| rc(our_mark(ctx).is_some_and(|(_, d)| &d == dir)),
        );
        let _ = param(b"", b"");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scscf::ImpuRecord;
    use crate::testutil::{Here, call, fixup_err, registry, rendered, reply_msg, request, s, with_msg, with_msg_on};

    /// Alice's filters: INVITE while originating-registered → AS 1; every
    /// request → AS 2.
    const IFCS: &str = "<IMSSubscription><ServiceProfile><PublicIdentity><Identity>sip:alice@ims.test</Identity></PublicIdentity>\
        <InitialFilterCriteria><Priority>1</Priority><TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF>\
        <SPT><Group>0</Group><Method>INVITE</Method></SPT><SPT><Group>1</Group><SessionCase>0</SessionCase></SPT></TriggerPoint>\
        <ApplicationServer><ServerName>sip:192.0.2.50:5070</ServerName></ApplicationServer></InitialFilterCriteria>\
        <InitialFilterCriteria><Priority>2</Priority><ApplicationServer><ServerName>sip:192.0.2.51;lr</ServerName></ApplicationServer></InitialFilterCriteria>\
        </ServiceProfile></IMSSubscription>";

    fn isc(registered: bool) -> Isc {
        let ul = Arc::new(UsrlocScscf::default());
        ul.put(ImpuRecord { impu: "sip:alice@ims.test".into(), registered, sub: crate::subscription::parse(IFCS).unwrap(), ..Default::default() });
        let i = Isc::default();
        let _ = i.ul.set(ul);
        i
    }

    /// (result, $du, the Route header added).
    fn route(i: &Isc, raw: &str, dir: &str) -> (i32, Option<String>, Option<String>) {
        with_msg_on(raw, &Here::default(), |ctx| {
            let rc = i.match_filter(ctx, dir);
            let out = rendered(ctx);
            let added = out.lines().nth(1).filter(|l| l.starts_with("Route: <sip:192.0.2.5")).map(str::to_string);
            (rc, ctx.dst.map(|d| d.addr.to_string()), added)
        })
    }

    const INVITE_BOB: (&str, &str) = ("sip:bob@ims.test", "sip:bob@ims.test");

    #[test]
    fn filters_in_priority_order_and_the_way_back() {
        let i = isc(true);
        let invite = |extra: &str| request("INVITE", INVITE_BOB.0, INVITE_BOB.1, extra, "");
        let (rc, du, r) = route(&i, &invite(""), "orig");
        assert_eq!((rc, du.as_deref()), (1, Some("192.0.2.50:5070")));
        assert_eq!(r.as_deref(), Some("Route: <sip:192.0.2.50:5070;lr>, <sip:127.0.0.1:5060;lr;s=1;d=orig>"));
        // Back from AS 1 (behind a foreign hop): the next filter, AS 2.
        let back = invite("Route: <sip:192.0.2.77;lr>, <sip:127.0.0.1:5060;lr;s=1;d=orig>\n");
        let (rc, du, r) = route(&i, &back, "orig");
        assert_eq!((rc, du.as_deref()), (1, Some("192.0.2.51:5060")));
        assert_eq!(r.as_deref(), Some("Route: <sip:192.0.2.51;lr>, <sip:127.0.0.1:5060;lr;s=2;d=orig>"), "one ;lr");
        // Back from AS 2: nothing more.
        assert_eq!(route(&i, &invite("Route: <sip:127.0.0.1:5060;lr;s=2;d=orig>\n"), "orig").0, -1);
        // A mark for the other direction does not count.
        assert_eq!(route(&i, &invite("Route: <sip:127.0.0.1:5060;lr;s=2;d=term>\n"), "orig").1.as_deref(), Some("192.0.2.50:5070"));
        // Our Route without s=: not a mark (starts over).
        assert_eq!(route(&i, &invite("Route: <sip:127.0.0.1:5060;lr>\n"), "orig").1.as_deref(), Some("192.0.2.50:5070"));
        // Not an INVITE: only AS 2.
        assert_eq!(route(&i, &request("MESSAGE", INVITE_BOB.0, INVITE_BOB.1, "", ""), "orig").1.as_deref(), Some("192.0.2.51:5060"));
    }

    #[test]
    fn served_user_and_session_case() {
        let reg = isc(true);
        let unreg = isc(false);
        let to_alice = request("INVITE", "sip:alice@ims.test", "sip:alice@ims.test", "", "").replace("From: <sip:alice@ims.test>", "From: <sip:bob@ims.test>");
        // Terminating (the R-URI): case 1, so only AS 2.
        assert_eq!(route(&reg, &to_alice, "term").1.as_deref(), Some("192.0.2.51:5060"));
        assert_eq!(route(&unreg, &to_alice, "term").1.as_deref(), Some("192.0.2.51:5060"));
        // Originating but not registered: case 3, so only AS 2.
        let from_alice = request("INVITE", INVITE_BOB.0, INVITE_BOB.1, "", "");
        assert_eq!(route(&unreg, &from_alice, "orig").1.as_deref(), Some("192.0.2.51:5060"));
        // P-Asserted-Identity names the served user.
        let pai = request("INVITE", INVITE_BOB.0, INVITE_BOB.1, "P-Asserted-Identity: <sip:carol@ims.test>, <tel:+1>\n", "");
        assert_eq!(route(&reg, &pai, "orig").0, -1, "carol has no record");
        assert_eq!(route(&reg, &to_alice, "orig").0, -1, "bob has no record");
        // A reply, and no usrloc.
        assert_eq!(route(&reg, &reply_msg(200, "", ""), "orig").0, -1);
        assert_eq!(route(&Isc::default(), &from_alice, "orig").0, -1);
    }

    #[test]
    fn exports() {
        let i = Arc::new(Isc::default());
        assert!(i.set_param("isc_my_uri", &s("sip:scscf.ims.test")).is_ok());
        assert!(sip_core::Registry::default().load(i).unwrap_err().contains("ims_usrloc_scscf"));
        let mut reg = registry(false);
        reg.load(Arc::new(UsrlocScscf::default())).unwrap();
        reg.load(Arc::new(Isc::default())).unwrap();
        assert!(fixup_err(&reg, "isc_match_filter", &[]).is_some());
        assert!(fixup_err(&reg, "isc_from_as", &[s("orig"), s("x")]).is_some());
        let from_as = |route: &str, dir: &str| {
            let msg = request("INVITE", INVITE_BOB.0, INVITE_BOB.1, route, "");
            with_msg_on(&msg, &Here::default(), |ctx| call(&reg, ctx, "isc_from_as", &[s(dir)]))
        };
        assert_eq!(from_as("Route: <sip:127.0.0.1:5060;lr;s=1;d=orig>\n", "orig"), 1);
        assert_eq!(from_as("Route: <sip:127.0.0.1:5060;lr;s=1;d=orig>\n", "term"), -1);
        assert_eq!(from_as("Route: <sip:192.0.2.77;lr;s=1;d=orig>\n", "orig"), -1, "not our Route");
        assert_eq!(from_as("", "orig"), -1);
        // No record for alice in this usrloc.
        let msg = request("INVITE", INVITE_BOB.0, INVITE_BOB.1, "", "");
        assert_eq!(with_msg(&msg, |ctx| call(&reg, ctx, "isc_match_filter", &[s("orig"), s("location")])), -1);
    }
}
