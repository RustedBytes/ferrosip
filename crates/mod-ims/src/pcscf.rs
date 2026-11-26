//! P-CSCF: `ims_usrloc_pcscf` (UE contacts with their Service-Route and
//! associated identities) and `ims_registrar_pcscf`:
//! * `pcscf_save_pending("location")` on a REGISTER from the UE (remembers
//!   where it came from),
//! * `save("location")` in the onreply_route of the 200 to that REGISTER
//!   (stores expiry, Service-Route, P-Associated-URI; expires 0 removes),
//! * `pcscf_is_registered("location")` — the request comes from a
//!   registered UE (by source address),
//! * `pcscf_follows_service_routes("location")` /
//!   `pcscf_force_service_routes("location")`,
//! * `pcscf_assert_identity("location", identity)` — identity is one of the
//!   UE's associated URIs. RPC `ulpcscf.showcontacts`.

use crate::impu_of;
use sip_core::module::{DynStr, rc};
use sip_core::schema::ParamSpec;
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Registry};
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UeContact {
    pub aor: String,
    pub contact: String,
    pub received: Dest,
    pub expires_at: u64,
    pub service_routes: Vec<String>,
    pub associated: Vec<String>,
    pub registered: bool,
}

#[derive(Default)]
pub struct UsrlocPcscf {
    /// Contact URI → entry.
    contacts: Mutex<HashMap<String, UeContact>>,
}

impl UsrlocPcscf {
    fn by_source(&self, src: &Dest) -> Option<UeContact> {
        let t = unix_secs();
        lock(&self.contacts).values().find(|c| c.registered && c.expires_at > t && c.received.addr == src.addr).cloned()
    }
}

impl Module for UsrlocPcscf {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "ims_usrloc_pcscf"
    }

    fn set_param(&self, _name: &str, _v: &Arg) -> Result<(), String> {
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        reg.provide(self.clone());
        let me = self.clone();
        reg.rpc.add("ulpcscf.showcontacts", "UE contacts", move |_| {
            let t = unix_secs();
            Ok(json!(
                lock(&me.contacts)
                    .values()
                    .map(|c| json!({"aor": c.aor, "contact": c.contact, "received": c.received.to_string(), "expires": c.expires_at.saturating_sub(t),
                    "state": if c.registered { "registered" } else { "pending" }, "service_routes": c.service_routes, "associated_uris": c.associated}))
                    .collect::<Vec<_>>()
            ))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("ulpcscf-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let t = unix_secs();
                    lock(&self.contacts).retain(|_, c| c.expires_at > t);
                }
            })
            .map_err(|e| format!("cannot start the ulpcscf timer thread: {e}"))?;
        Ok(())
    }
}

/// The registered UE of the current request.
struct CurrentUe(UeContact);

#[derive(Default)]
pub struct RegistrarPcscf {
    ul: OnceLock<Arc<UsrlocPcscf>>,
}

fn route_uris(ctx: &Ctx<'_, '_>) -> Vec<String> {
    ctx.msg
        .headers
        .iter()
        .filter(|h| h.kind == HdrKind::Route)
        .flat_map(|h| split_list(h.body))
        .map(|r| String::from_utf8_lossy(name_addr(r).0).into_owned())
        .collect()
}

impl RegistrarPcscf {
    /// The usrloc this registrar was bound to in `register` (`None` only
    /// if a function runs before the module was registered).
    fn ul(&self) -> Option<&UsrlocPcscf> {
        self.ul.get().map(|u| &**u)
    }

    fn save_pending(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        if ctx.msg.method() != Some(Method::Register) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let aor = ctx.msg.get(HdrKind::To).and_then(|h| impu_of(name_addr(h.body).0)).unwrap_or_default();
        let uris: Vec<String> = ctx
            .msg
            .headers
            .iter()
            .filter(|h| h.kind == HdrKind::Contact)
            .flat_map(|h| split_list(h.body))
            .map(|c| String::from_utf8_lossy(parse_contact(c).uri).into_owned())
            .collect();
        let Some(ul) = self.ul() else { return -1 };
        let mut map = lock(&ul.contacts);
        for c in uris.into_iter().filter(|c| c != "*") {
            let e = map.entry(c.clone()).or_insert_with(|| UeContact {
                aor: aor.clone(),
                contact: c,
                received: ctx.src,
                expires_at: unix_secs().saturating_add(120),
                service_routes: vec![],
                associated: vec![],
                registered: false,
            });
            e.received = ctx.src;
        }
        1
    }

    /// On the 200 OK of a REGISTER (onreply_route).
    fn save(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        if ctx.msg.is_request() || ctx.msg.status() != Some(200) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let m = &*ctx.msg;
        let routes: Vec<String> = m
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(b"service-route"))
            .flat_map(|h| split_list(h.body))
            .map(|r| s(r).trim().to_string())
            .collect();
        let assoc: Vec<String> =
            m.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"p-associated-uri")).flat_map(|h| split_list(h.body)).map(|r| s(name_addr(r).0)).collect();
        let contacts: Vec<(String, u64)> = m
            .headers
            .iter()
            .filter(|h| h.kind == HdrKind::Contact)
            .flat_map(|h| split_list(h.body))
            .map(|c| {
                let p = parse_contact(c);
                (s(p.uri), u64::from(p.expires.unwrap_or(0)))
            })
            .collect();
        let t = unix_secs();
        let Some(ul) = self.ul() else { return -1 };
        let mut map = lock(&ul.contacts);
        // Contacts the registrar no longer lists are gone.
        let listed: Vec<&String> = contacts.iter().map(|c| &c.0).collect();
        let aor = m.get(HdrKind::To).and_then(|h| impu_of(name_addr(h.body).0)).unwrap_or_default();
        map.retain(|k, c| c.aor != aor || listed.contains(&k) || !c.registered);
        let mut n = 0usize;
        for (uri, e) in contacts {
            if let Some(c) = map.get_mut(&uri) {
                if e == 0 {
                    map.remove(&uri);
                    continue;
                }
                c.expires_at = t.saturating_add(e);
                c.service_routes = routes.clone();
                c.associated = assoc.clone();
                c.registered = true;
                n = n.saturating_add(1);
            }
        }
        rc(n > 0)
    }

    fn current(&self, ctx: &mut Ctx<'_, '_>) -> Option<UeContact> {
        if let Some(c) = ctx.ext::<CurrentUe>() {
            return Some(c.0.clone());
        }
        let c = self.ul()?.by_source(&ctx.src)?;
        ctx.ext.push(Box::new(CurrentUe(c.clone())));
        Some(c)
    }
}

impl Module for RegistrarPcscf {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "ims_registrar_pcscf"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, sig};
        const LOC: &[&str] = &["location"];
        const ID: &[Param] = &[arg("identity", Uri)];
        Some(vec![
            sig("pcscf_save_pending", "save_pending", &[], Ret::Bool, "Remember this REGISTER's contacts until its 200 OK").fixed(LOC).allowed(ctx::REQUEST),
            sig("save", "save", &[], Ret::Bool, "Save the UE's registration from the REGISTER's 200 OK (with its Service-Routes)")
                .fixed(LOC)
                .allowed(ctx::REPLY),
            sig("pcscf_is_registered", "is_registered", &[], Ret::Bool, "The request comes from a registered UE").fixed(LOC),
            sig("pcscf_follows_service_routes", "follows_service_routes", &[], Ret::Bool, "The request's Routes are the UE's Service-Routes").fixed(LOC),
            sig("pcscf_force_service_routes", "force_service_routes", &[], Ret::Bool, "Replace the request's Routes with the UE's Service-Routes").fixed(LOC),
            sig("pcscf_assert_identity", "assert_identity", ID, Ret::Bool, "The identity is one of the UE's registered public identities").fixed(LOC),
        ])
    }

    fn set_param(&self, _name: &str, _v: &Arg) -> Result<(), String> {
        Ok(()) // is_registered_fallback2ip, publish_reginfo, subscribe_to_reginfo …
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.ul.set(reg.api::<UsrlocPcscf>().ok_or("ims_registrar_pcscf needs ims_usrloc_pcscf loaded first")?);
        let m = "ims_registrar_pcscf";
        let table = |a: &[Arg]| -> Result<(), String> {
            if a.is_empty() || a.len() > 2 {
                return Err("expected \"location\"".into());
            }
            Ok(())
        };
        let me = self.clone();
        reg.export(m, "pcscf_save_pending", table, move |ctx: &mut Ctx, _: &()| me.save_pending(ctx));
        let me = self.clone();
        reg.export(m, "save", table, move |ctx: &mut Ctx, _: &()| me.save(ctx));
        let me = self.clone();
        reg.export(m, "pcscf_is_registered", table, move |ctx: &mut Ctx, _: &()| rc(me.current(ctx).is_some()));
        let me = self.clone();
        reg.export(m, "pcscf_follows_service_routes", table, move |ctx: &mut Ctx, _: &()| {
            let Some(ue) = me.current(ctx) else { return -1 };
            if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                return -1;
            }
            let net = ctx.net;
            let given: Vec<String> = route_uris(ctx)
                .into_iter()
                .filter(|r| !sip_parser::parse_uri(r.as_bytes()).is_some_and(|u| sip_core::net::is_myself(net, &String::from_utf8_lossy(u.host))))
                .collect();
            let want: Vec<String> = ue.service_routes.iter().map(|r| String::from_utf8_lossy(name_addr(r.as_bytes()).0).into_owned()).collect();
            rc(given == want)
        });
        let me = self.clone();
        reg.export(m, "pcscf_force_service_routes", table, move |ctx: &mut Ctx, _: &()| {
            let Some(ue) = me.current(ctx) else { return -1 };
            if ue.service_routes.is_empty() || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                return -1;
            }
            let lines: Vec<(usize, usize)> = ctx.msg.headers.iter().filter(|h| h.kind == HdrKind::Route).map(|h| (h.start, h.end)).collect();
            for (s, e) in lines {
                ctx.lumps.delete(s, e.saturating_sub(s));
            }
            let at = ctx.msg.first_line_end;
            ctx.lumps.insert(at, format!("Route: {}\r\n", ue.service_routes.join(", ")).into_bytes());
            ctx.dst = ue.service_routes.first().and_then(|r| sip_core::pvcore::dest_from_uri(name_addr(r.as_bytes()).0));
            1
        });
        let me = self.clone();
        reg.export(
            m,
            "pcscf_assert_identity",
            |a: &[Arg]| {
                let [_, id] = crate::args(a)?;
                id.dyn_str()
            },
            move |ctx: &mut Ctx, id: &DynStr| {
                let id = id.eval(ctx).into_owned();
                let Some(ue) = me.current(ctx) else { return -1 };
                let want = impu_of(name_addr(id.as_bytes()).0).unwrap_or(id);
                rc(ue.associated.iter().any(|a| impu_of(a.as_bytes()).as_deref() == Some(want.as_str()) || *a == want))
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Here, call, fixup_err, registry, rendered, reply_msg, request, rpc, s, with_msg, with_msg_at, with_msg_on};

    fn registrar() -> sip_core::Registry {
        let mut reg = registry(false);
        reg.load(Arc::new(UsrlocPcscf::default())).unwrap();
        reg.load(Arc::new(RegistrarPcscf::default())).unwrap();
        reg
    }

    /// REGISTER from the UE (192.0.2.9) with these Contact lines.
    fn register(contacts: &str) -> String {
        request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", "").replace("Contact: <sip:alice@192.0.2.9:5060>\n", contacts)
    }

    const OK: &str = "Service-Route: <sip:orig@192.0.2.30:5060;lr>, <sip:as.ims.test;lr>\nP-Associated-URI: <sip:alice@ims.test>, <tel:+1>\n";

    /// A registered UE: alice@192.0.2.9 with the Service-Route and identities of `OK`.
    fn registered() -> sip_core::Registry {
        let reg = registrar();
        assert_eq!(with_msg(&register("Contact: <sip:alice@192.0.2.9:5060>, *\n"), |ctx| call(&reg, ctx, "pcscf_save_pending", &[s("location")])), 1);
        let ok = reply_msg(200, &format!("{OK}Contact: <sip:alice@192.0.2.9:5060>;expires=600\n"), "");
        assert_eq!(with_msg(&ok, |ctx| call(&reg, ctx, "save", &[s("location")])), 1);
        reg
    }

    #[test]
    fn registration_from_pending_to_saved_to_removed() {
        let reg = registrar();
        let ul = reg.api::<UsrlocPcscf>().unwrap();
        // Only a REGISTER is remembered; a reply is not a 200 REGISTER answer.
        assert_eq!(
            with_msg(&request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", ""), |ctx| call(&reg, ctx, "pcscf_save_pending", &[s("location")])),
            -1
        );
        assert_eq!(with_msg(&register(""), |ctx| call(&reg, ctx, "save", &[s("location")])), -1, "a request");
        assert_eq!(with_msg(&reply_msg(401, "", ""), |ctx| call(&reg, ctx, "save", &[s("location")])), -1);
        let reg = registered();
        let ul2 = reg.api::<UsrlocPcscf>().unwrap();
        assert!(lock(&ul.contacts).is_empty(), "registries do not share contacts");
        let c = lock(&ul2.contacts)["sip:alice@192.0.2.9:5060"].clone();
        assert!(c.registered && c.aor == "sip:alice@ims.test");
        assert_eq!(c.service_routes, ["<sip:orig@192.0.2.30:5060;lr>", "<sip:as.ims.test;lr>"]);
        assert_eq!(c.associated, ["sip:alice@ims.test", "tel:+1"]);
        let shown = rpc(&reg, "ulpcscf.showcontacts", sip_core::serde_json::json!([])).unwrap();
        assert_eq!(shown[0]["state"], "registered");
        // expires=0 removes a contact.
        let gone = reply_msg(200, "Contact: <sip:alice@192.0.2.9:5060>;expires=0\n", "");
        assert_eq!(with_msg(&gone, |ctx| call(&reg, ctx, "save", &[s("location")])), -1);
        assert!(lock(&ul2.contacts).is_empty());
        // So does a 200 that no longer lists it (and saves nothing for a
        // contact that was never pending).
        let reg = registered();
        let ul3 = reg.api::<UsrlocPcscf>().unwrap();
        let other = reply_msg(200, "Contact: <sip:alice@192.0.2.99>;expires=600\n", "");
        assert_eq!(with_msg(&other, |ctx| call(&reg, ctx, "save", &[s("location")])), -1);
        assert!(lock(&ul3.contacts).is_empty());
    }

    #[test]
    fn requests_from_the_registered_ue() {
        let reg = registered();
        let invite = |extra: &str| request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", extra, "");
        let from_ue = |f: &dyn Fn(&mut Ctx<'_, '_>) -> i32, raw: &str| with_msg_on(raw, &Here::default(), |ctx| f(ctx));
        let is_reg = |ctx: &mut Ctx<'_, '_>| call(&reg, ctx, "pcscf_is_registered", &[s("location")]);
        assert_eq!(from_ue(&is_reg, &invite("")), 1);
        assert_eq!(with_msg_at(&invite(""), &Here::default(), "192.0.2.10:5060", is_reg), -1, "another address");
        // Routes: the Service-Route, with our own hop left out.
        let follows = |ctx: &mut Ctx<'_, '_>| call(&reg, ctx, "pcscf_follows_service_routes", &[s("location")]);
        assert_eq!(from_ue(&follows, &invite("Route: <sip:127.0.0.1:5060;lr>\nRoute: <sip:orig@192.0.2.30:5060;lr>, <sip:as.ims.test;lr>\n")), 1);
        assert_eq!(from_ue(&follows, &invite("Route: <sip:orig@192.0.2.30:5060;lr>\n")), -1);
        assert_eq!(from_ue(&follows, &invite("")), -1);
        assert_eq!(with_msg_at(&invite(""), &Here::default(), "192.0.2.10:5060", follows), -1, "not registered");
        // Forced: every Route replaced, $du the first Service-Route hop.
        let (rc, out, du) = with_msg_on(&invite("Route: <sip:evil.example;lr>\n"), &Here::default(), |ctx| {
            let rc = call(&reg, ctx, "pcscf_force_service_routes", &[s("location")]);
            (rc, rendered(ctx), ctx.dst.map(|d| d.addr.to_string()))
        });
        assert_eq!(rc, 1);
        assert!(out.contains("\r\nRoute: <sip:orig@192.0.2.30:5060;lr>, <sip:as.ims.test;lr>\r\n") && !out.contains("evil"), "{out}");
        assert_eq!(du.as_deref(), Some("192.0.2.30:5060"));
        // Asserted identities: name-addr or URI, any associated one.
        let assert_id = |id: &str| with_msg(&invite(""), |ctx| call(&reg, ctx, "pcscf_assert_identity", &[s("location"), s(id)]));
        assert_eq!(assert_id("<sip:alice@IMS.test;user=phone>"), 1);
        assert_eq!(assert_id("tel:+1"), 1);
        assert_eq!(assert_id("sip:eve@ims.test"), -1);
        assert_eq!(
            with_msg_at(&invite(""), &Here::default(), "192.0.2.10:5060", |ctx| call(&reg, ctx, "pcscf_assert_identity", &[s("location"), s("tel:+1")])),
            -1
        );
    }

    #[test]
    fn forcing_needs_a_service_route() {
        let reg = registrar();
        with_msg(&register("Contact: <sip:alice@192.0.2.9:5060>\n"), |ctx| call(&reg, ctx, "pcscf_save_pending", &[s("location")]));
        let ok = reply_msg(200, "Contact: <sip:alice@192.0.2.9:5060>;expires=600\n", "");
        assert_eq!(with_msg(&ok, |ctx| call(&reg, ctx, "save", &[s("location")])), 1);
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "pcscf_force_service_routes", &[s("location")])), -1);
        assert_eq!(with_msg_at(&invite, &Here::default(), "192.0.2.10:5060", |ctx| call(&reg, ctx, "pcscf_force_service_routes", &[s("location")])), -1);
    }

    #[test]
    fn parameters_and_loading() {
        let ul = UsrlocPcscf::default();
        assert!(ul.set_param("hashing_type", &Arg::Int(1)).is_ok());
        let r = Arc::new(RegistrarPcscf::default());
        assert!(r.set_param("is_registered_fallback2ip", &Arg::Int(1)).is_ok());
        assert!(sip_core::Registry::default().load(r.clone()).unwrap_err().contains("ims_usrloc_pcscf loaded first"));
        // Before register: no usrloc.
        assert_eq!(with_msg(&register("Contact: <sip:a@192.0.2.9>\n"), |ctx| r.save_pending(ctx)), -1);
        assert_eq!(with_msg(&reply_msg(200, "", ""), |ctx| r.save(ctx)), -1);
        let reg = registrar();
        assert!(fixup_err(&reg, "save", &[]).is_some());
        assert!(fixup_err(&reg, "pcscf_is_registered", &[s("a"), s("b"), s("c")]).is_some());
        assert!(fixup_err(&reg, "pcscf_assert_identity", &[s("location")]).is_some());
    }
}
