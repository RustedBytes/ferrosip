//! `ims_diameter_server`: Diameter requests in the script (Kamailio's
//! module of that name; Sh and any other application).
//!
//! * Incoming requests that no IMS module handles run
//!   `event_route[diameter:request]` with `$diameter_command`,
//!   `$diameter_application` and `$diameter_request` (the AVPs as JSON);
//!   the answer is built from `$diameter_response` (AVPs as JSON), with
//!   Session-Id, Origin-Host/-Realm and Result-Code 2001 added when the
//!   script leaves them out. No `$diameter_response` (or JSON that does not
//!   parse): no answer, as in Kamailio. Without the event route: 3001.
//! * `diameter_request([peer,] appid, commandcode, message)` sends a
//!   request (AVPs as JSON) and waits for the answer, which is then in
//!   `$diameter_response`; `diameter_request_async(…)` returns 0 at once
//!   and runs `event_route[diameter:response]` with the answer.
//!
//! The JSON is Kamailio's (`avp_helper.c`): a list of AVPs, `{"avpCode":
//! 268, "vendorId": 0, "DataType": 3, "Flags": 64, "int32": 2001}`, with
//! the value in `int32`, `string`, `address`, `data` (octets, hex) or
//! `list` (a grouped AVP's AVPs); input takes `list`, `int32`, `int64`,
//! `string` or `hexdump`.

use crate::cdp;
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::ParamSpec;
use sip_core::serde_json::{Map, Value, json};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, RouteHub};
use sip_diameter::codes::*;
use sip_diameter::{Avp, FLAG_M, FLAG_V, Msg, Peers};
use std::sync::{Arc, Mutex, OnceLock};

const EVENT: &str = "diameter:request";
const EVENT_RESPONSE: &str = "diameter:response";

/// cdp's `AAA_AVPDataType` for an AVP (`set_avp_fields()`, by code only):
/// 0 data, 1 string, 2 address, 3 int32.
fn cdp_type(code: u32) -> u8 {
    match code {
        1 | 25 | 263 | 283 | 293 | 264 | 296 | 33 | 269 | 281 => 1,
        27 | 258 | 262 | 265 | 266 | 268 | 270 | 276 | 278 | 291 => 3,
        257 => 2,
        _ => 0,
    }
}

/// The flags cdp forces on the base AVPs it types (`set_avp_fields()`).
fn cdp_flags(code: u32, flags: u8) -> u8 {
    match code {
        1 | 25 | 263 | 283 | 293 | 264 | 296 | 27 | 258 | 262 | 265 | 266 | 268 | 270 | 276 | 278 | 291 | 257 => FLAG_M | (flags & 0x20),
        33 => FLAG_M,
        269 => 0,
        281 => flags & 0x20,
        _ => flags,
    }
}

/// AVPs whose value is a 64-bit integer: shown as `int64` (cdp shows them
/// as octets).
const INT64: &[AvpCode] = &[AvpCode(287), AvpCode(412), AvpCode(414), AvpCode(417), AvpCode(419), AvpCode(421), AvpCode(447)];

fn group_of(a: &Avp) -> Option<Vec<Avp>> {
    let g = a.group_avps();
    // A grouped AVP's payload re-encodes to itself.
    let mut re = Vec::new();
    for x in &g {
        x.encode(&mut re);
    }
    (!g.is_empty() && re == a.data).then_some(g)
}

/// The first four octets, big-endian.
fn be32(d: &[u8]) -> Option<u32> {
    d.first_chunk().copied().map(u32::from_be_bytes)
}

/// One AVP as Kamailio's ims_diameter_server writes it (`avp2json()`):
/// `avpCode`, `vendorId`, `DataType`, `Flags`, then the value. The base
/// AVPs cdp types are `string`, `int32` or `address`; the others are
/// octets: `data` (hex), plus `int32` for four octets, `string` for
/// longer text and `list` for a grouped AVP.
pub(crate) fn avp_json(a: &Avp) -> Value {
    let ty = if a.vendor.is_none() { cdp_type(a.code.get()) } else { 0 };
    let mut o = Map::new();
    o.insert("avpCode".into(), json!(a.code.get()));
    o.insert("vendorId".into(), json!(a.vendor.map_or(0, VendorId::get)));
    o.insert("DataType".into(), json!(ty));
    o.insert("Flags".into(), json!(a.flags));
    let d = &a.data[..];
    match (ty, be32(d)) {
        (1, _) => {
            o.insert("string".into(), json!(String::from_utf8_lossy(d)));
        }
        (3, Some(v)) => {
            o.insert("int32".into(), json!(v));
        }
        (2, _) if matches!(d.len(), 4 | 6 | 16 | 18) => {
            let ip = d.get(d.len() % 4..).unwrap_or_default();
            let text = if let [a, b, c, e] = ip {
                format!("{a}.{b}.{c}.{e}")
            } else {
                ip.as_chunks::<2>().0.iter().map(|w| format!("{:x}", u16::from_be_bytes(*w))).collect::<Vec<_>>().join(".")
            };
            o.insert("address".into(), json!(text));
        }
        (_, v) => {
            o.insert("data".into(), json!(crate::hex(d)));
            if let (4, Some(v)) = (d.len(), v) {
                o.insert("int32".into(), json!(v));
            } else if let (true, Ok(w)) = (INT64.contains(&a.code), <[u8; 8]>::try_from(d)) {
                o.insert("int64".into(), json!(u64::from_be_bytes(w)));
            } else if d.len() > 4 {
                if d.first() == Some(&0) {
                    if let Some(g) = group_of(a) {
                        o.insert("list".into(), Value::Array(g.iter().map(avp_json).collect()));
                    }
                } else {
                    // cdp prints the octets as text up to the first NUL.
                    let t = d.split(|&b| b == 0).next().unwrap_or(d);
                    o.insert("string".into(), json!(String::from_utf8_lossy(t)));
                }
            }
        }
    }
    Value::Object(o)
}

pub(crate) fn avps_json(avps: &[Avp]) -> String {
    Value::Array(avps.iter().map(avp_json).collect()).to_string()
}

/// cdp's `parse_hexdump()`: pairs of hex digits (anything else counts as
/// 0), a trailing odd digit dropped.
fn unhex(s: &str) -> Vec<u8> {
    let h = |c: u8| (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok()).unwrap_or(0);
    s.as_bytes().as_chunks::<2>().0.iter().map(|&[a, b]| (h(a) << 4) | h(b)).collect()
}

fn warn(m: String) {
    sip_core::log::log(sip_core::log::L_WARN, &format!("ims_diameter_server: {m}"));
}

/// A JSON float given as an integer AVP value, truncated toward zero
/// (jansson's `json_number_value()` cast to int, as cdp does); NaN is 0 and
/// out-of-range values saturate, then fail the caller's range check.
#[allow(clippy::cast_possible_truncation, reason = "truncation toward zero is the intended float-to-int conversion; `as` saturates")]
fn json_float_int(f: f64) -> i64 {
    f.trunc() as i64
}

/// One JSON AVP (`parselist()`): `avpCode` and the value are required, an
/// item without them is skipped with a warning, as Kamailio does. The
/// value is the first of `list`, `int32`, `int64`, `string` and `hexdump`
/// (`data` and `hex` are taken as `hexdump`).
fn json_avp(v: &Value) -> Option<Avp> {
    // Numbers past i64::MAX saturate: they are out of range for every field.
    let n = |k: &str| v.get(k).and_then(|x| x.as_i64().or_else(|| x.as_u64().map(|_| i64::MAX)));
    let Some(code) = n("avpCode") else {
        warn("mandatory field missing: avpCode".into());
        return None;
    };
    let Ok(code) = u32::try_from(code).map(AvpCode) else {
        warn(format!("avpCode {code} out of range"));
        return None;
    };
    let vendor = match n("vendorId").filter(|&x| x != 0).map(u32::try_from) {
        None => None,
        Some(Ok(x)) => Some(VendorId(x)),
        Some(Err(_)) => {
            warn(format!("AVP {code}: vendorId out of range"));
            return None;
        }
    };
    let data = if let Some(x) = v.get("list") {
        let mut d = Vec::new();
        for a in x.as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(json_avp) {
            a.encode(&mut d);
        }
        d
    } else if let Some(i) = v.get("int32").and_then(|x| x.as_i64().or_else(|| x.as_u64().map(|_| i64::MAX)).or_else(|| x.as_f64().map(json_float_int))) {
        // Integer32 or Unsigned32: either reading of the 32 bits is accepted.
        let Some(b) = i32::try_from(i).map(i32::to_be_bytes).ok().or_else(|| u32::try_from(i).map(u32::to_be_bytes).ok()) else {
            warn(format!("AVP {code}: int32 {i} out of range"));
            return None;
        };
        b.to_vec()
    } else if let Some(i) = v.get("int64").and_then(|x| x.as_i64().map(i64::cast_unsigned).or_else(|| x.as_u64())) {
        i.to_be_bytes().to_vec()
    } else if let Some(x) = v.get("string") {
        match x {
            Value::String(s) => s.as_bytes().to_vec(),
            o => o.to_string().into_bytes(),
        }
    } else if let Some(x) = ["hexdump", "data", "hex"].iter().find_map(|k| v.get(*k).and_then(Value::as_str)) {
        unhex(x)
    } else {
        warn(format!("AVP {code}: not a string, int32, list, hexdump? Invalid field definition"));
        return None;
    };
    let mut a = Avp::new(code, vendor, data);
    let Ok(flags) = u8::try_from(n("Flags").unwrap_or(0)) else {
        warn(format!("AVP {code}: Flags out of range"));
        return None;
    };
    a.flags = if vendor.is_some() { flags | FLAG_V } else { cdp_flags(code.get(), flags & !FLAG_V) };
    Some(a)
}

/// `$diameter_response`-style JSON → AVPs (a list, or one AVP object).
/// Only JSON that does not parse is an error; bad items are skipped.
pub(crate) fn json_avps(s: &str) -> Result<Vec<Avp>, String> {
    let v: Value = sip_core::serde_json::from_str(s).map_err(|e| format!("bad AVP JSON: {e}"))?;
    match &v {
        Value::Array(items) => Ok(items.iter().filter_map(json_avp).collect()),
        Value::Object(_) => Ok(json_avp(&v).into_iter().collect()),
        _ => Err("AVP JSON must be a list of AVPs".into()),
    }
}

/// The request an `event_route[diameter:request]` runs for.
struct DiamEvent {
    cmd: u32,
    app: u32,
    request: String,
    response: Arc<Mutex<Option<String>>>,
}

/// `$diameter_response` outside the event route: `diameter_request`'s answer.
#[derive(Default)]
struct DiamAnswer(Option<String>);

#[derive(Default)]
pub struct DiameterServer {
    peers: OnceLock<Arc<Peers>>,
    hub: OnceLock<Arc<RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl DiameterServer {
    /// Answer an incoming request through the event route.
    fn answer(&self, req: &Msg) -> Option<Msg> {
        let peers = self.peers.get()?;
        let mut ans = req.answer();
        if let Some(sid) = req.get(SESSION_ID, None) {
            ans.add(sid.clone());
        }
        let (Some(hub), Some(net)) = (self.hub.get(), self.net.get()) else { return None };
        let mut avps = Vec::new();
        if hub.has_event(EVENT) {
            let slot = Arc::new(Mutex::new(None));
            let ev = DiamEvent { cmd: req.cmd.get(), app: req.app.get(), request: avps_json(&req.avps), response: slot.clone() };
            hub.run_event_with(EVENT, &**net, None, move |ctx| ctx.ext.push(Box::new(ev)));
            let resp = lock(&slot).take();
            // As in Kamailio (callback_cdp_request()): no $diameter_response,
            // or one that does not parse, and the request is not answered.
            match resp.as_deref().filter(|r| !r.is_empty()).map(json_avps) {
                Some(Ok(v)) => avps = v,
                Some(Err(e)) => {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("ims_diameter_server: $diameter_response: {e}; not answering"));
                    return None;
                }
                None => {
                    warn(format!("no $diameter_response for command {}: not answering", req.cmd));
                    return None;
                }
            }
        } else {
            avps.push(Avp::u32(RESULT_CODE, None, DIAMETER_COMMAND_UNSUPPORTED.get()));
        }
        avps.retain(|a| !(a.code == SESSION_ID && a.vendor.is_none() && ans.get(SESSION_ID, None).is_some()));
        let has = |c: AvpCode| avps.iter().any(|a| a.code == c && a.vendor.is_none());
        if !has(RESULT_CODE) && !has(EXPERIMENTAL_RESULT) {
            ans.add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get()));
        }
        if !has(ORIGIN_HOST) {
            ans.add(Avp::str(ORIGIN_HOST, None, &peers.cfg.identity));
        }
        if !has(ORIGIN_REALM) {
            ans.add(Avp::str(ORIGIN_REALM, None, &peers.cfg.realm));
        }
        ans.avps.extend(avps);
        Some(ans)
    }

    /// The request `diameter_request` sends: `message`'s AVPs after a
    /// Session-Id; the realm and Destination-Host to route it by.
    fn build(peers: &Peers, peer: &str, app: AppId, cmd: CmdCode, message: &str) -> Result<(Msg, String, Option<String>), String> {
        let avps = json_avps(message)?;
        let mut m = Msg::request(cmd, app);
        // Session-Id first (RFC 6733 §8.8), as cdp does.
        if !avps.iter().any(|a| a.code == SESSION_ID && a.vendor.is_none()) {
            m.add(Avp::str(SESSION_ID, None, &peers.session_id("script")));
        }
        m.avps.extend(avps);
        let peer = peer.trim();
        let realm =
            m.str(DESTINATION_REALM).or_else(|| (!peer.is_empty()).then(|| peers.peer_realm(peer)).flatten()).unwrap_or_else(|| peers.cfg.realm.clone());
        let host = (!peer.is_empty() && m.get(DESTINATION_HOST, None).is_none()).then(|| peer.to_string());
        Ok((m, realm, host))
    }

    /// `diameter_request([peer,] appid, commandcode, message)`: 1 with the
    /// answer in `$diameter_response`, -1 when none came.
    fn request(&self, ctx: &mut Ctx<'_, '_>, peer: &str, app: AppId, cmd: CmdCode, message: &str) -> i32 {
        let Some(peers) = self.peers.get() else { return -1 };
        ctx.ext_mut::<DiamAnswer>().0 = None;
        let (m, realm, host) = match Self::build(peers, peer, app, cmd, message) {
            Ok(x) => x,
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("diameter_request: {e}"));
                return -1;
            }
        };
        match peers.request(m, &realm, host.as_deref()) {
            Ok(a) => {
                ctx.ext_mut::<DiamAnswer>().0 = Some(avps_json(&a.avps));
                1
            }
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("diameter_request: {e}"));
                -1
            }
        }
    }

    /// `diameter_request_async([peer,] appid, commandcode, message)`: 0
    /// (the route ends) once the request is sent; the answer runs
    /// `event_route[diameter:response]` with it in `$diameter_response`.
    /// -1 without that route or when the request cannot be built.
    fn request_async(&self, peer: &str, app: AppId, cmd: CmdCode, message: &str) -> i32 {
        let (Some(peers), Some(hub), Some(net)) = (self.peers.get(), self.hub.get(), self.net.get()) else { return -1 };
        if !hub.has_event(EVENT_RESPONSE) {
            sip_core::log::log(sip_core::log::L_ERR, "diameter_request_async: no event_route[diameter:response]: asynchronous operations disabled");
            return -1;
        }
        let (m, realm, host) = match Self::build(peers, peer, app, cmd, message) {
            Ok(x) => x,
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("diameter_request_async: {e}"));
                return -1;
            }
        };
        let (peers, hub, net) = (peers.clone(), hub.clone(), net.clone());
        let spawned = std::thread::Builder::new().name("diameter-async".into()).spawn(move || {
            sip_core::panic::expendable();
            match peers.request(m, &realm, host.as_deref()) {
                Ok(a) => {
                    let json = avps_json(&a.avps);
                    hub.run_event_with(EVENT_RESPONSE, &*net, None, move |ctx| ctx.ext_mut::<DiamAnswer>().0 = Some(json));
                }
                Err(e) => sip_core::log::log(sip_core::log::L_ERR, &format!("diameter_request_async: {e}")),
            }
        });
        if spawned.is_err() {
            return -1;
        }
        0
    }
}

impl Module for DiameterServer {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "ims_diameter_server"
    }

    fn set_param(&self, name: &str, _v: &Arg) -> Result<(), String> {
        Err(format!("ims_diameter_server: unknown parameter {name:?}"))
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, sig};
        const REQ: &[Param] = &[arg("peer", Str), arg("application", Int), arg("command", Int), arg("message", Str)];
        Some(vec![
            sig(
                "diameter_request",
                "request",
                REQ,
                Ret::Bool,
                "Send a Diameter request (AVPs as JSON) to `peer` (\"\": route by Destination-Realm; Kamailio's 3-argument form leaves it out) and wait; the answer's AVPs go in $diameter_response",
            )
            .allowed(ctx::ANY),
            sig(
                "diameter_request_async",
                "request_async",
                REQ,
                Ret::Action,
                "Send a Diameter request (AVPs as JSON) without waiting; the answer runs event_route[diameter:response] with its AVPs in $diameter_response. Returns 0: the route ends",
            )
            .allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let peers = cdp(reg, "ims_diameter_server")?;
        let _ = self.peers.set(peers.clone());
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        peers.set_fallback_handler(Arc::new(move |m: &Msg| me.answer(m)));
        let ev = |f: fn(&DiamEvent) -> Val| PvSpec::ro(move |c, _| c.ext::<DiamEvent>().map_or(Val::Null, f));
        reg.pv("diameter_command", ev(|e| Val::Int(i64::from(e.cmd))));
        reg.pv("diameter_application", ev(|e| Val::Int(i64::from(e.app))));
        reg.pv("diameter_request", ev(|e| Val::Str(e.request.clone())));
        reg.pv(
            "diameter_response",
            PvSpec::rw(
                |c, _| match c.ext::<DiamEvent>() {
                    Some(e) => lock(&e.response).clone().map_or(Val::Null, Val::Str),
                    None => c.ext::<DiamAnswer>().and_then(|a| a.0.clone()).map_or(Val::Null, Val::Str),
                },
                |c, _, v| {
                    let s = (!v.is_null()).then(|| v.as_str().into_owned());
                    match c.ext::<DiamEvent>() {
                        Some(e) => *lock(&e.response) = s,
                        None => c.ext_mut::<DiamAnswer>().0 = s,
                    }
                    Ok(())
                },
            ),
        );
        type ReqArgs = (Option<DynStr>, sip_core::module::DynInt, sip_core::module::DynInt, DynStr);
        // ([peer,] appid, commandcode, message), as in Kamailio.
        let args = |a: &[Arg]| -> Result<ReqArgs, String> {
            match a {
                [app, cmd, msg] => Ok((None, app.dyn_int()?, cmd.dyn_int()?, msg.dyn_str()?)),
                [peer, app, cmd, msg] => Ok((Some(peer.dyn_str()?), app.dyn_int()?, cmd.dyn_int()?, msg.dyn_str()?)),
                _ => Err("expected [peer,] appid, commandcode, message".into()),
            }
        };
        for (name, is_async) in [("diameter_request", false), ("diameter_request_async", true)] {
            let me = self.clone();
            reg.export("ims_diameter_server", name, args, move |ctx: &mut Ctx, (peer, app, cmd, msg): &ReqArgs| {
                let peer = peer.as_ref().map(|p| p.eval(ctx).into_owned()).unwrap_or_default();
                let (Some(app), Some(cmd)) = (app.eval(ctx), cmd.eval(ctx)) else { return -1 };
                let msg = msg.eval(ctx).into_owned();
                let (Ok(app), Ok(cmd)) = (u32::try_from(app).map(AppId), u32::try_from(cmd).map(CmdCode)) else {
                    warn(format!("{name}: application id {app} / command code {cmd} out of range"));
                    return -1;
                };
                if is_async { me.request_async(&peer, app, cmd, &msg) } else { me.request(ctx, &peer, app, cmd, &msg) }
            });
        }
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avps_to_json_and_back() {
        let avps = vec![
            Avp::str(SESSION_ID, None, "s;1"),
            Avp::u32(RESULT_CODE, None, 2001),
            Avp::str(PUBLIC_IDENTITY, V, "sip:alice@ims.test"),
            Avp::group(SIP_AUTH_DATA_ITEM, V, vec![Avp::str(SIP_AUTHENTICATION_SCHEME, V, "SIP Digest"), Avp::new(SIP_AUTHENTICATE, V, vec![0, 1, 2, 0xff])]),
            Avp::u64(AvpCode(421), None, 1 << 40), // CC-Total-Octets
            Avp::new(AvpCode(9999), None, vec![0xff, 0xfe]),
            Avp::new(HOST_IP_ADDRESS, None, vec![0, 1, 10, 0, 0, 1]),
        ];
        let j = avps_json(&avps);
        let v: Value = sip_core::serde_json::from_str(&j).unwrap();
        // Kamailio's avp2json(): cdp types the base AVPs, the rest are octets.
        assert_eq!(v[0], json!({"avpCode": 263, "vendorId": 0, "DataType": 1, "Flags": 64, "string": "s;1"}));
        assert_eq!(v[1], json!({"avpCode": 268, "vendorId": 0, "DataType": 3, "Flags": 64, "int32": 2001}));
        let pi = crate::hex(b"sip:alice@ims.test");
        assert_eq!(v[2], json!({"avpCode": 601, "vendorId": 10415, "DataType": 0, "Flags": 192, "data": pi, "string": "sip:alice@ims.test"}));
        assert_eq!(v[3]["list"][0]["string"], json!("SIP Digest"));
        assert_eq!(v[3]["list"][1]["int32"], json!(0x000102ff));
        assert_eq!(v[3]["list"][1]["data"], json!("000102ff"));
        assert_eq!(v[4]["int64"], json!(1u64 << 40));
        assert_eq!(v[5], json!({"avpCode": 9999, "vendorId": 0, "DataType": 0, "Flags": 64, "data": "fffe"}), "{j}");
        assert_eq!(v[6]["address"], json!("10.0.0.1"));
        let back = json_avps(&j).unwrap();
        assert_eq!(back[..6], avps[..6]);
        // Input: Flags default to none (V with a vendor; M on the base AVPs
        // cdp types); one object is one AVP; `hexdump` octets.
        let one = json_avps(r#"{"avpCode": 628, "vendorId": 10415, "list": [{"avpCode": 629, "vendorId": 10415, "int32": 1}]}"#).unwrap();
        assert_eq!(one[0].flags, FLAG_V);
        assert_eq!(one[0].group_avps()[0].as_u32(), Some(1));
        assert_eq!(json_avps(r#"[{"avpCode": 268, "vendorId": 0, "int32": 2001}]"#).unwrap()[0].flags, FLAG_M);
        assert_eq!(json_avps(r#"[{"avpCode": 9, "vendorId": 0, "hexdump": "0aFf"}]"#).unwrap()[0].data, vec![0x0a, 0xff]);
        // Items without avpCode or a value are skipped, as Kamailio does.
        assert_eq!(json_avps(r#"[{"avpCode": 1}, {"vendorId": 0, "int32": 1}, {"avpCode": 268, "int32": 2001}]"#).unwrap().len(), 1);
        // Out-of-range numbers are rejected instead of wrapping.
        assert!(json_avps(r#"[{"avpCode": 4294967558, "int32": 1}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": -1, "int32": 1}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": 1, "vendorId": 4294967296, "int32": 1}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": 1, "Flags": 256, "int32": 1}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": 1, "int32": 4294967296}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": 1, "int32": -2147483649}]"#).unwrap().is_empty());
        assert!(json_avps(r#"[{"avpCode": 1, "int32": 18446744073709551615}]"#).unwrap().is_empty());
        // Both readings of 32 bits, and floats, still encode as before.
        assert_eq!(json_avps(r#"[{"avpCode": 1, "int32": -1}]"#).unwrap()[0].data, vec![0xff; 4]);
        assert_eq!(json_avps(r#"[{"avpCode": 1, "int32": 4294967295}]"#).unwrap()[0].data, vec![0xff; 4]);
        assert_eq!(json_avps(r#"[{"avpCode": 1, "int32": 7.9}]"#).unwrap()[0].data, vec![0, 0, 0, 7]);
        assert_eq!(json_avps(r#"[{"avpCode": 1, "int64": -1}]"#).unwrap()[0].data, vec![0xff; 8]);
        assert!(json_avps("[1").is_err());
        assert!(json_avps("").is_err());
    }

    #[test]
    fn cdp_types_flags_and_values() {
        // cdp's forced flags: M on Proxy-Info (33), none on Error-Message
        // (269), only P on Error-Reporting-Host (281).
        let flags = |code: u32, f: u8| json_avps(&format!(r#"{{"avpCode": {code}, "Flags": {f}, "string": "x"}}"#)).unwrap()[0].flags;
        assert_eq!(flags(33, 0), FLAG_M);
        assert_eq!(flags(269, FLAG_M), 0);
        assert_eq!(flags(281, FLAG_M | 0x20), 0x20);
        assert_eq!(flags(9999, 0x20), 0x20, "others as given");
        // Host-IP-Address of an IPv6 host.
        let v6 = Avp::new(HOST_IP_ADDRESS, None, [vec![0, 2], vec![0x20, 0x01, 0x0d, 0xb8], vec![0; 11], vec![1]].concat());
        assert_eq!(avp_json(&v6)["address"], json!("2001.db8.0.0.0.0.0.1"));
        // Octets that start with NUL but are not a group: data only.
        assert_eq!(
            avp_json(&Avp::new(AvpCode(9999), None, vec![0, 0, 0, 1, 2])),
            json!({"avpCode": 9999, "vendorId": 0, "DataType": 0, "Flags": 64, "data": "0000000102"})
        );
        // A non-string "string" value is its JSON text; a scalar is no AVP list.
        assert_eq!(json_avps(r#"{"avpCode": 1, "string": 42}"#).unwrap()[0].data, b"42");
        assert!(json_avps("5").unwrap_err().contains("list of AVPs"));
    }

    /// A server registered on peers `p`, with a script whose
    /// `event_route[diameter:request]` answers what `answer` holds (and
    /// records the command, application and request JSON it saw).
    #[allow(clippy::type_complexity, reason = "test plumbing")]
    fn server(events: &[&str]) -> (DiameterServer, Arc<Mutex<Option<String>>>, Arc<Mutex<Vec<(u32, u32, String)>>>) {
        let d = DiameterServer::default();
        let _ = d.peers.set(crate::testutil::peers());
        let hub = Arc::new(RouteHub::default());
        let (answer, seen) = (Arc::new(Mutex::new(None::<String>)), Arc::new(Mutex::new(Vec::new())));
        let (a2, s2) = (answer.clone(), seen.clone());
        crate::testutil::script(
            &hub,
            events,
            &[],
            Box::new(move |_, ctx| {
                let ev = ctx.ext::<DiamEvent>().unwrap();
                lock(&s2).push((ev.cmd, ev.app, ev.request.clone()));
                *lock(&ev.response) = lock(&a2).clone();
                true
            }),
        );
        let _ = d.hub.set(hub);
        let _ = d.net.set(Arc::new(crate::testutil::NoNet));
        (d, answer, seen)
    }

    fn sh_request(with_sid: bool) -> Msg {
        let mut m = Msg::request(CmdCode(306), AppId(16777217));
        if with_sid {
            m.add(Avp::str(SESSION_ID, None, "hss;1;2"));
        }
        m.add(Avp::str(PUBLIC_IDENTITY, V, "sip:alice@ims.test"));
        m
    }

    #[test]
    fn requests_answered_by_the_event_route() {
        let (d, answer, seen) = server(&[EVENT]);
        // The script's AVPs, after the request's Session-Id (a second one
        // from the script is dropped); Result-Code and Origin-* added.
        *lock(&answer) = Some(r#"[{"avpCode": 263, "string": "other"}, {"avpCode": 9999, "vendorId": 10415, "string": "x"}]"#.into());
        let a = d.answer(&sh_request(true)).unwrap();
        assert!(!a.is_request());
        assert_eq!(a.get_all(SESSION_ID, None).len(), 1);
        assert_eq!(a.str(SESSION_ID).as_deref(), Some("hss;1;2"));
        assert_eq!(a.result(), Some(DIAMETER_SUCCESS));
        assert_eq!((a.str(ORIGIN_HOST).as_deref(), a.str(ORIGIN_REALM).as_deref()), (Some("scscf.ims.test"), Some("ims.test")));
        assert!(a.get(AvpCode(9999), V).is_some());
        let (cmd, app, req) = lock(&seen)[0].clone();
        assert_eq!((cmd, app), (306, 16777217));
        assert!(req.contains(r#""string":"sip:alice@ims.test""#), "{req}");
        // The script's own Result-Code, Origin-Host and Origin-Realm are kept.
        *lock(&answer) = Some(r#"[{"avpCode": 268, "int32": 5001}, {"avpCode": 264, "string": "as"}, {"avpCode": 296, "string": "as.realm"}]"#.into());
        let a = d.answer(&sh_request(false)).unwrap();
        assert_eq!((a.result().map(|r| r.get()), a.str(ORIGIN_HOST).as_deref(), a.str(ORIGIN_REALM).as_deref()), (Some(5001), Some("as"), Some("as.realm")));
        assert_eq!(a.get_all(ORIGIN_HOST, None).len(), 1);
        assert!(a.get(SESSION_ID, None).is_none(), "no Session-Id to copy");
        // No $diameter_response, an empty one, or JSON that doesn't parse: no answer.
        for r in [None, Some(""), Some("[{")] {
            *lock(&answer) = r.map(str::to_string);
            assert!(d.answer(&sh_request(true)).is_none(), "{r:?}");
        }
    }

    #[test]
    fn requests_without_the_event_route_get_3001() {
        let (d, _, seen) = server(&[]);
        let a = d.answer(&sh_request(true)).unwrap();
        assert_eq!(a.result(), Some(DIAMETER_COMMAND_UNSUPPORTED));
        assert_eq!(a.str(ORIGIN_HOST).as_deref(), Some("scscf.ims.test"));
        assert!(lock(&seen).is_empty());
        // Not set up (not registered, or not spawned): nothing.
        assert!(DiameterServer::default().answer(&sh_request(true)).is_none());
        let half = DiameterServer::default();
        let _ = half.peers.set(crate::testutil::peers());
        assert!(half.answer(&sh_request(true)).is_none());
    }

    #[test]
    fn requests_built_from_json() {
        let p = crate::testutil::peers();
        // The script's Session-Id is not doubled; a peer is the Destination-Host.
        let (m, realm, host) = DiameterServer::build(&p, " hss.ims.test ", AppId(16777217), CmdCode(306), r#"[{"avpCode": 263, "string": "mine"}]"#).unwrap();
        assert_eq!(m.get_all(SESSION_ID, None).len(), 1);
        assert_eq!((realm.as_str(), host.as_deref()), ("ims.test", Some("hss.ims.test")));
        // The message's Destination-Realm / -Host win.
        let (m, realm, host) =
            DiameterServer::build(&p, "hss", AppId(1), CmdCode(2), r#"[{"avpCode": 283, "string": "r.test"}, {"avpCode": 293, "string": "h"}]"#).unwrap();
        assert_eq!((realm.as_str(), host), ("r.test", None));
        assert!(m.str(SESSION_ID).is_some_and(|s| s.ends_with(";script")));
        assert!(DiameterServer::build(&p, "", AppId(1), CmdCode(2), "{").is_err());
    }

    #[test]
    fn sending_requests_without_a_peer() {
        use crate::testutil::{request, with_msg};
        let (d, _, _) = server(&[EVENT]);
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        // A message that doesn't parse, and no peer to answer: -1, no answer kept.
        let r = with_msg(&invite, |ctx| {
            ctx.ext_mut::<DiamAnswer>().0 = Some("old".into());
            let bad = d.request(ctx, "", AppId(1), CmdCode(2), "nope");
            let none = ctx.ext::<DiamAnswer>().and_then(|a| a.0.clone());
            (bad, none, d.request(ctx, "", AppId(1), CmdCode(2), "[]"))
        });
        assert_eq!(r, (-1, None, -1));
        assert_eq!(with_msg(&invite, |ctx| DiameterServer::default().request(ctx, "", AppId(1), CmdCode(2), "[]")), -1);
        // Asynchronous: needs event_route[diameter:response] and a message that parses.
        assert_eq!(d.request_async("", AppId(1), CmdCode(2), "[]"), -1, "no response route");
        let (d, _, _) = server(&[EVENT_RESPONSE]);
        assert_eq!(d.request_async("", AppId(1), CmdCode(2), "{"), -1);
        assert_eq!(d.request_async("", AppId(1), CmdCode(2), "[]"), 0, "sent (and the failure logged)");
        assert_eq!(DiameterServer::default().request_async("", AppId(1), CmdCode(2), "[]"), -1);
    }

    #[test]
    fn exports_and_variables() {
        use crate::testutil::{call, fixup_err, registry, request, s, with_msg};
        let d = Arc::new(DiameterServer::default());
        assert!(d.set_param("anything", &s("x")).unwrap_err().contains("unknown parameter"));
        let mut reg = registry(false);
        reg.load(d).unwrap();
        assert!(fixup_err(&reg, "diameter_request", &[s("1"), s("2")]).is_some());
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        let pv = |name: &str| sip_core::pv::parse_pv(name, reg.pvs()).unwrap();
        let r = with_msg(&invite, |ctx| {
            // Out-of-range ids: -1 before anything is sent.
            let bad = call(&reg, ctx, "diameter_request", &[Arg::Int(-1), Arg::Int(2), s("[]")]);
            let bad_async = call(&reg, ctx, "diameter_request_async", &[s("hss"), Arg::Int(1), Arg::Int(1 << 33), s("[]")]);
            // $diameter_response outside the event route: read/write.
            let resp = pv("$diameter_response");
            resp.set(ctx, Val::Str("[1]".into())).unwrap();
            let after_set = resp.get(ctx);
            let sent = call(&reg, ctx, "diameter_request", &[s("hss.ims.test"), Arg::Int(16777217), Arg::Int(306), s("[]")]);
            let after_fail = resp.get(ctx).is_null();
            resp.set(ctx, Val::Null).unwrap();
            (bad, bad_async, after_set, sent, after_fail, pv("$diameter_command").get(ctx).is_null())
        });
        assert_eq!(r, (-1, -1, Val::Str("[1]".into()), -1, true, true));
    }
}
