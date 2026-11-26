//! `ims_qos` — the Rx interface of a P-CSCF towards the PCRF:
//! `Rx_AAR(route, direction[, subscription_id[, subscription_id_type]])`
//! sends an AA-Request describing the session's media (one
//! Media-Component-Description per SDP `m=` line, with flow descriptions
//! from the `c=`/port); further calls for the same call update it. When the
//! call ends (the `dialog` module) the session is closed with an STR; an
//! Abort-Session-Request from the PCRF ends the call. Parameters:
//! `rx_dest_realm` (`af_signaling_ip` and the other Kamailio parameters are
//! accepted and ignored).

use crate::cdp;
use mod_dialog::Dialog;
use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry, ShardedMap};
use sip_diameter::codes::*;
use sip_diameter::{Avp, DiameterError, Msg, Peers};
use sip_parser::{HdrFlags, HdrKind};
use std::sync::{Arc, Mutex, OnceLock};

pub struct Qos {
    dest_realm: Mutex<String>,
    /// Call-ID → Rx Session-Id.
    sessions: ShardedMap<String, String>,
    peers: OnceLock<Arc<Peers>>,
    dlg: OnceLock<Arc<Dialog>>,
    tm: OnceLock<Arc<mod_txn::Tm>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

/// `await ims_qos.authorize_media(…)`: the AAA's outcome.
static AAA: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy { name: "AarResult", fields: &[("code", "$avp(aar_return_code)", sip_core::sig::FieldTy::Int)] };

impl Default for Qos {
    fn default() -> Self {
        Self {
            dest_realm: Mutex::new(String::new()),
            sessions: ShardedMap::new(16),
            peers: OnceLock::new(),
            dlg: OnceLock::new(),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
        }
    }
}

/// SDP → Media-Component-Descriptions.
fn media_components(sdp: &str) -> Vec<Avp> {
    let mut out = Vec::new();
    let mut session_ip = String::from("any");
    let mut n = 0u32;
    let mut cur: Option<(String, String, Option<String>)> = None; // (type, port, ip)
    let flush = |cur: &mut Option<(String, String, Option<String>)>, session_ip: &str, out: &mut Vec<Avp>, n: &mut u32| {
        if let Some((ty, port, ip)) = cur.take() {
            *n = n.saturating_add(1);
            let ip = ip.unwrap_or_else(|| session_ip.to_string());
            let media_type = match ty.as_str() {
                "audio" => 0,
                "video" => 1,
                "application" => 3,
                "message" => 6,
                "text" => 5,
                _ => 0xFFFF_FFFF,
            };
            out.push(Avp::group(
                MEDIA_COMPONENT_DESCRIPTION,
                V,
                vec![
                    Avp::u32(MEDIA_COMPONENT_NUMBER, V, *n),
                    Avp::u32(MEDIA_TYPE, V, media_type),
                    Avp::group(
                        MEDIA_SUB_COMPONENT,
                        V,
                        vec![
                            Avp::u32(FLOW_NUMBER, V, 1),
                            Avp::str(FLOW_DESCRIPTION, V, &format!("permit out 17 from any to {ip} {port}")),
                            Avp::str(FLOW_DESCRIPTION, V, &format!("permit in 17 from {ip} {port} to any")),
                        ],
                    ),
                ],
            ));
        }
    };
    for line in sdp.lines() {
        let line = line.trim_end();
        if let Some(c) = line.strip_prefix("c=") {
            let ip = c.split_whitespace().nth(2).unwrap_or("any").split('/').next().unwrap_or("any").to_string();
            match cur.as_mut() {
                Some(m) => m.2 = Some(ip),
                None => session_ip = ip,
            }
        } else if let Some(m) = line.strip_prefix("m=") {
            flush(&mut cur, &session_ip, &mut out, &mut n);
            let mut f = m.split_whitespace();
            let ty = f.next().unwrap_or("");
            // `port/count` (RFC 4566): the flow is for the first port.
            let port = f.next().map_or("0", |p| p.split('/').next().unwrap_or(p));
            cur = Some((ty.to_string(), port.to_string(), None));
        }
    }
    flush(&mut cur, &session_ip, &mut out, &mut n);
    out
}

impl Qos {
    fn realm(&self, peers: &Peers) -> String {
        let r = lock(&self.dest_realm).clone();
        if r.is_empty() { peers.cfg.realm.clone() } else { r }
    }

    /// Rx AAR for the message's SDP. Asynchronous (the transaction is
    /// suspended until the PCRF answers) from `.fsr` and with an existing
    /// Kamailio reply route; `$avp(aar_return_code)`: 1 granted, -1 not.
    fn aar(self: &Arc<Self>, ctx: &mut Ctx<'_, '_>, route: &str, sub: Option<(String, u32)>) -> i32 {
        let Some(peers) = self.peers.get() else { return -1 };
        let Some((callid, sid, aar)) = self.aar_msg(peers, ctx, sub) else {
            set_rc(ctx, "aar_return_code", -1);
            return -1;
        };
        if let (Some(tm), Some(hub)) = (self.tm.get(), self.hub.get())
            && crate::cx_async::wanted(hub, route)
        {
            let (me2, p, m2, realm) = (self.clone(), peers.clone(), aar.clone(), self.realm(peers));
            let (c2, s2) = (callid.clone(), sid.clone());
            let sent = crate::cx_async::run(
                tm,
                hub,
                ctx,
                route,
                peers.cfg.timeout,
                move |done| p.request_cb(m2, &realm, None, done),
                Box::new(move |res, c| {
                    let rc = me2.aar_answer(res, &c2, &s2);
                    set_rc(c, "aar_return_code", rc);
                }),
            );
            if let Some(rc) = sent {
                return rc;
            }
        }
        let rc = self.aar_answer(peers.request(aar, &self.realm(peers), None), &callid, &sid);
        set_rc(ctx, "aar_return_code", rc);
        rc
    }

    fn aar_answer(&self, res: Result<Msg, DiameterError>, callid: &str, sid: &str) -> i32 {
        match res {
            Ok(a) if a.result() == Some(DIAMETER_SUCCESS) => {
                self.sessions.insert(callid.to_string(), sid.to_string());
                1
            }
            Ok(a) => {
                sip_core::log::log(sip_core::log::L_WARN, &format!("ims_qos: AAA result {:?}", a.result()));
                -1
            }
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_qos: AAR: {e}"));
                -1
            }
        }
    }

    /// (Call-ID, Rx Session-Id, AAR) for the message's SDP.
    fn aar_msg(&self, peers: &Peers, ctx: &mut Ctx<'_, '_>, sub: Option<(String, u32)>) -> Option<(String, String, Msg)> {
        ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
        let callid = ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).into_owned())?;
        let sdp = String::from_utf8_lossy(&ctx.body()).into_owned();
        let comps = media_components(&sdp);
        if comps.is_empty() {
            return None;
        }
        let sid = self.sessions.get_cloned(&callid).unwrap_or_else(|| peers.session_id("rx"));
        let mut aar = Msg::request(CMD_AA, APP_RX);
        aar.add(Avp::str(SESSION_ID, None, &sid));
        aar.add(Avp::u32(AUTH_APPLICATION_ID, None, APP_RX.get())).add(Avp::str(AF_APPLICATION_IDENTIFIER, V, "IMS Services"));
        for c in comps {
            aar.add(c);
        }
        let (data, ty) = sub.unwrap_or_else(|| {
            let from = ctx.msg.get(HdrKind::From).map(|h| String::from_utf8_lossy(sip_parser::uri::name_addr(h.body).0).into_owned()).unwrap_or_default();
            (from, 2)
        });
        aar.add(Avp::group(SUBSCRIPTION_ID, None, vec![Avp::u32(SUBSCRIPTION_ID_TYPE, None, ty), Avp::str(SUBSCRIPTION_ID_DATA, None, &data)]));
        if let std::net::IpAddr::V4(ip) = ctx.src.addr.ip() {
            aar.add(Avp::new(FRAMED_IP_ADDRESS, None, ip.octets().to_vec()));
        }
        aar.add(Avp::u32(SPECIFIC_ACTION, V, 1)); // CHARGING_CORRELATION_EXCHANGE
        Some((callid, sid, aar))
    }

    fn str_(&self, callid: &str) {
        let (Some(peers), Some(sid)) = (self.peers.get(), self.sessions.remove(callid)) else { return };
        let mut m = Msg::request(CMD_ST, APP_RX);
        m.add(Avp::str(SESSION_ID, None, &sid)).add(Avp::u32(AUTH_APPLICATION_ID, None, APP_RX.get())).add(Avp::u32(TERMINATION_CAUSE, None, 1));
        if let Err(e) = peers.request(m, &self.realm(peers), None) {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_qos: Rx STR for {callid}: {e}"));
        }
    }
}

impl Module for Qos {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("rx_dest_realm", Ty::Str, "", "Destination realm of Rx requests to the PCRF (default: the cdp realm)")])
    }

    fn name(&self) -> &'static str {
        "ims_qos"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, opt, sig};
        const AAR: &[Param] = &[arg("direction", Enum(&["orig", "term"])).lit(), opt("subscription_id", Str), opt("subscription_type", Int)];
        Some(vec![
            sig(
                "Rx_AAR",
                "authorize_media",
                AAR,
                Ret::Await(&AAA),
                "Rx AAR for the call's media: `let r = await ims_qos.authorize_media(\"orig\")`; r.code 1 granted, -1 not (the transaction waits for the PCRF)",
            )
            .fixed(&[""]),
            sig("Rx_STR", "terminate_session", &[], Ret::Bool, "End this call's Rx session (false: there was none)").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "rx_dest_realm" => *lock(&self.dest_realm) = v.str()?.into(),
            "af_signaling_ip"
            | "af_signaling_ip6"
            | "rx_forced_peer"
            | "rx_auth_expiry"
            | "cdp_event_latency"
            | "authorize_video_flow"
            | "include_rtcp_fd"
            | "terminate_dialog_on_rx_failure"
            | "delete_contact_on_rx_failure"
            | "regex_sdp_ip_prefix_to_maintain_in_fd"
            | "early_qosrelease_reason"
            | "confirmed_qosrelease_headers"
            | "trust_bottom_via"
            | "recv_mode"
            | "dialog_direction" => {}
            _ => return Err(format!("ims_qos: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let peers = cdp(reg, "ims_qos")?;
        // ASR from the PCRF: the bearer is gone, end the call.
        let me = self.clone();
        peers.add_handler(
            APP_RX,
            CMD_AS,
            Arc::new(move |m: &Msg| {
                let sid = m.str(SESSION_ID).unwrap_or_default();
                let mut callid = None;
                me.sessions.for_each_mut(|k, v| {
                    if *v == sid {
                        callid = Some(k.clone());
                    }
                });
                if let (Some(c), Some(d)) = (callid, me.dlg.get()) {
                    d.end_by_callid(&c);
                }
                let mut a = m.answer();
                a.add(Avp::str(SESSION_ID, None, &sid)).add(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get()));
                Some(a)
            }),
        );
        let _ = self.peers.set(peers);
        if let Some(d) = reg.api::<Dialog>() {
            let me = self.clone();
            d.on_state(Arc::new(move |c| {
                if c.state == "terminated" {
                    me.str_(&c.callid);
                }
            }));
            let _ = self.dlg.set(d);
        }
        if let Some(tm) = reg.api::<mod_txn::Tm>() {
            let _ = self.tm.set(tm);
        }
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        type AarArgs = (String, Option<(DynStr, Option<DynStr>)>);
        reg.export(
            "ims_qos",
            "Rx_AAR",
            |a: &[Arg]| -> Result<AarArgs, String> {
                let route = a.first().and_then(|r| r.str().ok()).unwrap_or("").to_string();
                match a {
                    [_, _] => Ok((route, None)),
                    [_, _, sub] => Ok((route, Some((sub.dyn_str()?, None)))),
                    [_, _, sub, ty] => Ok((route, Some((sub.dyn_str()?, Some(ty.dyn_str()?))))),
                    _ => Err("expected route, direction[, subscription_id[, type]]".into()),
                }
            },
            move |ctx: &mut Ctx, (route, s): &AarArgs| {
                let sub = s.as_ref().map(|(d, t)| (d.eval(ctx).into_owned(), t.as_ref().and_then(|t| t.eval(ctx).trim().parse().ok()).unwrap_or(2)));
                me.aar(ctx, route, sub)
            },
        );
        let me = self.clone();
        reg.export(
            "ims_qos",
            "Rx_STR",
            |a: &[Arg]| sip_core::want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                let Some(c) = ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).into_owned()) else { return -1 };
                let had = me.sessions.get_cloned(&c).is_some();
                me.str_(&c);
                rc(had)
            },
        );
        Ok(())
    }
}

/// `$avp(name)` = rc, for the reply route or the code after `await`.
pub(crate) fn set_rc(ctx: &mut Ctx<'_, '_>, name: &str, rc: i32) {
    ctx.ext_mut::<sip_core::TxnVars>().avps.insert(name.to_string(), vec![sip_core::pv::Val::Int(rc.into())]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (media type, number, downlink flow, uplink flow) of each component.
    fn comps(sdp: &str) -> Vec<(u32, u32, String, String)> {
        media_components(sdp)
            .iter()
            .map(|c| {
                let g = c.group_avps();
                let u = |code| sip_diameter::find(&g, code, V).and_then(Avp::as_u32).unwrap();
                let sub = sip_diameter::find(&g, MEDIA_SUB_COMPONENT, V).unwrap().group_avps();
                let flows: Vec<String> = sub.iter().filter(|a| a.code == FLOW_DESCRIPTION).map(Avp::as_str).collect();
                (u(MEDIA_TYPE), u(MEDIA_COMPONENT_NUMBER), flows[0].clone(), flows[1].clone())
            })
            .collect()
    }

    #[test]
    fn media_types_numbers_and_addresses() {
        let sdp = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\nc=IN IP4 192.0.2.10/127\r\nt=0 0\r\n\
                   m=audio 4000 RTP/AVP 0\r\nm=text 4002 RTP/AVP 98\r\nc=IN IP6 2001:db8::5\r\n\
                   m=message 4004 TCP/MSRP *\r\nm=application 4006 UDP/BFCP *\r\nm=image 4008 udptl t38\r\n";
        let c = comps(sdp);
        let types: Vec<(u32, u32)> = c.iter().map(|x| (x.0, x.1)).collect();
        assert_eq!(types, [(0, 1), (5, 2), (6, 3), (3, 4), (0xFFFF_FFFF, 5)]);
        assert_eq!(c[0].2, "permit out 17 from any to 192.0.2.10 4000", "session c= without the TTL");
        assert_eq!(c[0].3, "permit in 17 from 192.0.2.10 4000 to any");
        assert_eq!(c[1].2, "permit out 17 from any to 2001:db8::5 4002", "media c= wins");
        assert_eq!(c[2].2, "permit out 17 from any to 192.0.2.10 4004", "it applies to its m= only");
        // No c= at all; no m= at all; LF line ends.
        assert_eq!(comps("m=audio 1000 RTP/AVP 0")[0].2, "permit out 17 from any to any 1000");
        assert_eq!(comps("c=IN IP4 1.2.3.4\nm=audio 4000/2 RTP/AVP 0\n")[0].2, "permit out 17 from any to 1.2.3.4 4000", "port/count: the first port");
        assert!(media_components("v=0\r\nc=IN IP4 1.2.3.4\r\n").is_empty());
        assert_eq!(comps("c=IN IP4 1.2.3.4\nm=video 9 RTP/AVP 96\n")[0].0, 1);
    }

    #[test]
    fn aar_for_the_sdp_of_a_request() {
        let q = Qos::default();
        let p = crate::testutil::peers();
        let invite = crate::testutil::request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 4000 RTP/AVP 0\r\n");
        let (callid, sid, aar) = crate::testutil::with_msg(&invite, |ctx| q.aar_msg(&p, ctx, None)).unwrap();
        assert_eq!(callid, "cid-1");
        assert_eq!((aar.cmd, aar.app), (CMD_AA, APP_RX));
        assert_eq!(aar.str(SESSION_ID), Some(sid.clone()));
        assert!(sid.starts_with("scscf.ims.test;") && sid.ends_with(";rx"), "{sid}");
        assert_eq!(aar.get(AF_APPLICATION_IDENTIFIER, V).map(Avp::as_str).as_deref(), Some("IMS Services"));
        assert_eq!(aar.get_all(MEDIA_COMPONENT_DESCRIPTION, V).len(), 1);
        let sub = aar.get(SUBSCRIPTION_ID, None).unwrap().group_avps();
        assert_eq!(sip_diameter::find(&sub, SUBSCRIPTION_ID_DATA, None).map(Avp::as_str).as_deref(), Some("sip:alice@ims.test"));
        assert_eq!(aar.get(FRAMED_IP_ADDRESS, None).map(|a| a.data.clone()), Some(vec![192, 0, 2, 9]));
        assert_eq!(aar.get(SPECIFIC_ACTION, V).and_then(Avp::as_u32), Some(1));
        // An explicit subscription id; a known call reuses its Rx session.
        q.sessions.insert("cid-1".into(), "kept-sid".into());
        let (_, sid2, aar2) = crate::testutil::with_msg(&invite, |ctx| q.aar_msg(&p, ctx, Some(("tel:+1".into(), 0)))).unwrap();
        assert_eq!(sid2, "kept-sid");
        let sub = aar2.get(SUBSCRIPTION_ID, None).unwrap().group_avps();
        assert_eq!(sip_diameter::find(&sub, SUBSCRIPTION_ID_TYPE, None).and_then(Avp::as_u32), Some(0));
        // No SDP: no AAR.
        let bye = crate::testutil::request("BYE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert!(crate::testutil::with_msg(&bye, |ctx| q.aar_msg(&p, ctx, None)).is_none());
    }

    #[test]
    fn aaa_outcomes() {
        let q = Qos::default();
        let aaa = |code: u32| {
            let mut a = Msg::request(CMD_AA, APP_RX).answer();
            a.add(Avp::u32(RESULT_CODE, None, code));
            a
        };
        assert_eq!(q.aar_answer(Ok(aaa(2001)), "c1", "s1"), 1);
        assert_eq!(q.sessions.get_cloned("c1").as_deref(), Some("s1"));
        assert_eq!(q.aar_answer(Ok(aaa(5065)), "c2", "s2"), -1);
        assert_eq!(q.aar_answer(Err(DiameterError::Timeout { peer: None }), "c3", "s3"), -1);
        assert!(q.sessions.get_cloned("c2").is_none() && q.sessions.get_cloned("c3").is_none());
    }

    #[test]
    fn sdp() {
        let c = media_components("v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\nm=video 5000 RTP/AVP 96\r\nc=IN IP4 10.0.0.2\r\n");
        assert_eq!(c.len(), 2);
        let g = c[1].group_avps();
        assert_eq!(sip_diameter::find(&g, MEDIA_TYPE, V).unwrap().as_u32(), Some(1));
        let sub = sip_diameter::find(&g, MEDIA_SUB_COMPONENT, V).unwrap().group_avps();
        assert_eq!(sip_diameter::find(&sub, FLOW_DESCRIPTION, V).unwrap().as_str(), "permit out 17 from any to 10.0.0.2 5000");
    }

    const SDP: &str = "v=0\r\nc=IN IP4 192.0.2.10\r\nm=audio 4000 RTP/AVP 0\r\n";

    /// A Qos registered with cdp (and tm when `tm`), its registry.
    fn loaded(tm: bool) -> (Arc<Qos>, sip_core::Registry) {
        let q = Arc::new(Qos::default());
        let mut reg = crate::testutil::registry(tm);
        reg.load(q.clone()).unwrap();
        (q, reg)
    }

    #[test]
    fn aar_without_media_or_without_an_answer() {
        use crate::testutil::{avp_int, reply_msg, request, with_msg};
        let (q, _reg) = loaded(true);
        // No SDP: no AAR, -1 at once.
        let bye = request("BYE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&bye, |ctx| (q.aar(ctx, "", None), avp_int(ctx, "aar_return_code"))), (-1, Some(-1)));
        // A 183 (onreply route) can't be suspended: the AAR is sent and
        // waited for; no PCRF peer, so -1.
        let r183 = reply_msg(183, "Content-Type: application/sdp\n", SDP);
        assert_eq!(with_msg(&r183, |ctx| (q.aar(ctx, "", Some(("tel:+1".into(), 0))), avp_int(ctx, "aar_return_code"))), (-1, Some(-1)));
        // A request is suspended while the PCRF answers.
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", SDP);
        assert_eq!(with_msg(&invite, |ctx| q.aar(ctx, "", None)), 0);
        // Not registered with cdp: -1.
        assert_eq!(with_msg(&invite, |ctx| Arc::new(Qos::default()).aar(ctx, "", None)), -1);
    }

    #[test]
    fn aar_from_an_ipv6_ue_has_no_framed_ip() {
        use crate::testutil::{NoNet, peers, request, with_msg_at};
        let q = Qos::default();
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", SDP);
        let aar = with_msg_at(&invite, &NoNet, "[2001:db8::9]:5060", |ctx| q.aar_msg(&peers(), ctx, None)).unwrap().2;
        assert!(aar.get(FRAMED_IP_ADDRESS, None).is_none());
        assert!(aar.get(SUBSCRIPTION_ID, None).is_some());
    }

    #[test]
    fn exports_parameters_and_session_termination() {
        use crate::testutil::{call, fixup_err, request, s, with_msg};
        let q = Qos::default();
        q.set_param("rx_dest_realm", &s("pcrf.test")).unwrap();
        for ignored in ["af_signaling_ip", "recv_mode", "dialog_direction"] {
            q.set_param(ignored, &s("x")).unwrap();
        }
        assert!(q.set_param("nope", &s("x")).unwrap_err().contains("unknown parameter"));
        assert!(sip_core::Registry::default().load(Arc::new(Qos::default())).unwrap_err().contains("needs cdp"));
        let (q, reg) = loaded(false);
        assert!(fixup_err(&reg, "Rx_AAR", &[s("")]).is_some());
        assert!(fixup_err(&reg, "Rx_AAR", &[s(""), s("orig"), s("a"), s("2"), s("x")]).is_some());
        assert!(fixup_err(&reg, "Rx_STR", &[s("x")]).is_some());
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", SDP);
        // No tm: sent and waited for (no PCRF: -1); a subscription id and type.
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "Rx_AAR", &[s(""), s("orig"), s("tel:+1"), s("0")])), -1);
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "Rx_AAR", &[s(""), s("orig"), s("tel:+1")])), -1);
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "Rx_AAR", &[s("R"), s("term")])), -1);
        // Rx_STR: 1 when the call had a session (which goes, even though
        // the STR finds no PCRF), else -1.
        q.sessions.insert("cid-1".into(), "rx-sid".into());
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "Rx_STR", &[])), 1);
        assert!(q.sessions.get_cloned("cid-1").is_none());
        assert_eq!(with_msg(&invite, |ctx| call(&reg, ctx, "Rx_STR", &[])), -1);
    }
}
