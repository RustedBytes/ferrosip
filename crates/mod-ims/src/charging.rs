//! `ims_charging` — online charging over Ro (Diameter Credit-Control,
//! RFC 4006 / TS 32.299) for calls the `dialog` module tracks:
//! `Ro_CCR(route, direction, reservation_units, incoming_trunk_id,
//! outgoing_trunk_id)` on the initial INVITE sends CCR-Initial asking for
//! `reservation_units` seconds; 1 if the OCS grants (then call
//! `t_relay()`), -1 if not (answer 402). While the call is up, a CCR-Update
//! reports the used time and asks for more before the grant runs out; a
//! refusal (e.g. 4012 credit limit reached) ends the call with BYEs. The
//! end of the call sends CCR-Termination with the time used.
//! Parameters: `destination_realm`, `service_context_id_root`
//! ("32260@3gpp.org"), `interim_update_credits` (seconds asked per update).

use crate::cdp;
use mod_dialog::{Dialog, DlgChange};
use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, ShardedMap};
use sip_diameter::codes::*;
use sip_diameter::{Avp, DiameterError, Msg, Peers, find};
use sip_parser::uri::name_addr;
use sip_parser::{HdrFlags, HdrKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug)]
struct Session {
    sid: String,
    subscriber: String,
    number: u32,
    granted: u64,
    /// When the call was answered / the last report.
    started: Option<u64>,
    reported_at: u64,
    used_total: u64,
}

/// Diameter `Time` (RFC 6733 §4.3.1): NTP seconds, which are defined
/// modulo 2^32 (the field rolls over in 2036).
#[allow(clippy::cast_possible_truncation, reason = "Diameter Time is NTP seconds modulo 2^32 by definition")]
fn ntp_time(unix: u64) -> u32 {
    unix.wrapping_add(2_208_988_800) as u32
}

/// A CC-Time (Unsigned32 seconds): a duration too long for the AVP is
/// reported as the largest one it can carry rather than wrapping.
fn cc_time(secs: u64) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX)
}

pub struct Charging {
    dest_realm: Mutex<String>,
    context: Mutex<String>,
    interim: AtomicU64,
    sessions: ShardedMap<String, Session>,
    peers: OnceLock<Arc<Peers>>,
    dlg: OnceLock<Arc<Dialog>>,
    tm: OnceLock<Arc<mod_txn::Tm>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

/// `await ims_charging.reserve(…)`: the CCA's outcome.
static CCA: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy { name: "CcaResult", fields: &[("code", "$avp(cca_return_code)", sip_core::sig::FieldTy::Int)] };

impl Default for Charging {
    fn default() -> Self {
        Self {
            dest_realm: Mutex::new(String::new()),
            context: Mutex::new("32260@3gpp.org".into()),
            interim: AtomicU64::new(30),
            sessions: ShardedMap::new(16),
            peers: OnceLock::new(),
            dlg: OnceLock::new(),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
        }
    }
}

impl Charging {
    fn realm(&self, peers: &Peers) -> String {
        let r = lock(&self.dest_realm).clone();
        if r.is_empty() { peers.cfg.realm.clone() } else { r }
    }

    fn ccr(&self, s: &Session, kind: u32, used: Option<u64>, requested: Option<u64>) -> Result<Msg, DiameterError> {
        let peers = self.peers.get().ok_or(DiameterError::NoCdp)?;
        peers.request(self.ccr_msg(s, kind, used, requested), &self.realm(peers), None)
    }

    fn ccr_msg(&self, s: &Session, kind: u32, used: Option<u64>, requested: Option<u64>) -> Msg {
        let mut m = Msg::request(CMD_CC, APP_CC);
        m.add(Avp::str(SESSION_ID, None, &s.sid))
            .add(Avp::u32(AUTH_APPLICATION_ID, None, APP_CC.get()))
            .add(Avp::str(SERVICE_CONTEXT_ID, None, &lock(&self.context)))
            .add(Avp::u32(CC_REQUEST_TYPE, None, kind))
            .add(Avp::u32(CC_REQUEST_NUMBER, None, s.number))
            .add(Avp::u32(EVENT_TIMESTAMP, None, ntp_time(unix_secs())))
            .add(Avp::group(SUBSCRIPTION_ID, None, vec![Avp::u32(SUBSCRIPTION_ID_TYPE, None, 2), Avp::str(SUBSCRIPTION_ID_DATA, None, &s.subscriber)]));
        let mut mscc = Vec::new();
        if let Some(r) = requested {
            mscc.push(Avp::group(REQUESTED_SERVICE_UNIT, None, vec![Avp::u32(CC_TIME, None, cc_time(r))]));
        }
        if let Some(u) = used {
            mscc.push(Avp::group(USED_SERVICE_UNIT, None, vec![Avp::u32(CC_TIME, None, cc_time(u))]));
        }
        m.add(Avp::group(MULTIPLE_SERVICES_CREDIT_CONTROL, None, mscc));
        m
    }

    /// Granted CC-Time of a CCA (MSCC or top level).
    fn granted(a: &Msg) -> Option<u64> {
        let from =
            |avps: &[Avp]| find(avps, GRANTED_SERVICE_UNIT, None).and_then(|g| find(&g.group_avps(), CC_TIME, None).and_then(Avp::as_u32)).map(u64::from);
        a.get(MULTIPLE_SERVICES_CREDIT_CONTROL, None).and_then(|m| from(&m.group_avps())).or_else(|| from(&a.avps))
    }

    /// Ro CCR-Initial for the call. Asynchronous (the transaction is
    /// suspended until the OCS answers) from `.fsr` and with an existing
    /// Kamailio reply route; `$avp(cca_return_code)`: 1 granted, -1 not.
    fn initial(self: &Arc<Self>, ctx: &mut Ctx<'_, '_>, route: &str, direction: &str, units: u64) -> i32 {
        let Some(peers) = self.peers.get() else { return -1 };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let Some(callid) = ctx.msg.get(HdrKind::CallId).map(|h| s(h.body)) else { return -1 };
        let subscriber = if direction.starts_with("term") {
            s(ctx.ruri())
        } else {
            let pai = ctx.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"p-asserted-identity")).map(|h| s(name_addr(h.body).0));
            pai.or_else(|| ctx.msg.get(HdrKind::From).map(|h| s(name_addr(h.body).0))).unwrap_or_default()
        };
        let sess = Session { sid: peers.session_id("ro"), subscriber, number: 0, granted: 0, started: None, reported_at: 0, used_total: 0 };
        let ccr = self.ccr_msg(&sess, CC_INITIAL, None, Some(units));
        if let (Some(tm), Some(hub)) = (self.tm.get(), self.hub.get())
            && crate::cx_async::wanted(hub, route)
        {
            let (me, p, m2, realm, c2, s2) = (self.clone(), peers.clone(), ccr.clone(), self.realm(peers), callid.clone(), sess.clone());
            let sent = crate::cx_async::run(
                tm,
                hub,
                ctx,
                route,
                peers.cfg.timeout,
                move |done| p.request_cb(m2, &realm, None, done),
                Box::new(move |res, c| {
                    let rc = me.initial_answer(res, c2, s2, units);
                    crate::qos::set_rc(c, "cca_return_code", rc);
                }),
            );
            if let Some(rc) = sent {
                return rc;
            }
        }
        let rc = self.initial_answer(peers.request(ccr, &self.realm(peers), None), callid, sess, units);
        crate::qos::set_rc(ctx, "cca_return_code", rc);
        rc
    }

    fn initial_answer(&self, res: Result<Msg, DiameterError>, callid: String, mut sess: Session, units: u64) -> i32 {
        match res {
            Ok(a) if a.result() == Some(DIAMETER_SUCCESS) => {
                sess.granted = Self::granted(&a).unwrap_or(units);
                sess.number = 1;
                self.sessions.insert(callid, sess);
                1
            }
            Ok(a) => {
                sip_core::log::log(sip_core::log::L_NOTICE, &format!("ims_charging: CCA-I result {:?}", a.result()));
                -1
            }
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_charging: CCR-I: {e}"));
                -1
            }
        }
    }

    fn on_change(&self, c: &DlgChange) {
        match c.state {
            "confirmed" => {
                self.sessions.with(&c.callid, |s| {
                    s.started = Some(unix_secs());
                    s.reported_at = unix_secs();
                });
            }
            "terminated" => {
                if let Some(mut s) = self.sessions.remove(&c.callid) {
                    let used = s.started.map_or(0, |_| unix_secs().saturating_sub(s.reported_at));
                    s.used_total = s.used_total.saturating_add(used);
                    if let Err(e) = self.ccr(&s, CC_TERMINATION, Some(used), None) {
                        // The final usage of this call was not reported.
                        sip_core::stats::inc(sip_core::stats::counter("ims_charging", "ccr_t_failed"));
                        sip_core::log::log(sip_core::log::L_ERR, &format!("ims_charging: CCR-T for {}: {e}", c.callid));
                    }
                }
            }
            _ => {}
        }
    }

    /// Interim updates; a refusal ends the call.
    fn tick(&self) {
        let t = unix_secs();
        let mut due = Vec::new();
        self.sessions.for_each_mut(|k, s| {
            if s.started.is_some() && t.saturating_add(1) >= s.reported_at.saturating_add(s.granted) {
                due.push((k.clone(), s.clone()));
            }
        });
        for (callid, mut s) in due {
            let used = t.saturating_sub(s.reported_at);
            let ask = self.interim.load(Ordering::Relaxed);
            let ok = match self.ccr(&s, CC_UPDATE, Some(used), Some(ask)) {
                Ok(a) if a.result() == Some(DIAMETER_SUCCESS) && Self::granted(&a).unwrap_or(0) > 0 => {
                    s.granted = Self::granted(&a).unwrap_or(ask);
                    true
                }
                _ => false,
            };
            s.number = s.number.saturating_add(1);
            s.used_total = s.used_total.saturating_add(used);
            s.reported_at = t;
            if ok {
                self.sessions.insert(callid, s);
            } else {
                sip_core::log::log(sip_core::log::L_NOTICE, &format!("ims_charging: no more credit for {callid}, ending the call"));
                self.sessions.insert(callid.clone(), Session { started: Some(t), reported_at: t, ..s });
                if let Some(d) = self.dlg.get() {
                    d.end_by_callid(&callid);
                }
            }
        }
    }
}

impl Module for Charging {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("destination_realm", Ty::Str, "", "Destination realm of Ro requests to the OCS (default: the cdp realm)"),
            p("service_context_id_root", Ty::Str, "32260@3gpp.org", "Service-Context-Id of the credit-control requests"),
            p("interim_update_credits", Ty::Duration(Unit::Sec), "30s", "Call time asked for in each credit update"),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_charging"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, opt, sig};
        const CCR: &[Param] = &[arg("direction", Enum(&["orig", "term"])).lit(), arg("units", Int), opt("incoming_trunk", Str), opt("outgoing_trunk", Str)];
        Some(vec![
            sig(
                "Ro_CCR",
                "reserve",
                CCR,
                Ret::Await(&CCA),
                "Ro CCR-Initial: `let r = await ims_charging.reserve(\"orig\", 30)`; r.code 1 credit granted, -1 not (the transaction waits for the OCS)",
            )
            .fixed(&[""]),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "destination_realm" => *lock(&self.dest_realm) = v.str()?.into(),
            "service_context_id_root" => *lock(&self.context) = v.str()?.into(),
            "interim_update_credits" => self.interim.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "origin_host"
            | "origin_realm"
            | "destination_host"
            | "service_context_id_ext"
            | "service_context_id_mnc"
            | "service_context_id_mcc"
            | "service_context_id_release"
            | "voice_service_identifier"
            | "voice_rating_group"
            | "video_service_identifier"
            | "video_rating_group"
            | "timer_buffer"
            | "ro_forced_peer"
            | "ro_auth_expiry"
            | "cdp_event_latency"
            | "single_ro_session_per_dialog"
            | "strip_plus_from_e164"
            | "use_pani_from_term_invite"
            | "node_func"
            | "custom_user_avp"
            | "app_provided_party_avp"
            | "vendor_specific_chargeinfo"
            | "vendor_specific_id"
            | "db_url"
            | "db_mode" => {}
            _ => return Err(format!("ims_charging: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.peers.set(cdp(reg, "ims_charging")?);
        let dlg = reg.api::<Dialog>().ok_or("ims_charging needs dialog loaded first")?;
        let me = self.clone();
        dlg.on_state(Arc::new(move |c| me.on_change(c)));
        let _ = self.dlg.set(dlg);
        if let Some(tm) = reg.api::<mod_txn::Tm>() {
            let _ = self.tm.set(tm);
        }
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        reg.export(
            "ims_charging",
            "Ro_CCR",
            |a: &[Arg]| match a {
                [route, dir, units, ..] if a.len() <= 5 => Ok((route.str().unwrap_or("").to_string(), dir.str()?.to_string(), units.dyn_str()?)),
                _ => Err("expected route, direction, reservation_units[, incoming_trunk, outgoing_trunk]".to_string()),
            },
            move |ctx: &mut Ctx, (route, dir, units): &(String, String, DynStr)| {
                let units = units.eval(ctx).trim().parse().unwrap_or(30);
                me.initial(ctx, route, dir, units)
            },
        );
        let me = self.clone();
        reg.rpc.add("ro.sessions", "Ro sessions", move |_| {
            let mut v = Vec::new();
            me.sessions.for_each_mut(|k, s| {
                v.push(json!({"callid": k, "session_id": s.sid, "granted": s.granted, "answered": s.started.is_some(), "requests": s.number}))
            });
            Ok(json!(v))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("ims-charging".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    self.tick();
                }
            })
            .map_err(|e| format!("cannot start the ims charging timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(sid: &str) -> Session {
        Session { sid: sid.into(), subscriber: "sip:alice@ims.test".into(), number: 3, granted: 0, started: None, reported_at: 0, used_total: 0 }
    }

    /// CC-Time inside `group` (Requested/Used-Service-Unit) of the MSCC.
    fn cc_time_in(m: &Msg, group: AvpCode) -> Option<u32> {
        let mscc = m.get(MULTIPLE_SERVICES_CREDIT_CONTROL, None)?.group_avps();
        find(&find(&mscc, group, None)?.group_avps(), CC_TIME, None)?.as_u32()
    }

    #[test]
    fn ccr_carries_type_number_subscriber_and_units() {
        let c = Charging::default();
        c.set_param("service_context_id_root", &Arg::Str("ctx@3gpp.org".into())).unwrap();
        let m = c.ccr_msg(&session("s1"), CC_UPDATE, Some(u64::from(u32::MAX) + 1), Some(30));
        assert_eq!((m.cmd, m.app, m.is_request()), (CMD_CC, APP_CC, true));
        assert_eq!(m.str(SESSION_ID).as_deref(), Some("s1"));
        assert_eq!(m.get(AUTH_APPLICATION_ID, None).and_then(Avp::as_u32), Some(4));
        assert_eq!(m.get(CC_REQUEST_TYPE, None).and_then(Avp::as_u32), Some(CC_UPDATE));
        assert_eq!(m.get(CC_REQUEST_NUMBER, None).and_then(Avp::as_u32), Some(3));
        let sub = m.get(SUBSCRIPTION_ID, None).unwrap().group_avps();
        assert_eq!(find(&sub, SUBSCRIPTION_ID_TYPE, None).and_then(Avp::as_u32), Some(2), "END_USER_SIP_URI");
        assert_eq!(find(&sub, SUBSCRIPTION_ID_DATA, None).map(Avp::as_str).as_deref(), Some("sip:alice@ims.test"));
        assert_eq!(cc_time_in(&m, REQUESTED_SERVICE_UNIT), Some(30));
        assert_eq!(cc_time_in(&m, USED_SERVICE_UNIT), Some(u32::MAX), "saturated");
        let t = m.get(EVENT_TIMESTAMP, None).and_then(Avp::as_u32).unwrap();
        assert!(t.wrapping_sub(ntp_time(unix_secs())) <= 1 || ntp_time(unix_secs()).wrapping_sub(t) <= 1, "NTP time now: {t}");
        assert_eq!(m.str(SERVICE_CONTEXT_ID).as_deref(), Some("ctx@3gpp.org"));
        // Initial: requested only; termination: used only.
        let i = c.ccr_msg(&session("s"), CC_INITIAL, None, Some(60));
        assert_eq!((cc_time_in(&i, REQUESTED_SERVICE_UNIT), cc_time_in(&i, USED_SERVICE_UNIT)), (Some(60), None));
        let t = c.ccr_msg(&session("s"), CC_TERMINATION, Some(12), None);
        assert_eq!((cc_time_in(&t, REQUESTED_SERVICE_UNIT), cc_time_in(&t, USED_SERVICE_UNIT)), (None, Some(12)));
        assert!(Msg::decode(&m.try_encode().unwrap()).is_some());
    }

    fn cca(code: u32, gsu: Option<(bool, u32)>) -> Msg {
        let mut a = Msg::request(CMD_CC, APP_CC).answer();
        a.add(Avp::u32(RESULT_CODE, None, code));
        if let Some((in_mscc, secs)) = gsu {
            let g = Avp::group(GRANTED_SERVICE_UNIT, None, vec![Avp::u32(CC_TIME, None, secs)]);
            a.add(if in_mscc { Avp::group(MULTIPLE_SERVICES_CREDIT_CONTROL, None, vec![g]) } else { g });
        }
        a
    }

    #[test]
    fn granted_time_from_the_mscc_or_the_top_level() {
        assert_eq!(Charging::granted(&cca(2001, Some((true, 90)))), Some(90));
        assert_eq!(Charging::granted(&cca(2001, Some((false, 45)))), Some(45));
        assert_eq!(Charging::granted(&cca(2001, None)), None);
        // An MSCC without a grant falls back to a top-level one.
        let mut both = cca(2001, Some((false, 20)));
        both.add(Avp::group(MULTIPLE_SERVICES_CREDIT_CONTROL, None, vec![]));
        assert_eq!(Charging::granted(&both), Some(20));
    }

    #[test]
    fn cca_initial_outcomes() {
        let c = Charging::default();
        // (answer, return, session kept with this grant)
        let cases: Vec<(Result<Msg, DiameterError>, i32, Option<u64>)> = vec![
            (Ok(cca(2001, Some((true, 90)))), 1, Some(90)),
            (Ok(cca(2001, None)), 1, Some(30)),
            (Ok(cca(4012, Some((true, 90)))), -1, None),
            (Ok(cca(5030, None)), -1, None),
            (Err(DiameterError::Timeout { peer: None }), -1, None),
        ];
        for (i, (res, rc, kept)) in cases.into_iter().enumerate() {
            let callid = format!("call-{i}");
            assert_eq!(c.initial_answer(res, callid.clone(), session("s"), 30), rc, "case {i}");
            let s = c.sessions.get_cloned(&callid);
            assert_eq!(s.as_ref().map(|s| s.granted), kept, "case {i}");
            if let Some(s) = s {
                assert_eq!(s.number, 1, "the next CCR is number 1");
            }
        }
    }

    #[test]
    fn a_failed_update_counts_the_usage_and_keeps_the_session_until_the_bye() {
        let c = Charging::default();
        let t = unix_secs();
        c.sessions.insert("call".into(), Session { granted: 30, started: Some(t - 100), reported_at: t - 40, number: 1, ..session("s") });
        // Not started (not answered) yet: never due.
        c.sessions.insert("ringing".into(), Session { granted: 0, ..session("r") });
        // No OCS: the update fails, the call is ended (no dialog module here).
        c.tick();
        let s = c.sessions.get_cloned("call").unwrap();
        assert_eq!(s.number, 2);
        assert!((40..=41).contains(&s.used_total), "{}", s.used_total);
        assert!(s.reported_at >= t && s.started.is_some());
        assert_eq!(c.sessions.get_cloned("ringing").map(|s| s.number), Some(3));
        // Not due again before the last grant runs out.
        c.tick();
        assert_eq!(c.sessions.get_cloned("call").unwrap().number, 2);
        // The end of the call drops the session (the CCR-T fails without an OCS).
        let end = DlgChange {
            state: "terminated",
            callid: "call".into(),
            from_uri: String::new(),
            to_uri: String::new(),
            from_tag: String::new(),
            to_tag: String::new(),
            req_uri: String::new(),
            flags: 0,
        };
        c.on_change(&end);
        assert!(c.sessions.get_cloned("call").is_none());
    }

    #[test]
    fn an_answered_call_starts_the_clock() {
        let c = Charging::default();
        c.sessions.insert("call".into(), session("s"));
        let ch = |state| DlgChange {
            state,
            callid: "call".into(),
            from_uri: String::new(),
            to_uri: String::new(),
            from_tag: String::new(),
            to_tag: String::new(),
            req_uri: String::new(),
            flags: 0,
        };
        c.on_change(&ch("early"));
        assert!(c.sessions.get_cloned("call").unwrap().started.is_none());
        c.on_change(&ch("confirmed"));
        let s = c.sessions.get_cloned("call").unwrap();
        assert!(s.started.is_some() && s.reported_at >= unix_secs().saturating_sub(1));
    }

    #[test]
    fn cc_time_saturates_instead_of_wrapping() {
        assert_eq!(cc_time(30), 30);
        assert_eq!(cc_time(u64::from(u32::MAX) + 5), u32::MAX);
    }

    #[test]
    fn ntp_time_wraps_modulo_2_32() {
        assert_eq!(ntp_time(0), 2_208_988_800);
        // 2036-02-07T06:28:16Z is NTP era 1, second 0.
        assert_eq!(ntp_time(2_085_978_496), 0);
    }

    #[test]
    fn ccr_initial_without_an_ocs_or_suspended() {
        use crate::testutil::{avp_int, peers, registry, reply_msg, request, with_msg};
        let c = Arc::new(Charging::default());
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "P-Asserted-Identity: <sip:alice@ims.test>\n", "");
        assert_eq!(with_msg(&invite, |ctx| c.initial(ctx, "", "orig", 30)), -1, "not registered with cdp");
        let _ = c.peers.set(peers());
        // No tm: the CCR is sent and waited for; no OCS, so -1.
        for dir in ["orig", "term"] {
            assert_eq!(with_msg(&invite, |ctx| (c.initial(ctx, "", dir, 30), avp_int(ctx, "cca_return_code"))), (-1, Some(-1)), "{dir}");
        }
        // With tm: a request is suspended until the OCS answers.
        let reg = registry(true);
        let _ = c.tm.set(reg.api::<mod_txn::Tm>().unwrap());
        let _ = c.hub.set(reg.hub.clone());
        assert_eq!(with_msg(&invite, |ctx| c.initial(ctx, "", "orig", 30)), 0);
        // A reply route the script lacks: synchronous (so `if (!Ro_CCR(…))` keeps its meaning).
        assert_eq!(with_msg(&invite.replace("z9hG4bK1", "z9hG4bK2"), |ctx| c.initial(ctx, "NO_SUCH_ROUTE", "orig", 30)), -1);
        // A reply can't be suspended either.
        assert_eq!(with_msg(&reply_msg(183, "", ""), |ctx| c.initial(ctx, "", "term", 30)), -1);
        assert!(c.sessions.get_cloned("cid-1").is_none());
    }

    #[test]
    fn parameters_and_loading() {
        let c = Charging::default();
        c.set_param("destination_realm", &Arg::Str("ocs.test".into())).unwrap();
        c.set_param("interim_update_credits", &Arg::Int(0)).unwrap();
        assert_eq!(c.interim.load(Ordering::Relaxed), 1, "at least a second");
        for ignored in ["ro_forced_peer", "db_mode", "voice_rating_group"] {
            c.set_param(ignored, &Arg::Int(1)).unwrap();
        }
        assert!(c.set_param("nope", &Arg::Int(1)).unwrap_err().contains("unknown parameter"));
        assert_eq!(c.realm(&crate::testutil::peers()), "ocs.test");
        assert_eq!(Charging::default().realm(&crate::testutil::peers()), "ims.test", "the cdp realm by default");
        // Without dialog the module does not load.
        let mut reg = crate::testutil::registry(false);
        assert!(reg.load(Arc::new(Charging::default())).unwrap_err().contains("needs dialog"));
    }
}
