//! `sca` — Shared Call Appearances (BroadSoft SCA, the Kamailio `sca`
//! module): phones sharing a line subscribe to its AoR for `call-info`
//! (appearance states) and `line-seize` (grab an appearance before
//! dialing); calls on the line update the appearances.
//!
//! * `sca_handle_subscribe()`: call-info → NOTIFY with a `Call-Info`
//!   header listing every appearance (`appearance-index`,
//!   `appearance-state`, `appearance-uri`); line-seize → the lowest free
//!   appearance becomes `seized` for that phone (480 if none), released
//!   when the line-seize subscription ends. Unsubscribing from call-info
//!   is answered with a terminated NOTIFY (Sipwise `call-info-unsubscribe`).
//! * `sca_call_info_update([mask])` in request and reply routes: an INVITE
//!   from an SCA phone with `Call-Info: …;appearance-index=N` → progressing,
//!   18x → alerting, 2xx → active, ≥ 300/CANCEL → idle; an answered call
//!   *to* the line takes the lowest free appearance (Call-Info added to the
//!   2xx); re-INVITEs toggle held/active from the SDP direction in either
//!   direction of the dialog (Sipwise upstream-flow fixes); BYE → idle with
//!   a NOTIFY even after the dialog is gone (Sipwise `notify-after-bye`).
//!   `pai_avp` (Sipwise): P-Asserted-Identity for the 2xx of an answered
//!   shared-line call, from that AVP (none if it's empty).
//! * RPC: `sca.all_subscriptions`, `sca.all_appearances`,
//!   `sca.release_appearance <aor> <index>`.

use crate::notifier::{Notifier, Outcome};
use crate::{aor, header};
use mod_txn::Tm;
use sip_core::pv::{PvRef, parse_pv};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, ShardedMap};
use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug)]
struct Appearance {
    index: u32,
    state: &'static str,
    /// The other party.
    uri: String,
    callid: String,
    from_tag: String,
    to_tag: String,
    /// Watcher that seized it (line-seize subscription Call-ID).
    seized_by: Option<String>,
}

pub struct Sca {
    apps: ShardedMap<String, Vec<Appearance>>,
    notifier: Arc<Notifier>,
    max_apps: AtomicU32,
    pai_avp: Mutex<Option<String>>,
    pai: OnceLock<PvRef>,
}

impl Default for Sca {
    fn default() -> Self {
        Self {
            apps: ShardedMap::new(64),
            notifier: Arc::new(Notifier::default()),
            max_apps: AtomicU32::new(10),
            pai_avp: Mutex::new(None),
            pai: OnceLock::new(),
        }
    }
}

fn call_info(aor: &str, apps: &[Appearance]) -> String {
    if apps.is_empty() {
        return format!("Call-Info: <{aor}>;appearance-index=*;appearance-state=idle\r\n");
    }
    let items: Vec<String> = apps
        .iter()
        .map(|a| {
            let mut s = format!("<{aor}>;appearance-index={};appearance-state={}", a.index, a.state);
            if !a.uri.is_empty() {
                s.push_str(&format!(";appearance-uri=\"<{}>\"", a.uri));
            }
            s
        })
        .collect();
    format!("Call-Info: {}\r\n", items.join(","))
}

/// SDP direction → held / active.
fn hold_state(body: &str) -> &'static str {
    let l = body.to_ascii_lowercase();
    if l.contains("a=sendonly") || l.contains("a=inactive") || l.contains("c=in ip4 0.0.0.0") { "held" } else { "active" }
}

impl Sca {
    fn is_sca(&self, aor: &str) -> bool {
        !self.notifier.watchers(aor, "call-info").is_empty()
    }

    fn notify_all(&self, aor: &str) {
        let apps = self.apps.get_cloned(aor).unwrap_or_default();
        let hdr = call_info(aor, &apps);
        for s in self.notifier.watchers(aor, "call-info") {
            self.notifier.notify(&s, "active", None, b"", &hdr);
        }
    }

    fn lowest_free(&self, aor: &str) -> Option<u32> {
        let apps = self.apps.get_cloned(aor).unwrap_or_default();
        (1..=self.max_apps.load(Ordering::Relaxed)).find(|i| !apps.iter().any(|a| a.index == *i))
    }

    fn set(&self, aor: &str, f: impl FnOnce(&mut Vec<Appearance>) -> bool) -> bool {
        let changed = self.apps.alter(aor.to_string(), |cur| {
            let mut v = cur.unwrap_or_default();
            let c = f(&mut v);
            v.sort_by_key(|a| a.index);
            ((!v.is_empty()).then_some(v), c)
        });
        if changed {
            self.notify_all(aor);
        }
        changed
    }

    fn handle_subscribe(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let event = header(ctx, "Event").or_else(|| header(ctx, "o")).unwrap_or_default();
        let pkg = event.split(';').next().unwrap_or("").trim().to_string();
        let Some(line) = aor(ctx.ruri()) else { return -1 };
        let new = ctx.msg.parse_headers(HdrFlags::EOH).is_ok() && ctx.msg.get(HdrKind::To).is_some_and(|h| param(name_addr(h.body).1, b"tag").is_none());
        let expires0 = header(ctx, "Expires").is_some_and(|e| e.trim() == "0");
        if pkg == "line-seize" && new && !expires0 && self.lowest_free(&line).is_none() {
            let _ = ctx.reply(480, "All Appearances In Use");
            return -1;
        }
        match self.notifier.subscribe(ctx, &["call-info", "line-seize"], Some(line.clone()), false) {
            Ok(Outcome::New(s)) | Ok(Outcome::Refreshed(s)) if pkg == "call-info" => {
                let hdr = call_info(&line, &self.apps.get_cloned(&line).unwrap_or_default());
                self.notifier.notify(&s, "active", None, b"", &hdr);
                1
            }
            Ok(Outcome::New(s)) => {
                // line-seize: grab the lowest free appearance for this phone.
                let callid = lock(&s).callid.clone();
                let max = self.max_apps.load(Ordering::Relaxed);
                let idx = self.apps.alter(line.clone(), |cur| {
                    let mut v = cur.unwrap_or_default();
                    let idx = (1..=max).find(|i| !v.iter().any(|a| a.index == *i)).unwrap_or(0);
                    if idx > 0 {
                        v.push(Appearance {
                            index: idx,
                            state: "seized",
                            uri: String::new(),
                            callid: String::new(),
                            from_tag: String::new(),
                            to_tag: String::new(),
                            seized_by: Some(callid),
                        });
                        v.sort_by_key(|a| a.index);
                    }
                    ((!v.is_empty()).then_some(v), idx)
                });
                // The seizing phone hears first, then everybody's call-info.
                let hdr = format!("Call-Info: <{line}>;appearance-index={idx};appearance-state=seized\r\n");
                self.notifier.notify(&s, "active", None, b"", &hdr);
                self.notify_all(&line);
                1
            }
            Ok(Outcome::Refreshed(_)) => 1,
            Ok(Outcome::Ended(s)) => {
                let (callid, ev) = {
                    let g = lock(&s);
                    (g.callid.clone(), g.event.clone())
                };
                if ev.starts_with("line-seize") {
                    // Release a still-seized appearance of this phone.
                    self.set(&line, |v| {
                        let n = v.len();
                        v.retain(|a| !(a.state == "seized" && a.seized_by.as_deref() == Some(callid.as_str())));
                        v.len() != n
                    });
                    self.notifier.notify(&s, "terminated", None, b"", "");
                } else {
                    let hdr = call_info(&line, &self.apps.get_cloned(&line).unwrap_or_default());
                    self.notifier.notify(&s, "terminated", None, b"", &hdr);
                }
                1
            }
            Err(r) => r,
        }
    }

    /// The appearance index a phone put in its INVITE.
    fn invite_index(ctx: &mut Ctx<'_, '_>) -> Option<u32> {
        let ci = header(ctx, "Call-Info")?;
        let p = ci.split(';').find_map(|kv| kv.trim().strip_prefix("appearance-index="))?;
        p.trim().parse().ok()
    }

    fn update(&self, ctx: &mut Ctx<'_, '_>, mask: i64) -> i32 {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let m = &*ctx.msg;
        let (Some(from), Some(to), Some(cid), Some(cseq)) = (m.get(HdrKind::From), m.get(HdrKind::To), m.get(HdrKind::CallId), m.get(HdrKind::CSeq)) else {
            return -1;
        };
        let callid = s(cid.body);
        let (furi, fp) = name_addr(from.body);
        let (turi, tp) = name_addr(to.body);
        let (from_aor, to_aor) = (aor(furi).unwrap_or_default(), aor(turi).unwrap_or_default());
        let (ftag, ttag) = (param(fp, b"tag").map(s).unwrap_or_default(), param(tp, b"tag").map(s));
        let cseq_method = sip_parser::Method::from_cseq(cseq.body);
        let (furi, turi) = (s(furi), s(turi));
        let caller_side = mask & 1 != 0;
        let callee_side = mask & 2 != 0;

        if ctx.msg.is_request() {
            let method = ctx.msg.method();
            match method {
                Some(Method::Invite) if ttag.is_none() && caller_side => {
                    let Some(idx) = Self::invite_index(ctx) else { return 1 };
                    self.set(&from_aor, |v| match v.iter_mut().find(|a| a.index == idx) {
                        Some(a) => {
                            a.state = "progressing";
                            a.uri = turi.clone();
                            a.callid = callid.clone();
                            a.from_tag = ftag.clone();
                            true
                        }
                        None => {
                            v.push(Appearance {
                                index: idx,
                                state: "progressing",
                                uri: turi.clone(),
                                callid: callid.clone(),
                                from_tag: ftag.clone(),
                                to_tag: String::new(),
                                seized_by: None,
                            });
                            true
                        }
                    });
                }
                Some(Method::Invite) => {
                    // re-INVITE in either direction: hold / resume.
                    let st = hold_state(&String::from_utf8_lossy(&ctx.body()));
                    for line in [&from_aor, &to_aor] {
                        self.set(line, |v| match v.iter_mut().find(|a| a.callid == callid && a.state != st && (a.state == "active" || a.state == "held")) {
                            Some(a) => {
                                a.state = st;
                                true
                            }
                            None => false,
                        });
                    }
                }
                Some(Method::Bye) | Some(Method::Cancel) => {
                    for line in [&from_aor, &to_aor] {
                        self.set(line, |v| {
                            let n = v.len();
                            v.retain(|a| a.callid != callid);
                            v.len() != n
                        });
                    }
                }
                _ => {}
            }
            return 1;
        }
        // Replies to INVITE.
        if cseq_method != Method::Invite {
            return 1;
        }
        let code = ctx.msg.status().unwrap_or(0);
        if caller_side {
            self.set(&from_aor, |v| match v.iter().position(|a| a.callid == callid) {
                Some(i) if code >= 300 => {
                    v.remove(i);
                    true
                }
                Some(i) => v.get_mut(i).is_some_and(|a| match code {
                    180..=189 if a.state == "progressing" => {
                        a.state = "alerting";
                        true
                    }
                    200..=299 if a.state != "active" && a.state != "held" => {
                        a.state = "active";
                        a.to_tag = ttag.clone().unwrap_or_default();
                        true
                    }
                    _ => false,
                }),
                None => false,
            });
        }
        if callee_side && (200..300).contains(&code) && self.is_sca(&to_aor) {
            let exists = self.apps.get_cloned(&to_aor).unwrap_or_default().iter().any(|a| a.callid == callid);
            if !exists && let Some(idx) = self.lowest_free(&to_aor) {
                self.set(&to_aor, |v| {
                    v.push(Appearance {
                        index: idx,
                        state: "active",
                        uri: furi.clone(),
                        callid: callid.clone(),
                        from_tag: ftag.clone(),
                        to_tag: ttag.clone().unwrap_or_default(),
                        seized_by: None,
                    });
                    true
                });
                let mut h = format!("Call-Info: <{to_aor}>;appearance-index={idx}\r\n");
                if let Some(pv) = self.pai.get() {
                    let v = pv.get(ctx).as_str().into_owned();
                    if !v.is_empty() {
                        h.push_str(&format!("P-Asserted-Identity: <{v}>\r\n"));
                    }
                }
                let at = ctx.msg.eoh_offset().unwrap_or(ctx.msg.buf.len());
                ctx.lumps.insert(at, h.into_bytes());
            }
        }
        1
    }
}

impl Module for Sca {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("max_appearances", Ty::Int { min: 1, max: 99 }, "10", "Appearances per shared line"),
            p("pai_avp", Ty::Str, "", "AVP with the P-Asserted-Identity for the 2xx of an answered shared-line call"),
        ])
    }

    fn name(&self) -> &'static str {
        "sca"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, ctx, opt, sig};
        const MASK: &[Param] = &[opt("mask", Int).lit().eg("3")];
        Some(vec![
            sig("sca_handle_subscribe", "handle_subscribe", &[], Ret::Action, "Handle a call-info / line-seize SUBSCRIBE and answer it").allowed(ctx::REQUEST),
            sig(
                "sca_call_info_update",
                "call_info_update",
                MASK,
                Ret::Bool,
                "Update shared line appearances from this message (mask: 1 caller, 2 callee, 3 both)",
            )
            .allowed(ctx::ROUTE | ctx::REPLY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "max_appearances" => self.max_apps.store(u32::try_from(v.int()?.clamp(1, 99)).unwrap_or(1), Ordering::Relaxed),
            "pai_avp" => *lock(&self.pai_avp) = Some(v.str()?.into()),
            "db_url"
            | "subs_table"
            | "db_update_interval"
            | "hash_table_size"
            | "call_info_max_expires"
            | "line_seize_max_expires"
            | "purge_expired_interval"
            | "onhold_bflag"
            | "server_address"
            | "from_uri_avp"
            | "to_uri_avp"
            | "debug" => {}
            _ => return Err(format!("sca: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.notifier.set_tm(reg.api::<Tm>().ok_or("sca needs tm loaded first")?);
        if let Some(p) = lock(&self.pai_avp).clone() {
            let p = if p.starts_with('$') { p } else { format!("$avp({p})") };
            let _ = self.pai.set(parse_pv(&p, reg.pvs())?);
        }
        let me = self.clone();
        reg.export(
            "sca",
            "sca_handle_subscribe",
            |a: &[Arg]| if a.len() > 2 { Err("too many arguments".to_string()) } else { Ok(()) },
            move |ctx: &mut Ctx, _: &()| me.handle_subscribe(ctx),
        );
        let me = self.clone();
        reg.export(
            "sca",
            "sca_call_info_update",
            |a: &[Arg]| -> Result<i64, String> {
                match a {
                    [] => Ok(3),
                    [mask, ..] if a.len() <= 3 => Ok(mask.int().unwrap_or(3)),
                    _ => Err("expected [mask[, to[, from]]]".into()),
                }
            },
            move |ctx: &mut Ctx, &mask: &i64| me.update(ctx, if mask == 0 { 3 } else { mask }),
        );
        let me = self.clone();
        reg.rpc.add("sca.all_subscriptions", "SCA subscriptions", move |_| {
            Ok(json!(me
                .notifier
                .all()
                .iter()
                .map(|s| {
                    let g = lock(s);
                    json!({"aor": g.pres_uri, "event": g.event, "subscriber": g.watcher_uri, "contact": g.contact, "expires": g.expires_at.saturating_sub(unix_secs())})
                })
                .collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("sca.all_appearances", "Appearances per line", move |_| {
            let mut v = Vec::new();
            me.apps.for_each_mut(|aor, apps| {
                for a in apps.iter() {
                    v.push(json!({"aor": aor, "index": a.index, "state": a.state, "uri": a.uri, "callid": a.callid}));
                }
            });
            Ok(json!(v))
        });
        let me = self.clone();
        reg.rpc.add("sca.release_appearance", "sca.release_appearance <aor> <index>", move |p| {
            let aor_ = sip_core::rpc::str_param(p, 0)?;
            // An index past u32 is refused rather than wrapped onto another appearance.
            let idx = u32::try_from(sip_core::rpc::int_param(p, 1)?).map_err(|_| "no such appearance".to_string())?;
            let line = aor(aor_.as_bytes()).unwrap_or(aor_);
            if me.set(&line, |v| {
                let n = v.len();
                v.retain(|a| a.index != idx);
                v.len() != n
            }) {
                Ok(json!(0))
            } else {
                Err("no such appearance".into())
            }
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        self.notifier.set_net(net);
        std::thread::Builder::new()
            .name("sca-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    for s in self.notifier.take_expired() {
                        let (line, ev, callid) = {
                            let g = lock(&s);
                            (g.pres_uri.clone(), g.event.clone(), g.callid.clone())
                        };
                        if ev.starts_with("line-seize") {
                            self.set(&line, |v| {
                                let n = v.len();
                                v.retain(|a| !(a.state == "seized" && a.seized_by.as_deref() == Some(callid.as_str())));
                                v.len() != n
                            });
                        }
                        self.notifier.notify(&s, "terminated;reason=timeout", None, b"", "");
                    }
                }
            })
            .map_err(|e| format!("cannot start the sca timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::{hdr, reply, request, with_msg};

    const LINE: &str = "sip:line@ex.com";

    /// SUBSCRIBE to the line: (return, code, reply).
    fn subscribe(sca: &Sca, callid: &str, to_tag: Option<&str>, extra: &str) -> (i32, u16, String) {
        let raw = request("SUBSCRIBE", LINE, to_tag, extra, "").replace("Call-ID: cid-1", &format!("Call-ID: {callid}"));
        with_msg(&raw, |ctx| {
            let r = sca.handle_subscribe(ctx);
            let (code, out) = reply(ctx);
            (r, code, out)
        })
    }

    fn states(sca: &Sca) -> Vec<(u32, &'static str)> {
        sca.apps.get_cloned(LINE).unwrap_or_default().iter().map(|a| (a.index, a.state)).collect()
    }

    /// A message between the line and sip:far@ex.com, through `sca.update`.
    fn msg(sca: &Sca, first: &str, from_line: bool, to_tag: bool, cseq: &str, extra: &str, body: &str) -> String {
        let (from, to) = if from_line { (LINE, "sip:far@ex.com") } else { ("sip:far@ex.com", LINE) };
        let tt = if to_tag { ";tag=tt" } else { "" };
        let raw = format!(
            "{first}\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <{from}>;tag=ft\nTo: <{to}>{tt}\nCall-ID: call-1\nCSeq: {cseq}\n{extra}Content-Length: {}\n\n{body}",
            body.len()
        );
        with_msg(&raw, |ctx| {
            assert_eq!(sca.update(ctx, 3), 1);
            let mut out = Vec::new();
            ctx.lumps.apply(ctx.msg.buf, &mut out);
            String::from_utf8(out).unwrap()
        })
    }

    #[test]
    fn line_seize_takes_the_lowest_free_appearance() {
        let sca = Sca::default();
        sca.set_param("max_appearances", &Arg::Int(2)).unwrap();
        assert_eq!(subscribe(&sca, "s1", None, "Event: line-seize\nExpires: 30\n").1, 200);
        assert_eq!(subscribe(&sca, "s2", None, "Event: line-seize\nExpires: 30\n").1, 200);
        assert_eq!(states(&sca), [(1, "seized"), (2, "seized")]);
        let (r, code, _) = subscribe(&sca, "s3", None, "Event: line-seize\nExpires: 30\n");
        assert_eq!((r, code), (-1, 480));
        // Ending s1's line-seize frees appearance 1, which the next one gets.
        let tag = format!("{:016x}", sip_core::fx_hash(b"s1"));
        assert_eq!(subscribe(&sca, "s1", Some(&tag), "Event: line-seize\nExpires: 0\n").1, 200);
        assert_eq!(states(&sca), [(2, "seized")]);
        assert_eq!(subscribe(&sca, "s4", None, "Event: line-seize\nExpires: 30\n").1, 200);
        assert_eq!(states(&sca), [(1, "seized"), (2, "seized")]);
        // A fetch (Expires: 0) of line-seize is not refused when full.
        assert_eq!(subscribe(&sca, "s5", None, "Event: line-seize\nExpires: 0\n").1, 200);
    }

    #[test]
    fn calls_from_the_line_walk_through_the_states() {
        let sca = Sca::default();
        let inv = "INVITE sip:far@ex.com SIP/2.0";
        msg(&sca, inv, true, false, "1 INVITE", "Call-Info: <sip:line@ex.com>;appearance-index=2\n", "");
        assert_eq!(states(&sca), [(2, "progressing")]);
        assert_eq!(sca.apps.get_cloned(LINE).unwrap()[0].uri, "sip:far@ex.com");
        msg(&sca, "SIP/2.0 100 Trying", true, false, "1 INVITE", "", "");
        assert_eq!(states(&sca), [(2, "progressing")]);
        msg(&sca, "SIP/2.0 180 Ringing", true, true, "1 INVITE", "", "");
        assert_eq!(states(&sca), [(2, "alerting")]);
        msg(&sca, "SIP/2.0 200 OK", true, true, "1 INVITE", "", "");
        assert_eq!(states(&sca), [(2, "active")]);
        assert_eq!(sca.apps.get_cloned(LINE).unwrap()[0].to_tag, "tt");
        // A 200 to another method changes nothing.
        msg(&sca, "SIP/2.0 200 OK", true, true, "2 UPDATE", "", "");
        assert_eq!(states(&sca), [(2, "active")]);
        // Hold and resume, from either side.
        let reinv = "INVITE sip:x@192.0.2.1 SIP/2.0";
        msg(&sca, reinv, true, true, "3 INVITE", "", "v=0\r\nc=IN IP4 0.0.0.0\r\n");
        assert_eq!(states(&sca), [(2, "held")]);
        msg(&sca, reinv, false, true, "4 INVITE", "", "v=0\r\na=sendrecv\r\n");
        assert_eq!(states(&sca), [(2, "active")]);
        msg(&sca, reinv, false, true, "5 INVITE", "", "v=0\r\na=inactive\r\n");
        assert_eq!(states(&sca), [(2, "held")]);
        msg(&sca, "BYE sip:x@192.0.2.1 SIP/2.0", false, true, "6 BYE", "", "");
        assert!(states(&sca).is_empty());
    }

    #[test]
    fn failed_calls_free_the_appearance_and_invites_without_an_index_are_ignored() {
        let sca = Sca::default();
        let inv = "INVITE sip:far@ex.com SIP/2.0";
        msg(&sca, inv, true, false, "1 INVITE", "", "");
        assert!(states(&sca).is_empty(), "no Call-Info");
        msg(&sca, inv, true, false, "1 INVITE", "Call-Info: <sip:line@ex.com>;appearance-index=*\n", "");
        assert!(states(&sca).is_empty(), "no number");
        msg(&sca, inv, true, false, "1 INVITE", "Call-Info: <sip:line@ex.com> ; appearance-index= 1 \n", "");
        assert_eq!(states(&sca), [(1, "progressing")]);
        msg(&sca, "SIP/2.0 486 Busy Here", true, true, "1 INVITE", "", "");
        assert!(states(&sca).is_empty());
    }

    #[test]
    fn answered_calls_to_a_subscribed_line_take_an_appearance() {
        let sca = Sca::default();
        // Not an SCA line yet: nothing.
        let out = msg(&sca, "SIP/2.0 200 OK", false, true, "1 INVITE", "", "");
        assert!(states(&sca).is_empty() && !out.contains("Call-Info"));
        let (_, code, sub_reply) = subscribe(&sca, "w1", None, "Event: call-info\n");
        assert_eq!(code, 200, "{sub_reply}");
        sca.apps.insert(
            LINE.into(),
            vec![Appearance {
                index: 1,
                state: "active",
                uri: String::new(),
                callid: "other".into(),
                from_tag: String::new(),
                to_tag: String::new(),
                seized_by: None,
            }],
        );
        let out = msg(&sca, "SIP/2.0 200 OK", false, true, "1 INVITE", "", "");
        assert_eq!(states(&sca), [(1, "active"), (2, "active")]);
        assert_eq!(hdr(&out, "Call-Info").as_deref(), Some("<sip:line@ex.com>;appearance-index=2"), "{out}");
        // A retransmitted 2xx doesn't take another one.
        msg(&sca, "SIP/2.0 200 OK", false, true, "1 INVITE", "", "");
        assert_eq!(states(&sca).len(), 2);
    }

    #[test]
    fn invite_index_and_hold_state() {
        let idx = |ci: &str| with_msg(&request("INVITE", LINE, None, ci, ""), Sca::invite_index);
        assert_eq!(idx("Call-Info: <sip:l@x>;appearance-index=3\n"), Some(3));
        assert_eq!(idx("Call-Info: <sip:l@x>;foo=1;appearance-index=12;x\n"), Some(12));
        assert_eq!(idx("Call-Info: <sip:l@x>\n"), None);
        assert_eq!(idx(""), None);
        assert_eq!(hold_state("v=0\r\nC=IN IP4 0.0.0.0\r\n"), "held");
        assert_eq!(hold_state("v=0\r\na=recvonly\r\n"), "active");
        assert_eq!(hold_state(""), "active");
        let a = |i, st| Appearance {
            index: i,
            state: st,
            uri: String::new(),
            callid: String::new(),
            from_tag: String::new(),
            to_tag: String::new(),
            seized_by: None,
        };
        assert_eq!(
            call_info("sip:l@x", &[a(1, "seized"), a(3, "held")]),
            "Call-Info: <sip:l@x>;appearance-index=1;appearance-state=seized,<sip:l@x>;appearance-index=3;appearance-state=held\r\n"
        );
    }

    #[test]
    fn headers() {
        assert_eq!(call_info("sip:l@x", &[]), "Call-Info: <sip:l@x>;appearance-index=*;appearance-state=idle\r\n");
        let a = Appearance {
            index: 1,
            state: "active",
            uri: "sip:b@x".into(),
            callid: "c".into(),
            from_tag: String::new(),
            to_tag: String::new(),
            seized_by: None,
        };
        assert_eq!(call_info("sip:l@x", &[a]), "Call-Info: <sip:l@x>;appearance-index=1;appearance-state=active;appearance-uri=\"<sip:b@x>\"\r\n");
        assert_eq!(hold_state("v=0\r\na=sendonly\r\n"), "held");
        assert_eq!(hold_state("v=0\r\na=sendrecv\r\n"), "active");
    }
}
