//! `pua` — presence user agent: sends and refreshes PUBLISHes for other
//! modules (entity tags, refresh before expiry, 412 → fresh publication,
//! updates queued while one is in flight); RPC `pua.publish`.
//!
//! `pua_dialoginfo` — publishes dialog state (RFC 4235 dialog-info) for
//! the caller and the callee of every dialog the `dialog` module tracks:
//! trying → early → confirmed → terminated. Parameters: `presence_server`
//! (where PUBLISHes go), `caller_trying` (1; Sipwise: 0 publishes the caller
//! only from the first provisional), `callee_trying` (0), `include_callid`,
//! `include_tags`, `include_localremote` (1), `override_lifetime`
//! (default 3600 s; terminated states use 10 s), `send_publish_flag`
//! (only dialogs whose INVITE had this flag; -1 = all).

use crate::xml;
use mod_dialog::{Dialog, DlgChange};
use mod_txn::{Tm, UacRequest};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Module, Outbound, Registry, ShardedMap};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

type Key = (String, String, String);

#[derive(Debug, Default)]
struct PubState {
    etag: Option<String>,
    expires: u64,
    next_refresh: u64,
    ctype: String,
    in_flight: bool,
    /// Update queued while a PUBLISH is in flight: (body, expires).
    pending: Option<(Option<Vec<u8>>, u64)>,
    /// The publication's next hop (presence server), for queued updates
    /// and refreshes too.
    dst: Option<String>,
}

pub struct Pua {
    pubs: ShardedMap<Key, Arc<Mutex<PubState>>>,
    outbound_proxy: Mutex<Option<String>>,
    tm: OnceLock<Arc<Tm>>,
}

impl Default for Pua {
    fn default() -> Self {
        Self { pubs: ShardedMap::new(64), outbound_proxy: Mutex::new(None), tm: OnceLock::new() }
    }
}

/// When to refresh a publication that lasts `exp` seconds from `now`:
/// 10 % before it expires, but at least 10 s, and at most half its lifetime,
/// so a short publication isn't re-sent every second; 0 (never) for `exp`
/// 0. `exp` comes from the reply's Expires: saturating, never overflowing.
fn next_refresh(now: u64, exp: u64) -> u64 {
    if exp == 0 { 0 } else { now.saturating_add(exp.saturating_sub((exp / 2).min(10).max(exp / 10))) }
}

fn header<'a>(msg: &'a [u8], name: &str) -> Option<&'a str> {
    let head = msg.windows(4).position(|w| w == b"\r\n\r\n").and_then(|end| msg.get(..end)).unwrap_or(msg);
    std::str::from_utf8(head).ok()?.split("\r\n").skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

/// One publication request.
pub struct PubReq<'a> {
    pub pres_uri: &'a str,
    pub event: &'a str,
    /// Distinguishes publications of the same entity/event (one per call…).
    pub id: &'a str,
    pub ctype: &'a str,
    /// None = refresh only.
    pub body: Option<Vec<u8>>,
    pub expires: u64,
    /// Next hop (presence server); default `outbound_proxy` or the R-URI.
    pub dst: Option<String>,
}

impl Pua {
    pub fn publish(self: &Arc<Self>, r: PubReq<'_>) {
        let PubReq { pres_uri, event, id, ctype, body, expires, dst } = r;
        let key: Key = (pres_uri.into(), event.into(), id.into());
        let st = self.pubs.alter(key.clone(), |cur| {
            let s = cur.unwrap_or_else(|| Arc::new(Mutex::new(PubState { ctype: ctype.into(), ..Default::default() })));
            (Some(s.clone()), s)
        });
        {
            let mut g = lock(&st);
            if dst.is_some() {
                g.dst = dst.clone();
            }
            if g.in_flight {
                g.pending = Some((body, expires));
                return;
            }
            g.in_flight = true;
            g.ctype = ctype.into();
        }
        self.send(key, st, body, expires, dst);
    }

    fn send(self: &Arc<Self>, key: Key, st: Arc<Mutex<PubState>>, body: Option<Vec<u8>>, expires: u64, dst: Option<String>) {
        let Some(tm) = self.tm.get() else { return };
        let (etag, ctype, dst) = {
            let g = lock(&st);
            (g.etag.clone(), g.ctype.clone(), dst.or_else(|| g.dst.clone()))
        };
        let mut h = format!("Event: {}\r\nExpires: {expires}\r\n", key.1);
        if let Some(e) = &etag {
            h.push_str(&format!("SIP-If-Match: {e}\r\n"));
        }
        let body = body.unwrap_or_default();
        if !body.is_empty() {
            h.push_str(&format!("Content-Type: {ctype}\r\n"));
        }
        let proxy = dst.clone().or_else(|| lock(&self.outbound_proxy).clone());
        let req = UacRequest {
            method: "PUBLISH".into(),
            ruri: key.0.clone(),
            dst: proxy.as_deref().and_then(|p| sip_core::pvcore::dest_from_uri(p.as_bytes())),
            from: Some(key.0.clone()),
            to: Some(key.0.clone()),
            headers: h,
            body: body.clone(),
            ..Default::default()
        };
        let me = self.clone();
        let (k2, st2) = (key.clone(), st.clone());
        let res = tm.t_uac(
            req,
            Some(Box::new(move |code, reply| {
                let next = {
                    let mut g = lock(&st2);
                    g.in_flight = false;
                    match code {
                        200..=299 => {
                            g.etag = header(reply, "SIP-ETag").map(String::from);
                            let exp = header(reply, "Expires").and_then(|e| e.parse().ok()).unwrap_or(expires);
                            g.expires = exp;
                            g.next_refresh = next_refresh(unix_secs(), exp);
                            if exp == 0 {
                                g.etag = None;
                            }
                        }
                        412 if g.etag.is_some() && !body.is_empty() => {
                            // Unknown entity tag: start a fresh publication.
                            g.etag = None;
                            g.pending.get_or_insert((Some(body.clone()), expires));
                        }
                        _ => {
                            sip_core::log::log(sip_core::log::L_WARN, &format!("pua: PUBLISH for {} got {code}", k2.0));
                            g.etag = None;
                        }
                    }
                    g.pending.take()
                };
                if lock(&st2).expires == 0 && lock(&st2).etag.is_none() && next.is_none() {
                    me.pubs.remove(&k2);
                }
                if let Some((b, e)) = next {
                    lock(&st2).in_flight = true;
                    me.send(k2, st2, b, e, None);
                }
            })),
        );
        if res.is_err() {
            lock(&st).in_flight = false;
        }
    }

    fn refresh_due(self: &Arc<Self>) {
        let t = unix_secs();
        let mut due = Vec::new();
        self.pubs.for_each_mut(|k, s| {
            let g = lock(s);
            if !g.in_flight && g.etag.is_some() && g.expires > 0 && g.next_refresh <= t {
                due.push((k.clone(), s.clone(), g.expires));
            }
        });
        for (k, s, exp) in due {
            lock(&s).in_flight = true;
            self.send(k, s, None, exp, None);
        }
    }
}

impl Module for Pua {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("outbound_proxy", Ty::Str, "", "Next hop for PUBLISHes that name no destination (default: the R-URI)")])
    }

    fn name(&self) -> &'static str {
        "pua"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "outbound_proxy" => *lock(&self.outbound_proxy) = Some(v.str()?.into()),
            "db_url"
            | "db_table"
            | "db_mode"
            | "hash_size"
            | "min_expires"
            | "default_expires"
            | "update_period"
            | "check_remote_contact"
            | "fetch_rows"
            | "dlginfo_increase_version"
            | "reginfo_increase_version" => {}
            _ => return Err(format!("pua: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let tm = reg.api::<Tm>().ok_or("pua needs tm loaded first")?;
        let _ = self.tm.set(tm);
        reg.provide(self.clone());
        let me = self.clone();
        reg.rpc.add("pua.publish", "pua.publish <pres_uri> <expires> <event> <content_type> <body>", move |p| {
            let u = sip_core::rpc::str_param(p, 0)?;
            let e = sip_core::rpc::int_param(p, 1)?.max(0).unsigned_abs();
            let ev = sip_core::rpc::str_param(p, 2)?;
            let ct = sip_core::rpc::str_param(p, 3)?;
            let body = sip_core::rpc::str_param(p, 4).ok().filter(|b| !b.is_empty() && b != ".").map(String::into_bytes);
            me.publish(PubReq { pres_uri: &u, event: &ev, id: "rpc", ctype: &ct, body, expires: e, dst: None });
            Ok(json!(0))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("pua-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    self.refresh_due();
                }
            })
            .map_err(|e| format!("cannot start the pua timer thread: {e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------- pua_dialoginfo --

pub struct PuaDialoginfo {
    server: Mutex<Option<String>>,
    caller_trying: AtomicBool,
    callee_trying: AtomicBool,
    include_callid: AtomicBool,
    include_tags: AtomicBool,
    include_localremote: AtomicBool,
    lifetime: AtomicU64,
    flag: AtomicI64,
    /// (callid, entity) pairs published so far (terminated goes to these).
    published: Mutex<HashSet<(String, String)>>,
    pua: OnceLock<Arc<Pua>>,
}

impl Default for PuaDialoginfo {
    fn default() -> Self {
        Self {
            server: Mutex::new(None),
            caller_trying: AtomicBool::new(true),
            callee_trying: AtomicBool::new(false),
            include_callid: AtomicBool::new(true),
            include_tags: AtomicBool::new(true),
            include_localremote: AtomicBool::new(true),
            lifetime: AtomicU64::new(3600),
            flag: AtomicI64::new(-1),
            published: Mutex::new(HashSet::new()),
            pua: OnceLock::new(),
        }
    }
}

impl PuaDialoginfo {
    fn body(&self, c: &DlgChange, initiator: bool, state: &str) -> Vec<u8> {
        let (entity, local, remote, ltag, rtag) =
            if initiator { (&c.from_uri, &c.from_uri, &c.to_uri, &c.from_tag, &c.to_tag) } else { (&c.to_uri, &c.to_uri, &c.from_uri, &c.to_tag, &c.from_tag) };
        let e = xml::escape;
        let mut d = format!("<dialog id=\"{}\"", e(&c.callid));
        if self.include_callid.load(Ordering::Relaxed) {
            d.push_str(&format!(" call-id=\"{}\"", e(&c.callid)));
        }
        if self.include_tags.load(Ordering::Relaxed) {
            if !ltag.is_empty() {
                d.push_str(&format!(" local-tag=\"{}\"", e(ltag)));
            }
            if !rtag.is_empty() {
                d.push_str(&format!(" remote-tag=\"{}\"", e(rtag)));
            }
        }
        d.push_str(&format!(" direction=\"{}\"><state>{state}</state>", if initiator { "initiator" } else { "recipient" }));
        if self.include_localremote.load(Ordering::Relaxed) {
            d.push_str(&format!(
                "<local><identity>{}</identity><target uri=\"{}\"/></local><remote><identity>{}</identity><target uri=\"{}\"/></remote>",
                e(local),
                e(local),
                e(remote),
                e(remote)
            ));
        }
        d.push_str("</dialog>");
        format!(
            "<?xml version=\"1.0\"?>\n<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" state=\"full\" entity=\"{}\">{d}</dialog-info>",
            e(entity)
        )
        .into_bytes()
    }

    fn on_change(&self, c: &DlgChange) {
        let f = self.flag.load(Ordering::Relaxed);
        if (0..64).contains(&f) && c.flags & (1 << f) == 0 {
            return;
        }
        let Some(pua) = self.pua.get() else { return };
        let server = lock(&self.server).clone();
        let caller = crate::aor(c.from_uri.as_bytes()).unwrap_or_else(|| c.from_uri.clone());
        let callee = crate::aor(c.to_uri.as_bytes()).unwrap_or_else(|| c.to_uri.clone());
        let (do_caller, do_callee) = match c.state {
            "trying" => (self.caller_trying.load(Ordering::Relaxed), self.callee_trying.load(Ordering::Relaxed)),
            "terminated" => {
                let p = lock(&self.published);
                (p.contains(&(c.callid.clone(), caller.clone())), p.contains(&(c.callid.clone(), callee.clone())))
            }
            _ => (true, true),
        };
        let life = if c.state == "terminated" { 10 } else { self.lifetime.load(Ordering::Relaxed) };
        for (go, ent, init) in [(do_caller, &caller, true), (do_callee, &callee, false)] {
            if !go {
                continue;
            }
            let mut p = lock(&self.published);
            if c.state == "terminated" {
                p.remove(&(c.callid.clone(), ent.clone()));
            } else {
                p.insert((c.callid.clone(), ent.clone()));
            }
            drop(p);
            let body = self.body(c, init, c.state);
            let id = format!("{}-{}", c.callid, if init { "i" } else { "r" });
            pua.publish(PubReq {
                pres_uri: ent,
                event: "dialog",
                id: &id,
                ctype: "application/dialog-info+xml",
                body: Some(body),
                expires: life,
                dst: server.clone(),
            });
        }
    }
}

impl Module for PuaDialoginfo {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("presence_server", Ty::Str, "", "Where PUBLISHes go (default: the presentity URI)"),
            p("caller_trying", Ty::Bool, "true", "Publish the caller's trying state (false: only from the first provisional)"),
            p("callee_trying", Ty::Bool, "false", "Publish the callee's trying state"),
            p("include_callid", Ty::Bool, "true", "Include the Call-ID in the dialog-info"),
            p("include_tags", Ty::Bool, "true", "Include the local and remote tags in the dialog-info"),
            p("include_localremote", Ty::Bool, "true", "Include the local and remote parties in the dialog-info"),
            p("override_lifetime", Ty::Duration(Unit::Sec), "3600s", "Expiry of the PUBLISHes (terminated states use 10 s)"),
            p("send_publish_flag", Ty::Int { min: -1, max: 63 }, "-1", "Publish only dialogs whose INVITE had this flag (-1: all)"),
        ])
    }

    fn name(&self) -> &'static str {
        "pua_dialoginfo"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let b = || v.int().map(|x| x != 0);
        match name {
            "presence_server" => *lock(&self.server) = Some(v.str()?.into()),
            "caller_trying" => self.caller_trying.store(b()?, Ordering::Relaxed),
            "callee_trying" => self.callee_trying.store(b()?, Ordering::Relaxed),
            "include_callid" => self.include_callid.store(b()?, Ordering::Relaxed),
            "include_tags" => self.include_tags.store(b()?, Ordering::Relaxed),
            "include_localremote" => self.include_localremote.store(b()?, Ordering::Relaxed),
            "override_lifetime" => self.lifetime.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "send_publish_flag" => self.flag.store(v.int()?, Ordering::Relaxed),
            "caller_confirmed"
            | "use_pubruri_avps"
            | "pubruri_caller_avp"
            | "pubruri_callee_avp"
            | "disable_caller_publish_flag"
            | "disable_callee_publish_flag"
            | "pubruri_caller_dlg_var"
            | "pubruri_callee_dlg_var"
            | "callee_entity_avp" => {}
            _ => return Err(format!("pua_dialoginfo: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let pua = reg.api::<Pua>().ok_or("pua_dialoginfo needs pua loaded first")?;
        let dlg = reg.api::<Dialog>().ok_or("pua_dialoginfo needs dialog loaded first")?;
        let _ = self.pua.set(pua);
        let me = self.clone();
        dlg.on_state(Arc::new(move |c| me.on_change(c)));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_margin_is_a_tenth_but_at_least_ten_seconds() {
        // (expires, seconds after `now` the refresh is due); under 20 s the
        // margin is half the lifetime.
        let cases = [(1, 1), (2, 1), (5, 3), (10, 5), (11, 6), (19, 10), (20, 10), (21, 11), (60, 50), (100, 90), (101, 91), (200, 180), (86400, 77760)];
        for (exp, after) in cases {
            assert_eq!(next_refresh(500, exp), 500 + after, "expires {exp}");
        }
    }

    #[test]
    fn reply_header_lookup_edges() {
        let m = b"SIP/2.0 200 OK\r\nsip-etag :  e1 \r\nX: a:b\r\n\r\n";
        assert_eq!(header(m, "SIP-ETag"), Some("e1"));
        assert_eq!(header(m, "x"), Some("a:b"), "only the first colon splits");
        assert_eq!(header(m, "Expires"), None);
        // The status line is never a header.
        assert_eq!(header(b"Expires: 1\r\nExpires: 2\r\n\r\n", "Expires"), Some("2"));
        assert_eq!(header(b"\xff\xfe", "Expires"), None);
    }

    fn change(state: &'static str) -> DlgChange {
        DlgChange {
            state,
            callid: "c<1>".into(),
            from_uri: "sip:alice@ex.com".into(),
            to_uri: "sip:bob@ex.com".into(),
            from_tag: "ft".into(),
            to_tag: String::new(),
            req_uri: "sip:bob@ex.com".into(),
            flags: 0,
        }
    }

    #[test]
    fn dialog_info_bodies_for_both_sides() {
        let p = PuaDialoginfo::default();
        let caller = String::from_utf8(p.body(&change("early"), true, "early")).unwrap();
        assert_eq!(
            caller,
            "<?xml version=\"1.0\"?>\n<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"1\" state=\"full\" entity=\"sip:alice@ex.com\">\
             <dialog id=\"c&lt;1&gt;\" call-id=\"c&lt;1&gt;\" local-tag=\"ft\" direction=\"initiator\"><state>early</state>\
             <local><identity>sip:alice@ex.com</identity><target uri=\"sip:alice@ex.com\"/></local>\
             <remote><identity>sip:bob@ex.com</identity><target uri=\"sip:bob@ex.com\"/></remote></dialog></dialog-info>"
        );
        let mut c = change("confirmed");
        c.to_tag = "tt".into();
        let callee = String::from_utf8(p.body(&c, false, "confirmed")).unwrap();
        assert_eq!(xml::attr(&callee, "dialog-info", "entity").as_deref(), Some("sip:bob@ex.com"));
        assert_eq!(xml::attr(&callee, "dialog", "local-tag").as_deref(), Some("tt"));
        assert_eq!(xml::attr(&callee, "dialog", "remote-tag").as_deref(), Some("ft"));
        assert_eq!(xml::attr(&callee, "dialog", "direction").as_deref(), Some("recipient"));
        // The include_* switches.
        for name in ["include_callid", "include_tags", "include_localremote"] {
            p.set_param(name, &Arg::Int(0)).unwrap();
        }
        let bare = String::from_utf8(p.body(&c, true, "confirmed")).unwrap();
        assert!(bare.contains("<dialog id=\"c&lt;1&gt;\" direction=\"initiator\"><state>confirmed</state></dialog>"), "{bare}");
        assert!(p.set_param("bogus", &Arg::Int(0)).is_err());
    }

    #[test]
    fn refresh_time() {
        assert_eq!(next_refresh(1000, 0), 0);
        assert_eq!(next_refresh(1000, 3600), 1000 + 3240);
        assert_eq!(next_refresh(1000, 60), 1000 + 50);
        assert_eq!(next_refresh(1_800_000_000, u64::MAX), 1_800_000_000 + (u64::MAX - u64::MAX / 10));
        assert_eq!(next_refresh(u64::MAX - 5, 3600), u64::MAX);
    }

    #[test]
    fn header_lookup() {
        let m = b"SIP/2.0 200 OK\r\nSIP-ETag: e1\r\nExpires: 60\r\n\r\nExpires: 1";
        assert_eq!(header(m, "expires"), Some("60"));
        assert_eq!(header(b"SIP/2.0 200 OK\r\nExpires: 5", "Expires"), Some("5"));
    }
}
