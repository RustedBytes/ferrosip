//! `presence` — the PUBLISH/SUBSCRIBE/NOTIFY presence server (RFC 3903,
//! RFC 6665): publications per (presentity, event) with entity tags and
//! expiry, subscriptions, NOTIFYs with the aggregated state whenever it
//! changes. Event packages come from `presence_xml` ("presence", PIDF)
//! and `presence_dialoginfo` ("dialog").
//!
//! Functions: `handle_publish([sender_uri])`, `handle_subscribe()`,
//! `pres_has_subscribers(uri, event)`, `pres_refresh_watchers(uri, event,
//! type)`, `pres_update_watchers(uri, event)`, `pres_auth_status(watcher,
//! presentity)` (always 1: active — no XCAP authorization rules).
//! presence_xml adds `pres_check_basic(uri, status)` and
//! `pres_check_activities(uri, activity)`.
//! RPC: `presence.presentity_list`, `presence.presentity_show <uri>`,
//! `presence.watcher_list`, `presence.refreshWatchers <uri> <event>`,
//! `presence.cleanup`. State is kept in memory (Kamailio `subs_db_mode=0`,
//! `publ_cache` on).

use crate::notifier::{Notifier, Outcome, SubRef};
use crate::{aor, header, xml};
use mod_txn::Tm;
use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, ShardedMap, want_args};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub type Aggregate = Arc<dyn Fn(&str, &[Vec<u8>]) -> Vec<u8> + Send + Sync>;
pub type EmptyBody = Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;
/// Per-subscription rewrite of the body (dialog-info `version`), gets the
/// NOTIFY number.
pub type PerSub = Arc<dyn Fn(&str, u32, Vec<u8>) -> Vec<u8> + Send + Sync>;
pub type ChangeHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct EventPkg {
    pub name: String,
    pub ctype: String,
    pub aggregate: Aggregate,
    pub empty: Option<EmptyBody>,
    pub per_sub: Option<PerSub>,
}

#[derive(Clone, Debug)]
struct Publication {
    etag: String,
    body: Vec<u8>,
    expires_at: u64,
    sender: String,
}

pub struct Presence {
    events: RwLock<HashMap<String, Arc<EventPkg>>>,
    pubs: ShardedMap<(String, String), Vec<Publication>>,
    pub notifier: Arc<Notifier>,
    max_expires: AtomicU64,
    etag_seq: AtomicU64,
    hooks: RwLock<Vec<ChangeHook>>,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            pubs: ShardedMap::new(64),
            notifier: Arc::new(Notifier::default()),
            max_expires: AtomicU64::new(3600),
            etag_seq: AtomicU64::new(1),
            hooks: RwLock::new(Vec::new()),
        }
    }
}

impl Presence {
    /// Register an event package (presence_xml, presence_dialoginfo, …).
    pub fn add_event(&self, p: EventPkg) {
        write(&self.events).insert(p.name.clone(), Arc::new(p));
    }

    /// Called after a presentity's state changed (rls).
    pub fn on_change(&self, h: ChangeHook) {
        write(&self.hooks).push(h);
    }

    fn pkg(&self, name: &str) -> Option<Arc<EventPkg>> {
        read(&self.events).get(name).cloned()
    }

    pub fn event_names(&self) -> Vec<String> {
        let mut v: Vec<String> = read(&self.events).keys().cloned().collect();
        v.sort();
        v
    }

    /// Aggregated state: (content type, body) — body may be empty.
    pub fn state(&self, pres_uri: &str, event: &str) -> Option<(String, Vec<u8>)> {
        let pkg = self.pkg(event)?;
        let t = unix_secs();
        let bodies: Vec<Vec<u8>> = self
            .pubs
            .get_cloned(&(pres_uri.to_string(), event.to_string()))
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.expires_at > t)
            .map(|p| p.body)
            .collect();
        let body = if bodies.is_empty() { pkg.empty.as_ref().and_then(|f| f(pres_uri)).unwrap_or_default() } else { (pkg.aggregate)(pres_uri, &bodies) };
        Some((pkg.ctype.clone(), body))
    }

    fn notify_one(&self, sub: &SubRef, state: &str) {
        let (pres_uri, event, version) = {
            let g = lock(sub);
            (g.pres_uri.clone(), g.event.split(';').next().unwrap_or("").to_string(), g.version.saturating_add(1))
        };
        let Some((ctype, mut body)) = self.state(&pres_uri, &event) else { return };
        if let Some(f) = self.pkg(&event).and_then(|p| p.per_sub.clone())
            && !body.is_empty()
        {
            body = f(&pres_uri, version, body);
        }
        self.notifier.notify(sub, state, Some(&ctype), &body, "");
    }

    /// NOTIFY every watcher of (pres_uri, event).
    pub fn notify_watchers(&self, pres_uri: &str, event: &str) -> usize {
        let w = self.notifier.watchers(pres_uri, event);
        for s in &w {
            self.notify_one(s, "active");
        }
        let hooks = read(&self.hooks).clone();
        for h in hooks {
            h(pres_uri, event);
        }
        w.len()
    }

    fn handle_publish(&self, ctx: &mut Ctx<'_, '_>, sender: Option<String>) -> i32 {
        let Some(pres_uri) = aor(ctx.ruri()) else {
            let _ = ctx.reply(400, "Bad Request-URI");
            return -1;
        };
        let event = header(ctx, "Event").or_else(|| header(ctx, "o")).unwrap_or_default();
        let event = event.split(';').next().unwrap_or("").trim().to_string();
        if self.pkg(&event).is_none() {
            let allow = self.event_names().join(", ");
            let _ = ctx.reply_with(489, "Bad Event", format!("Allow-Events: {allow}\r\n").as_bytes());
            return -1;
        }
        let expires = header(ctx, "Expires").and_then(|e| e.parse::<u64>().ok()).unwrap_or(3600).min(self.max_expires.load(Ordering::Relaxed));
        let if_match = header(ctx, "SIP-If-Match");
        let body = ctx.body();
        let key = (pres_uri.clone(), event.clone());
        let etag = format!("a.{}.{}", unix_secs(), self.etag_seq.fetch_add(1, Ordering::Relaxed));
        let sender = sender
            .unwrap_or_else(|| String::from_utf8_lossy(&ctx.msg.get(sip_parser::HdrKind::From).map(|h| h.body.to_vec()).unwrap_or_default()).into_owned());
        let res: Result<bool, (u16, &str)> = self.pubs.alter(key, |cur| {
            let mut list = cur.unwrap_or_default();
            let t = unix_secs();
            list.retain(|p| p.expires_at > t);
            let r = match &if_match {
                Some(m) if expires == 0 => match list.iter().position(|p| &p.etag == m) {
                    None => Err((412, "Conditional Request Failed")),
                    Some(i) => {
                        list.remove(i);
                        Ok(true)
                    }
                },
                Some(m) => match list.iter_mut().find(|p| &p.etag == m) {
                    None => Err((412, "Conditional Request Failed")),
                    Some(p) => {
                        p.etag = etag.clone();
                        p.expires_at = t.saturating_add(expires);
                        let changed = !body.is_empty() && body != p.body;
                        if !body.is_empty() {
                            p.body = body.clone();
                        }
                        Ok(changed)
                    }
                },
                None if body.is_empty() => Err((400, "Missing body")),
                None if expires == 0 => Ok(false),
                None => {
                    list.push(Publication { etag: etag.clone(), body: body.clone(), expires_at: t.saturating_add(expires), sender: sender.clone() });
                    Ok(true)
                }
            };
            ((!list.is_empty()).then_some(list), r)
        });
        match res {
            Err((code, reason)) => {
                let _ = ctx.reply(code, reason);
                -1
            }
            Ok(changed) => {
                let _ = ctx.reply_with(200, "OK", format!("SIP-ETag: {etag}\r\nExpires: {expires}\r\n").as_bytes());
                if changed {
                    self.notify_watchers(&pres_uri, &event);
                }
                1
            }
        }
    }

    fn handle_subscribe(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let names = self.event_names();
        let evs: Vec<&str> = names.iter().map(String::as_str).collect();
        match self.notifier.subscribe(ctx, &evs, None, false) {
            Ok(Outcome::New(s)) | Ok(Outcome::Refreshed(s)) => {
                self.notify_one(&s, "active");
                1
            }
            Ok(Outcome::Ended(s)) => {
                self.notify_one(&s, "terminated;reason=timeout");
                1
            }
            Err(r) => r,
        }
    }

    fn tick(&self) {
        // Expired publications: the state changed.
        let t = unix_secs();
        let mut changed = Vec::new();
        self.pubs.retain(|k, list| {
            let n = list.len();
            list.retain(|p| p.expires_at > t);
            if list.len() != n {
                changed.push(k.clone());
            }
            !list.is_empty()
        });
        for (u, e) in changed {
            self.notify_watchers(&u, &e);
        }
        for s in self.notifier.take_expired() {
            self.notify_one(&s, "terminated;reason=timeout");
        }
    }
}

impl Module for Presence {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("max_expires", Ty::Duration(Unit::Sec), "3600s", "Longest accepted PUBLISH expiry"),
            p("max_expires_subscribe", Ty::Duration(Unit::Sec), "3600s", "Longest accepted SUBSCRIBE expiry"),
            p("min_expires", Ty::Duration(Unit::Sec), "0s", "Shortest accepted SUBSCRIBE expiry"),
            p("default_expires", Ty::Duration(Unit::Sec), "3600s", "SUBSCRIBE expiry when the request has no Expires"),
        ])
    }

    fn name(&self) -> &'static str {
        "presence"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, opt, sig};
        const SENDER: &[Param] = &[opt("sender", Uri)];
        const UE: &[Param] = &[arg("uri", Uri), arg("event", Str).eg("\"presence\"")];
        const AUTH: &[Param] = &[arg("watcher", Uri), arg("presentity", Uri)];
        Some(vec![
            sig("handle_publish", "handle_publish", SENDER, Ret::Action, "Store a PUBLISH and answer it (sender: the publisher instead of From)"),
            sig("handle_subscribe", "handle_subscribe", &[], Ret::Action, "Create, refresh or end a SUBSCRIBE's subscription and answer it"),
            sig("pres_has_subscribers", "has_subscribers", UE, Ret::Bool, "The presentity has watchers for this event"),
            sig("pres_refresh_watchers", "refresh_watchers", UE, Ret::Void, "Notify the presentity's watchers of this event again"),
            sig("pres_update_watchers", "update_watchers", UE, Ret::Void, "Notify the presentity's watchers of this event (after a state change)"),
            sig("pres_auth_status", "auth_status", AUTH, Ret::Bool, "The watcher may see the presentity (always true: no authorization rules)"),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = || v.int().map(|x| x.max(0).unsigned_abs());
        match name {
            "max_expires" | "max_expires_publish" => self.max_expires.store(n()?, Ordering::Relaxed),
            "max_expires_subscribe" => self.notifier.max_expires.store(n()?, Ordering::Relaxed),
            "min_expires" => self.notifier.min_expires.store(n()?, Ordering::Relaxed),
            "default_expires" => self.notifier.default_expires.store(n()?, Ordering::Relaxed),
            "subs_db_mode"
            | "db_url"
            | "presentity_table"
            | "active_watchers_table"
            | "watchers_table"
            | "server_address"
            | "fallback2db"
            | "send_fast_notify"
            | "expires_offset"
            | "clean_period"
            | "db_update_period"
            | "waitn_time"
            | "notifier_processes"
            | "publ_cache"
            | "subs_htable_size"
            | "pres_htable_size"
            | "timeout_rm_subs"
            | "sip_uri_match"
            | "enable_sphere_check"
            | "local_log_level"
            | "startup_mode"
            | "retry_presentity_cleanup" => {}
            _ => return Err(format!("presence: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let tm = reg.api::<Tm>().ok_or("presence needs tm loaded first")?;
        self.notifier.set_tm(tm);
        reg.provide(self.clone());
        let m = "presence";
        let me = self.clone();
        reg.export(
            m,
            "handle_publish",
            |a: &[Arg]| -> Result<Option<DynStr>, String> {
                match a {
                    [] => Ok(None),
                    [sender] => Ok(Some(sender.dyn_str()?)),
                    _ => Err("expected [sender_uri]".into()),
                }
            },
            move |ctx: &mut Ctx, s: &Option<DynStr>| {
                let s = s.as_ref().map(|s| s.eval(ctx).into_owned());
                me.handle_publish(ctx, s)
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "handle_subscribe",
            |a: &[Arg]| if a.len() > 1 { Err("expected [watcher_uri]".to_string()) } else { Ok(()) },
            move |ctx: &mut Ctx, _: &()| me.handle_subscribe(ctx),
        );
        let two = |a: &[Arg]| -> Result<Vec<DynStr>, String> {
            if a.len() < 2 || a.len() > 3 {
                return Err("expected uri, event[, type]".into());
            }
            a.iter().map(Arg::dyn_str).collect()
        };
        let me = self.clone();
        reg.export(m, "pres_has_subscribers", two, move |ctx: &mut Ctx, a: &Vec<DynStr>| {
            let [u, e, ..] = a.as_slice() else { return -1 };
            let (u, e) = (u.eval(ctx).into_owned(), e.eval(ctx).into_owned());
            let u = aor(u.as_bytes()).unwrap_or(u);
            if me.notifier.watchers(&u, &e).is_empty() { -1 } else { 1 }
        });
        for name in ["pres_refresh_watchers", "pres_update_watchers"] {
            let me = self.clone();
            reg.export(m, name, two, move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                let [u, e, ..] = a.as_slice() else { return -1 };
                let (u, e) = (u.eval(ctx).into_owned(), e.eval(ctx).into_owned());
                let u = aor(u.as_bytes()).unwrap_or(u);
                me.notify_watchers(&u, &e);
                1
            });
        }
        reg.export(m, "pres_auth_status", |a: &[Arg]| want_args(a, 2), |_: &mut Ctx, _: &()| 1);
        // RPC
        let me = self.clone();
        reg.rpc.add("presence.presentity_list", "Presentities with publications", move |_| {
            let t = unix_secs();
            let mut v = Vec::new();
            me.pubs.for_each_mut(|(u, e), l| {
                for p in l.iter().filter(|p| p.expires_at > t) {
                    v.push(json!({"pres_uri": u, "event": e, "etag": p.etag, "expires": p.expires_at.saturating_sub(t), "sender": p.sender}));
                }
            });
            Ok(json!(v))
        });
        let me = self.clone();
        reg.rpc.add("presence.presentity_show", "presence.presentity_show <uri> [event]", move |p| {
            let u = sip_core::rpc::str_param(p, 0)?;
            let e = sip_core::rpc::str_param(p, 1).unwrap_or_else(|_| "presence".into());
            let (ct, body) = me.state(&aor(u.as_bytes()).unwrap_or(u), &e).ok_or("no such event")?;
            Ok(json!({"content_type": ct, "body": String::from_utf8_lossy(&body)}))
        });
        let me = self.clone();
        reg.rpc.add("presence.watcher_list", "Active subscriptions", move |_| {
            let t = unix_secs();
            Ok(json!(me
                .notifier
                .all()
                .iter()
                .map(|s| {
                    let g = lock(s);
                    json!({"pres_uri": g.pres_uri, "watcher": g.watcher_uri, "event": g.event, "expires": g.expires_at.saturating_sub(t), "callid": g.callid})
                })
                .collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("presence.refreshWatchers", "presence.refreshWatchers <uri> <event>", move |p| {
            let u = sip_core::rpc::str_param(p, 0)?;
            let e = sip_core::rpc::str_param(p, 1)?;
            Ok(json!(me.notify_watchers(&aor(u.as_bytes()).unwrap_or(u), &e)))
        });
        let me = self.clone();
        reg.rpc.add("presence.cleanup", "Drop expired publications and subscriptions now", move |_| {
            me.tick();
            Ok(json!(0))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        self.notifier.set_net(net);
        std::thread::Builder::new()
            .name("presence-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    self.tick();
                }
            })
            .map_err(|e| format!("cannot start the presence timer thread: {e}"))?;
        Ok(())
    }
}

// ------------------------------------------------------------ presence_xml --

/// Merge PIDF documents: the first document's `<presence>` element with
/// the children (tuples, persons, devices, notes) of all of them.
pub fn merge_pidf(_uri: &str, bodies: &[Vec<u8>]) -> Vec<u8> {
    let [first, rest @ ..] = bodies else { return Vec::new() };
    if rest.is_empty() {
        return first.clone();
    }
    let docs: Vec<String> = bodies.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    let Some(open) = docs.first().and_then(|d| xml::open_tag(d, "presence")) else { return first.clone() };
    let mut out = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{open}>");
    for d in &docs {
        if let Some(i) = xml::inner(d, "presence") {
            out.push_str(i.trim());
        }
    }
    out.push_str("</presence>");
    out.into_bytes()
}

#[derive(Default)]
pub struct PresenceXml {
    force_dummy: AtomicBool,
    pres: OnceLock<Arc<Presence>>,
}

impl Module for PresenceXml {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("force_dummy_presence", Ty::Bool, "false", "Send a dummy PIDF document for presentities without publications")])
    }

    fn name(&self) -> &'static str {
        "presence_xml"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, sig};
        const BASIC: &[Param] = &[arg("uri", Uri), arg("status", Enum(&["open", "closed"]))];
        const ACT: &[Param] = &[arg("uri", Uri), arg("activity", Str).eg("\"busy\"")];
        Some(vec![
            sig("pres_check_basic", "check_basic", BASIC, Ret::Bool, "The presentity's PIDF basic status is this (open/closed)"),
            sig("pres_check_activities", "check_activities", ACT, Ret::Bool, "The presentity's PIDF activities include this one (e.g. busy, away)"),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "force_dummy_presence" => self.force_dummy.store(v.int()? != 0, Ordering::Relaxed),
            "force_active"
            | "integrated_xcap_server"
            | "xcap_table"
            | "disable_presence"
            | "disable_winfo"
            | "disable_bla"
            | "passive_mode"
            | "pidf_manipulation"
            | "xcap_server"
            | "db_url"
            | "default_expires"
            | "force_presence_single_body"
            | "presence_single_body_priorities"
            | "presence_single_body_lookup_element" => {}
            _ => return Err(format!("presence_xml: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let pres = reg.api::<Presence>().ok_or("presence_xml needs presence loaded first")?;
        let dummy = self.force_dummy.load(Ordering::Relaxed);
        pres.add_event(EventPkg {
            name: "presence".into(),
            ctype: "application/pidf+xml".into(),
            aggregate: Arc::new(merge_pidf),
            empty: dummy.then(|| -> EmptyBody {
                Arc::new(|uri: &str| {
                    Some(
                        format!(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"{}\"><tuple id=\"dummy\"><status><basic>closed</basic></status></tuple></presence>",
                            xml::escape(uri)
                        )
                        .into_bytes(),
                    )
                })
            }),
            per_sub: None,
        });
        let _ = self.pres.set(pres);
        let me = self.clone();
        let two = |a: &[Arg]| {
            want_args(a, 2)?;
            a.iter().map(Arg::dyn_str).collect::<Result<Vec<_>, _>>()
        };
        reg.export("presence_xml", "pres_check_basic", two, move |ctx: &mut Ctx, a: &Vec<DynStr>| {
            let [u, st] = a.as_slice() else { return -1 };
            let (u, st) = (u.eval(ctx).into_owned(), st.eval(ctx).into_owned());
            let Some((_, body)) = me.pres.get().and_then(|p| p.state(&aor(u.as_bytes()).unwrap_or(u), "presence")) else { return -1 };
            let doc = String::from_utf8_lossy(&body);
            if xml::all(&doc, "basic").iter().any(|b| xml::inner(b, "basic").is_some_and(|x| x.trim().eq_ignore_ascii_case(&st))) { 1 } else { -1 }
        });
        let me = self.clone();
        reg.export("presence_xml", "pres_check_activities", two, move |ctx: &mut Ctx, a: &Vec<DynStr>| {
            let [u, act] = a.as_slice() else { return -1 };
            let (u, act) = (u.eval(ctx).into_owned(), act.eval(ctx).into_owned());
            let Some((_, body)) = me.pres.get().and_then(|p| p.state(&aor(u.as_bytes()).unwrap_or(u), "presence")) else { return -1 };
            let doc = String::from_utf8_lossy(&body);
            let hit = xml::all(&doc, "activities").iter().any(|a| xml::element(a, &act, 0).is_some());
            if hit { 1 } else { -1 }
        });
        Ok(())
    }
}

// ----------------------------------------------------- presence_dialoginfo --

/// Rank of a dialog-info state (for force_single_dialog).
fn state_rank(d: &str) -> u8 {
    match xml::inner(d, "state").map(str::trim) {
        Some("confirmed") => 4,
        Some("early") => 3,
        Some("proceeding") => 2,
        Some("trying") => 1,
        _ => 0,
    }
}

pub fn merge_dialoginfo(uri: &str, bodies: &[Vec<u8>], single: bool) -> Vec<u8> {
    let docs: Vec<String> = bodies.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect();
    let mut dialogs: Vec<String> = docs.iter().flat_map(|d| xml::all(d, "dialog")).collect();
    if single && dialogs.len() > 1 {
        dialogs.sort_by_key(|d| std::cmp::Reverse(state_rank(d)));
        dialogs.truncate(1);
    }
    let mut out = format!(
        "<?xml version=\"1.0\"?>\n<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"0\" state=\"full\" entity=\"{}\">",
        xml::escape(uri)
    );
    for d in dialogs {
        out.push_str(&d);
    }
    out.push_str("</dialog-info>");
    out.into_bytes()
}

/// Rewrite the root's `version` to the subscription's NOTIFY count.
fn set_version(_uri: &str, version: u32, body: Vec<u8>) -> Vec<u8> {
    let s = String::from_utf8_lossy(&body).into_owned();
    let Some(open) = xml::open_tag(&s, "dialog-info") else { return body };
    let Some((head, value)) = open.split_once("version=") else { return body };
    // The quote is the character after `=` (taken as a char: the body is
    // from the wire, and a byte offset could fall inside a character).
    let mut chars = value.chars();
    let q = chars.next().unwrap_or('"');
    let Some((_, tail)) = chars.as_str().split_once(q) else { return body };
    let new_open = format!("{head}version={q}{version}{q}{tail}");
    s.replacen(&open, &new_open, 1).into_bytes()
}

#[derive(Default)]
pub struct PresenceDialoginfo {
    force_single: AtomicBool,
    force_dummy: AtomicBool,
}

impl Module for PresenceDialoginfo {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("force_single_dialog", Ty::Bool, "false", "Aggregate to a single dialog (the most interesting state)"),
            p("force_dummy_dialog", Ty::Bool, "false", "Send an empty dialog-info document for presentities without publications"),
        ])
    }

    fn name(&self) -> &'static str {
        "presence_dialoginfo"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "force_single_dialog" => self.force_single.store(v.int()? != 0, Ordering::Relaxed),
            "force_dummy_dialog" => self.force_dummy.store(v.int()? != 0, Ordering::Relaxed),
            _ => return Err(format!("presence_dialoginfo: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let pres = reg.api::<Presence>().ok_or("presence_dialoginfo needs presence loaded first")?;
        let single = self.force_single.load(Ordering::Relaxed);
        let dummy = self.force_dummy.load(Ordering::Relaxed);
        pres.add_event(EventPkg {
            name: "dialog".into(),
            ctype: "application/dialog-info+xml".into(),
            aggregate: Arc::new(move |u, b| merge_dialoginfo(u, b, single)),
            empty: dummy.then(|| -> EmptyBody { Arc::new(|u: &str| Some(merge_dialoginfo(u, &[], false))) }),
            per_sub: Some(Arc::new(set_version)),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::testutil::{hdr, reply, request, with_msg};

    fn pidf(basic: &str, id: &str) -> String {
        format!(
            r#"<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:pres@ex.com"><tuple id="{id}"><status><basic>{basic}</basic></status></tuple></presence>"#
        )
    }

    /// A presence server with the PIDF package.
    fn server() -> Presence {
        let p = Presence::default();
        p.add_event(EventPkg { name: "presence".into(), ctype: "application/pidf+xml".into(), aggregate: Arc::new(merge_pidf), empty: None, per_sub: None });
        p
    }

    /// PUBLISH to sip:pres@ex.com: (return, code, reply).
    fn publish(p: &Presence, extra: &str, body: &str) -> (i32, u16, String) {
        with_msg(&request("PUBLISH", "sip:pres@ex.com", None, extra, body), |ctx| {
            let r = p.handle_publish(ctx, None);
            let (code, out) = reply(ctx);
            (r, code, out)
        })
    }

    fn body_of(p: &Presence) -> String {
        String::from_utf8(p.state("sip:pres@ex.com", "presence").unwrap().1).unwrap()
    }

    #[test]
    fn publish_create_refresh_modify_remove() {
        let p = server();
        let (r, code, out) = publish(&p, "Event: presence\nExpires: 120\n", &pidf("open", "t1"));
        assert_eq!((r, code), (1, 200), "{out}");
        assert_eq!(hdr(&out, "Expires").as_deref(), Some("120"));
        let etag = hdr(&out, "SIP-ETag").unwrap();
        assert!(body_of(&p).contains("<basic>open</basic>"));
        // A refresh (no body) gets a new entity tag and keeps the state.
        let (_, code, out) = publish(&p, &format!("Event: presence\nSIP-If-Match: {etag}\nExpires: 60\n"), "");
        let etag2 = hdr(&out, "SIP-ETag").unwrap();
        assert_eq!(code, 200);
        assert_ne!(etag2, etag);
        assert!(body_of(&p).contains("<basic>open</basic>"));
        // The old entity tag is gone.
        assert_eq!(publish(&p, &format!("Event: presence\nSIP-If-Match: {etag}\n"), "").1, 412);
        // A modification replaces the body.
        let (_, code, out) = publish(&p, &format!("Event: presence\nSIP-If-Match: {etag2}\n"), &pidf("closed", "t1"));
        let etag3 = hdr(&out, "SIP-ETag").unwrap();
        assert_eq!(code, 200);
        assert!(body_of(&p).contains("<basic>closed</basic>") && !body_of(&p).contains("open"));
        // Expires: 0 removes it.
        assert_eq!(publish(&p, &format!("Event: presence\nSIP-If-Match: {etag3}\nExpires: 0\n"), "").1, 200);
        assert_eq!(body_of(&p), "");
        assert_eq!(publish(&p, &format!("Event: presence\nSIP-If-Match: {etag3}\nExpires: 0\n"), "").1, 412);
    }

    #[test]
    fn publish_errors() {
        let p = server();
        let (r, code, out) = publish(&p, "Event: dialog\n", &pidf("open", "t"));
        assert_eq!((r, code), (-1, 489));
        assert_eq!(hdr(&out, "Allow-Events").as_deref(), Some("presence"));
        assert_eq!(publish(&p, "", &pidf("open", "t")).1, 489, "no Event");
        assert_eq!(publish(&p, "Event: presence\n", "").1, 400, "a new publication needs a body");
        assert_eq!(publish(&p, "Event: presence\nSIP-If-Match: nope\n", "").1, 412);
        let no_user = with_msg(&request("PUBLISH", "sip:ex.com", None, "Event: presence\n", "x"), |ctx| (p.handle_publish(ctx, None), reply(ctx).0));
        assert_eq!(no_user, (-1, 400));
        // A new publication with Expires: 0 is answered, and stores nothing.
        assert_eq!(publish(&p, "Event: presence\nExpires: 0\n", &pidf("open", "t")).1, 200);
        assert_eq!(body_of(&p), "");
    }

    #[test]
    fn publish_expiry_is_capped_and_defaults_to_an_hour() {
        let p = server();
        let exp = |extra: &str| hdr(&publish(&p, extra, &pidf("open", "t")).2, "Expires");
        assert_eq!(exp("Event: presence\n").as_deref(), Some("3600"));
        p.set_param("max_expires", &Arg::Int(100)).unwrap();
        assert_eq!(exp("Event: presence\nExpires: 500\n").as_deref(), Some("100"));
        assert_eq!(exp("Event: presence;id=1\nExpires: 50\n").as_deref(), Some("50"), "event parameters are ignored");
    }

    #[test]
    fn publications_are_merged_and_expired_ones_left_out() {
        let p = server();
        publish(&p, "Event: presence\n", &pidf("open", "a"));
        publish(&p, "Event: presence\n", &pidf("closed", "b"));
        let b = body_of(&p);
        assert_eq!(xml::all(&b, "tuple").len(), 2, "{b}");
        // Expire one of them.
        p.pubs.alter(("sip:pres@ex.com".to_string(), "presence".to_string()), |cur| {
            let mut v = cur.unwrap();
            v[0].expires_at = 0;
            (Some(v), ())
        });
        let b = body_of(&p);
        assert_eq!(xml::all(&b, "tuple").len(), 1);
        assert!(b.contains("closed"));
        assert!(p.state("sip:pres@ex.com", "dialog").is_none(), "unknown package");
    }

    #[test]
    fn pidf_merge_edges() {
        assert!(merge_pidf("u", &[]).is_empty());
        let one = pidf("open", "x").into_bytes();
        assert_eq!(merge_pidf("u", std::slice::from_ref(&one)), one, "one document passes unchanged");
        // Without a <presence> root the first document wins.
        assert_eq!(merge_pidf("u", &[b"junk".to_vec(), one.clone()]), b"junk");
        let m = String::from_utf8(merge_pidf("u", &[one.clone(), b"<presence/>".to_vec(), pidf("closed", "y").into_bytes()])).unwrap();
        assert!(
            m.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" entity=\"sip:pres@ex.com\">"),
            "{m}"
        );
        assert_eq!(xml::all(&m, "tuple").len(), 2);
        assert!(m.ends_with("</presence>"));
    }

    #[test]
    fn dialoginfo_single_dialog_ranking_and_escaping() {
        let d = |id: &str, st: &str| format!(r#"<dialog-info><dialog id="{id}"><state>{st}</state></dialog></dialog-info>"#).into_bytes();
        // (states, the one kept)
        let cases = [
            (vec!["trying", "proceeding"], "proceeding"),
            (vec!["early", "confirmed", "trying"], "confirmed"),
            (vec!["terminated", "trying"], "trying"),
            (vec!["early", "early"], "early"),
        ];
        for (states, want) in cases {
            let bodies: Vec<Vec<u8>> = states.iter().enumerate().map(|(i, s)| d(&i.to_string(), s)).collect();
            let m = String::from_utf8(merge_dialoginfo("sip:a@x", &bodies, true)).unwrap();
            let kept = xml::all(&m, "dialog");
            assert_eq!(kept.len(), 1, "{m}");
            assert_eq!(xml::inner(&kept[0], "state"), Some(want), "{states:?}");
        }
        // Equal ranks keep the first one.
        let m = String::from_utf8(merge_dialoginfo("sip:a@x", &[d("first", "early"), d("second", "early")], true)).unwrap();
        assert_eq!(xml::attr(&m, "dialog", "id").as_deref(), Some("first"));
        let empty = String::from_utf8(merge_dialoginfo("sip:a&b@x", &[], false)).unwrap();
        assert_eq!(
            empty,
            "<?xml version=\"1.0\"?>\n<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\"0\" state=\"full\" entity=\"sip:a&amp;b@x\"></dialog-info>"
        );
        // The version that set_version rewrites is the root's.
        let v = String::from_utf8(set_version("", 42, empty.into_bytes())).unwrap();
        assert!(v.contains("<?xml version=\"1.0\"?>") && v.contains("version=\"42\" state=\"full\""), "{v}");
        assert_eq!(set_version("", 1, b"no root".to_vec()), b"no root");
    }

    #[test]
    fn pres_check_helpers_parse_the_state() {
        let doc = r#"<presence><tuple><status><basic> Open </basic></status></tuple><dm:person><rpid:activities><rpid:busy/></rpid:activities></dm:person></presence>"#;
        assert!(xml::all(doc, "basic").iter().any(|b| xml::inner(b, "basic").is_some_and(|x| x.trim().eq_ignore_ascii_case("open"))));
        assert!(xml::all(doc, "activities").iter().any(|a| xml::element(a, "busy", 0).is_some()));
        assert!(!xml::all(doc, "activities").iter().any(|a| xml::element(a, "away", 0).is_some()));
    }

    #[test]
    fn merging() {
        let a = br#"<?xml version="1.0"?><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:a@x"><tuple id="1"><status><basic>open</basic></status></tuple></presence>"#.to_vec();
        let b = br#"<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:a@x"><tuple id="2"><status><basic>closed</basic></status></tuple></presence>"#
            .to_vec();
        let m = String::from_utf8(merge_pidf("sip:a@x", &[a, b])).unwrap();
        assert_eq!(xml::all(&m, "tuple").len(), 2);
        assert!(m.contains("entity=\"sip:a@x\""));
        let d1 = br#"<dialog-info version="1"><dialog id="1"><state>early</state></dialog></dialog-info>"#.to_vec();
        let d2 = br#"<dialog-info version="1"><dialog id="2"><state>confirmed</state></dialog></dialog-info>"#.to_vec();
        let m = String::from_utf8(merge_dialoginfo("sip:a@x", &[d1.clone(), d2.clone()], false)).unwrap();
        assert_eq!(xml::all(&m, "dialog").len(), 2);
        let s = String::from_utf8(merge_dialoginfo("sip:a@x", &[d1, d2], true)).unwrap();
        assert_eq!(xml::all(&s, "dialog"), vec![r#"<dialog id="2"><state>confirmed</state></dialog>"#]);
        let v = String::from_utf8(set_version("", 7, s.into_bytes())).unwrap();
        assert!(v.contains("version=\"7\""));
    }

    #[test]
    fn set_version_on_odd_bodies_does_not_panic() {
        let set = |b: &str| String::from_utf8(set_version("", 7, b.as_bytes().to_vec())).unwrap();
        assert_eq!(set("<dialog-info version='3' x='1'></dialog-info>"), "<dialog-info version='7' x='1'></dialog-info>");
        // `version=` ending the tag, and a multi-byte character after `=`:
        // no slice out of range or inside a character.
        assert_eq!(set("<dialog-info version=></dialog-info>"), "<dialog-info version=></dialog-info>");
        assert_eq!(set("<dialog-info version=\u{e9}3\u{e9}></dialog-info>"), "<dialog-info version=\u{e9}7\u{e9}></dialog-info>");
        assert_eq!(set("<dialog-info version=\u{e9}3></dialog-info>"), "<dialog-info version=\u{e9}3></dialog-info>");
    }
}
