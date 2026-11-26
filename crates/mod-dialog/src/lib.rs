//! `dialog` — call (INVITE dialog) tracking, the Kamailio `dialog` module.
//!
//! `dlg_manage()` on an initial INVITE creates a dialog keyed by Call-ID
//! and From tag. Its state follows the replies tm *sends upstream* (the
//! winning ones, including tm's own 408/487 — `Tm::on_reply_out`):
//! 1 unconfirmed → 2 early (1xx with To tag) → 3 confirmed (2xx) → 4
//! confirmed by ACK → 5 deleted (BYE, timeout, or a final ≥ 300 before
//! confirmation). In-dialog requests are matched by the `did` cookie the
//! dialog adds to Record-Route and/or by Call-ID + tags in either
//! direction (`dlg_match_mode`). With `dlg_flag`, an INVITE relayed by tm
//! with that flag set creates the dialog too.
//!
//! * Timeouts: `default_timeout` (43200 s), `dlg_set_timeout(secs)`; on
//!   expiry, with `send_bye=1` or `dlg_set_property("timeout-bye")`, BYE is
//!   sent to both sides through tm's UAC API. Unconfirmed dialogs are
//!   dropped after `early_timeout` (300 s).
//! * Keep-alives: `ka_interval` (0 = off) + `dlg_set_property("ka-src" |
//!   "ka-dst")`: in-dialog OPTIONS; a 408/481 ends the dialog (with BYEs).
//! * Profiles: `profiles_with_value` / `profiles_no_value` ("a;b"),
//!   `set_dlg_profile`, `unset_dlg_profile`, `is_in_profile`,
//!   `get_profile_size(profile[, value], $var)`.
//! * Variables: `$dlg_var(name)` (rw), `$dlg(h_id|h_entry|state|callid|
//!   from_uri|from_tag|to_uri|to_tag|start_ts|timeout|lifetime)`.
//! * Events: `event_route[dialog:start]`, `[dialog:end]`, `[dialog:failed]`.
//! * Persistence: `db_url` + `db_mode=1` keeps confirmed dialogs in the
//!   `dialog` table (loaded at startup).
//! * Per-dialog flags (`dlg_setflag`), `dlg_get`, `$dlg_ctx`, `dlg_refer`
//!   (in-dialog REFER) and `dlg_bridge` (INVITE + REFER + BYE).
//! * RPC: `dlg.list[_ctx]`, `dlg.dlg_list[_ctx]`, `dlg.end_dlg`,
//!   `dlg.terminate_dlg`, `dlg.is_alive`, `dlg.bridge_dlg`,
//!   `dlg.profile_get_size`, `dlg.profile_list`, `dlg.stats_active`,
//!   `dlg.set_state`, `dlg.briefing`.
//! * `dlg_set_timeout_by_profile(profile, [value,] timeout)`.

pub mod dlgs;

use bumpalo::Bump;
use mod_txn::{Tm, UacRequest};
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, Unit, p, pr};
use sip_core::serde_json::{Value, json};
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Registry, RouteHub, ShardedMap, fx_hash, want_args};
use sip_parser::uri::{name_addr, param, split_list};
use sip_parser::{HdrFlags, HdrKind, Method, Msg, parse_uri};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Unconfirmed = 1,
    Early = 2,
    Confirmed = 3,
    ConfirmedAck = 4,
    Deleted = 5,
}

#[derive(Clone, Debug, Default)]
struct Leg {
    tag: String,
    contact: String,
    cseq: u32,
    /// Where requests to this leg go when no route set (its last source).
    src: Option<Dest>,
    /// Route set towards this leg, nearest hop first.
    route: Vec<String>,
}

#[derive(Debug)]
pub struct Dlg {
    h_entry: u32,
    h_id: u32,
    callid: String,
    from_hdr: String,
    to_hdr: String,
    from_uri: String,
    to_uri: String,
    state: State,
    init_ts: u64,
    start_ts: u64,
    /// Lifetime once confirmed (seconds).
    lifetime: u64,
    timeout_at: u64,
    caller: Leg,
    callee: Leg,
    /// 2xx/1xx sources by To tag (from received replies).
    reply_src: HashMap<String, Dest>,
    vars: HashMap<String, String>,
    /// Why it ended (`$dlg(end_reason)`): caller_bye, callee_bye, timeout,
    /// admin, keepalive, failed.
    end_reason: &'static str,
    end_ts: u64,
    profiles: Vec<(String, Option<String>)>,
    timeout_bye: bool,
    ka_src: bool,
    ka_dst: bool,
    next_ka: u64,
    req_uri: String,
    flags: u64,
    /// Script flags (`dlg_setflag`, 0..31).
    sflags: u32,
    /// `timeout-noreset`: in-dialog requests don't restart the timeout.
    timeout_noreset: bool,
    /// `route[name]` run when the dialog times out (`$dlg_ctx(timeout_route)`).
    timeout_route: Option<String>,
}

type DlgRef = Arc<Mutex<Dlg>>;

/// A confirmed dialog that ended (for acc CDRs).
#[derive(Clone, Debug)]
pub struct DlgEnd {
    pub callid: String,
    pub from_uri: String,
    pub to_uri: String,
    pub from_tag: String,
    pub to_tag: String,
    pub start_ts: u64,
    pub end_ts: u64,
    pub vars: HashMap<String, String>,
}

pub type EndHook = Arc<dyn Fn(&DlgEnd) + Send + Sync>;

/// A dialog state change (pua_dialoginfo).
#[derive(Clone, Debug)]
pub struct DlgChange {
    /// "trying" (created), "early", "confirmed" or "terminated".
    pub state: &'static str,
    pub callid: String,
    pub from_uri: String,
    pub to_uri: String,
    pub from_tag: String,
    pub to_tag: String,
    /// The R-URI of the initial INVITE.
    pub req_uri: String,
    /// Message flags of the initial INVITE (publish-control flags).
    pub flags: u64,
}

pub type StateHook = Arc<dyn Fn(&DlgChange) + Send + Sync>;
type Key = (Box<str>, Box<str>);

/// The dialog of the message being processed.
#[derive(Clone)]
struct Current(DlgRef);

/// Kamailio's dialog context: settings made while the message has no
/// dialog yet, applied when one is created (`dlg_flag` at `t_relay`).
#[derive(Default)]
struct DlgCtx {
    /// `$dlg_ctx(on)`: create the dialog when tm relays the INVITE.
    on: bool,
    flags: u32,
    timeout: Option<u64>,
    timeout_route: Option<String>,
    timeout_bye: Option<bool>,
    ka_src: Option<bool>,
    ka_dst: Option<bool>,
    noreset: Option<bool>,
}

/// The `did` Record-Route cookie: Kamailio writes h_entry and h_id as
/// hex with the least significant digit first.
fn rev_hex(mut n: u32) -> String {
    if n == 0 {
        return "0".into();
    }
    let mut s = String::new();
    while n > 0 {
        s.push(char::from_digit(n & 0xf, 16).unwrap_or('0'));
        n >>= 4;
    }
    s
}

fn parse_rev_hex(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 8 {
        return None;
    }
    s.iter().rev().try_fold(0u32, |acc, &c| Some((acc << 4) | (c as char).to_digit(16)?))
}

fn did_value(h_entry: u32, h_id: u32) -> String {
    format!("{}.{}", rev_hex(h_entry), rev_hex(h_id))
}

fn parse_did(v: &[u8]) -> Option<(u32, u32)> {
    let mut parts = v.splitn(2, |&c| c == b'.');
    Some((parse_rev_hex(parts.next()?)?, parse_rev_hex(parts.next()?)?))
}

/// Exactly `N` script arguments (the message of [`want_args`] otherwise).
pub(crate) fn args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

/// `dlg_bridge`'s INVITE body when none is given: on hold, no media.
const HOLD_SDP: &str = "v=0\r\no=ferrosip-bridge 0 0 IN IP4 0.0.0.0\r\ns=ferrosip\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n\
m=audio 9 RTP/AVP 8 0\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";

/// Our side of a dialog we started (`dlg_bridge`), learned from the 2xx.
#[derive(Clone, Debug)]
struct UacDlg {
    from: String,
    to: String,
    callid: String,
    contact: String,
    /// Route set: the 2xx's Record-Route, reversed.
    route: Vec<String>,
    /// Outbound proxy, when there is no route set.
    op: Option<Dest>,
}

impl UacDlg {
    fn from_2xx(reply: &[u8], op: Option<Dest>) -> Option<Self> {
        let arena = Bump::new();
        let mut m = Msg::parse(reply, &arena).ok()?;
        let i = info(&mut m)?;
        i.ttag.as_ref()?;
        let mut route = i.rr;
        route.reverse();
        Some(UacDlg { from: i.from_hdr, to: i.to_hdr, callid: i.callid, contact: i.contact?, route, op })
    }

    fn req(&self, method: &str, cseq: u32, extra: &str) -> UacRequest {
        let mut headers = format!("From: {}\r\nTo: {}\r\n", self.from, self.to);
        if !self.route.is_empty() {
            headers.push_str(&format!("Route: {}\r\n", self.route.join(",")));
        }
        headers.push_str(extra);
        let dst = match self.route.first() {
            Some(r) => sip_core::pvcore::dest_from_uri(name_addr(r.as_bytes()).0),
            None => self.op,
        };
        UacRequest { method: method.into(), ruri: self.contact.clone(), dst, call_id: Some(self.callid.clone()), cseq, headers, ..Default::default() }
    }
}

/// `<uri>` for a header value.
fn angle(u: &str) -> String {
    let u = u.trim();
    if u.starts_with('<') { u.to_string() } else { format!("<{u}>") }
}

/// What dialog handling needs from a request or reply.
#[derive(Debug)]
struct Info {
    callid: String,
    ftag: String,
    ttag: Option<String>,
    from_hdr: String,
    to_hdr: String,
    from_uri: String,
    to_uri: String,
    cseq: u32,
    cseq_method: Method,
    contact: Option<String>,
    rr: Vec<String>,
}

fn info(m: &mut Msg<'_>) -> Option<Info> {
    m.parse_headers(HdrFlags::EOH).ok()?;
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let from = m.get(HdrKind::From)?;
    let to = m.get(HdrKind::To)?;
    let (furi, fparams) = name_addr(from.body);
    let (turi, tparams) = name_addr(to.body);
    let cseq = m.get(HdrKind::CSeq)?.body;
    let mut cs = cseq.split(|c| c.is_ascii_whitespace()).filter(|x| !x.is_empty());
    let num = std::str::from_utf8(cs.next()?).ok()?.parse().ok()?;
    let meth = Method::from_bytes(cs.next()?);
    let contact = m.get(HdrKind::Contact).and_then(|h| split_list(h.body).first().map(|c| s(name_addr(c).0)));
    let rr = m.headers.iter().filter(|h| h.kind == HdrKind::RecordRoute).flat_map(|h| split_list(h.body)).map(|x| s(x.trim_ascii())).collect();
    Some(Info {
        callid: s(m.get(HdrKind::CallId)?.body),
        ftag: s(param(fparams, b"tag")?),
        ttag: param(tparams, b"tag").map(s),
        from_hdr: s(from.body),
        to_hdr: s(to.body),
        from_uri: s(furi),
        to_uri: s(turi),
        cseq: num,
        cseq_method: meth,
        contact,
        rr,
    })
}

pub struct Dialog {
    dlgs: ShardedMap<Key, DlgRef>,
    by_hid: ShardedMap<u32, Key>,
    count: AtomicUsize,
    next_id: AtomicU32,
    default_timeout: AtomicU64,
    early_timeout: AtomicU64,
    send_bye: AtomicBool,
    ka_interval: AtomicU64,
    profiles_val: Mutex<HashSet<String>>,
    profiles_noval: Mutex<HashSet<String>>,
    db_url: Mutex<Option<String>>,
    db_mode: AtomicU32,
    db: OnceLock<Arc<dyn sip_db::DbConn>>,
    tm: OnceLock<Arc<Tm>>,
    hub: OnceLock<Arc<RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
    end_hooks: std::sync::RwLock<Vec<EndHook>>,
    state_hooks: std::sync::RwLock<Vec<StateHook>>,
    /// `dlg_flag`: message flag that makes tm's relay create the dialog (-1: none).
    dlg_flag: AtomicI32,
    /// 0: by the `did` cookie only, 1: cookie, then SIP ids, 2: SIP ids only.
    match_mode: AtomicU32,
    /// `timeout_noreset` modparam.
    timeout_noreset: AtomicBool,
    rr_param: Mutex<String>,
    db_update_period: AtomicU64,
    /// db_mode 2: dialogs to write and rows to delete at the next flush.
    db_dirty: Mutex<HashMap<u32, DlgRef>>,
    db_gone: Mutex<HashSet<u32>>,
    db_flushed: AtomicU64,
    bridge_controller: Mutex<String>,
    bridge_contact: Mutex<Option<String>>,
}

impl Default for Dialog {
    fn default() -> Self {
        Self {
            dlgs: ShardedMap::new(256),
            by_hid: ShardedMap::new(256),
            count: AtomicUsize::new(0),
            next_id: AtomicU32::new(1),
            default_timeout: AtomicU64::new(43200),
            early_timeout: AtomicU64::new(300),
            send_bye: AtomicBool::new(false),
            ka_interval: AtomicU64::new(0),
            profiles_val: Mutex::new(HashSet::new()),
            profiles_noval: Mutex::new(HashSet::new()),
            db_url: Mutex::new(None),
            db_mode: AtomicU32::new(0),
            db: OnceLock::new(),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
            net: OnceLock::new(),
            end_hooks: Default::default(),
            state_hooks: Default::default(),
            dlg_flag: AtomicI32::new(-1),
            match_mode: AtomicU32::new(1),
            timeout_noreset: AtomicBool::new(false),
            rr_param: Mutex::new("did".into()),
            db_update_period: AtomicU64::new(60),
            db_dirty: Mutex::new(HashMap::new()),
            db_gone: Mutex::new(HashSet::new()),
            db_flushed: AtomicU64::new(0),
            bridge_controller: Mutex::new("sip:controller@ferrosip.invalid".into()),
            bridge_contact: Mutex::new(None),
        }
    }
}

fn stat(name: &str) -> &'static std::sync::atomic::AtomicI64 {
    sip_core::stats::counter("dialog", name)
}

impl Dialog {
    /// Called whenever a confirmed dialog ends (acc CDRs).
    pub fn on_end(&self, h: EndHook) {
        write(&self.end_hooks).push(h);
    }

    /// End a confirmed call (BYE both ways) by Call-ID — cnxcc, RPC.
    pub fn end_by_callid(&self, callid: &str) -> bool {
        let found = self.all().into_iter().find(|d| {
            let g = lock(d);
            g.callid == callid && g.state >= State::Confirmed && g.state != State::Deleted
        });
        match found {
            Some(d) => {
                self.end(&d, None, true, "admin");
                true
            }
            None => false,
        }
    }

    /// Called on every state change (pua_dialoginfo).
    pub fn on_state(&self, h: StateHook) {
        write(&self.state_hooks).push(h);
    }

    fn changed(&self, d: &DlgRef, state: &'static str) {
        let hooks = read(&self.state_hooks).clone();
        if hooks.is_empty() {
            return;
        }
        let c = {
            let g = lock(d);
            DlgChange {
                state,
                callid: g.callid.clone(),
                from_uri: g.from_uri.clone(),
                to_uri: g.to_uri.clone(),
                from_tag: g.caller.tag.clone(),
                to_tag: g.callee.tag.clone(),
                req_uri: g.req_uri.clone(),
                flags: g.flags,
            }
        };
        for h in hooks {
            h(&c);
        }
    }

    fn lookup(&self, callid: &str, ftag: &str, ttag: Option<&str>) -> Option<DlgRef> {
        let k: Key = (callid.into(), ftag.into());
        if let Some(d) = self.dlgs.get_cloned(&k) {
            return Some(d);
        }
        let t = ttag?;
        let d = self.dlgs.get_cloned(&(callid.into(), t.into()))?;
        // From the callee: its From tag must be the callee's tag.
        let ok = {
            let g = lock(&d);
            g.callee.tag.is_empty() || g.callee.tag == ftag
        };
        ok.then_some(d)
    }

    fn by_id(&self, h_id: u32) -> Option<DlgRef> {
        let k = self.by_hid.get_cloned(&h_id)?;
        self.dlgs.get_cloned(&k)
    }

    fn all(&self) -> Vec<DlgRef> {
        let mut v = Vec::new();
        self.dlgs.for_each_mut(|_, d| v.push(d.clone()));
        v
    }

    fn create(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        if ctx.msg.method() != Some(Method::Invite) {
            return if ctx.ext::<Current>().is_some() { 1 } else { -1 };
        }
        let Some(i) = info(ctx.msg) else { return -1 };
        if i.ttag.is_some() {
            return if ctx.ext::<Current>().is_some() { 1 } else { -1 };
        }
        let key: Key = (i.callid.as_str().into(), i.ftag.as_str().into());
        if let Some(d) = self.dlgs.get_cloned(&key) {
            ctx.ext.push(Box::new(Current(d)));
            return 1;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let h_entry = (fx_hash(i.callid.as_bytes()) & 0xfff) as u32;
        let dc = ctx.ext::<DlgCtx>();
        let d = Arc::new(Mutex::new(Dlg {
            h_entry,
            h_id: id,
            callid: i.callid,
            from_hdr: i.from_hdr,
            to_hdr: i.to_hdr,
            from_uri: i.from_uri,
            to_uri: i.to_uri,
            state: State::Unconfirmed,
            init_ts: unix_secs(),
            start_ts: 0,
            lifetime: dc.and_then(|c| c.timeout).unwrap_or_else(|| self.default_timeout.load(Ordering::Relaxed)),
            timeout_at: 0,
            caller: Leg { tag: i.ftag, contact: i.contact.unwrap_or_default(), cseq: i.cseq, src: Some(ctx.src), route: i.rr },
            callee: Leg::default(),
            reply_src: HashMap::new(),
            vars: HashMap::new(),
            end_reason: "",
            end_ts: 0,
            profiles: Vec::new(),
            timeout_bye: dc.and_then(|c| c.timeout_bye).unwrap_or(false),
            ka_src: dc.and_then(|c| c.ka_src).unwrap_or(false),
            ka_dst: dc.and_then(|c| c.ka_dst).unwrap_or(false),
            next_ka: 0,
            req_uri: String::from_utf8_lossy(ctx.ruri()).into_owned(),
            flags: ctx.ext::<sip_core::TxnVars>().map_or(0, |t| t.flags),
            sflags: dc.map_or(0, |c| c.flags),
            timeout_noreset: dc.and_then(|c| c.noreset).unwrap_or(false),
            timeout_route: dc.and_then(|c| c.timeout_route.clone()),
        }));
        if self.dlgs.insert_if_absent(key.clone(), d.clone()) {
            self.by_hid.insert(id, key);
            // The Record-Route cookie in-dialog requests are matched by.
            if self.match_mode.load(Ordering::Relaxed) != 2 {
                let p = format!("{}={}", lock(&self.rr_param), did_value(h_entry, id));
                sip_core::rr::add_params(ctx, vec![p]);
            }
            self.count.fetch_add(1, Ordering::Relaxed);
            sip_core::stats::inc(stat("processed_dialogs"));
            self.changed(&d, "trying");
            ctx.ext.push(Box::new(Current(d)));
        } else if let Some(d) = self.dlgs.get_cloned(&key) {
            ctx.ext.push(Box::new(Current(d)));
        }
        1
    }

    fn remove(&self, d: &DlgRef) {
        let (key, id) = {
            let g = lock(d);
            ((Box::<str>::from(g.callid.as_str()), Box::<str>::from(g.caller.tag.as_str())), g.h_id)
        };
        if self.dlgs.remove_if(&key, |x| Arc::ptr_eq(x, d)).is_some() {
            self.by_hid.remove(&id);
            self.count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn event(&self, name: &str, d: &DlgRef, msg: Option<&[u8]>) {
        let (Some(hub), Some(net)) = (self.hub.get(), self.net.get()) else { return };
        if hub.has_event(name) {
            let d = d.clone();
            hub.run_event_with(name, &**net, msg, move |c| c.ext.push(Box::new(Current(d))));
        }
    }

    /// End a dialog (BYE seen, timeout, dlg.end_dlg, keep-alive failure).
    fn end(&self, d: &DlgRef, msg: Option<&[u8]>, bye: bool, reason: &'static str) {
        let info = {
            let mut g = lock(d);
            if g.state == State::Deleted {
                return;
            }
            let confirmed = g.state >= State::Confirmed;
            g.state = State::Deleted;
            g.end_reason = reason;
            g.end_ts = unix_secs();
            confirmed.then(|| DlgEnd {
                callid: g.callid.clone(),
                from_uri: g.from_uri.clone(),
                to_uri: g.to_uri.clone(),
                from_tag: g.caller.tag.clone(),
                to_tag: g.callee.tag.clone(),
                start_ts: g.start_ts,
                end_ts: unix_secs(),
                vars: g.vars.clone(),
            })
        };
        self.changed(d, "terminated");
        if let Some(info) = info {
            let hooks = read(&self.end_hooks).clone();
            for h in hooks {
                h(&info);
            }
        }
        if bye {
            self.send_bye(d, true, true);
        }
        self.remove(d);
        self.db_delete(d);
        self.event("dialog:end", d, msg);
    }

    fn fail(&self, d: &DlgRef, msg: Option<&[u8]>) {
        {
            let mut g = lock(d);
            if g.state >= State::Confirmed {
                return;
            }
            g.state = State::Deleted;
            g.end_reason = "failed";
            g.end_ts = unix_secs();
        }
        self.remove(d);
        sip_core::stats::inc(stat("failed_dialogs"));
        self.changed(d, "terminated");
        self.event("dialog:failed", d, msg);
    }

    /// Is this Record-Route / Route entry one of ours?
    fn ours(&self, rr: &str) -> bool {
        let Some(net) = self.net.get() else { return false };
        let uri = name_addr(rr.as_bytes()).0;
        parse_uri(uri).is_some_and(|u| sip_core::net::is_myself(&**net, &String::from_utf8_lossy(u.host)))
    }

    /// An INVITE with a dialog answered statelessly (`sl_send_reply(404)`
    /// after `dlg_manage()`): no transaction will report the final reply,
    /// so a failure ends the dialog here. Kamailio creates no dialog in
    /// that case; without this it lingered until `early_timeout`.
    fn on_ctx_send(&self, ctx: &Ctx<'_, '_>) {
        let Some(Current(d)) = ctx.ext::<Current>() else { return };
        if ctx.msg.method() != Some(Method::Invite) {
            return;
        }
        let out: &[u8] = ctx.out;
        let code = out.strip_prefix(b"SIP/2.0 ").and_then(|r| std::str::from_utf8(r.get(..3)?).ok()?.parse::<u16>().ok());
        if code.is_some_and(|c| c >= 300) {
            self.fail(d, Some(out));
        }
    }

    /// A reply tm sent upstream.
    fn on_reply_out(&self, reply: &[u8]) {
        if self.count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let arena = Bump::new();
        let Ok(mut m) = Msg::parse(reply, &arena) else { return };
        let Some(code) = m.status() else { return };
        let Some(i) = info(&mut m) else { return };
        if i.cseq_method != Method::Invite {
            return;
        }
        let Some(d) = self.dlgs.get_cloned(&(i.callid.as_str().into(), i.ftag.as_str().into())) else { return };
        match code {
            100..=199 => {
                let early = {
                    let mut g = lock(&d);
                    let e = g.state == State::Unconfirmed && i.ttag.is_some();
                    if e {
                        g.state = State::Early;
                        g.callee.tag = i.ttag.clone().unwrap_or_default();
                    }
                    e
                };
                if early {
                    self.changed(&d, "early");
                }
            }
            200..=299 => {
                let Some(ttag) = i.ttag else { return };
                {
                    let mut g = lock(&d);
                    if g.state >= State::Confirmed {
                        return; // retransmission or a second forked 2xx
                    }
                    // Route set towards the callee: Record-Route entries
                    // added downstream of us (above ours), nearest first.
                    let mut route: Vec<String> = i.rr.iter().take_while(|r| !self.ours(r)).cloned().collect();
                    route.reverse();
                    let src = g.reply_src.get(&ttag).copied();
                    g.callee = Leg { tag: ttag, contact: i.contact.unwrap_or_default(), cseq: 0, src, route };
                    g.state = State::Confirmed;
                    g.start_ts = unix_secs();
                    g.timeout_at = g.start_ts.saturating_add(g.lifetime);
                    g.reply_src.clear();
                }
                self.db_write(&d);
                self.changed(&d, "confirmed");
                self.event("dialog:start", &d, Some(reply));
            }
            _ => self.fail(&d, Some(reply)),
        }
    }

    /// tm got a request (`t_relay`, `t_newtran`): an initial INVITE with
    /// `dlg_flag` set (or `$dlg_ctx(on)`) gets its dialog now.
    fn on_relay(&self, ctx: &mut Ctx<'_, '_>) {
        if ctx.msg.method() != Some(Method::Invite) || ctx.ext::<Current>().is_some() {
            return;
        }
        let flag = self.dlg_flag.load(Ordering::Relaxed);
        let flagged = flag >= 0 && ctx.ext::<sip_core::TxnVars>().is_some_and(|t| t.flags & (1u64 << flag) != 0);
        if flagged || ctx.ext::<DlgCtx>().is_some_and(|c| c.on) {
            self.create(ctx);
        }
    }

    /// `(h_entry, h_id)` from the `did` parameter of one of our Route entries.
    fn did_of(&self, m: &Msg<'_>) -> Option<(u32, u32)> {
        let name = lock(&self.rr_param).clone();
        m.headers.iter().filter(|h| h.kind == HdrKind::Route).flat_map(|h| split_list(h.body)).find_map(|r| {
            let r = r.trim_ascii();
            let u = parse_uri(name_addr(r).0)?;
            let v = u.param(name.as_bytes())?;
            if self.net.get().is_some() && !self.ours(&String::from_utf8_lossy(r)) {
                return None;
            }
            parse_did(v)
        })
    }

    /// The dialog of an in-dialog request, by `dlg_match_mode`.
    fn match_request(&self, m: &Msg<'_>, i: &Info, ttag: &str) -> Option<DlgRef> {
        let mode = self.match_mode.load(Ordering::Relaxed);
        if mode != 2
            && let Some((e, id)) = self.did_of(m)
        {
            let d = self.by_id(id).filter(|d| {
                let g = lock(d);
                g.h_entry == e && g.callid == i.callid && (g.caller.tag == i.ftag || g.callee.tag == i.ftag)
            });
            if d.is_some() {
                return d;
            }
        }
        if mode == 0 {
            return None;
        }
        self.lookup(&i.callid, &i.ftag, Some(ttag))
    }

    /// Requests: in-dialog matching (ACK confirms, BYE ends).
    fn on_request(&self, ctx: &mut Ctx<'_, '_>) {
        if self.count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let Some(i) = info(ctx.msg) else { return };
        let Some(ttag) = i.ttag.as_deref() else { return };
        let Some(d) = self.match_request(ctx.msg, &i, ttag) else { return };
        ctx.ext.push(Box::new(Current(d.clone())));
        let method = ctx.msg.method().unwrap_or(Method::Other);
        let from_caller = lock(&d).caller.tag == i.ftag;
        {
            let mut g = lock(&d);
            let leg = if from_caller { &mut g.caller } else { &mut g.callee };
            if method != Method::Ack && method != Method::Cancel {
                leg.cseq = leg.cseq.max(i.cseq);
            }
            if from_caller
                && let Some(c) = &i.contact
                && method == Method::Invite
            {
                g.caller.contact = c.clone();
            }
            // In-dialog requests restart the timeout with the dialog's
            // lifetime (Kamailio's dlg_onroute()), except with the
            // timeout-noreset property or modparam; the ACK that confirms
            // the call always does.
            if g.state >= State::Confirmed && g.state != State::Deleted && !matches!(method, Method::Bye | Method::Cancel) {
                let confirming = method == Method::Ack && g.state == State::Confirmed;
                if confirming || !(g.timeout_noreset || self.timeout_noreset.load(Ordering::Relaxed)) {
                    g.timeout_at = unix_secs().saturating_add(g.lifetime);
                }
            }
            if method == Method::Ack && g.state == State::Confirmed {
                g.state = State::ConfirmedAck;
            }
        }
        if method == Method::Bye {
            let raw = ctx.msg.buf.to_vec();
            self.end(&d, Some(&raw), false, if from_caller { "caller_bye" } else { "callee_bye" });
        }
    }

    fn uac_for(&self, g: &Dlg, to_callee: bool, method: &str) -> Option<UacRequest> {
        let (leg, from, to) = if to_callee {
            (&g.callee, g.from_hdr.clone(), format!("{};tag={}", strip_tag(&g.to_hdr), g.callee.tag))
        } else {
            (&g.caller, format!("{};tag={}", strip_tag(&g.to_hdr), g.callee.tag), g.from_hdr.clone())
        };
        if leg.contact.is_empty() {
            return None;
        }
        let dst = match leg.route.first() {
            Some(r) => sip_core::pvcore::dest_from_uri(name_addr(r.as_bytes()).0),
            None => leg.src.or_else(|| sip_core::pvcore::dest_from_uri(leg.contact.as_bytes())),
        };
        let mut headers = format!("From: {from}\r\nTo: {to}\r\n");
        if !leg.route.is_empty() {
            headers.push_str(&format!("Route: {}\r\n", leg.route.join(",")));
        }
        // CSeq in the sender's space: one above what the other side used
        // (none left once it reached 2^32 - 1).
        let cseq = if to_callee { g.caller.cseq.checked_add(1)? } else { g.callee.cseq.max(1).checked_add(1)? };
        Some(UacRequest { method: method.into(), ruri: leg.contact.clone(), dst, call_id: Some(g.callid.clone()), cseq, headers, ..Default::default() })
    }

    fn send_bye(&self, d: &DlgRef, caller: bool, callee: bool) -> bool {
        let Some(tm) = self.tm.get() else { return false };
        let reqs: Vec<UacRequest> = {
            let mut g = lock(d);
            let mut v = Vec::new();
            if callee {
                v.extend(self.uac_for(&g, true, "BYE"));
                g.caller.cseq = g.caller.cseq.saturating_add(1);
            }
            if caller {
                v.extend(self.uac_for(&g, false, "BYE"));
                g.callee.cseq = g.callee.cseq.max(1).saturating_add(1);
            }
            v
        };
        let mut ok = !reqs.is_empty();
        for r in reqs {
            ok &= tm.t_uac(r, None).is_ok();
        }
        ok
    }

    /// `dlg_refer`: REFER one side of a confirmed dialog to `target`.
    fn refer(&self, d: &DlgRef, to_callee: bool, target: &str) -> bool {
        let Some(tm) = self.tm.get() else { return false };
        let ctrl = lock(&self.bridge_controller).clone();
        let req = {
            let mut g = lock(d);
            if !matches!(g.state, State::Confirmed | State::ConfirmedAck) {
                return false;
            }
            let Some(mut r) = self.uac_for(&g, to_callee, "REFER") else { return false };
            // Sent as the other party: its contact gets the NOTIFYs.
            let other = if to_callee { &g.caller.contact } else { &g.callee.contact };
            if !other.is_empty() {
                r.headers.push_str(&format!("Contact: {}\r\n", angle(other)));
            }
            r.headers.push_str(&format!("Referred-By: {}\r\nRefer-To: {}\r\n", angle(&ctrl), angle(target)));
            if to_callee {
                g.caller.cseq = g.caller.cseq.saturating_add(1);
            } else {
                g.callee.cseq = g.callee.cseq.max(1).saturating_add(1);
            }
            r
        };
        match tm.t_uac(req, None) {
            Ok(()) => true,
            Err(e) => {
                sip_core::elog!("dlg_refer: {e}");
                false
            }
        }
    }

    /// `dlg_bridge(from, to, op)`: call `from` (on hold), and once it
    /// answers, ACK, REFER it to `to`, then BYE our call leg.
    fn bridge(&self, from: &str, to: &str, op: &str, body: Option<&str>) -> Result<(), String> {
        let tm = self.tm.get().ok_or("tm not loaded")?.clone();
        let net = self.net.get().ok_or("not started")?;
        let op = match op.trim() {
            "" => None,
            o => Some(sip_core::pvcore::dest_from_uri(o.as_bytes()).ok_or_else(|| format!("bad outbound proxy {o:?}"))?),
        };
        let from = from.trim().trim_start_matches('<').trim_end_matches('>').to_string();
        let to = to.trim().to_string();
        let ctrl = lock(&self.bridge_controller).clone();
        let contact = match lock(&self.bridge_contact).clone() {
            Some(c) => c,
            None => {
                let proto = op.map_or(sip_core::Proto::Udp, |d| d.proto);
                let adv = net.advertise(proto).ok_or("no listening address")?;
                format!("sip:controller@{adv}")
            }
        };
        let req = UacRequest {
            method: "INVITE".into(),
            ruri: from.clone(),
            dst: op,
            from: Some(ctrl.trim_start_matches('<').trim_end_matches('>').to_string()),
            to: Some(from.clone()),
            cseq: 1,
            headers: format!("Contact: {}\r\nContent-Type: application/sdp\r\n", angle(&contact)),
            body: body.unwrap_or(HOLD_SDP).as_bytes().to_vec(),
            ..Default::default()
        };
        let tm2 = tm.clone();
        tm.t_uac(
            req,
            Some(Box::new(move |code, reply| {
                if !(200..300).contains(&code) {
                    sip_core::log::log(sip_core::log::L_INFO, &format!("dlg_bridge: {from} answered {code}"));
                    return;
                }
                let Some(ud) = UacDlg::from_2xx(reply, op) else {
                    sip_core::elog!("dlg_bridge: 2xx from {from} without Contact or To tag");
                    return;
                };
                if let Err(e) = tm2.send_stateless(ud.req("ACK", 1, "")) {
                    sip_core::elog!("dlg_bridge: ACK: {e}");
                }
                let hdrs = format!("Contact: {}\r\nReferred-By: {}\r\nRefer-To: {}\r\n", angle(&contact), angle(&ctrl), angle(&to));
                let tm3 = tm2.clone();
                let ud2 = ud.clone();
                // A REFER that can't be sent may still get its callback (a
                // local 477): our leg is hung up once either way.
                let hung_up = Arc::new(AtomicBool::new(false));
                let hung_up2 = hung_up.clone();
                let res = tm2.t_uac(
                    ud.req("REFER", 2, &hdrs),
                    Some(Box::new(move |code, _| {
                        if code >= 300 {
                            sip_core::elog!("dlg_bridge: REFER got {code}");
                        }
                        hung_up2.store(true, Ordering::Relaxed);
                        if let Err(e) = tm3.t_uac(ud2.req("BYE", 3, ""), None) {
                            sip_core::log::log(sip_core::log::L_ERR, &format!("dlg_bridge: BYE: {e}"));
                        }
                    })),
                );
                if let Err(e) = res {
                    sip_core::elog!("dlg_bridge: REFER: {e}");
                    if !hung_up.swap(true, Ordering::Relaxed)
                        && let Err(e) = tm2.t_uac(ud.req("BYE", 3, ""), None)
                    {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("dlg_bridge: BYE: {e}"));
                    }
                }
            })),
        )
    }

    fn keepalive(self: &Arc<Self>, d: &DlgRef) {
        let Some(tm) = self.tm.get() else { return };
        let reqs: Vec<UacRequest> = {
            let mut g = lock(d);
            let mut v = Vec::new();
            if g.ka_dst {
                v.extend(self.uac_for(&g, true, "OPTIONS"));
                g.caller.cseq = g.caller.cseq.saturating_add(1);
            }
            if g.ka_src {
                v.extend(self.uac_for(&g, false, "OPTIONS"));
                g.callee.cseq = g.callee.cseq.max(1).saturating_add(1);
            }
            v
        };
        for r in reqs {
            let me = self.clone();
            let dd = d.clone();
            let res = tm.t_uac(
                r,
                Some(Box::new(move |code, _| {
                    if code == 408 || code == 481 {
                        sip_core::log::log(sip_core::log::L_INFO, &format!("dialog: keep-alive got {code}, ending the call"));
                        me.end(&dd, None, true, "keepalive");
                    }
                })),
            );
            if let Err(e) = res {
                sip_core::log::log(sip_core::log::L_ERR, &format!("dialog: keep-alive OPTIONS: {e}"));
            }
        }
    }

    fn tick(self: &Arc<Self>) {
        let t = unix_secs();
        let early = self.early_timeout.load(Ordering::Relaxed);
        let ka = self.ka_interval.load(Ordering::Relaxed);
        let send_bye = self.send_bye.load(Ordering::Relaxed);
        for d in self.all() {
            let (state, timed_out, stale, bye, ka_due) = {
                let mut g = lock(&d);
                let due = ka > 0 && (g.ka_src || g.ka_dst) && g.state >= State::Confirmed && t >= g.next_ka;
                if due {
                    g.next_ka = t.saturating_add(ka);
                }
                (
                    g.state,
                    g.state >= State::Confirmed && g.timeout_at <= t,
                    g.state < State::Confirmed && g.init_ts.saturating_add(early) <= t,
                    send_bye || g.timeout_bye,
                    due,
                )
            };
            if state == State::Deleted {
                continue;
            }
            if timed_out {
                sip_core::stats::inc(stat("expired_dialogs"));
                let route = lock(&d).timeout_route.clone();
                if let (Some(r), Some(hub), Some(net)) = (route, self.hub.get(), self.net.get()) {
                    let dd = d.clone();
                    hub.run_route_with(&r, &**net, None, move |c| c.ext.push(Box::new(Current(dd))));
                }
                self.end(&d, None, bye, "timeout");
            } else if stale {
                self.fail(&d, None);
            } else if ka_due {
                self.keepalive(&d);
            }
        }
        let period = self.db_update_period.load(Ordering::Relaxed).max(1);
        if self.db_mode.load(Ordering::Relaxed) == 2 && self.db_flushed.load(Ordering::Relaxed).saturating_add(period) <= t {
            self.db_flushed.store(t, Ordering::Relaxed);
            self.db_flush();
        }
    }

    // ---------------------------------------------------------------- db --

    /// The dialog changed: written now (db_mode 1), at the next flush
    /// (2) or at shutdown (3).
    fn db_write(&self, d: &DlgRef) {
        if self.db.get().is_none() {
            return;
        }
        match self.db_mode.load(Ordering::Relaxed) {
            1 => self.db_store(d),
            2 => {
                let id = lock(d).h_id;
                lock(&self.db_dirty).insert(id, d.clone());
            }
            _ => {}
        }
    }

    /// Write db_mode 2's pending changes.
    fn db_flush(&self) {
        let Some(db) = self.db.get() else { return };
        let gone: Vec<u32> = lock(&self.db_gone).drain().collect();
        for id in gone {
            if let Err(e) = db.delete("dialog", &[("hash_id", sip_db::DbVal::Int(i64::from(id)))]) {
                sip_core::log::log(sip_core::log::L_ERR, &format!("dialog: db delete of dialog {id}: {e}"));
            }
        }
        let dirty: Vec<DlgRef> = lock(&self.db_dirty).drain().map(|(_, d)| d).collect();
        for d in dirty {
            if lock(&d).state != State::Deleted {
                self.db_store(&d);
            }
        }
    }

    fn db_store(&self, d: &DlgRef) {
        let Some(db) = self.db.get() else { return };
        use sip_db::DbVal::{Int, Str};
        let g = lock(d);
        if g.state < State::Confirmed {
            return;
        }
        let src = |l: &Leg| l.src.map(|s| sip_core::pvcore::dest_to_uri(&s)).unwrap_or_default();
        let xdata = json!({"from_hdr": g.from_hdr, "to_hdr": g.to_hdr, "vars": g.vars,
            "profiles": g.profiles.iter().map(|(p, v)| json!([p, v])).collect::<Vec<_>>(), "timeout_bye": g.timeout_bye,
            "sflags": g.sflags, "timeout_noreset": g.timeout_noreset, "timeout_route": g.timeout_route});
        let res = db.delete("dialog", &[("hash_id", Int(i64::from(g.h_id)))]).and_then(|_| {
            db.insert(
                "dialog",
                &[
                    "hash_entry",
                    "hash_id",
                    "callid",
                    "from_uri",
                    "from_tag",
                    "to_uri",
                    "to_tag",
                    "caller_cseq",
                    "callee_cseq",
                    "caller_route_set",
                    "callee_route_set",
                    "caller_contact",
                    "callee_contact",
                    "caller_sock",
                    "callee_sock",
                    "state",
                    "start_time",
                    "timeout",
                    "xdata",
                ],
                &[
                    Int(i64::from(g.h_entry)),
                    Int(i64::from(g.h_id)),
                    Str(g.callid.clone()),
                    Str(g.from_uri.clone()),
                    Str(g.caller.tag.clone()),
                    Str(g.to_uri.clone()),
                    Str(g.callee.tag.clone()),
                    Int(i64::from(g.caller.cseq)),
                    Int(i64::from(g.callee.cseq)),
                    Str(g.caller.route.join(",")),
                    Str(g.callee.route.join(",")),
                    Str(g.caller.contact.clone()),
                    Str(g.callee.contact.clone()),
                    Str(src(&g.caller)),
                    Str(src(&g.callee)),
                    Int(g.state as i64),
                    Int(int_of(g.start_ts)),
                    Int(int_of(g.timeout_at)),
                    Str(xdata.to_string()),
                ],
            )
        });
        if let Err(e) = res {
            sip_core::log::log(sip_core::log::L_ERR, &format!("dialog: db write: {e}"));
        }
    }

    fn db_delete(&self, d: &DlgRef) {
        let Some(db) = self.db.get() else { return };
        let id = lock(d).h_id;
        match self.db_mode.load(Ordering::Relaxed) {
            1 => drop(db.delete("dialog", &[("hash_id", sip_db::DbVal::Int(i64::from(id)))])),
            2 => {
                lock(&self.db_dirty).remove(&id);
                lock(&self.db_gone).insert(id);
            }
            _ => {}
        }
    }

    fn db_load(&self) -> Result<usize, String> {
        let Some(db) = self.db.get() else { return Ok(0) };
        let rows = db.query(
            "dialog",
            &[
                "hash_entry",
                "hash_id",
                "callid",
                "from_uri",
                "from_tag",
                "to_uri",
                "to_tag",
                "caller_cseq",
                "callee_cseq",
                "caller_route_set",
                "callee_route_set",
                "caller_contact",
                "callee_contact",
                "caller_sock",
                "callee_sock",
                "state",
                "start_time",
                "timeout",
                "xdata",
            ],
            &[],
        )?;
        let t = unix_secs();
        let mut n = 0usize;
        for r in rows.rows {
            let int = |i: usize| r.get(i).and_then(sip_db::DbVal::int).unwrap_or(0);
            let txt = |i: usize| r.get(i).map(sip_db::DbVal::text).unwrap_or_default();
            // Rows with a past (or negative) timeout, or ids / CSeqs out of
            // range, are stale or corrupt: skip them.
            let Some(timeout_at) = u64::try_from(int(17)).ok().filter(|&e| e > t) else { continue };
            let uint = |i: usize| u32::try_from(int(i)).ok();
            let (Some(h_entry), Some(id), Some(caller_cseq), Some(callee_cseq)) = (uint(0), uint(1), uint(7), uint(8)) else { continue };
            let start_ts = u64::try_from(int(16)).unwrap_or(0);
            let x: Value = sip_core::serde_json::from_str(&txt(18)).unwrap_or(Value::Null);
            let routes =
                |s: String| if s.is_empty() { vec![] } else { split_list(s.as_bytes()).iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect() };
            let src = |s: String| sip_core::pvcore::dest_from_uri(s.as_bytes());
            let d = Dlg {
                h_entry,
                h_id: id,
                callid: txt(2),
                from_uri: txt(3),
                to_uri: txt(5),
                from_hdr: x.get("from_hdr").and_then(Value::as_str).unwrap_or_default().to_string(),
                to_hdr: x.get("to_hdr").and_then(Value::as_str).unwrap_or_default().to_string(),
                state: if int(15) == 4 { State::ConfirmedAck } else { State::Confirmed },
                init_ts: start_ts,
                start_ts,
                lifetime: timeout_at.saturating_sub(start_ts),
                timeout_at,
                caller: Leg { tag: txt(4), contact: txt(11), cseq: caller_cseq, src: src(txt(13)), route: routes(txt(9)) },
                callee: Leg { tag: txt(6), contact: txt(12), cseq: callee_cseq, src: src(txt(14)), route: routes(txt(10)) },
                reply_src: HashMap::new(),
                vars: x
                    .get("vars")
                    .and_then(Value::as_object)
                    .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
                    .unwrap_or_default(),
                end_reason: "",
                end_ts: 0,
                profiles: x
                    .get("profiles")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1).and_then(Value::as_str).map(String::from)))).collect())
                    .unwrap_or_default(),
                timeout_bye: x.get("timeout_bye").and_then(Value::as_bool).unwrap_or(false),
                ka_src: false,
                ka_dst: false,
                next_ka: 0,
                req_uri: String::new(),
                flags: 0,
                sflags: x.get("sflags").and_then(Value::as_u64).and_then(|f| u32::try_from(f).ok()).unwrap_or(0),
                timeout_noreset: x.get("timeout_noreset").and_then(Value::as_bool).unwrap_or(false),
                timeout_route: x.get("timeout_route").and_then(Value::as_str).map(String::from),
            };
            let key: Key = (d.callid.as_str().into(), d.caller.tag.as_str().into());
            self.dlgs.insert(key.clone(), Arc::new(Mutex::new(d)));
            self.by_hid.insert(id, key);
            self.count.fetch_add(1, Ordering::Relaxed);
            self.next_id.fetch_max(id.saturating_add(1), Ordering::Relaxed);
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    // ---------------------------------------------------------- profiles --

    fn profile_size(&self, p: &str, v: Option<&str>) -> usize {
        self.all()
            .iter()
            .filter(|d| {
                let g = lock(d);
                g.state != State::Deleted && g.profiles.iter().any(|(n, val)| n == p && v.is_none_or(|v| val.as_deref() == Some(v)))
            })
            .count()
    }

    /// The dialogs of profile `p` (with value `v`) in state early or later
    /// get `secs` as their timeout.
    fn set_timeout_by_profile(&self, p: &str, v: Option<&str>, secs: u64) -> usize {
        let mut n = 0usize;
        for d in self.all() {
            let hit = {
                let g = lock(&d);
                g.state >= State::Early
                    && g.state != State::Deleted
                    && g.profiles.iter().any(|(name, x)| name == p && v.is_none_or(|v| x.as_deref() == Some(v)))
            };
            if hit {
                Dialog::set_lifetime(&d, secs);
                self.db_write(&d);
                n = n.saturating_add(1);
            }
        }
        n
    }

    /// RPC `dlg.set_state` (Kamailio dialog.c rpc_dlg_set_state()): force
    /// the state of a dialog. Meant for 4 (confirmed) → 5 (deleted), which
    /// drops the dialog quietly: no BYE, no `dialog:end`, no CDR, as in
    /// Kamailio, where only the cleanup timer frees it.
    fn force_state(&self, d: &DlgRef, state: State) -> State {
        let old = {
            let mut g = lock(d);
            let old = g.state;
            g.state = state;
            if state == State::Deleted {
                g.end_reason = "admin";
                // Kamailio sets both to now for a confirmed dialog.
                if old == State::ConfirmedAck {
                    g.init_ts = unix_secs();
                }
                g.end_ts = unix_secs();
            } else if state >= State::Confirmed && g.timeout_at == 0 {
                // Never confirmed before: its lifetime starts now (else
                // the timer would end it at once).
                g.start_ts = unix_secs();
                g.timeout_at = unix_secs().saturating_add(g.lifetime);
            }
            old
        };
        if state == State::Deleted {
            self.remove(d);
            self.db_delete(d);
        } else {
            self.db_write(d);
        }
        sip_core::log::log(
            sip_core::log::L_NOTICE,
            &format!("dialog callid '{}' - state change forced - old: {} - new: {}", lock(d).callid, old as u8, state as u8),
        );
        old
    }

    /// RPC `dlg.briefing [fmt]` (Kamailio dialog.c rpc_dlg_briefing()): per
    /// dialog h_entry, h_id and the fields `fmt` names (default "ftcFT"):
    /// f from_uri, t to_uri, c call-id, F from_tag, T to_tag, I init_ts,
    /// S start_ts, E end_ts, s state.
    fn briefing(&self, fmt: &str) -> Value {
        let mut out = Vec::new();
        for d in self.all() {
            let g = lock(&d);
            let mut o = sip_core::serde_json::Map::new();
            o.insert("h_entry".into(), json!(g.h_entry));
            o.insert("h_id".into(), json!(g.h_id));
            for c in fmt.chars() {
                let (k, v) = match c {
                    'f' => ("from_uri", json!(g.from_uri)),
                    't' => ("to_uri", json!(g.to_uri)),
                    'c' => ("call-id", json!(g.callid)),
                    'F' => ("from_tag", json!(g.caller.tag)),
                    'T' => ("to_tag", json!(g.callee.tag)),
                    'I' => ("init_ts", json!(g.init_ts)),
                    'S' => ("start_ts", json!(g.start_ts)),
                    'E' => ("end_ts", json!(g.end_ts)),
                    's' => ("state", json!(g.state as u8)),
                    _ => continue,
                };
                o.insert(k.into(), v);
            }
            out.push(Value::Object(o));
        }
        Value::Array(out)
    }

    fn check_profile(&self, p: &str, has_value: bool) -> Result<(), String> {
        let with = lock(&self.profiles_val).contains(p);
        let without = lock(&self.profiles_noval).contains(p);
        match (with, without) {
            (false, false) => Err(format!("dialog: no profile {p:?} (profiles_with_value / profiles_no_value)")),
            (true, _) if !has_value => Err(format!("dialog: profile {p:?} needs a value")),
            (false, true) if has_value => Err(format!("dialog: profile {p:?} takes no value")),
            _ => Ok(()),
        }
    }

    fn json(d: &DlgRef) -> Value {
        Self::json_with(d, false)
    }

    /// `dlg.list` entry; `ctx` adds the settings (`dlg.list_ctx`).
    fn json_with(d: &DlgRef, ctx: bool) -> Value {
        let g = lock(d);
        let mut v = json!({"h_entry": g.h_entry, "h_id": g.h_id, "call-id": g.callid, "from_uri": g.from_uri, "from_tag": g.caller.tag,
            "to_uri": g.to_uri, "to_tag": g.callee.tag, "state": g.state as u8, "start_ts": g.start_ts, "timeout": g.timeout_at,
            "caller_contact": g.caller.contact, "callee_contact": g.callee.contact,
            "variables": g.vars, "profiles": g.profiles.iter().map(|(p, v)| json!({p.clone(): v})).collect::<Vec<_>>()});
        if ctx && let Some(o) = v.as_object_mut() {
            o.insert(
                "context".into(),
                json!({"sflags": g.sflags, "lifetime": g.lifetime, "timeout_bye": g.timeout_bye, "ka_src": g.ka_src,
                "ka_dst": g.ka_dst, "timeout_noreset": g.timeout_noreset, "timeout_route": g.timeout_route}),
            );
        }
        v
    }

    /// Dialogs with this Call-ID (and From tag).
    fn by_callid(&self, callid: &str, ftag: Option<&str>) -> Vec<DlgRef> {
        self.all()
            .into_iter()
            .filter(|d| {
                let g = lock(d);
                g.callid == callid && ftag.is_none_or(|t| g.caller.tag == t)
            })
            .collect()
    }

    /// `dlg_get(callid, ftag, ttag)`: the dialog with these ids, in either
    /// direction.
    fn get(&self, callid: &str, ftag: &str, ttag: &str) -> Option<DlgRef> {
        let ok = |d: &DlgRef, f: &str, t: &str| {
            let g = lock(d);
            g.caller.tag == f && g.callee.tag == t && g.state != State::Deleted
        };
        if let Some(d) = self.dlgs.get_cloned(&(callid.into(), ftag.into()))
            && ok(&d, ftag, ttag)
        {
            return Some(d);
        }
        self.dlgs.get_cloned(&(callid.into(), ttag.into())).filter(|d| ok(d, ttag, ftag))
    }

    /// Lifetime of an existing dialog (`dlg_set_timeout`, `$dlg_ctx(timeout)`):
    /// restarted now when confirmed, and later in-dialog requests restart
    /// it with this lifetime (Kamailio's update_dlg_timeout()).
    fn set_lifetime(d: &DlgRef, secs: u64) {
        let mut g = lock(d);
        g.lifetime = secs.max(1);
        if g.state >= State::Confirmed {
            g.timeout_at = unix_secs().saturating_add(g.lifetime);
        }
    }
}

/// A unix time or duration as a script / DB integer (saturating).
fn int_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn strip_tag(h: &str) -> String {
    match h.split_once(";tag=") {
        Some((head, tag)) => match tag.split_once(';') {
            Some((_, params)) => format!("{head};{params}"),
            None => head.to_string(),
        },
        None => h.to_string(),
    }
}

/// The module instance, for finding the dialog of a request rebuilt by tm
/// (failure route, the code after `await`), which `dlg_manage` never saw.
static INSTANCE: OnceLock<std::sync::Weak<Dialog>> = OnceLock::new();

fn current(ctx: &mut Ctx<'_, '_>) -> Option<DlgRef> {
    if let Some(c) = ctx.ext::<Current>() {
        return Some(c.0.clone());
    }
    // Kamailio finds the dialog through the transaction there; the initial
    // INVITE's Call-ID and From tag name it just as well.
    ctx.ext::<sip_core::module::FakedMsg>()?;
    if ctx.msg.method() != Some(Method::Invite) {
        return None;
    }
    let me = INSTANCE.get()?.upgrade()?;
    let i = info(ctx.msg)?;
    let d = me.dlgs.get_cloned(&(i.callid.as_str().into(), i.ftag.as_str().into()))?;
    ctx.ext.push(Box::new(Current(d.clone())));
    Some(d)
}

type ProfileArgs = (String, Option<DynStr>);

impl Module for Dialog {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            pr("default_timeout", Ty::Duration(Unit::Sec), "12h", "Confirmed dialogs end after this"),
            pr("early_timeout", Ty::Duration(Unit::Sec), "5m", "Unconfirmed dialogs are dropped after this"),
            pr("send_bye", Ty::Bool, "false", "On timeout, send BYE to both sides"),
            pr("ka_interval", Ty::Duration(Unit::Sec), "0s", "In-dialog OPTIONS keep-alive interval (0: off)"),
            p("profiles_with_value", Ty::Str, "", "Dialog profiles with a value, ';'-separated"),
            p("profiles_no_value", Ty::Str, "", "Dialog profiles without a value, ';'-separated"),
            p("db_url", Ty::Str, "", "Database for db_mode"),
            p(
                "db_mode",
                Ty::Enum(&[("off", "0"), ("realtime", "1"), ("delayed", "2"), ("shutdown", "3")]),
                "off",
                "Store dialogs in the database (survive restarts): on every change, every db_update_period, or at shutdown",
            ),
            p("db_update_period", Ty::Duration(Unit::Sec), "60s", "How often db_mode delayed writes the changes"),
            p("dlg_flag", Ty::Int { min: -1, max: 63 }, "-1", "Message flag that makes t_relay create the dialog of an INVITE (-1: none)"),
            p(
                "dlg_match_mode",
                Ty::Int { min: 0, max: 2 },
                "1",
                "In-dialog matching: 0 by the Record-Route cookie, 1 cookie then Call-ID and tags, 2 Call-ID and tags (no cookie)",
            ),
            p("rr_param", Ty::Str, "did", "Name of the Record-Route cookie parameter"),
            p("timeout_noreset", Ty::Bool, "false", "In-dialog requests don't restart any dialog's timeout (the timeout-noreset property for all)"),
            p("bridge_controller", Ty::Str, "sip:controller@ferrosip.invalid", "From of dlg_bridge's INVITE, Referred-By of REFERs"),
            p("bridge_contact", Ty::Str, "", "Contact of dlg_bridge's call leg (default: sip:controller@ our address)"),
        ])
    }

    fn name(&self) -> &'static str {
        "dialog"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let set = |m: &Mutex<HashSet<String>>| -> Result<(), String> {
            lock(m).extend(v.str()?.split(';').map(str::trim).filter(|s| !s.is_empty()).map(String::from));
            Ok(())
        };
        match name {
            "default_timeout" => self.default_timeout.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "early_timeout" => self.early_timeout.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "send_bye" => self.send_bye.store(v.int()? != 0, Ordering::Relaxed),
            "ka_interval" => self.ka_interval.store(v.int()?.max(0).unsigned_abs(), Ordering::Relaxed),
            "profiles_with_value" => set(&self.profiles_val)?,
            "profiles_no_value" => set(&self.profiles_noval)?,
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "db_mode" => self.db_mode.store(u32::try_from(v.int()?.clamp(0, 3)).unwrap_or(0), Ordering::Relaxed),
            "db_update_period" => self.db_update_period.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "dlg_flag" => {
                let f = v.int()?;
                match i32::try_from(f) {
                    Ok(f @ -1..64) => self.dlg_flag.store(f, Ordering::Relaxed),
                    _ => return Err(format!("dialog: dlg_flag {f} is not a flag (0..63)")),
                }
            }
            "dlg_match_mode" => {
                let m = v.int()?;
                match u32::try_from(m) {
                    Ok(m @ 0..=2) => self.match_mode.store(m, Ordering::Relaxed),
                    _ => return Err(format!("dialog: dlg_match_mode {m} is not 0, 1 or 2")),
                }
            }
            "rr_param" => {
                let p = v.str()?.trim();
                if p.is_empty() || p.contains([';', '=', ' ']) {
                    return Err(format!("dialog: bad rr_param {p:?}"));
                }
                *lock(&self.rr_param) = p.to_string();
            }
            "bridge_controller" => *lock(&self.bridge_controller) = v.str()?.to_string(),
            "bridge_contact" => *lock(&self.bridge_contact) = Some(v.str()?.to_string()).filter(|c| !c.is_empty()),
            "timeout_noreset" => self.timeout_noreset.store(v.int()? != 0, Ordering::Relaxed),
            "ka_timer" | "hash_size" | "timeout_avp" | "track_cseq_updates" | "enable_stats" => {}
            _ => return Err(format!("dialog: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, opt, sig};
        const TIMEOUT: &[Param] = &[arg("timeout", Duration(Unit::Sec))];
        const TIMEOUT_OF: &[Param] = &[arg("timeout", Duration(Unit::Sec)), arg("h_entry", Int), arg("h_id", Int)];
        const SIDE: &[Param] = &[arg("side", Enum(&["all", "caller", "callee"])).lit()];
        const PROP: &[Param] = &[arg("property", Enum(&["timeout-bye", "ka-src", "ka-dst", "timeout-noreset"])).lit()];
        const PROF: &[Param] = &[arg("profile", Str).lit().eg("\"calls\"")];
        const PROF_VAL: &[Param] = &[arg("profile", Str).lit().eg("\"caller\""), arg("value", Str)];
        const IN_PROF: &[Param] = &[arg("profile", Str).lit(), opt("value", Str)];
        const SIZE: &[Param] = &[arg("profile", Str).lit(), arg("out", Var)];
        const SIZE_VAL: &[Param] = &[arg("profile", Str).lit(), arg("value", Str), arg("out", Var)];
        const FLAG: &[Param] = &[arg("flag", Int).eg("3")];
        const PROF_TIMEOUT: &[Param] = &[arg("profile", Str).lit().eg("\"calls\""), arg("timeout", Duration(Unit::Sec))];
        const PROF_VAL_TIMEOUT: &[Param] = &[arg("profile", Str).lit().eg("\"caller\""), arg("value", Str), arg("timeout", Duration(Unit::Sec))];
        const GET: &[Param] = &[arg("call_id", Str), arg("from_tag", Str), arg("to_tag", Str)];
        const REFER: &[Param] = &[arg("side", Enum(&["caller", "callee"])).lit(), arg("to", Uri).eg("\"sip:bob@example.com\"")];
        const BRIDGE: &[Param] =
            &[arg("from", Uri).eg("\"sip:alice@example.com\""), arg("to", Uri).eg("\"sip:bob@example.com\""), arg("proxy", Str).eg("\"\""), opt("sdp", Str)];
        let rr = ctx::ROUTE | ctx::REPLY;
        Some(vec![
            sig("dlg_manage", "manage", &[], Ret::Bool, "Track this INVITE's dialog (and match in-dialog requests to it)").allowed(ctx::REQUEST),
            sig("is_known_dlg", "is_known", &[], Ret::Bool, "The message belongs to a tracked dialog").allowed(rr),
            sig("dlg_set_timeout", "set_timeout", TIMEOUT, Ret::Bool, "End the current dialog after this long once confirmed (false without a dialog)"),
            sig("dlg_set_timeout", "set_timeout_of", TIMEOUT_OF, Ret::Bool, "Set the timeout of the dialog with this h_entry and h_id"),
            sig("dlg_bye", "bye", SIDE, Ret::Bool, "Send BYE to the caller, the callee or both, ending a confirmed dialog")
                .allowed(ctx::ROUTE | ctx::REPLY | ctx::EVENT),
            sig("dlg_set_property", "set_property", PROP, Ret::Bool, "Turn a dialog property on (timeout-bye, ka-src, ka-dst, timeout-noreset)"),
            sig("dlg_reset_property", "reset_property", PROP, Ret::Bool, "Turn a dialog property off"),
            sig("set_dlg_profile", "set_profile", PROF, Ret::Bool, "Add the dialog to a profile without values").allowed(rr),
            sig("set_dlg_profile", "set_profile_value", PROF_VAL, Ret::Bool, "Add the dialog to a profile with values, under this value").allowed(rr),
            sig("unset_dlg_profile", "unset_profile", PROF, Ret::Bool, "Remove the dialog from a profile without values").allowed(rr),
            sig("unset_dlg_profile", "unset_profile_value", PROF_VAL, Ret::Bool, "Remove the dialog from a profile with values, for this value").allowed(rr),
            sig("is_in_profile", "in_profile", IN_PROF, Ret::Bool, "The dialog is in this profile (with this value, if given)").allowed(rr),
            sig("get_profile_size", "profile_size", SIZE, Ret::Bool, "Store the number of dialogs in a profile into `out`").allowed(ctx::ANY),
            sig("get_profile_size", "profile_value_size", SIZE_VAL, Ret::Bool, "Store the number of dialogs in a profile with this value into `out`")
                .allowed(ctx::ANY),
            sig(
                "dlg_set_timeout_by_profile",
                "set_timeout_by_profile",
                PROF_TIMEOUT,
                Ret::Bool,
                "Set the timeout of every dialog (early or later) in a profile",
            )
            .allowed(ctx::ANY),
            sig(
                "dlg_set_timeout_by_profile",
                "set_timeout_by_profile_value",
                PROF_VAL_TIMEOUT,
                Ret::Bool,
                "Set the timeout of every dialog (early or later) in a profile with values, under this value",
            )
            .allowed(ctx::ANY),
            sig("dlg_setflag", "set_flag", FLAG, Ret::Bool, "Set a dialog flag (0..31), on the dialog or for the one this request will create"),
            sig("dlg_resetflag", "reset_flag", FLAG, Ret::Bool, "Clear a dialog flag (0..31)"),
            sig("dlg_isflagset", "is_flag_set", FLAG, Ret::Bool, "The dialog flag (0..31) is set"),
            sig("dlg_get", "get", GET, Ret::Bool, "Make the dialog with this Call-ID, From tag and To tag the current one (false: none)").allowed(ctx::ANY),
            sig("dlg_refer", "refer", REFER, Ret::Bool, "Send REFER to one side of the confirmed dialog, transferring it to `to`").allowed(ctx::ANY),
            sig("dlg_bridge", "bridge", BRIDGE, Ret::Bool, "Call `from` (via `proxy` unless empty) and, once it answers, REFER it to `to`").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = INSTANCE.set(Arc::downgrade(&self));
        let tm = reg.api::<Tm>().ok_or("dialog needs tm: put loadmodule \"tm\" before \"dialog\"")?;
        let me = self.clone();
        tm.on_reply_out(Arc::new(move |o| me.on_reply_out(o.reply)));
        let me = self.clone();
        tm.on_request_in(Arc::new(move |ctx| me.on_relay(ctx)));
        let me = self.clone();
        sip_core::module::add_ctx_send_hook(Arc::new(move |ctx| me.on_ctx_send(ctx)));
        let _ = self.tm.set(tm);
        let _ = self.hub.set(reg.hub.clone());
        reg.provide(self.clone());
        if self.db_mode.load(Ordering::Relaxed) > 0 {
            let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("dialog"));
            let _ = self.db.set(sip_db::connect(&url)?);
            let n = self.db_load()?;
            sip_core::log::log(sip_core::log::L_INFO, &format!("dialog: loaded {n} dialogs from the database"));
        }
        let me = self.clone();
        sip_core::stats::gauge("dialog", "active_dialogs", move || {
            let n = me.all().iter().filter(|d| lock(d).state >= State::Confirmed && lock(d).state != State::Deleted).count();
            i64::try_from(n).unwrap_or(i64::MAX)
        });
        let me = self.clone();
        sip_core::stats::gauge("dialog", "early_dialogs", move || {
            i64::try_from(me.all().iter().filter(|d| lock(d).state < State::Confirmed).count()).unwrap_or(i64::MAX)
        });

        let m = "dialog";
        let me = self.clone();
        reg.export(m, "dlg_manage", |a: &[Arg]| want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.create(ctx));
        reg.export(m, "is_known_dlg", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| if current(ctx).is_some() { 1 } else { -1 });
        reg.export(
            m,
            "dlg_set_timeout",
            |a: &[Arg]| {
                if a.is_empty() || a.len() == 2 || a.len() > 3 {
                    return Err("expected timeout[, h_entry, h_id]".into());
                }
                a.iter().map(Arg::dyn_int).collect::<Result<Vec<_>, _>>()
            },
            {
                let me = self.clone();
                move |ctx: &mut Ctx, a: &Vec<sip_core::module::DynInt>| {
                    // Kamailio's w_dlg_set_timeout(): a timeout > 0 for an
                    // existing dialog, else -1 ($dlg_ctx(timeout) is for
                    // the one this request will create).
                    let Some(secs) = a.first().and_then(|t| t.eval(ctx)).filter(|&s| s > 0) else { return -1 };
                    let secs = secs.unsigned_abs();
                    let d = match a.get(2) {
                        Some(id) => match id.eval(ctx).and_then(|id| u32::try_from(id).ok().and_then(|id| me.by_id(id))) {
                            Some(d) => d,
                            None => return -1,
                        },
                        None => match current(ctx) {
                            Some(d) => d,
                            None => return -1,
                        },
                    };
                    Dialog::set_lifetime(&d, secs);
                    1
                }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "dlg_bye",
            |a: &[Arg]| {
                let [who] = args(a)?;
                match who.str()? {
                    "all" => Ok((true, true)),
                    "caller" => Ok((true, false)),
                    "callee" => Ok((false, true)),
                    s => Err(format!("dlg_bye: {s:?} is not all|caller|callee")),
                }
            },
            move |ctx: &mut Ctx, &(caller, callee): &(bool, bool)| {
                let Some(d) = current(ctx) else { return -1 };
                // Not before it's confirmed, nor once it ended (dialog:end).
                if !matches!(lock(&d).state, State::Confirmed | State::ConfirmedAck) {
                    return -1;
                }
                let ok = me.send_bye(&d, caller, callee);
                if caller && callee {
                    me.end(&d, None, false, "admin");
                }
                if ok { 1 } else { -1 }
            },
        );
        for (fname, on) in [("dlg_set_property", true), ("dlg_reset_property", false)] {
            reg.export(
                m,
                fname,
                |a: &[Arg]| {
                    let [prop] = args(a)?;
                    match prop.str()? {
                        p @ ("timeout-bye" | "ka-src" | "ka-dst" | "timeout-noreset") => Ok(p.to_string()),
                        p => Err(format!("unknown dialog property {p:?}")),
                    }
                },
                move |ctx: &mut Ctx, p: &String| {
                    let Some(d) = current(ctx) else {
                        // For the dialog this request will create.
                        let c = ctx.ext_mut::<DlgCtx>();
                        *match p.as_str() {
                            "timeout-bye" => &mut c.timeout_bye,
                            "ka-src" => &mut c.ka_src,
                            "ka-dst" => &mut c.ka_dst,
                            _ => &mut c.noreset,
                        } = Some(on);
                        return 1;
                    };
                    let mut g = lock(&d);
                    match p.as_str() {
                        "timeout-bye" => g.timeout_bye = on,
                        "ka-src" => g.ka_src = on,
                        "ka-dst" => g.ka_dst = on,
                        _ => g.timeout_noreset = on,
                    }
                    1
                },
            );
        }
        // profiles
        let prof_fix = {
            let me = self.clone();
            move |a: &[Arg]| -> Result<ProfileArgs, String> {
                let (p, v) = match a {
                    [p] => (p, None),
                    [p, v] => (p, Some(v)),
                    _ => return Err("expected profile[, value]".into()),
                };
                let p = p.str()?.to_string();
                me.check_profile(&p, v.is_some())?;
                Ok((p, v.map(Arg::dyn_str).transpose()?))
            }
        };
        // Kamailio's dlg_set_timeout_by_profile(profile, [value,] timeout)
        // (dialog.c w_dlg_set_timeout_by_profile3(), dlg_profile.c
        // dlg_set_timeout_by_profile()): every early or later dialog of the
        // profile (with that value, for a profile with values) gets the
        // timeout, restarted now when confirmed (update_dlg_timeout()).
        let me = self.clone();
        reg.export(
            m,
            "dlg_set_timeout_by_profile",
            move |a: &[Arg]| -> Result<(String, Option<DynStr>, sip_core::module::DynInt), String> {
                let (p, v, t) = match a {
                    [p, t] => (p, None, t),
                    [p, v, t] => (p, Some(v), t),
                    _ => return Err("expected profile, [value,] timeout".into()),
                };
                let p = p.str()?.to_string();
                if !lock(&me.profiles_val).contains(&p) && !lock(&me.profiles_noval).contains(&p) {
                    return Err(format!("dialog: no profile {p:?} (profiles_with_value / profiles_no_value)"));
                }
                // A value only matters for a profile with values.
                let v = match v {
                    Some(v) if lock(&me.profiles_val).contains(&p) => Some(v.dyn_str()?),
                    _ => None,
                };
                Ok((p, v, t.dyn_int()?))
            },
            {
                let me = self.clone();
                move |ctx: &mut Ctx, (p, v, t): &(String, Option<DynStr>, sip_core::module::DynInt)| {
                    let v = match v {
                        Some(v) => match v.eval(ctx) {
                            x if x.is_empty() => return -1,
                            x => Some(x.into_owned()),
                        },
                        None => None,
                    };
                    let Some(secs) = t.eval(ctx) else { return -1 };
                    me.set_timeout_by_profile(p, v.as_deref(), secs.max(0).unsigned_abs());
                    1
                }
            },
        );
        reg.export(m, "set_dlg_profile", prof_fix.clone(), |ctx: &mut Ctx, (p, v): &ProfileArgs| {
            let Some(d) = current(ctx) else { return -1 };
            let v = v.as_ref().map(|v| v.eval(ctx).into_owned());
            let mut g = lock(&d);
            if !g.profiles.iter().any(|(n, x)| n == p && *x == v) {
                g.profiles.push((p.clone(), v));
            }
            1
        });
        reg.export(m, "unset_dlg_profile", prof_fix.clone(), |ctx: &mut Ctx, (p, v): &ProfileArgs| {
            let Some(d) = current(ctx) else { return -1 };
            let v = v.as_ref().map(|v| v.eval(ctx).into_owned());
            let mut g = lock(&d);
            let n = g.profiles.len();
            g.profiles.retain(|(name, x)| !(name == p && (v.is_none() || *x == v)));
            if g.profiles.len() < n { 1 } else { -1 }
        });
        reg.export(
            m,
            "is_in_profile",
            |a: &[Arg]| -> Result<ProfileArgs, String> {
                let (p, v) = match a {
                    [p] => (p, None),
                    [p, v] => (p, Some(v)),
                    _ => return Err("expected profile[, value]".into()),
                };
                Ok((p.str()?.to_string(), v.map(Arg::dyn_str).transpose()?))
            },
            |ctx: &mut Ctx, (p, v): &ProfileArgs| {
                let Some(d) = current(ctx) else { return -1 };
                let v = v.as_ref().map(|v| v.eval(ctx).into_owned());
                let g = lock(&d);
                if g.profiles.iter().any(|(n, x)| n == p && (v.is_none() || *x == v)) { 1 } else { -1 }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "get_profile_size",
            |a: &[Arg]| -> Result<(String, Option<DynStr>, sip_core::PvRef), String> {
                let (p, v, out) = match a {
                    [p, out] => (p.str()?, None, out),
                    [p, v, out] => (p.str()?, Some(v.dyn_str()?), out),
                    _ => return Err("expected profile[, value], $var".into()),
                };
                let out = match out {
                    Arg::Fmt(f) => f.single_pv().cloned().ok_or("expected a variable")?,
                    _ => return Err("expected a variable like $var(n)".into()),
                };
                Ok((p.to_string(), v, out))
            },
            move |ctx: &mut Ctx, (p, v, out): &(String, Option<DynStr>, sip_core::PvRef)| {
                let v = v.as_ref().map(|v| v.eval(ctx).into_owned());
                let n = me.profile_size(p, v.as_deref());
                if out.set(ctx, Val::Int(i64::try_from(n).unwrap_or(i64::MAX))).is_ok() { 1 } else { -1 }
            },
        );
        // dialog flags: on the dialog, and in the context for the one the
        // request will create
        let flag_fix = |a: &[Arg]| {
            let [f] = args(a)?;
            if let Ok(n) = f.int()
                && !(0..32).contains(&n)
            {
                return Err(format!("dialog flag {n} is not 0..31"));
            }
            f.dyn_int()
        };
        let flag = |ctx: &mut Ctx, f: &sip_core::module::DynInt| f.eval(ctx).filter(|n| (0..32).contains(n)).map(|n| 1u32 << n);
        reg.export(m, "dlg_setflag", flag_fix, move |ctx: &mut Ctx, f: &sip_core::module::DynInt| {
            let Some(bit) = flag(ctx, f) else { return -1 };
            ctx.ext_mut::<DlgCtx>().flags |= bit;
            if let Some(d) = current(ctx) {
                lock(&d).sflags |= bit;
            }
            1
        });
        reg.export(m, "dlg_resetflag", flag_fix, move |ctx: &mut Ctx, f: &sip_core::module::DynInt| {
            let Some(bit) = flag(ctx, f) else { return -1 };
            ctx.ext_mut::<DlgCtx>().flags &= !bit;
            if let Some(d) = current(ctx) {
                lock(&d).sflags &= !bit;
            }
            1
        });
        reg.export(m, "dlg_isflagset", flag_fix, move |ctx: &mut Ctx, f: &sip_core::module::DynInt| {
            let Some(bit) = flag(ctx, f) else { return -1 };
            let flags = match current(ctx) {
                Some(d) => lock(&d).sflags,
                None => ctx.ext::<DlgCtx>().map_or(0, |c| c.flags),
            };
            if flags & bit != 0 { 1 } else { -1 }
        });
        let me = self.clone();
        reg.export(
            m,
            "dlg_get",
            |a: &[Arg]| {
                want_args(a, 3)?;
                a.iter().map(Arg::dyn_str).collect::<Result<Vec<_>, _>>()
            },
            move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                let v: Vec<String> = a.iter().map(|x| x.eval(ctx).into_owned()).collect();
                let [callid, ftag, ttag] = v.as_slice() else { return -1 };
                let Some(d) = me.get(callid, ftag, ttag) else { return -1 };
                ctx.ext.retain(|e| !e.is::<Current>());
                ctx.ext.push(Box::new(Current(d)));
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "dlg_refer",
            |a: &[Arg]| {
                let [side, to] = args(a)?;
                let callee = match side.str()? {
                    "caller" => false,
                    "callee" => true,
                    s => return Err(format!("dlg_refer: {s:?} is not caller|callee")),
                };
                Ok((callee, to.dyn_str()?))
            },
            move |ctx: &mut Ctx, (callee, to): &(bool, DynStr)| {
                let to = to.eval(ctx).into_owned();
                let Some(d) = current(ctx) else { return -1 };
                if me.refer(&d, *callee, &to) { 1 } else { -1 }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "dlg_bridge",
            |a: &[Arg]| {
                if !(3..=4).contains(&a.len()) {
                    return Err("expected from, to, op[, sdp]".into());
                }
                a.iter().map(Arg::dyn_str).collect::<Result<Vec<_>, _>>()
            },
            move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                let v: Vec<String> = a.iter().map(|x| x.eval(ctx).into_owned()).collect();
                let [from, to, op, sdp @ ..] = v.as_slice() else { return -1 };
                match me.bridge(from, to, op, sdp.first().map(String::as_str).filter(|b| !b.is_empty())) {
                    Ok(()) => 1,
                    Err(e) => {
                        sip_core::elog!("dlg_bridge: {e}");
                        -1
                    }
                }
            },
        );
        // $dlg_var(name), $dlg(attr)
        let me = self.clone();
        reg.pv(
            "dlg_var",
            PvSpec::rw(
                |ctx, p| current(ctx).and_then(|d| lock(&d).vars.get(&p.name).cloned()).map_or(Val::Null, Val::Str),
                move |ctx, p, v| {
                    let Some(d) = current(ctx) else { return Err("no dialog for this message".into()) };
                    {
                        let mut g = lock(&d);
                        if v.is_null() {
                            g.vars.remove(&p.name);
                        } else {
                            g.vars.insert(p.name.clone(), v.as_str().into_owned());
                        }
                    }
                    me.db_write(&d);
                    Ok(())
                },
            )
            .with_param(),
        );
        reg.pv(
            "dlg",
            PvSpec::ro(|ctx, p| {
                let Some(d) = current(ctx) else { return Val::Null };
                let g = lock(&d);
                match p.name.as_str() {
                    "h_id" => Val::Int(i64::from(g.h_id)),
                    "h_entry" => Val::Int(i64::from(g.h_entry)),
                    "state" => Val::Int(g.state as i64),
                    "callid" => Val::str(&g.callid),
                    "from_uri" => Val::str(&g.from_uri),
                    "from_tag" => Val::str(&g.caller.tag),
                    "to_uri" => Val::str(&g.to_uri),
                    "to_tag" => Val::str(&g.callee.tag),
                    "start_ts" => Val::Int(int_of(g.start_ts)),
                    "timeout" => Val::Int(int_of(g.timeout_at)),
                    "lifetime" => Val::Int(int_of(g.lifetime)),
                    "sflags" => Val::Int(i64::from(g.sflags)),
                    "from_contact" => Val::str(&g.caller.contact),
                    "to_contact" => Val::str(&g.callee.contact),
                    "from_cseq" => Val::Int(i64::from(g.caller.cseq)),
                    "to_cseq" => Val::Int(i64::from(g.callee.cseq)),
                    "from_rs" => Val::str(g.caller.route.join(",")),
                    "to_rs" => Val::str(g.callee.route.join(",")),
                    "toroute_name" => g.timeout_route.as_deref().map_or(Val::Null, Val::str),
                    "end_reason" if !g.end_reason.is_empty() => Val::str(g.end_reason),
                    // Seconds since it was confirmed (until it ended).
                    "duration" if g.start_ts > 0 => {
                        let end = if g.end_ts > 0 { g.end_ts } else { unix_secs() };
                        Val::Int(int_of(end.saturating_sub(g.start_ts)))
                    }
                    _ => Val::Null,
                }
            })
            .with_param(),
        );
        // $dlg_ctx(attr): the dialog context
        reg.pv(
            "dlg_ctx",
            PvSpec::rw(
                |ctx, p| {
                    let cur = current(ctx);
                    let c = ctx.ext::<DlgCtx>();
                    match p.name.as_str() {
                        "on" => Val::Int(i64::from(c.is_some_and(|c| c.on))),
                        "flags" => Val::Int(i64::from(c.map_or(0, |c| c.flags))),
                        "timeout" => Val::Int(int_of(c.and_then(|c| c.timeout).unwrap_or(0))),
                        "timeout_bye" => Val::Int(i64::from(c.and_then(|c| c.timeout_bye).unwrap_or(false))),
                        "timeout_route" => c.and_then(|c| c.timeout_route.as_deref()).map_or(Val::Null, Val::str),
                        "set" => Val::Int(i64::from(cur.is_some())),
                        // 1: from the caller (downstream), 2: from the callee, 0: none.
                        "dir" => {
                            let Some(d) = cur else { return Val::Int(0) };
                            let caller_tag = lock(&d).caller.tag.clone();
                            match info(ctx.msg) {
                                Some(i) if ctx.msg.is_request() => Val::Int(if i.ftag == caller_tag { 1 } else { 2 }),
                                Some(i) => Val::Int(if i.ftag == caller_tag { 2 } else { 1 }),
                                None => Val::Int(0),
                            }
                        }
                        _ => Val::Null,
                    }
                },
                |ctx, p, v| {
                    let int = || v.as_str().trim().parse::<i64>().map_err(|_| format!("$dlg_ctx({}) needs a number", p.name));
                    let cur = current(ctx);
                    match p.name.as_str() {
                        "on" => ctx.ext_mut::<DlgCtx>().on = int()? != 0,
                        "flags" => {
                            // 32 flag bits: a negative value is their signed reading.
                            let f = int()?;
                            let bits = u32::try_from(f).or_else(|_| i32::try_from(f).map(i32::cast_unsigned));
                            ctx.ext_mut::<DlgCtx>().flags = bits.map_err(|_| format!("$dlg_ctx(flags): {f} is not 32 flag bits"))?;
                        }
                        "timeout" => {
                            let secs = int()?.max(1).unsigned_abs();
                            ctx.ext_mut::<DlgCtx>().timeout = Some(secs);
                            if let Some(d) = cur {
                                Dialog::set_lifetime(&d, secs);
                            }
                        }
                        "timeout_bye" => {
                            let on = int()? != 0;
                            ctx.ext_mut::<DlgCtx>().timeout_bye = Some(on);
                            if let Some(d) = cur {
                                lock(&d).timeout_bye = on;
                            }
                        }
                        "timeout_route" => {
                            let r = (!v.is_null()).then(|| v.as_str().into_owned()).filter(|r| !r.is_empty());
                            ctx.ext_mut::<DlgCtx>().timeout_route = r.clone();
                            if let Some(d) = cur {
                                lock(&d).timeout_route = r;
                            }
                        }
                        n => return Err(format!("$dlg_ctx({n}) is read-only or unknown")),
                    }
                    Ok(())
                },
            )
            .with_param(),
        );
        // RPC
        let me = self.clone();
        reg.rpc.add("dlg.list", "List dialogs", move |_| Ok(json!(me.all().iter().map(Dialog::json).collect::<Vec<_>>())));
        let me = self.clone();
        reg.rpc.add("dlg.list_ctx", "List dialogs with their settings", move |_| {
            Ok(json!(me.all().iter().map(|d| Dialog::json_with(d, true)).collect::<Vec<_>>()))
        });
        for (name, ctx) in [("dlg.dlg_list", false), ("dlg.dlg_list_ctx", true)] {
            let me = self.clone();
            reg.rpc.add(name, &format!("{name} <callid> [from_tag]"), move |p| {
                let cid = sip_core::rpc::str_param(p, 0)?;
                let ftag = sip_core::rpc::str_param(p, 1).ok();
                Ok(json!(me.by_callid(&cid, ftag.as_deref()).iter().map(|d| Dialog::json_with(d, ctx)).collect::<Vec<_>>()))
            });
        }
        let me = self.clone();
        reg.rpc.add("dlg.terminate_dlg", "dlg.terminate_dlg <callid> <from_tag> <to_tag>: BYE both sides", move |p| {
            let (cid, f, t) = (sip_core::rpc::str_param(p, 0)?, sip_core::rpc::str_param(p, 1)?, sip_core::rpc::str_param(p, 2)?);
            let d = me.get(&cid, &f, &t).ok_or("dialog not found")?;
            if lock(&d).state < State::Confirmed {
                return Err("dialog not confirmed".into());
            }
            me.end(&d, None, true, "admin");
            Ok(json!(0))
        });
        let me = self.clone();
        reg.rpc.add("dlg.is_alive", "dlg.is_alive <h_entry> <h_id>: ok if the dialog is confirmed", move |p| {
            let id = u32::try_from(sip_core::rpc::int_param(p, 1)?).map_err(|_| "dialog not found")?;
            let d = me.by_id(id).ok_or("dialog not found")?;
            if matches!(lock(&d).state, State::Confirmed | State::ConfirmedAck) { Ok(json!(0)) } else { Err("dialog not confirmed".into()) }
        });
        let me = self.clone();
        reg.rpc.add("dlg.bridge_dlg", "dlg.bridge_dlg <from> <to> [op]: call from, then REFER it to to", move |p| {
            let (from, to) = (sip_core::rpc::str_param(p, 0)?, sip_core::rpc::str_param(p, 1)?);
            let op = sip_core::rpc::str_param(p, 2).unwrap_or_default();
            let op = if op == "." { String::new() } else { op };
            me.bridge(&from, &to, &op, None)?;
            Ok(json!(0))
        });
        let me = self.clone();
        reg.rpc.add("dlg.stats_active", "Dialog counts by state", move |_| {
            let mut by = [0usize; 6];
            for d in me.all() {
                if let Some(n) = by.get_mut(lock(&d).state as usize) {
                    *n = n.saturating_add(1);
                }
            }
            let [_, starting, connecting, answering, ongoing, _] = by;
            let all = [starting, connecting, answering, ongoing].iter().fold(0usize, |a, n| a.saturating_add(*n));
            Ok(json!({"starting": starting, "connecting": connecting, "answering": answering, "ongoing": ongoing, "all": all}))
        });
        let me = self.clone();
        reg.rpc.add("dlg.end_dlg", "dlg.end_dlg <h_entry> <h_id>: BYE both sides", move |p| {
            let id = u32::try_from(sip_core::rpc::int_param(p, 1)?).map_err(|_| "dialog not found")?;
            let d = me.by_id(id).ok_or("dialog not found")?;
            if lock(&d).state < State::Confirmed {
                return Err("dialog not confirmed".into());
            }
            me.end(&d, None, true, "admin");
            Ok(json!(0))
        });
        let me = self.clone();
        reg.rpc.add("dlg.set_state", "dlg.set_state <callid> <from_tag> <to_tag> [state]: force the state (default 5, deleted)", move |p| {
            let (cid, f, t) = match (sip_core::rpc::str_param(p, 0), sip_core::rpc::str_param(p, 1), sip_core::rpc::str_param(p, 2)) {
                (Ok(c), Ok(f), Ok(t)) => (c, f, t),
                _ => return Err("Need the callid, from tag,to tag and state".into()),
            };
            let state = match p.get(3) {
                None => 5,
                Some(_) => sip_core::rpc::int_param(p, 3)?,
            };
            let state = match state {
                1 => State::Unconfirmed,
                2 => State::Early,
                3 => State::Confirmed,
                4 => State::ConfirmedAck,
                5 => State::Deleted,
                _ => return Err("Invalid state value".into()),
            };
            let d = me.get(&cid, &f, &t).ok_or("Dialog not found")?;
            me.force_state(&d, state);
            Ok(json!("Done"))
        });
        let me = self.clone();
        reg.rpc.add("dlg.briefing", "dlg.briefing [fmt]: h_entry, h_id and the fields of fmt (default ftcFT) of each dialog", move |p| {
            let fmt = sip_core::rpc::str_param(p, 0).unwrap_or_else(|_| "ftcFT".into());
            Ok(me.briefing(&fmt))
        });
        let me = self.clone();
        reg.rpc.add("dlg.profile_get_size", "dlg.profile_get_size <profile> [value]", move |p| {
            let prof = sip_core::rpc::str_param(p, 0)?;
            let v = sip_core::rpc::str_param(p, 1).ok();
            Ok(json!(me.profile_size(&prof, v.as_deref())))
        });
        let me = self.clone();
        reg.rpc.add("dlg.profile_list", "dlg.profile_list <profile> [value]", move |p| {
            let prof = sip_core::rpc::str_param(p, 0)?;
            let v = sip_core::rpc::str_param(p, 1).ok();
            Ok(json!(
                me.all()
                    .iter()
                    .filter(|d| lock(d).profiles.iter().any(|(n, x)| *n == prof && v.as_ref().is_none_or(|v| x.as_ref() == Some(v))))
                    .map(Dialog::json)
                    .collect::<Vec<_>>()
            ))
        });
        Ok(())
    }

    fn observes(&self) -> bool {
        true
    }

    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        self.on_request(ctx);
    }

    /// db_mode 2 writes what is pending; db_mode 3 replaces the table
    /// with the confirmed dialogs.
    fn shutdown(&self) {
        let Some(db) = self.db.get() else { return };
        match self.db_mode.load(Ordering::Relaxed) {
            2 => self.db_flush(),
            3 => {
                if let Err(e) = db.delete("dialog", &[]) {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("dialog: db clear before saving the dialogs: {e}"));
                }
                for d in self.all() {
                    self.db_store(&d);
                }
            }
            _ => {}
        }
    }

    /// Remember where 1xx/2xx with a To tag come from (the callee leg's
    /// next hop when it has no route set).
    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        if self.count.load(Ordering::Relaxed) == 0 || !ctx.msg.status().is_some_and(|c| (101..300).contains(&c)) {
            return;
        }
        let Some(i) = info(ctx.msg) else { return };
        if i.cseq_method != Method::Invite {
            return;
        }
        let (Some(t), Some(d)) = (i.ttag, self.dlgs.get_cloned(&(i.callid.as_str().into(), i.ftag.as_str().into()))) else { return };
        let mut g = lock(&d);
        if g.state < State::Confirmed && g.reply_src.len() < 16 {
            g.reply_src.insert(t, ctx.src);
        }
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        std::thread::Builder::new()
            .name("dialog-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    self.tick();
                }
            })
            .map_err(|e| format!("cannot start the dialog timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_info_and_tags() {
        let raw = b"INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: \"A\" <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\n\
Call-ID: c\r\nCSeq: 7 INVITE\r\nContact: <sip:a@1.2.3.4>\r\nRecord-Route: <sip:p1;lr>, <sip:p2;lr>\r\nContent-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let mut m = Msg::parse(raw, &arena).unwrap();
        let i = info(&mut m).unwrap();
        assert_eq!((i.callid.as_str(), i.ftag.as_str(), i.ttag, i.cseq), ("c", "1", None, 7));
        assert_eq!(i.contact.as_deref(), Some("sip:a@1.2.3.4"));
        assert_eq!(i.rr, vec!["<sip:p1;lr>", "<sip:p2;lr>"]);
        assert_eq!(strip_tag("<sip:b@x>;tag=9;x=1"), "<sip:b@x>;x=1");
    }

    #[test]
    fn did_cookie_is_reverse_hex() {
        // Kamailio's int2reverse_hex: least significant digit first.
        assert_eq!(rev_hex(0), "0");
        assert_eq!(rev_hex(0x1a3), "3a1");
        assert_eq!(did_value(0x1a3, 0x10), "3a1.01");
        assert_eq!(parse_did(b"3a1.01"), Some((0x1a3, 0x10)));
        for (e, i) in [(0, 1), (4095, 123456), (7, u32::MAX)] {
            assert_eq!(parse_did(did_value(e, i).as_bytes()), Some((e, i)));
        }
        assert_eq!(parse_did(b"zz.1"), None);
        assert_eq!(parse_did(b"12"), None);
    }

    #[test]
    fn match_by_did_cookie_and_by_ids() {
        let raw = b"INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\n\
Call-ID: c\r\nCSeq: 1 INVITE\r\nContact: <sip:a@1.2.3.4>\r\nContent-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let mut m = Msg::parse(raw, &arena).unwrap();
        let i = info(&mut m).unwrap();
        let dlg = Dialog::default();
        let d = Arc::new(Mutex::new(Dlg {
            h_entry: 5,
            h_id: 9,
            callid: "c".into(),
            from_hdr: String::new(),
            to_hdr: String::new(),
            from_uri: String::new(),
            to_uri: String::new(),
            state: State::ConfirmedAck,
            init_ts: 0,
            start_ts: 0,
            lifetime: 10,
            timeout_at: 0,
            caller: Leg { tag: "1".into(), ..Default::default() },
            callee: Leg { tag: "2".into(), ..Default::default() },
            reply_src: HashMap::new(),
            vars: HashMap::new(),
            end_reason: "",
            end_ts: 0,
            profiles: vec![],
            timeout_bye: false,
            ka_src: false,
            ka_dst: false,
            next_ka: 0,
            req_uri: String::new(),
            flags: 0,
            sflags: 0,
            timeout_noreset: false,
            timeout_route: None,
        }));
        dlg.dlgs.insert(("c".into(), "1".into()), d.clone());
        dlg.by_hid.insert(9, ("c".into(), "1".into()));
        let req = |route: &str, ftag: &str, ttag: &str| {
            format!(
                "BYE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK2\r\n{route}From: <sip:a@x>;tag={ftag}\r\nTo: <sip:b@x>;tag={ttag}\r\n\
Call-ID: c\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
            )
        };
        let found = |mode: u32, raw: &str| {
            dlg.match_mode.store(mode, Ordering::Relaxed);
            let arena = Bump::new();
            let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
            let i = info(&mut m).unwrap();
            let t = i.ttag.clone().unwrap();
            dlg.match_request(&m, &i, &t).is_some()
        };
        let cookie = req("Route: <sip:10.0.0.1;lr;did=5.9>\r\n", "1", "2");
        let wrong = req("Route: <sip:10.0.0.1;lr;did=5.8>\r\n", "1", "2");
        let none = req("", "2", "1");
        assert!(found(0, &cookie) && found(1, &cookie) && found(2, &cookie));
        assert!(!found(0, &wrong) && found(1, &wrong), "mode 1 falls back to the SIP ids");
        assert!(!found(0, &none) && found(1, &none) && found(2, &none));
        assert_eq!(i.ftag, "1");
    }

    /// A `dialog` table that returns fixed rows.
    struct Rows(Vec<Vec<sip_db::DbVal>>);
    impl sip_db::DbConn for Rows {
        fn query(&self, _: &str, cols: &[&str], _: sip_db::Filter<'_>) -> Result<sip_db::Rows, sip_db::DbError> {
            Ok(sip_db::Rows { cols: cols.iter().map(|c| (*c).to_string()).collect(), rows: self.0.clone() })
        }
        fn insert(&self, _: &str, _: &[&str], _: &[sip_db::DbVal]) -> Result<(), sip_db::DbError> {
            Ok(())
        }
        fn update(&self, _: &str, _: sip_db::Filter<'_>, _: &[(&str, sip_db::DbVal)]) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
        fn delete(&self, _: &str, _: sip_db::Filter<'_>) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
    }

    #[test]
    fn db_load_skips_rows_out_of_range() {
        use sip_db::DbVal::{Int, Str};
        let now = i64::try_from(unix_secs()).unwrap();
        let row = |h_entry: i64, h_id: i64, cseq: i64, start: i64, timeout: i64| {
            let mut r = vec![Int(h_entry), Int(h_id)];
            r.extend(["c", "sip:a@x", "1", "sip:b@x", "2"].map(|s| Str(s.into())));
            r.extend([Int(cseq), Int(cseq)]);
            r.extend(["", "", "sip:a@1.2.3.4", "sip:b@1.2.3.5", "udp:1.2.3.4:5060", "udp:1.2.3.5:5060"].map(|s| Str(s.into())));
            r.extend([Int(4), Int(start), Int(timeout), Str("{}".into())]);
            r
        };
        let dlg = Dialog::default();
        let _ = dlg.db.set(Arc::new(Rows(vec![
            row(1, 1, 1, now - 10, now + 100),
            // A negative timeout must not become a huge u64 (loaded forever).
            row(1, 2, 1, now - 10, -1),
            // Ids and CSeqs past 32 bits must not wrap onto other values.
            row(1, (1 << 32) + 1, 1, now - 10, now + 100),
            row(1, 3, 1 << 32, now - 10, now + 100),
        ])));
        assert_eq!(dlg.db_load(), Ok(1));
        let d = dlg.by_id(1).unwrap();
        let g = lock(&d);
        assert_eq!((g.lifetime, g.caller.cseq), (110, 1));
    }

    #[test]
    fn cseq_and_id_at_32_bit_limit() {
        use sip_db::DbVal::{Int, Str};
        let now = i64::try_from(unix_secs()).unwrap();
        let row = |h_id: i64, cseq: i64, callid: &'static str| {
            let mut r = vec![Int(1), Int(h_id)];
            r.extend([callid, "sip:a@x", "1", "sip:b@x", "2"].map(|s| Str(s.into())));
            r.extend([Int(cseq), Int(cseq)]);
            r.extend(["", "", "sip:a@1.2.3.4", "sip:b@1.2.3.5", "udp:1.2.3.4:5060", "udp:1.2.3.5:5060"].map(|s| Str(s.into())));
            r.extend([Int(4), Int(now - 10), Int(now + 100), Str("{}".into())]);
            r
        };
        let dlg = Dialog::default();
        // h_id and CSeqs of 2^32 - 1 (CSeq straight from the caller's
        // INVITE): `id + 1` and `cseq + 1` must not overflow.
        let max = i64::from(u32::MAX);
        let _ = dlg.db.set(Arc::new(Rows(vec![row(max, max, "c1"), row(7, 7, "c2")])));
        assert_eq!(dlg.db_load(), Ok(2));
        let d = dlg.by_id(u32::MAX).unwrap();
        let g = lock(&d);
        assert!(dlg.uac_for(&g, true, "BYE").is_none() && dlg.uac_for(&g, false, "BYE").is_none());
        let d = dlg.by_id(7).unwrap();
        let g = lock(&d);
        assert_eq!(dlg.uac_for(&g, true, "BYE").map(|r| r.cseq), Some(8));
        assert_eq!(dlg.uac_for(&g, false, "BYE").map(|r| r.cseq), Some(8));
    }

    // ------------------------------------------------- state machine tests --

    use sip_core::{Lumps, Proto};
    use std::net::SocketAddr;

    /// Advertises 192.0.2.10:5060 (our address); sends nothing.
    struct Us;
    impl Outbound for Us {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            Some(SocketAddr::from(([192, 0, 2, 10], 5060)))
        }
    }

    fn crlf(s: &str) -> String {
        s.replace("\r\n", "\n").replace('\n', "\r\n")
    }

    fn src(a: &str) -> Dest {
        Dest::new(Proto::Udp, a.parse().unwrap())
    }

    /// Runs `f` on a context for `raw`, received from `from`.
    fn with_ctx<R>(raw: &str, from: Dest, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        let raw = crlf(raw);
        let arena = Bump::new();
        let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &Us, None, from, 0);
        f(&mut ctx)
    }

    const CALLER: &str = "198.51.100.1:5060";
    const CALLEE: &str = "203.0.113.2:5060";

    /// The caller's INVITE (Call-ID c1, From tag ft), with extra headers.
    fn invite(extra: &str) -> String {
        format!(
            "INVITE sip:bob@b.example SIP/2.0\nVia: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\nFrom: \"Alice\" <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>\nCall-ID: c1\nCSeq: 10 INVITE\nContact: <sip:alice@198.51.100.1>\n{extra}Content-Length: 0\n\n"
        )
    }

    /// A reply upstream to the INVITE (To tag `ttag` unless empty).
    fn reply(status: &str, ttag: &str, extra: &str) -> Vec<u8> {
        let tag = if ttag.is_empty() { String::new() } else { format!(";tag={ttag}") };
        crlf(&format!(
            "SIP/2.0 {status}\nVia: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\nFrom: \"Alice\" <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>{tag}\nCall-ID: c1\nCSeq: 10 INVITE\n{extra}Content-Length: 0\n\n"
        ))
        .into_bytes()
    }

    /// An in-dialog request: from the caller (`from_caller`) or the callee.
    fn in_dialog(method: &str, cseq: u32, from_caller: bool, extra: &str) -> String {
        let (from, to) = if from_caller {
            ("\"Alice\" <sip:alice@a.example>;tag=ft", "<sip:bob@b.example>;tag=tt")
        } else {
            ("<sip:bob@b.example>;tag=tt", "\"Alice\" <sip:alice@a.example>;tag=ft")
        };
        format!(
            "{method} sip:x@h SIP/2.0\nVia: SIP/2.0/UDP 10.0.0.9;branch=z9hG4bK{cseq}\nFrom: {from}\nTo: {to}\nCall-ID: c1\nCSeq: {cseq} {method}\n{extra}Content-Length: 0\n\n"
        )
    }

    /// dlg_manage() on `msg`: the return code and the dialog.
    fn manage(dlg: &Dialog, msg: &str) -> (i32, Option<DlgRef>) {
        with_ctx(msg, src(CALLER), |ctx| {
            let rc = dlg.create(ctx);
            (rc, ctx.ext::<Current>().map(|c| c.0.clone()))
        })
    }

    fn state(d: &DlgRef) -> State {
        lock(d).state
    }

    type Seen<T> = Arc<Mutex<Vec<T>>>;

    /// Records state changes and ends.
    fn watch(dlg: &Dialog) -> (Seen<&'static str>, Seen<DlgEnd>) {
        let states = Arc::new(Mutex::new(Vec::new()));
        let ends = Arc::new(Mutex::new(Vec::new()));
        let s = states.clone();
        dlg.on_state(Arc::new(move |c: &DlgChange| lock(&s).push(c.state)));
        let e = ends.clone();
        dlg.on_end(Arc::new(move |x: &DlgEnd| lock(&e).push(x.clone())));
        (states, ends)
    }

    #[test]
    fn dialog_is_created_by_an_initial_invite_only() {
        let dlg = Dialog::default();
        let (rc, d) = manage(&dlg, &invite("Record-Route: <sip:10.0.0.1;lr>, <sip:10.0.0.2;lr>\n"));
        let d = d.unwrap();
        assert_eq!(rc, 1);
        {
            let g = lock(&d);
            assert_eq!((g.state, g.callid.as_str(), g.caller.tag.as_str(), g.caller.cseq), (State::Unconfirmed, "c1", "ft", 10));
            assert_eq!((g.from_uri.as_str(), g.to_uri.as_str(), g.req_uri.as_str()), ("sip:alice@a.example", "sip:bob@b.example", "sip:bob@b.example"));
            assert_eq!(g.caller.contact, "sip:alice@198.51.100.1");
            assert_eq!(g.caller.route, ["<sip:10.0.0.1;lr>", "<sip:10.0.0.2;lr>"]);
            assert_eq!(g.caller.src, Some(src(CALLER)));
            assert_eq!(g.h_entry, (fx_hash(b"c1".as_slice()) & 0xfff) as u32, "h_entry: 12 bits of the Call-ID hash");
            assert_eq!((g.lifetime, g.timeout_at), (43200, 0));
        }
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
        // A retransmission finds the same dialog.
        let (rc, again) = manage(&dlg, &invite(""));
        assert!(rc == 1 && Arc::ptr_eq(&again.unwrap(), &d));
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
        // Not an initial INVITE: no dialog.
        assert_eq!(manage(&dlg, &in_dialog("BYE", 11, true, "")).0, -1);
        assert_eq!(manage(&dlg, &in_dialog("INVITE", 11, true, "")).0, -1, "re-INVITE");
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dialog_record_route_cookie_names_the_dialog() {
        let dlg = Dialog::default();
        let (pending, d) = with_ctx(&invite(""), src(CALLER), |ctx| {
            dlg.create(ctx);
            (ctx.ext::<sip_core::rr::PendingParams>().map(|p| p.0.clone()), ctx.ext::<Current>().map(|c| c.0.clone()).unwrap())
        });
        let (e, id) = {
            let g = lock(&d);
            (g.h_entry, g.h_id)
        };
        assert_eq!(pending, Some(vec![format!("did={}", did_value(e, id))]));
        // Another cookie name; none with match mode 2.
        let dlg = Dialog::default();
        dlg.set_param("rr_param", &Arg::Str("dlgid".into())).unwrap();
        let p = with_ctx(&invite(""), src(CALLER), |ctx| {
            dlg.create(ctx);
            ctx.ext::<sip_core::rr::PendingParams>().map(|p| p.0.clone()).unwrap()
        });
        assert!(p[0].starts_with("dlgid="), "{p:?}");
        let dlg = Dialog::default();
        dlg.set_param("dlg_match_mode", &Arg::Int(2)).unwrap();
        let p = with_ctx(&invite(""), src(CALLER), |ctx| {
            dlg.create(ctx);
            ctx.ext::<sip_core::rr::PendingParams>().map(|p| p.0.clone())
        });
        assert_eq!(p, None);
    }

    #[test]
    fn dialog_context_settings_apply_at_creation() {
        let dlg = Dialog::default();
        let d = with_ctx(&invite(""), src(CALLER), |ctx| {
            *ctx.ext_mut::<DlgCtx>() = DlgCtx {
                on: true,
                flags: 0b101,
                timeout: Some(90),
                timeout_route: Some("tr".into()),
                timeout_bye: Some(true),
                ka_src: Some(true),
                ka_dst: None,
                noreset: Some(true),
            };
            ctx.ext_mut::<sip_core::TxnVars>().flags = 1 << 7;
            dlg.on_relay(ctx);
            ctx.ext::<Current>().map(|c| c.0.clone()).unwrap()
        });
        let g = lock(&d);
        assert_eq!((g.sflags, g.lifetime, g.timeout_route.as_deref(), g.flags), (0b101, 90, Some("tr"), 1 << 7));
        assert!(g.timeout_bye && g.ka_src && !g.ka_dst && g.timeout_noreset);
    }

    #[test]
    fn dialog_flag_on_relay_creates_the_dialog() {
        let dlg = Dialog::default();
        dlg.set_param("dlg_flag", &Arg::Int(4)).unwrap();
        let relay = |flags: u64| {
            with_ctx(&invite(""), src(CALLER), |ctx| {
                ctx.ext_mut::<sip_core::TxnVars>().flags = flags;
                dlg.on_relay(ctx);
                ctx.ext::<Current>().is_some()
            })
        };
        assert!(!relay(1 << 3));
        assert!(relay(1 << 4));
        assert!(relay(u64::MAX));
        let off = Dialog::default();
        let created = with_ctx(&invite(""), src(CALLER), |ctx| {
            ctx.ext_mut::<sip_core::TxnVars>().flags = u64::MAX;
            off.on_relay(ctx);
            ctx.ext::<Current>().is_some()
        });
        assert!(!created, "dlg_flag -1: never");
    }

    #[test]
    fn dialog_states_follow_the_replies_sent_upstream() {
        let dlg = Dialog::default();
        let (states, ends) = watch(&dlg);
        let d = manage(&dlg, &invite("")).1.unwrap();
        dlg.on_reply_out(&reply("180 Ringing", "", ""));
        assert_eq!(state(&d), State::Unconfirmed, "1xx without To tag");
        dlg.on_reply_out(&reply("180 Ringing", "tt", ""));
        assert_eq!((state(&d), lock(&d).callee.tag.clone()), (State::Early, "tt".to_string()));
        dlg.on_reply_out(&reply("183 Session Progress", "other", ""));
        assert_eq!(lock(&d).callee.tag, "tt", "a second early leg doesn't take over");
        let before = unix_secs();
        dlg.on_reply_out(&reply("200 OK", "tt", "Contact: <sip:bob@203.0.113.2>\n"));
        {
            let g = lock(&d);
            assert_eq!((g.state, g.callee.contact.as_str()), (State::Confirmed, "sip:bob@203.0.113.2"));
            assert!(g.start_ts >= before && g.timeout_at == g.start_ts + 43200, "timeout = start + lifetime");
        }
        // A retransmitted or forked 2xx changes nothing.
        dlg.on_reply_out(&reply("200 OK", "fork2", "Contact: <sip:other@203.0.113.3>\n"));
        {
            let g = lock(&d);
            assert_eq!((g.callee.tag.as_str(), g.callee.contact.as_str()), ("tt", "sip:bob@203.0.113.2"));
        }
        // A late error does not fail a confirmed dialog.
        dlg.on_reply_out(&reply("487 Request Terminated", "tt", ""));
        assert_eq!(state(&d), State::Confirmed);
        with_ctx(&in_dialog("ACK", 10, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
        assert_eq!(state(&d), State::ConfirmedAck);
        with_ctx(&in_dialog("BYE", 1, false, ""), src(CALLEE), |ctx| dlg.on_request(ctx));
        assert_eq!((state(&d), lock(&d).end_reason), (State::Deleted, "callee_bye"));
        assert_eq!(dlg.count.load(Ordering::Relaxed), 0);
        assert!(dlg.lookup("c1", "ft", None).is_none(), "removed");
        assert_eq!(*lock(&states), ["trying", "early", "confirmed", "terminated"]);
        let ends = lock(&ends);
        assert_eq!(ends.len(), 1);
        assert_eq!((ends[0].callid.as_str(), ends[0].from_tag.as_str(), ends[0].to_tag.as_str()), ("c1", "ft", "tt"));
    }

    #[test]
    fn dialog_100_trying_is_provisional() {
        let dlg = Dialog::default();
        let d = manage(&dlg, &invite("")).1.unwrap();
        dlg.on_reply_out(&reply("100 Trying", "", ""));
        assert_eq!(state(&d), State::Unconfirmed, "a 100 must not fail the dialog");
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
        dlg.on_reply_out(&reply("200 OK", "tt", "Contact: <sip:bob@203.0.113.2>\n"));
        assert_eq!(state(&d), State::Confirmed);
    }

    #[test]
    fn dialog_fails_on_an_error_before_confirmation() {
        let dlg = Dialog::default();
        let (states, ends) = watch(&dlg);
        let d = manage(&dlg, &invite("")).1.unwrap();
        // Not about the INVITE, or another dialog: ignored.
        let mut bye_reply = reply("481 Gone", "tt", "");
        bye_reply = String::from_utf8(bye_reply).unwrap().replace("10 INVITE", "11 BYE").into_bytes();
        dlg.on_reply_out(&bye_reply);
        dlg.on_reply_out(&String::from_utf8(reply("486 Busy Here", "tt", "")).unwrap().replace("c1", "c2").into_bytes());
        assert_eq!(state(&d), State::Unconfirmed);
        dlg.on_reply_out(&reply("180 Ringing", "tt", ""));
        dlg.on_reply_out(&reply("486 Busy Here", "tt", ""));
        assert_eq!((state(&d), lock(&d).end_reason), (State::Deleted, "failed"));
        assert_eq!(dlg.count.load(Ordering::Relaxed), 0);
        assert_eq!(*lock(&states), ["trying", "early", "terminated"]);
        assert!(lock(&ends).is_empty(), "no CDR for a call that never connected");
    }

    #[test]
    fn dialog_fails_when_the_invite_is_answered_statelessly() {
        let dlg = Dialog::default();
        with_ctx(&invite(""), src(CALLER), |ctx| {
            dlg.create(ctx);
            ctx.out.extend_from_slice(b"SIP/2.0 180 Ringing\r\n");
            dlg.on_ctx_send(ctx);
            assert_eq!(dlg.count.load(Ordering::Relaxed), 1, "a provisional keeps it");
            ctx.out.clear();
            ctx.out.extend_from_slice(b"SIP/2.0 404 Not Found\r\n");
            dlg.on_ctx_send(ctx);
        });
        assert_eq!(dlg.count.load(Ordering::Relaxed), 0);
    }

    /// A confirmed dialog (caller Contact/route from `inv_extra`, the 2xx's
    /// headers `ok_extra`).
    fn confirmed(dlg: &Dialog, inv_extra: &str, ok_extra: &str) -> DlgRef {
        let d = manage(dlg, &invite(inv_extra)).1.unwrap();
        dlg.on_reply_out(&reply("200 OK", "tt", &format!("Contact: <sip:bob@203.0.113.2>\n{ok_extra}")));
        assert_eq!(state(&d), State::Confirmed);
        d
    }

    #[test]
    fn dialog_route_sets_towards_both_sides() {
        let dlg = Dialog::default();
        let _ = dlg.net.set(Arc::new(Us));
        let d = confirmed(
            &dlg,
            "Record-Route: <sip:10.0.0.1;lr>\nRecord-Route: <sip:10.0.0.0;lr>\n",
            "Record-Route: <sip:10.0.0.3;lr>, <sip:10.0.0.2;lr>, <sip:192.0.2.10;lr;did=x>, <sip:10.0.0.1;lr>, <sip:10.0.0.0;lr>\n",
        );
        let g = lock(&d);
        assert_eq!(g.callee.route, ["<sip:10.0.0.2;lr>", "<sip:10.0.0.3;lr>"], "entries above ours, nearest first");
        let to_callee = dlg.uac_for(&g, true, "BYE").unwrap();
        assert_eq!((to_callee.ruri.as_str(), to_callee.cseq, to_callee.call_id.as_deref()), ("sip:bob@203.0.113.2", 11, Some("c1")));
        assert_eq!(to_callee.dst.map(|x| x.addr.to_string()).as_deref(), Some("10.0.0.2:5060"));
        assert_eq!(
            to_callee.headers,
            "From: \"Alice\" <sip:alice@a.example>;tag=ft\r\nTo: <sip:bob@b.example>;tag=tt\r\nRoute: <sip:10.0.0.2;lr>,<sip:10.0.0.3;lr>\r\n"
        );
        let to_caller = dlg.uac_for(&g, false, "BYE").unwrap();
        assert_eq!((to_caller.ruri.as_str(), to_caller.cseq), ("sip:alice@198.51.100.1", 2), "callee CSeq space starts at 1");
        assert_eq!(
            to_caller.headers,
            "From: <sip:bob@b.example>;tag=tt\r\nTo: \"Alice\" <sip:alice@a.example>;tag=ft\r\nRoute: <sip:10.0.0.1;lr>,<sip:10.0.0.0;lr>\r\n"
        );
        assert_eq!(to_caller.dst, Some(src("10.0.0.1:5060")));
    }

    #[test]
    fn dialog_without_route_set_sends_to_the_last_source() {
        let dlg = Dialog::default();
        let d = manage(&dlg, &invite("")).1.unwrap();
        // The 2xx came from the callee's address.
        let ok = String::from_utf8(reply("200 OK", "tt", "Contact: <sip:bob@203.0.113.2:5080>\n")).unwrap();
        with_ctx(&ok, src("203.0.113.99:5099"), |ctx| dlg.observe_reply(ctx));
        dlg.on_reply_out(ok.as_bytes());
        let g = lock(&d);
        assert!(g.callee.route.is_empty() && g.reply_src.is_empty());
        assert_eq!(dlg.uac_for(&g, true, "BYE").unwrap().dst, Some(src("203.0.113.99:5099")), "the 2xx's source");
        assert_eq!(dlg.uac_for(&g, false, "BYE").unwrap().dst, Some(src(CALLER)), "the INVITE's source");
        drop(g);
        lock(&d).callee.src = None;
        assert_eq!(dlg.uac_for(&lock(&d), true, "BYE").unwrap().dst, Some(src("203.0.113.2:5080")), "else the Contact");
        lock(&d).callee.contact.clear();
        assert!(dlg.uac_for(&lock(&d), true, "BYE").is_none(), "no Contact: nowhere to send");
    }

    #[test]
    fn dialog_remembers_at_most_16_reply_sources() {
        let dlg = Dialog::default();
        let d = manage(&dlg, &invite("")).1.unwrap();
        for i in 0..20 {
            let r = String::from_utf8(reply("183 Session Progress", &format!("t{i}"), "")).unwrap();
            with_ctx(&r, src(&format!("203.0.113.{i}:5060")), |ctx| dlg.observe_reply(ctx));
        }
        let r = String::from_utf8(reply("100 Trying", "x", "")).unwrap();
        with_ctx(&r, src("203.0.113.200:5060"), |ctx| dlg.observe_reply(ctx));
        assert_eq!(lock(&d).reply_src.len(), 16);
        assert!(!lock(&d).reply_src.contains_key("x"), "100 is not a dialog reply");
    }

    #[test]
    fn dialog_in_dialog_requests_track_cseq_contact_and_timeout() {
        let dlg = Dialog::default();
        let d = confirmed(&dlg, "", "");
        lock(&d).timeout_at = 0;
        let before = unix_secs();
        with_ctx(&in_dialog("INVITE", 20, true, "Contact: <sip:alice@198.51.100.7>\n"), src(CALLER), |ctx| dlg.on_request(ctx));
        {
            let g = lock(&d);
            assert_eq!((g.caller.cseq, g.caller.contact.as_str()), (20, "sip:alice@198.51.100.7"), "re-INVITE: new target");
            assert!(g.timeout_at >= before + 43200, "restarted");
        }
        // ACK and CANCEL don't move the CSeq; a lower CSeq neither.
        with_ctx(&in_dialog("ACK", 99, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
        with_ctx(&in_dialog("INFO", 15, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
        assert_eq!(lock(&d).caller.cseq, 20);
        // The callee's requests count in its own space; its Contact stays.
        with_ctx(&in_dialog("INVITE", 5, false, "Contact: <sip:bob@203.0.113.9>\n"), src(CALLEE), |ctx| dlg.on_request(ctx));
        {
            let g = lock(&d);
            assert_eq!((g.callee.cseq, g.callee.contact.as_str()), (5, "sip:bob@203.0.113.2"));
        }
        // A From tag that is neither leg's: no match.
        let stranger = in_dialog("INFO", 6, false, "").replace("tag=tt", "tag=zz");
        assert!(!with_ctx(&stranger, src(CALLEE), |ctx| {
            dlg.on_request(ctx);
            ctx.ext::<Current>().is_some()
        }));
    }

    #[test]
    fn dialog_timeout_noreset_keeps_the_timeout_except_for_the_confirming_ack() {
        for (property, modparam) in [(true, false), (false, true)] {
            let dlg = Dialog::default();
            dlg.timeout_noreset.store(modparam, Ordering::Relaxed);
            let d = confirmed(&dlg, "", "");
            lock(&d).timeout_noreset = property;
            lock(&d).timeout_at = 7;
            with_ctx(&in_dialog("INFO", 11, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
            assert_eq!(lock(&d).timeout_at, 7, "property {property}, modparam {modparam}");
            with_ctx(&in_dialog("ACK", 10, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
            assert!(lock(&d).timeout_at > 7, "the confirming ACK restarts it");
            lock(&d).timeout_at = 7;
            with_ctx(&in_dialog("ACK", 10, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
            assert_eq!(lock(&d).timeout_at, 7, "a later ACK doesn't");
        }
    }

    #[test]
    fn dialog_timer_ends_expired_and_stale_dialogs() {
        let dlg = Arc::new(Dialog::default());
        let (states, ends) = watch(&dlg);
        let expired = confirmed(&dlg, "", "");
        lock(&expired).timeout_at = unix_secs().saturating_sub(1);
        let live = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        lock(&live).init_ts = unix_secs();
        let stale = manage(&dlg, &invite("").replace("c1", "c3")).1.unwrap();
        lock(&stale).init_ts = unix_secs().saturating_sub(301);
        dlg.tick();
        assert_eq!((state(&expired), lock(&expired).end_reason), (State::Deleted, "timeout"));
        assert_eq!((state(&stale), lock(&stale).end_reason), (State::Deleted, "failed"), "unconfirmed past early_timeout");
        assert_eq!(state(&live), State::Unconfirmed);
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
        assert_eq!(lock(&ends).len(), 1);
        assert_eq!(lock(&states).iter().filter(|s| **s == "terminated").count(), 2);
        // Exactly at the boundary: due.
        let edge = confirmed(&dlg, "", "");
        lock(&edge).timeout_at = unix_secs();
        dlg.tick();
        assert_eq!(state(&edge), State::Deleted);
    }

    #[test]
    fn dialog_lifetime_changes() {
        let dlg = Dialog::default();
        let early = manage(&dlg, &invite("")).1.unwrap();
        Dialog::set_lifetime(&early, 0);
        {
            let g = lock(&early);
            assert_eq!((g.lifetime, g.timeout_at), (1, 0), "at least 1s; not running before confirmation");
        }
        let d = confirmed(&dlg, "", "");
        let before = unix_secs();
        Dialog::set_lifetime(&d, 30);
        let at = lock(&d).timeout_at;
        assert!(at >= before + 30 && at <= unix_secs() + 30);
        Dialog::set_lifetime(&d, u64::MAX);
        assert_eq!(lock(&d).timeout_at, u64::MAX, "saturates");
    }

    #[test]
    fn dialog_profiles_sizes_and_timeouts() {
        let dlg = Dialog::default();
        dlg.set_param("profiles_with_value", &Arg::Str("caller; ;dest".into())).unwrap();
        dlg.set_param("profiles_no_value", &Arg::Str("calls".into())).unwrap();
        assert!(dlg.check_profile("caller", true).is_ok() && dlg.check_profile("calls", false).is_ok());
        assert!(dlg.check_profile("caller", false).unwrap_err().contains("needs a value"));
        assert!(dlg.check_profile("calls", true).unwrap_err().contains("takes no value"));
        assert!(dlg.check_profile("nope", false).unwrap_err().contains("no profile"));
        assert!(dlg.check_profile("", false).is_err(), "empty names are dropped");
        let mk = |cid: &str, profiles: Vec<(&str, Option<&str>)>| {
            let d = manage(&dlg, &invite("").replace("c1", cid)).1.unwrap();
            lock(&d).profiles = profiles.into_iter().map(|(p, v)| (p.to_string(), v.map(String::from))).collect();
            d
        };
        let a = mk("a", vec![("calls", None), ("caller", Some("alice"))]);
        let b = mk("b", vec![("calls", None), ("caller", Some("bob"))]);
        let c = mk("c", vec![("caller", Some("alice"))]);
        assert_eq!(dlg.profile_size("calls", None), 2);
        assert_eq!(dlg.profile_size("caller", None), 3);
        assert_eq!(dlg.profile_size("caller", Some("alice")), 2);
        assert_eq!(dlg.profile_size("caller", Some("carol")), 0);
        lock(&c).state = State::Deleted;
        assert_eq!(dlg.profile_size("caller", Some("alice")), 1, "deleted dialogs don't count");
        // Timeouts by profile: early or later only.
        lock(&a).state = State::Early;
        lock(&b).state = State::Unconfirmed;
        assert_eq!(dlg.set_timeout_by_profile("calls", None, 77), 1);
        assert_eq!((lock(&a).lifetime, lock(&b).lifetime), (77, 43200));
        lock(&b).state = State::Confirmed;
        assert_eq!(dlg.set_timeout_by_profile("caller", Some("bob"), 0), 1);
        assert_eq!(lock(&b).lifetime, 1);
        assert!(lock(&b).timeout_at > 0, "confirmed: restarted");
    }

    #[test]
    fn dialog_lookups_by_ids() {
        let dlg = Dialog::default();
        let d = confirmed(&dlg, "", "");
        let same = |x: Option<DlgRef>| x.is_some_and(|x| Arc::ptr_eq(&x, &d));
        assert!(same(dlg.get("c1", "ft", "tt")) && same(dlg.get("c1", "tt", "ft")), "either direction");
        assert!(dlg.get("c1", "ft", "xx").is_none() && dlg.get("c9", "ft", "tt").is_none());
        assert!(same(dlg.lookup("c1", "tt", Some("ft"))), "from the callee");
        assert!(dlg.lookup("c1", "zz", Some("ft")).is_none(), "a From tag that isn't the callee's");
        assert_eq!(dlg.by_callid("c1", None).len(), 1);
        assert_eq!(dlg.by_callid("c1", Some("tt")).len(), 0, "by the caller's tag");
        assert!(same(dlg.by_id(lock(&d).h_id)));
        // Early dialogs aren't ended by Call-ID.
        let early = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        assert!(!dlg.end_by_callid("c2"));
        assert_eq!(state(&early), State::Unconfirmed);
        assert!(dlg.end_by_callid("c1"));
        assert_eq!((state(&d), lock(&d).end_reason), (State::Deleted, "admin"));
        assert!(dlg.get("c1", "ft", "tt").is_none());
        assert!(!dlg.end_by_callid("c1"), "once");
    }

    #[test]
    fn dialog_forced_states() {
        let dlg = Dialog::default();
        let d = manage(&dlg, &invite("")).1.unwrap();
        assert_eq!(dlg.force_state(&d, State::Confirmed), State::Unconfirmed);
        {
            let g = lock(&d);
            assert!(g.start_ts > 0 && g.timeout_at == g.start_ts + g.lifetime, "its lifetime starts now");
        }
        lock(&d).timeout_at = 5;
        assert_eq!(dlg.force_state(&d, State::ConfirmedAck), State::Confirmed);
        assert_eq!(lock(&d).timeout_at, 5, "already running: kept");
        assert_eq!(dlg.force_state(&d, State::Deleted), State::ConfirmedAck);
        assert_eq!((lock(&d).end_reason, dlg.count.load(Ordering::Relaxed)), ("admin", 0));
    }

    #[test]
    fn dialog_json_and_briefing() {
        let dlg = Dialog::default();
        let d = confirmed(&dlg, "", "");
        lock(&d).vars.insert("k".into(), "v".into());
        lock(&d).profiles = vec![("calls".into(), None), ("caller".into(), Some("alice".into()))];
        let j = Dialog::json(&d);
        assert_eq!((j["call-id"].as_str(), j["from_tag"].as_str(), j["to_tag"].as_str(), j["state"].as_u64()), (Some("c1"), Some("ft"), Some("tt"), Some(3)));
        assert_eq!(j["variables"]["k"], "v");
        assert_eq!(j["profiles"], json!([{"calls": null}, {"caller": "alice"}]));
        assert!(j.get("context").is_none());
        assert_eq!(Dialog::json_with(&d, true)["context"]["lifetime"], 43200);
        let b = dlg.briefing("cFTsx");
        let h_id = lock(&d).h_id;
        assert_eq!(b, json!([{"h_entry": lock(&d).h_entry, "h_id": h_id, "call-id": "c1", "from_tag": "ft", "to_tag": "tt", "state": 3}]));
        assert_eq!(dlg.briefing("")[0].as_object().unwrap().len(), 2, "h_entry and h_id only");
    }

    /// A `dialog` table kept in memory (delete by hash_id or all).
    #[derive(Default)]
    struct Table(Mutex<Vec<(Vec<String>, Vec<sip_db::DbVal>)>>, AtomicUsize);
    impl sip_db::DbConn for Table {
        fn query(&self, _: &str, cols: &[&str], _: sip_db::Filter<'_>) -> Result<sip_db::Rows, sip_db::DbError> {
            let rows = lock(&self.0)
                .iter()
                .map(|(names, vals)| cols.iter().map(|c| names.iter().position(|n| n == c).map_or(sip_db::DbVal::Null, |i| vals[i].clone())).collect())
                .collect();
            Ok(sip_db::Rows { cols: cols.iter().map(|c| (*c).to_string()).collect(), rows })
        }
        fn insert(&self, _: &str, cols: &[&str], vals: &[sip_db::DbVal]) -> Result<(), sip_db::DbError> {
            self.1.fetch_add(1, Ordering::Relaxed);
            lock(&self.0).push((cols.iter().map(|c| (*c).to_string()).collect(), vals.to_vec()));
            Ok(())
        }
        fn update(&self, _: &str, _: sip_db::Filter<'_>, _: &[(&str, sip_db::DbVal)]) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
        fn delete(&self, _: &str, f: sip_db::Filter<'_>) -> Result<usize, sip_db::DbError> {
            let mut t = lock(&self.0);
            let n = t.len();
            t.retain(|(names, vals)| !f.iter().all(|(k, v)| names.iter().position(|n| n == k).is_some_and(|i| vals[i] == *v)));
            Ok(n.saturating_sub(t.len()))
        }
    }

    fn rows(t: &Table) -> usize {
        lock(&t.0).len()
    }

    #[test]
    fn dialog_db_modes_write_when_they_should() {
        // Realtime: on confirmation, gone when it ends.
        let dlg = Dialog::default();
        dlg.set_param("db_mode", &Arg::Int(1)).unwrap();
        let t = Arc::new(Table::default());
        let _ = dlg.db.set(t.clone());
        let d = manage(&dlg, &invite("")).1.unwrap();
        dlg.db_write(&d);
        assert_eq!(rows(&t), 0, "unconfirmed dialogs aren't stored");
        dlg.on_reply_out(&reply("200 OK", "tt", "Contact: <sip:bob@203.0.113.2>\n"));
        assert_eq!(rows(&t), 1);
        dlg.db_write(&d);
        assert_eq!((rows(&t), t.1.load(Ordering::Relaxed)), (1, 2), "rewritten, not duplicated");
        dlg.end(&d, None, false, "admin");
        assert_eq!(rows(&t), 0);
        // Delayed: only at the flush.
        let dlg = Dialog::default();
        dlg.set_param("db_mode", &Arg::Int(2)).unwrap();
        let t = Arc::new(Table::default());
        let _ = dlg.db.set(t.clone());
        let d = confirmed(&dlg, "", "");
        assert_eq!(rows(&t), 0);
        dlg.db_flush();
        assert_eq!(rows(&t), 1);
        dlg.end(&d, None, false, "admin");
        assert_eq!(rows(&t), 1, "deleted at the next flush");
        dlg.db_flush();
        assert_eq!(rows(&t), 0);
        // Shutdown mode: the whole table at shutdown.
        let dlg = Dialog::default();
        dlg.set_param("db_mode", &Arg::Int(3)).unwrap();
        let t = Arc::new(Table::default());
        let _ = dlg.db.set(t.clone());
        confirmed(&dlg, "", "");
        manage(&dlg, &invite("").replace("c1", "c2"));
        assert_eq!(rows(&t), 0);
        dlg.shutdown();
        assert_eq!(rows(&t), 1, "the confirmed one");
    }

    #[test]
    fn dialog_db_row_round_trip() {
        let dlg = Dialog::default();
        dlg.set_param("db_mode", &Arg::Int(1)).unwrap();
        let t = Arc::new(Table::default());
        let _ = dlg.db.set(t.clone());
        let d = manage(&dlg, &invite("Record-Route: <sip:10.0.0.1;lr>, <sip:10.0.0.2;lr>\n")).1.unwrap();
        {
            let mut g = lock(&d);
            g.vars.insert("k".into(), "v".into());
            g.profiles = vec![("calls".into(), None), ("caller".into(), Some("alice".into()))];
            (g.timeout_bye, g.sflags, g.timeout_noreset, g.timeout_route) = (true, 6, true, Some("tr".into()));
        }
        dlg.on_reply_out(&reply("200 OK", "tt", "Contact: <sip:bob@203.0.113.2>\nRecord-Route: <sip:10.0.0.3;lr>\n"));
        with_ctx(&in_dialog("ACK", 10, true, ""), src(CALLER), |ctx| dlg.on_request(ctx));
        dlg.db_write(&d);
        let back = Dialog::default();
        let _ = back.db.set(t.clone());
        assert_eq!(back.db_load(), Ok(1));
        let id = lock(&d).h_id;
        let loaded = back.by_id(id).unwrap();
        let (a, b) = (lock(&d), lock(&loaded));
        assert_eq!((b.h_entry, b.callid.as_str(), b.state), (a.h_entry, "c1", State::ConfirmedAck));
        assert_eq!(
            (b.from_hdr.as_str(), b.to_hdr.as_str(), b.from_uri.as_str(), b.to_uri.as_str()),
            (a.from_hdr.as_str(), a.to_hdr.as_str(), "sip:alice@a.example", "sip:bob@b.example")
        );
        for (x, y) in [(&a.caller, &b.caller), (&a.callee, &b.callee)] {
            assert_eq!((&x.tag, &x.contact, x.cseq, &x.route, x.src), (&y.tag, &y.contact, y.cseq, &y.route, y.src));
        }
        assert_eq!((b.start_ts, b.timeout_at, b.lifetime), (a.start_ts, a.timeout_at, a.timeout_at - a.start_ts));
        assert_eq!((&b.vars, &b.profiles), (&a.vars, &a.profiles));
        assert_eq!((b.timeout_bye, b.sflags, b.timeout_noreset, b.timeout_route.as_deref()), (true, 6, true, Some("tr")));
        assert!(back.next_id.load(Ordering::Relaxed) > a.h_id, "new ids don't collide");
    }

    #[test]
    fn uac_dialog_from_a_2xx() {
        let ok = crlf(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK1\nFrom: <sip:controller@x>;tag=a\nTo: <sip:alice@a.example>;tag=b\n\
Call-ID: br1\nCSeq: 1 INVITE\nContact: <sip:alice@198.51.100.1>\nRecord-Route: <sip:10.0.0.2;lr>, <sip:10.0.0.1;lr>\nContent-Length: 0\n\n",
        );
        let u = UacDlg::from_2xx(ok.as_bytes(), None).unwrap();
        assert_eq!(u.route, ["<sip:10.0.0.1;lr>", "<sip:10.0.0.2;lr>"], "reversed: our next hop first");
        let r = u.req("BYE", 3, "X: y\r\n");
        assert_eq!((r.method.as_str(), r.ruri.as_str(), r.cseq, r.call_id.as_deref()), ("BYE", "sip:alice@198.51.100.1", 3, Some("br1")));
        assert_eq!(r.headers, "From: <sip:controller@x>;tag=a\r\nTo: <sip:alice@a.example>;tag=b\r\nRoute: <sip:10.0.0.1;lr>,<sip:10.0.0.2;lr>\r\nX: y\r\n");
        assert_eq!(r.dst, Some(src("10.0.0.1:5060")));
        let op = Some(src("192.0.2.99:5060"));
        let plain = ok.replace("Record-Route: <sip:10.0.0.2;lr>, <sip:10.0.0.1;lr>\r\n", "");
        let u = UacDlg::from_2xx(plain.as_bytes(), op).unwrap();
        assert_eq!(u.req("ACK", 1, "").dst, op, "no route set: the outbound proxy");
        assert!(UacDlg::from_2xx(ok.replace(";tag=b", "").as_bytes(), None).is_none(), "no To tag");
        assert!(UacDlg::from_2xx(ok.replace("Contact: <sip:alice@198.51.100.1>\r\n", "").as_bytes(), None).is_none(), "no Contact");
    }

    #[test]
    fn small_helpers() {
        assert_eq!(angle(" sip:a@b "), "<sip:a@b>");
        assert_eq!(angle("<sip:a@b>"), "<sip:a@b>");
        for (h, want) in
            [("<sip:b@x>;tag=9", "<sip:b@x>"), ("<sip:b@x>", "<sip:b@x>"), ("<sip:b@x>;x=1;tag=9", "<sip:b@x>;x=1"), ("<sip:b@x>;tag=9;y=2", "<sip:b@x>;y=2")]
        {
            assert_eq!(strip_tag(h), want, "{h}");
        }
        assert_eq!((int_of(5), int_of(u64::MAX)), (5, i64::MAX));
        for (s, want) in [(&b""[..], None), (b"123456789", None), (b"ffffffff", Some(u32::MAX)), (b"A", Some(10)), (b"01", Some(16)), (b"g", None)] {
            assert_eq!(parse_rev_hex(s), want, "{:?}", String::from_utf8_lossy(s));
        }
        assert_eq!(parse_did(b"1.2.3"), None, "h_id must be hex");
        assert_eq!(parse_did(b".1"), None);
    }

    #[test]
    fn dialog_parameters() {
        let dlg = Dialog::default();
        let ok = |name: &str, v: Arg| dlg.set_param(name, &v).is_ok();
        assert!(ok("dlg_flag", Arg::Int(-1)) && ok("dlg_flag", Arg::Int(63)));
        assert!(!ok("dlg_flag", Arg::Int(64)) && !ok("dlg_flag", Arg::Int(-2)) && !ok("dlg_flag", Arg::Int(1 << 40)));
        assert!(ok("dlg_match_mode", Arg::Int(0)) && !ok("dlg_match_mode", Arg::Int(3)) && !ok("dlg_match_mode", Arg::Int(-1)));
        for bad in ["", "a;b", "a=b", "a b"] {
            assert!(!ok("rr_param", Arg::Str(bad.into())), "{bad:?}");
        }
        assert!(ok("default_timeout", Arg::Int(0)) && ok("early_timeout", Arg::Int(-5)) && ok("db_mode", Arg::Int(9)));
        assert_eq!((dlg.default_timeout.load(Ordering::Relaxed), dlg.early_timeout.load(Ordering::Relaxed), dlg.db_mode.load(Ordering::Relaxed)), (1, 1, 3));
        assert!(ok("bridge_contact", Arg::Str(String::new())));
        assert!(lock(&dlg.bridge_contact).is_none(), "empty: the default");
        assert!(ok("hash_size", Arg::Int(4)) && !ok("bogus", Arg::Int(1)));
    }

    // ------------------------------------- exported functions, $dlg*, RPC --

    use sip_core::pv::{PvRef, parse_fmt, parse_pv};

    /// Keeps what is sent (also the attempts that fail while `down`);
    /// advertises 192.0.2.10:5060.
    #[derive(Default)]
    struct Wire {
        sent: Mutex<Vec<(Dest, String, bool)>>,
        down: AtomicBool,
    }

    impl Outbound for Wire {
        fn send(&self, d: &Dest, m: &[u8]) -> std::io::Result<()> {
            let ok = !self.down.load(Ordering::Relaxed);
            lock(&self.sent).push((*d, String::from_utf8_lossy(m).into_owned(), ok));
            if ok { Ok(()) } else { Err(std::io::Error::other("network down")) }
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            Some(SocketAddr::from(([192, 0, 2, 10], 5060)))
        }
    }

    impl Wire {
        /// The distinct requests of this method sent (or tried), in order
        /// (UDP retransmissions are byte-identical and counted once).
        fn requests(&self, method: &str) -> Vec<(Dest, String)> {
            let mut v: Vec<(Dest, String)> = Vec::new();
            for (d, m, _) in lock(&self.sent).iter() {
                if m.starts_with(&format!("{method} ")) && !v.iter().any(|(_, x)| x == m) {
                    v.push((*d, m.clone()));
                }
            }
            v
        }
    }

    /// The value of header `name` in `msg`.
    fn hdr(msg: &str, name: &str) -> Option<String> {
        msg.lines().find_map(|l| l.strip_prefix(name)?.strip_prefix(':').map(|v| v.trim().to_string()))
    }

    /// Feed tm a reply to `req` (one it sent), with a To tag.
    fn answer(tm: &Tm, req: &str, status: &str, extra: &str) {
        let h = |n: &str| format!("{n}: {}", hdr(req, n).unwrap());
        let to = h("To");
        let to = if to.contains(";tag=") { to } else { format!("{to};tag=rt") };
        let raw = format!("SIP/2.0 {status}\n{}\n{}\n{to}\n{}\n{}\n{extra}Content-Length: 0\n\n", h("Via"), h("From"), h("Call-ID"), h("CSeq"));
        assert!(with_ctx(&raw, src(CALLEE), |ctx| Module::on_reply(tm, ctx)), "tm knows the transaction of {raw}");
    }

    /// The core variables, tm and the dialog module (tm not started).
    fn registry(dlg: &Arc<Dialog>) -> Registry {
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        reg.load(Arc::new(Tm::default())).unwrap();
        reg.load(dlg.clone()).unwrap();
        reg
    }

    /// Start the registry's tm on a [`Wire`], which the dialog uses too
    /// (the dialog's own timer is not started: tests call `tick`).
    fn start(reg: &Registry, dlg: &Dialog) -> Arc<Wire> {
        let wire = Arc::new(Wire::default());
        Module::spawn(reg.api::<Tm>().unwrap(), wire.clone()).unwrap();
        let _ = dlg.net.set(wire.clone());
        wire
    }

    fn call(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[Arg]) -> i32 {
        let e = reg.get(name).unwrap_or_else(|| panic!("{name}"));
        let fixed = (e.fixup)(args).unwrap_or_else(|err| panic!("{name}: {err}"));
        (e.func)(ctx, &*fixed)
    }

    fn fixup_err(reg: &Registry, name: &str, args: &[Arg]) -> String {
        match (reg.get(name).unwrap().fixup)(args) {
            Ok(_) => panic!("{name}({args:?}) accepted"),
            Err(e) => e,
        }
    }

    fn s(x: &str) -> Arg {
        Arg::Str(x.into())
    }

    fn fmt(reg: &Registry, x: &str) -> Arg {
        Arg::Fmt(Arc::new(parse_fmt(x, reg.pvs()).unwrap()))
    }

    fn pv(reg: &Registry, x: &str) -> PvRef {
        parse_pv(x, reg.pvs()).unwrap()
    }

    /// Runs `f` on an in-dialog INFO from the caller whose dialog is `d`
    /// (none: a message without a dialog).
    fn with_dlg<R>(d: Option<&DlgRef>, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        with_ctx(&in_dialog("INFO", 30, true, ""), src(CALLER), |ctx| {
            if let Some(d) = d {
                ctx.ext.push(Box::new(Current(d.clone())));
            }
            f(ctx)
        })
    }

    /// A JSON-RPC call: the result, or the error message.
    fn rpc(reg: &Registry, method: &str, params: Value) -> Result<Value, String> {
        let r = reg.rpc.call(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
        match r.get("result") {
            Some(v) => Ok(v.clone()),
            None => Err(r["error"]["message"].as_str().unwrap_or_default().to_string()),
        }
    }

    #[test]
    fn dialog_function_fixups_refuse_bad_arguments() {
        let dlg = Arc::new(Dialog::default());
        dlg.set_param("profiles_with_value", &s("caller")).unwrap();
        dlg.set_param("profiles_no_value", &s("calls")).unwrap();
        let reg = registry(&dlg);
        let var = fmt(&reg, "$var(n)");
        let cases: &[(&str, Vec<Arg>, &str)] = &[
            ("dlg_set_timeout", vec![], "expected timeout"),
            ("dlg_set_timeout", vec![Arg::Int(1), Arg::Int(2)], "expected timeout"),
            ("dlg_set_timeout", vec![Arg::Int(1), Arg::Int(2), Arg::Int(3), Arg::Int(4)], "expected timeout"),
            ("dlg_bye", vec![s("both")], "not all|caller|callee"),
            ("dlg_set_property", vec![s("ka-both")], "unknown dialog property"),
            ("dlg_reset_property", vec![s("")], "unknown dialog property"),
            ("set_dlg_profile", vec![], "expected profile[, value]"),
            ("set_dlg_profile", vec![s("calls"), s("a"), s("b")], "expected profile[, value]"),
            ("set_dlg_profile", vec![s("nope")], "no profile"),
            ("unset_dlg_profile", vec![s("caller")], "needs a value"),
            ("dlg_set_timeout_by_profile", vec![s("calls")], "expected profile, [value,] timeout"),
            ("dlg_set_timeout_by_profile", vec![s("nope"), Arg::Int(5)], "no profile"),
            ("is_in_profile", vec![], "expected profile[, value]"),
            ("get_profile_size", vec![s("calls")], "expected profile[, value], $var"),
            ("get_profile_size", vec![s("calls"), s("n")], "expected a variable like $var(n)"),
            ("get_profile_size", vec![s("calls"), fmt(&reg, "x$var(n)")], "expected a variable"),
            ("get_profile_size", vec![s("caller"), s("v"), var.clone(), var.clone()], "expected profile[, value], $var"),
            ("dlg_setflag", vec![Arg::Int(32)], "not 0..31"),
            ("dlg_resetflag", vec![Arg::Int(-1)], "not 0..31"),
            ("dlg_refer", vec![s("both"), s("sip:c@x")], "not caller|callee"),
            ("dlg_bridge", vec![s("sip:a@x"), s("sip:b@x")], "expected from, to, op[, sdp]"),
        ];
        for (name, args, want) in cases {
            let e = fixup_err(&reg, name, args);
            assert!(e.contains(want), "{name}({args:?}): {e}");
        }
    }

    #[test]
    fn dlg_set_timeout_on_the_current_dialog_or_by_id() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let d = confirmed(&dlg, "", "");
        let (e, id) = {
            let g = lock(&d);
            (i64::from(g.h_entry), i64::from(g.h_id))
        };
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_set_timeout", &[Arg::Int(60)])), -1, "no dialog");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_set_timeout", &[Arg::Int(0)])), -1, "a timeout must be > 0");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_set_timeout", &[Arg::Int(60)])), 1);
        assert_eq!(lock(&d).lifetime, 60);
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_set_timeout", &[Arg::Int(70), Arg::Int(e), Arg::Int(id)])), 1, "by id");
        assert_eq!(lock(&d).lifetime, 70);
        for bad in [id + 1000, -1, 1 << 40] {
            assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_set_timeout", &[Arg::Int(80), Arg::Int(e), Arg::Int(bad)])), -1, "h_id {bad}");
        }
        assert_eq!(lock(&d).lifetime, 70);
    }

    #[test]
    fn dlg_bye_sends_bye_to_the_chosen_sides_of_a_confirmed_dialog() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let wire = start(&reg, &dlg);
        let early = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        assert_eq!(with_dlg(Some(&early), |ctx| call(&reg, ctx, "dlg_bye", &[s("all")])), -1, "not before it's confirmed");
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_bye", &[s("all")])), -1, "no dialog");
        let d = confirmed(&dlg, "", "");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("callee")])), 1);
        let byes = wire.requests("BYE");
        assert_eq!(byes.len(), 1);
        assert!(byes[0].1.starts_with("BYE sip:bob@203.0.113.2 SIP/2.0\r\n") && byes[0].1.contains("\r\nCSeq: 11 BYE\r\n"), "{}", byes[0].1);
        assert_eq!(state(&d), State::Confirmed, "one side only: the dialog stays");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("caller")])), 1);
        let byes = wire.requests("BYE");
        assert!(byes.len() == 2 && byes[1].1.starts_with("BYE sip:alice@198.51.100.1 SIP/2.0\r\n") && byes[1].1.contains("\r\nCSeq: 2 BYE\r\n"), "{byes:?}");
        assert_eq!(byes[1].0, src(CALLER));
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("all")])), 1);
        assert_eq!(wire.requests("BYE").len(), 4);
        assert!(wire.requests("BYE")[2].1.contains("\r\nCSeq: 12 BYE\r\n"), "the caller's CSeq space moved on");
        assert_eq!((state(&d), lock(&d).end_reason), (State::Deleted, "admin"));
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("all")])), -1, "once it ended");
    }

    #[test]
    fn dlg_bye_without_a_running_tm_fails_but_still_ends_the_dialog() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let d = confirmed(&dlg, "", "");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("callee")])), -1);
        assert_eq!(state(&d), State::Confirmed);
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_bye", &[s("all")])), -1);
        assert_eq!(state(&d), State::Deleted);
        // No tm at all: nothing is sent.
        let bare = Dialog::default();
        let d = confirmed(&bare, "", "");
        assert!(!bare.send_bye(&d, true, true) && !bare.refer(&d, true, "sip:x@y"));
    }

    #[test]
    fn dialog_properties_go_to_the_dialog_or_the_context() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let props = ["timeout-bye", "ka-src", "ka-dst", "timeout-noreset"];
        let c = with_dlg(None, |ctx| {
            for p in props {
                assert_eq!(call(&reg, ctx, "dlg_set_property", &[s(p)]), 1, "{p}");
            }
            call(&reg, ctx, "dlg_reset_property", &[s("ka-dst")]);
            let c = ctx.ext::<DlgCtx>().unwrap();
            (c.timeout_bye, c.ka_src, c.ka_dst, c.noreset)
        });
        assert_eq!(c, (Some(true), Some(true), Some(false), Some(true)));
        let d = confirmed(&dlg, "", "");
        let flags = |d: &DlgRef| {
            let g = lock(d);
            (g.timeout_bye, g.ka_src, g.ka_dst, g.timeout_noreset)
        };
        for p in props {
            assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_set_property", &[s(p)])), 1);
        }
        assert_eq!(flags(&d), (true, true, true, true));
        for p in props {
            assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_reset_property", &[s(p)])), 1);
        }
        assert_eq!(flags(&d), (false, false, false, false));
    }

    #[test]
    fn dialog_profiles_from_the_script() {
        let dlg = Arc::new(Dialog::default());
        dlg.set_param("profiles_with_value", &s("caller")).unwrap();
        dlg.set_param("profiles_no_value", &s("calls")).unwrap();
        let reg = registry(&dlg);
        let d = confirmed(&dlg, "", "");
        let on = |name: &str, args: &[Arg]| with_dlg(Some(&d), |ctx| call(&reg, ctx, name, args));
        for f in ["set_dlg_profile", "unset_dlg_profile", "is_in_profile"] {
            assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, f, &[s("calls")])), -1, "{f} without a dialog");
        }
        assert_eq!(on("is_in_profile", &[s("calls")]), -1);
        assert_eq!(on("set_dlg_profile", &[s("calls")]), 1);
        assert_eq!(on("set_dlg_profile", &[s("calls")]), 1);
        assert_eq!(on("set_dlg_profile", &[s("caller"), s("alice")]), 1);
        assert_eq!(on("set_dlg_profile", &[s("caller"), s("bob")]), 1);
        assert_eq!(lock(&d).profiles.len(), 3, "set twice, kept once");
        assert_eq!(on("is_in_profile", &[s("calls")]), 1);
        assert_eq!(on("is_in_profile", &[s("caller")]), 1, "any value");
        assert_eq!(on("is_in_profile", &[s("caller"), s("bob")]), 1);
        assert_eq!(on("is_in_profile", &[s("caller"), s("carol")]), -1);
        let size = |args: &[Arg]| {
            with_dlg(None, |ctx| {
                assert_eq!(call(&reg, ctx, "get_profile_size", args), 1);
                pv(&reg, "$var(n)").get(ctx)
            })
        };
        let var = fmt(&reg, "$var(n)");
        assert_eq!(size(&[s("caller"), var.clone()]), Val::Int(1));
        assert_eq!(size(&[s("caller"), s("bob"), var.clone()]), Val::Int(1));
        assert_eq!(size(&[s("caller"), s("carol"), var.clone()]), Val::Int(0));
        assert_eq!(on("unset_dlg_profile", &[s("caller"), s("carol")]), -1, "not in it");
        assert_eq!(on("unset_dlg_profile", &[s("caller"), s("bob")]), 1);
        assert_eq!(on("is_in_profile", &[s("caller"), s("bob")]), -1);
        assert_eq!(on("is_in_profile", &[s("caller"), s("alice")]), 1, "only that value went");
        assert_eq!(on("unset_dlg_profile", &[s("calls")]), 1);
        assert_eq!(on("unset_dlg_profile", &[s("calls")]), -1);
        // dlg_set_timeout_by_profile: an empty value matches nothing; a value
        // given for a profile without values is ignored.
        let by_profile = |args: &[Arg]| with_dlg(None, |ctx| call(&reg, ctx, "dlg_set_timeout_by_profile", args));
        assert_eq!(by_profile(&[s("caller"), s(""), Arg::Int(5)]), -1);
        assert_eq!(by_profile(&[s("caller"), s("alice"), Arg::Int(55)]), 1);
        assert_eq!(lock(&d).lifetime, 55);
        assert_eq!(on("set_dlg_profile", &[s("calls")]), 1);
        assert_eq!(by_profile(&[s("calls"), s("ignored"), Arg::Int(66)]), 1);
        assert_eq!(lock(&d).lifetime, 66);
    }

    #[test]
    fn dialog_flags_on_the_dialog_or_the_context() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        with_dlg(None, |ctx| {
            assert_eq!(call(&reg, ctx, "dlg_isflagset", &[Arg::Int(3)]), -1);
            assert_eq!(call(&reg, ctx, "dlg_setflag", &[Arg::Int(3)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_setflag", &[Arg::Int(31)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_isflagset", &[Arg::Int(3)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_resetflag", &[Arg::Int(3)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_isflagset", &[Arg::Int(3)]), -1);
            assert_eq!(ctx.ext::<DlgCtx>().unwrap().flags, 1 << 31);
            // A flag from a variable out of range: refused when run.
            pv(&reg, "$var(f)").set(ctx, Val::Int(40)).unwrap();
            for f in ["dlg_setflag", "dlg_resetflag", "dlg_isflagset"] {
                assert_eq!(call(&reg, ctx, f, &[fmt(&reg, "$var(f)")]), -1, "{f}");
            }
        });
        let d = confirmed(&dlg, "", "");
        with_dlg(Some(&d), |ctx| {
            assert_eq!(call(&reg, ctx, "dlg_setflag", &[Arg::Int(0)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_setflag", &[Arg::Int(5)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_resetflag", &[Arg::Int(0)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_isflagset", &[Arg::Int(5)]), 1);
            assert_eq!(call(&reg, ctx, "dlg_isflagset", &[Arg::Int(0)]), -1);
        });
        assert_eq!(lock(&d).sflags, 1 << 5);
    }

    #[test]
    fn dlg_refer_sends_refer_to_one_side_as_the_other() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let to = [s("callee"), s("sip:carol@c.example")];
        let d = confirmed(&dlg, "", "");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_refer", &to)), -1, "tm not started");
        let wire = start(&reg, &dlg);
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_refer", &to)), -1, "no dialog");
        let early = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        assert_eq!(with_dlg(Some(&early), |ctx| call(&reg, ctx, "dlg_refer", &to)), -1, "not confirmed");
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_refer", &to)), 1);
        let r = &wire.requests("REFER")[0].1;
        assert!(r.starts_with("REFER sip:bob@203.0.113.2 SIP/2.0\r\n"), "{r}");
        assert_eq!(hdr(r, "Refer-To").as_deref(), Some("<sip:carol@c.example>"));
        assert_eq!(hdr(r, "Referred-By").as_deref(), Some("<sip:controller@ferrosip.invalid>"));
        assert_eq!(hdr(r, "Contact").as_deref(), Some("<sip:alice@198.51.100.1>"), "the caller gets the NOTIFYs");
        assert_eq!(hdr(r, "CSeq").as_deref(), Some("12 REFER"), "11 went to the REFER that could not be sent");
        assert_eq!(lock(&d).caller.cseq, 12);
        // To the caller, whose peer has no Contact: none is added.
        lock(&d).callee.contact.clear();
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_refer", &[s("caller"), s("<sip:dave@d.example>")])), 1);
        let r = &wire.requests("REFER")[1].1;
        assert!(r.starts_with("REFER sip:alice@198.51.100.1 SIP/2.0\r\n") && hdr(r, "Contact").is_none(), "{r}");
        assert_eq!((hdr(r, "Refer-To").as_deref(), hdr(r, "CSeq").as_deref()), (Some("<sip:dave@d.example>"), Some("2 REFER")));
        assert_eq!(lock(&d).callee.cseq, 2);
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_refer", &to)), -1, "the callee has no Contact: nowhere to send it");
        lock(&d).caller.contact.clear();
        assert_eq!(with_dlg(Some(&d), |ctx| call(&reg, ctx, "dlg_refer", &[s("caller"), s("x")])), -1);
    }

    #[test]
    fn dlg_bridge_calls_answers_refers_and_hangs_up() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let args = [s("<sip:alice@198.51.100.1>"), s("sip:bob@b.example"), s("")];
        let e = dlg.bridge("sip:alice@198.51.100.1", "sip:bob@b.example", "", None).unwrap_err();
        assert_eq!(e, "not started");
        let wire = start(&reg, &dlg);
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_bridge", &[s("sip:a@x"), s("sip:b@x"), s("not a uri")])), -1, "bad proxy");
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_bridge", &args)), 1);
        let tm = reg.api::<Tm>().unwrap();
        let inv = wire.requests("INVITE")[0].1.clone();
        assert!(inv.starts_with("INVITE sip:alice@198.51.100.1 SIP/2.0\r\n"), "{inv}");
        assert_eq!(hdr(&inv, "Contact").as_deref(), Some("<sip:controller@192.0.2.10:5060>"), "our address");
        assert!(hdr(&inv, "From").unwrap().starts_with("<sip:controller@ferrosip.invalid>;tag="));
        assert!(inv.ends_with(HOLD_SDP), "on hold");
        answer(&tm, &inv, "200 OK", "Contact: <sip:alice@198.51.100.1:5070>\n");
        let ack = &wire.requests("ACK")[0].1;
        assert!(ack.starts_with("ACK sip:alice@198.51.100.1:5070 SIP/2.0\r\n") && hdr(ack, "CSeq").as_deref() == Some("1 ACK"), "{ack}");
        let refer = wire.requests("REFER")[0].1.clone();
        assert_eq!((hdr(&refer, "Refer-To").as_deref(), hdr(&refer, "CSeq").as_deref()), (Some("<sip:bob@b.example>"), Some("2 REFER")));
        assert!(wire.requests("BYE").is_empty(), "not before the REFER is answered");
        answer(&tm, &refer, "603 Declined", "");
        let byes = wire.requests("BYE");
        assert_eq!(byes.len(), 1, "our leg is hung up even when the REFER fails");
        assert_eq!(hdr(&byes[0].1, "CSeq").as_deref(), Some("3 BYE"));
        // The callee refuses; or answers without a Contact: nothing more.
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_bridge", &[s("sip:x@198.51.100.2"), s("sip:y@b.example"), s(""), s("v=0\r\n")])), 1);
        let inv = wire.requests("INVITE").pop().unwrap().1;
        assert!(inv.starts_with("INVITE sip:x@198.51.100.2 ") && inv.ends_with("\r\n\r\nv=0\r\n"), "the given SDP: {inv}");
        answer(&tm, &inv, "486 Busy Here", "");
        assert_eq!(wire.requests("REFER").len(), 1);
        assert!(rpc(&reg, "dlg.bridge_dlg", json!(["sip:z@198.51.100.3", "sip:y@b.example", "."])).is_ok());
        let inv = wire.requests("INVITE").pop().unwrap().1;
        assert!(inv.starts_with("INVITE sip:z@198.51.100.3 "), "{inv}");
        let acks = wire.requests("ACK").len();
        answer(&tm, &inv, "200 OK", "");
        assert_eq!((wire.requests("ACK").len(), wire.requests("REFER").len()), (acks, 1), "a 2xx without Contact: no dialog");
        // bridge_contact and an outbound proxy.
        dlg.set_param("bridge_contact", &s("sip:me@192.0.2.10:5099")).unwrap();
        assert_eq!(with_dlg(None, |ctx| call(&reg, ctx, "dlg_bridge", &[s("sip:w@w.example"), s("sip:y@b.example"), s("sip:192.0.2.77")])), 1);
        let (dst, inv) = wire.requests("INVITE").pop().unwrap();
        assert_eq!((dst, hdr(&inv, "Contact").as_deref()), (src("192.0.2.77:5060"), Some("<sip:me@192.0.2.10:5099>")));
        assert!(rpc(&reg, "dlg.bridge_dlg", json!(["sip:w@w.example", "sip:y@b.example", "bad proxy"])).unwrap_err().contains("bad outbound proxy"));
    }

    #[test]
    fn dlg_bridge_sends_one_bye_when_the_refer_cannot_be_sent() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let wire = start(&reg, &dlg);
        let tm = reg.api::<Tm>().unwrap();
        dlg.bridge("sip:alice@198.51.100.1", "sip:bob@b.example", "", None).unwrap();
        let inv = wire.requests("INVITE")[0].1.clone();
        wire.down.store(true, Ordering::Relaxed);
        answer(&tm, &inv, "200 OK", "Contact: <sip:alice@198.51.100.1>\n");
        assert_eq!((wire.requests("ACK").len(), wire.requests("REFER").len()), (1, 1), "tried");
        assert_eq!(wire.requests("BYE").len(), 1, "{:?}", wire.requests("BYE"));
    }

    #[test]
    fn dialog_keepalives_probe_both_sides_and_end_the_call_on_481() {
        let dlg = Arc::new(Dialog::default());
        dlg.set_param("ka_interval", &Arg::Int(30)).unwrap();
        let reg = registry(&dlg);
        let (_, ends) = watch(&dlg);
        let d = confirmed(&dlg, "", "");
        dlg.tick();
        // No tm running yet: the OPTIONS can't go out (logged).
        lock(&d).ka_src = true;
        lock(&d).ka_dst = true;
        dlg.tick();
        assert_eq!(state(&d), State::Confirmed);
        let wire = start(&reg, &dlg);
        lock(&d).next_ka = 0;
        dlg.tick();
        let opts = wire.requests("OPTIONS");
        assert_eq!(opts.len(), 2, "{opts:?}");
        // The probes that could not go out used CSeq 11 and 2.
        assert!(opts[0].1.starts_with("OPTIONS sip:bob@203.0.113.2 ") && hdr(&opts[0].1, "CSeq").as_deref() == Some("12 OPTIONS"));
        assert!(opts[1].1.starts_with("OPTIONS sip:alice@198.51.100.1 ") && hdr(&opts[1].1, "CSeq").as_deref() == Some("3 OPTIONS"));
        assert!(lock(&d).next_ka >= unix_secs() + 29, "next probe in ka_interval");
        dlg.tick();
        assert_eq!(wire.requests("OPTIONS").len(), 2, "not due yet");
        let tm = reg.api::<Tm>().unwrap();
        answer(&tm, &opts[0].1, "200 OK", "");
        assert_eq!(state(&d), State::Confirmed);
        answer(&tm, &opts[1].1, "481 Call/Transaction Does Not Exist", "");
        assert_eq!((state(&d), lock(&d).end_reason), (State::Deleted, "keepalive"));
        assert_eq!(wire.requests("BYE").len(), 2, "both sides");
        assert_eq!(lock(&ends).len(), 1);
        // Only the callee probed, on an unconfirmed dialog: never.
        let early = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        lock(&early).ka_dst = true;
        lock(&early).init_ts = unix_secs();
        dlg.tick();
        assert_eq!(wire.requests("OPTIONS").len(), 2);
        // Without tm: nothing.
        let bare = Arc::new(Dialog::default());
        let x = confirmed(&bare, "", "");
        bare.keepalive(&x);
        assert_eq!(lock(&x).caller.cseq, 10);
    }

    #[test]
    fn dialog_timer_skips_ended_dialogs_still_listed() {
        let dlg = Arc::new(Dialog::default());
        let (_, ends) = watch(&dlg);
        let d = confirmed(&dlg, "", "");
        {
            let mut g = lock(&d);
            g.state = State::Deleted;
            g.timeout_at = 0;
        }
        dlg.tick();
        assert!(lock(&ends).is_empty() && lock(&d).end_reason.is_empty(), "not ended twice");
        assert_eq!(dlg.count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dialog_end_and_remove_happen_once() {
        let dlg = Dialog::default();
        let (states, ends) = watch(&dlg);
        let d = confirmed(&dlg, "", "");
        dlg.end(&d, None, false, "admin");
        dlg.end(&d, None, false, "timeout");
        dlg.remove(&d);
        assert_eq!((lock(&d).end_reason, dlg.count.load(Ordering::Relaxed), lock(&ends).len()), ("admin", 0, 1));
        assert_eq!(lock(&states).iter().filter(|s| **s == "terminated").count(), 1);
        dlg.fail(&d, None);
        assert_eq!(lock(&d).end_reason, "admin", "a failure after the end changes nothing");
    }

    #[test]
    fn dialog_did_cookie_only_counts_on_our_own_route_entry() {
        let dlg = Dialog::default();
        let _ = dlg.net.set(Arc::new(Us));
        dlg.match_mode.store(0, Ordering::Relaxed);
        let d = confirmed(&dlg, "", "");
        let did = {
            let g = lock(&d);
            did_value(g.h_entry, g.h_id)
        };
        let matched = |route: &str| {
            with_ctx(&in_dialog("INFO", 12, true, &format!("Route: {route}\n")), src(CALLER), |ctx| {
                dlg.on_request(ctx);
                ctx.ext::<Current>().is_some()
            })
        };
        assert!(matched(&format!("<sip:192.0.2.10;lr;did={did}>")));
        assert!(!matched(&format!("<sip:10.9.9.9;lr;did={did}>")), "someone else's cookie");
        assert!(matched(&format!("<sip:10.9.9.9;lr;did=0.0>, <sip:192.0.2.10;lr;did={did}>")), "ours further down");
    }

    #[test]
    fn dialog_is_not_found_for_a_rebuilt_non_invite() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        confirmed(&dlg, "", "");
        let rc = with_ctx(&in_dialog("BYE", 11, true, ""), src(CALLER), |ctx| {
            ctx.ext.push(Box::new(sip_core::module::FakedMsg));
            call(&reg, ctx, "is_known_dlg", &[])
        });
        assert_eq!(rc, -1);
    }

    #[test]
    fn dialog_variables() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let d = confirmed(&dlg, "Record-Route: <sip:10.0.0.1;lr>\n", "Record-Route: <sip:10.0.0.3;lr>, <sip:10.0.0.1;lr>\n");
        {
            let mut g = lock(&d);
            (g.sflags, g.timeout_route, g.callee.cseq, g.start_ts) = (6, Some("tr".into()), 4, unix_secs() - 5);
        }
        let (e, id, start, timeout) = {
            let g = lock(&d);
            (i64::from(g.h_entry), i64::from(g.h_id), int_of(g.start_ts), int_of(g.timeout_at))
        };
        let cases: Vec<(&str, Val)> = vec![
            ("h_id", Val::Int(id)),
            ("h_entry", Val::Int(e)),
            ("state", Val::Int(3)),
            ("callid", Val::str("c1")),
            ("from_uri", Val::str("sip:alice@a.example")),
            ("from_tag", Val::str("ft")),
            ("to_uri", Val::str("sip:bob@b.example")),
            ("to_tag", Val::str("tt")),
            ("start_ts", Val::Int(start)),
            ("timeout", Val::Int(timeout)),
            ("lifetime", Val::Int(43200)),
            ("sflags", Val::Int(6)),
            ("from_contact", Val::str("sip:alice@198.51.100.1")),
            ("to_contact", Val::str("sip:bob@203.0.113.2")),
            ("from_cseq", Val::Int(10)),
            ("to_cseq", Val::Int(4)),
            ("from_rs", Val::str("<sip:10.0.0.1;lr>")),
            ("to_rs", Val::str("<sip:10.0.0.1;lr>,<sip:10.0.0.3;lr>")),
            ("toroute_name", Val::str("tr")),
            ("end_reason", Val::Null),
            ("bogus", Val::Null),
        ];
        with_dlg(Some(&d), |ctx| {
            for (name, want) in &cases {
                assert_eq!(pv(&reg, &format!("$dlg({name})")).get(ctx), *want, "$dlg({name})");
            }
            let Val::Int(dur) = pv(&reg, "$dlg(duration)").get(ctx) else { panic!("duration") };
            assert!((5..=7).contains(&dur), "running: until now ({dur})");
        });
        with_dlg(None, |ctx| assert_eq!(pv(&reg, "$dlg(callid)").get(ctx), Val::Null, "no dialog"));
        lock(&d).timeout_route = None;
        with_dlg(Some(&d), |ctx| assert_eq!(pv(&reg, "$dlg(toroute_name)").get(ctx), Val::Null));
        dlg.end(&d, None, false, "admin");
        {
            let mut g = lock(&d);
            g.end_ts = g.start_ts + 42;
        }
        with_dlg(Some(&d), |ctx| {
            assert_eq!(pv(&reg, "$dlg(end_reason)").get(ctx), Val::str("admin"));
            assert_eq!(pv(&reg, "$dlg(duration)").get(ctx), Val::Int(42), "ended: until the end");
        });
        // $dlg_var: set, read, removed by $null.
        let d = confirmed(&dlg, "", "");
        let var = pv(&reg, "$dlg_var(k)");
        with_dlg(Some(&d), |ctx| {
            var.set(ctx, Val::str("v")).unwrap();
            assert_eq!(var.get(ctx), Val::str("v"));
            var.set(ctx, Val::Null).unwrap();
            assert_eq!(var.get(ctx), Val::Null);
        });
        assert!(lock(&d).vars.is_empty());
        with_dlg(None, |ctx| assert!(var.set(ctx, Val::str("v")).is_err(), "no dialog"));
    }

    #[test]
    fn dialog_context_variable() {
        let dlg = Arc::new(Dialog::default());
        let reg = registry(&dlg);
        let get = |ctx: &mut Ctx<'_, '_>, n: &str| pv(&reg, &format!("$dlg_ctx({n})")).get(ctx);
        let set = |ctx: &mut Ctx<'_, '_>, n: &str, v: Val| pv(&reg, &format!("$dlg_ctx({n})")).set(ctx, v);
        with_dlg(None, |ctx| {
            for (n, want) in [("on", 0), ("flags", 0), ("timeout", 0), ("timeout_bye", 0), ("set", 0), ("dir", 0)] {
                assert_eq!(get(ctx, n), Val::Int(want), "{n}");
            }
            assert_eq!((get(ctx, "timeout_route"), get(ctx, "bogus")), (Val::Null, Val::Null));
            set(ctx, "on", Val::str("1")).unwrap();
            set(ctx, "flags", Val::Int(-1)).unwrap();
            assert_eq!(ctx.ext::<DlgCtx>().unwrap().flags, u32::MAX, "-1: all 32 bits");
            set(ctx, "flags", Val::Int(5)).unwrap();
            assert!(set(ctx, "flags", Val::Int(1 << 33)).unwrap_err().contains("not 32 flag bits"));
            set(ctx, "timeout", Val::Int(0)).unwrap();
            set(ctx, "timeout_bye", Val::Int(1)).unwrap();
            set(ctx, "timeout_route", Val::str("tr")).unwrap();
            assert!(set(ctx, "on", Val::str("yes")).unwrap_err().contains("needs a number"));
            assert!(set(ctx, "set", Val::Int(1)).unwrap_err().contains("read-only or unknown"));
            for (n, want) in
                [("on", Val::Int(1)), ("flags", Val::Int(5)), ("timeout", Val::Int(1)), ("timeout_bye", Val::Int(1)), ("timeout_route", Val::str("tr"))]
            {
                assert_eq!(get(ctx, n), want, "{n}");
            }
            set(ctx, "timeout_route", Val::Null).unwrap();
            assert_eq!(get(ctx, "timeout_route"), Val::Null);
        });
        // With a dialog: applied to it too; the direction of the message.
        let d = confirmed(&dlg, "", "");
        with_dlg(Some(&d), |ctx| {
            assert_eq!((get(ctx, "set"), get(ctx, "dir")), (Val::Int(1), Val::Int(1)), "from the caller");
            set(ctx, "timeout", Val::Int(99)).unwrap();
            set(ctx, "timeout_bye", Val::Int(1)).unwrap();
            set(ctx, "timeout_route", Val::str("")).unwrap();
        });
        {
            let g = lock(&d);
            assert_eq!((g.lifetime, g.timeout_bye, g.timeout_route.as_deref()), (99, true, None), "an empty name: none");
        }
        with_dlg(Some(&d), |ctx| set(ctx, "timeout_route", Val::str("tr2")).unwrap());
        assert_eq!(lock(&d).timeout_route.as_deref(), Some("tr2"));
        let dir = |msg: &str, from: &str| {
            with_ctx(msg, src(from), |ctx| {
                ctx.ext.push(Box::new(Current(d.clone())));
                get(ctx, "dir")
            })
        };
        assert_eq!(dir(&in_dialog("INFO", 5, false, ""), CALLEE), Val::Int(2), "a request from the callee");
        let ok = String::from_utf8(reply("200 OK", "tt", "")).unwrap();
        assert_eq!(dir(&ok, CALLEE), Val::Int(2), "a reply to the caller's request");
        let ok_up = ok.replace("From: \"Alice\" <sip:alice@a.example>;tag=ft", "From: <sip:bob@b.example>;tag=tt");
        assert_eq!(dir(&ok_up, CALLER), Val::Int(1), "a reply to the callee's request");
        let broken = in_dialog("INFO", 5, false, "").replace(";tag=tt", "");
        assert_eq!(dir(&broken, CALLEE), Val::Int(0), "no From tag");
    }

    #[test]
    fn dialog_rpc_commands() {
        let dlg = Arc::new(Dialog::default());
        dlg.set_param("profiles_with_value", &s("caller")).unwrap();
        let reg = registry(&dlg);
        let early = manage(&dlg, &invite("").replace("c1", "c2")).1.unwrap();
        let d = confirmed(&dlg, "", "");
        lock(&d).profiles = vec![("caller".into(), Some("alice".into()))];
        lock(&early).profiles = vec![("caller".into(), Some("bob".into()))];
        assert_eq!(rpc(&reg, "dlg.stats_active", json!([])), Ok(json!({"starting": 1, "connecting": 0, "answering": 1, "ongoing": 0, "all": 2})));
        let ids = |p: Value| rpc(&reg, "dlg.profile_list", p).unwrap().as_array().unwrap().iter().map(|j| j["call-id"].clone()).collect::<Vec<_>>();
        assert_eq!(ids(json!(["caller", "alice"])), [json!("c1")]);
        assert_eq!(ids(json!(["caller"])).len(), 2);
        assert!(ids(json!(["calls"])).is_empty());
        assert!(rpc(&reg, "dlg.profile_list", json!([])).is_err());
        assert_eq!(rpc(&reg, "dlg.profile_get_size", json!(["caller", "bob"])), Ok(json!(1)));
        // Not confirmed yet: refused.
        let early_id = lock(&early).h_id;
        assert_eq!(rpc(&reg, "dlg.terminate_dlg", json!(["c2", "ft", ""])), Err("dialog not confirmed".into()));
        assert_eq!(rpc(&reg, "dlg.end_dlg", json!([0, early_id])), Err("dialog not confirmed".into()));
        assert_eq!(rpc(&reg, "dlg.is_alive", json!([0, early_id])), Err("dialog not confirmed".into()));
        assert_eq!(rpc(&reg, "dlg.end_dlg", json!([0, -1])), Err("dialog not found".into()));
        let id = lock(&d).h_id;
        assert_eq!(rpc(&reg, "dlg.is_alive", json!([0, id])), Ok(json!(0)));
        // dlg.set_state: every state, defaults to 5.
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft"])), Err("Need the callid, from tag,to tag and state".into()));
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", "", 9])), Err("Invalid state value".into()));
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", "", "x"])).unwrap_err(), "expected an integer, got \"x\"");
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c9", "ft", "", 2])), Err("Dialog not found".into()));
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", "", 2])), Ok(json!("Done")));
        assert_eq!(state(&early), State::Early);
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", "", 4])), Ok(json!("Done")));
        assert_eq!(state(&early), State::ConfirmedAck);
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", "", 1])), Ok(json!("Done")));
        assert_eq!(state(&early), State::Unconfirmed);
        assert_eq!(rpc(&reg, "dlg.set_state", json!(["c2", "ft", ""])), Ok(json!("Done")));
        assert_eq!(state(&early), State::Deleted);
        assert_eq!(rpc(&reg, "dlg.stats_active", json!([])).unwrap()["all"], 1);
        assert_eq!(rpc(&reg, "dlg.terminate_dlg", json!(["c1", "ft", "tt"])), Ok(json!(0)));
        assert_eq!(state(&d), State::Deleted);
        assert_eq!(rpc(&reg, "dlg.terminate_dlg", json!(["c1", "ft", "tt"])), Err("dialog not found".into()));
    }
}
