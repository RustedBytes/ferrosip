//! `dispatcher` — load balancing and failover over sets of destinations.
//!
//! Destinations come from `list_file` (Kamailio `dispatcher.list` format:
//! `setid uri [flags [priority [attrs]]]`) or the `dispatcher` table of
//! `db_url`. `ds_select_dst(set, alg)` picks the first destination and
//! keeps the others, in failover order, in `$xavp(_dsdst_)` — which tm
//! carries into `failure_route`, where `ds_next_dst()` moves on.
//!
//! Destinations are probed with OPTIONS through tm's UAC API
//! (`ds_ping_interval`); state changes raise `event_route[dispatcher:dst-down]`
//! and `event_route[dispatcher:dst-up]` (with `$ru` = the destination).

use crate::{args, attr, parse_ip, rand_u64, uri_dest};
use mod_txn::{Tm, UacRequest};
use sip_core::module::{DynInt, DynStr, rc};
use sip_core::pv::{PvRef, Val};
use sip_core::schema::{ParamSpec, Ty, Unit, p, pr};
use sip_core::serde_json::{Value, json};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Registry, RouteHub, TxnVars, fx_hash, want_args};
use sip_parser::uri::name_addr;
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub const DS_INACTIVE: u8 = 1;
pub const DS_TRYING: u8 = 2;
pub const DS_DISABLED: u8 = 4;
pub const DS_PROBING: u8 = 8;

const XAVP: &str = "_dsdst_";

pub struct Dst {
    pub setid: i32,
    pub uri: String,
    pub dest: Option<Dest>,
    pub priority: i32,
    pub attrs: String,
    weight: u32,
    rweight: u32,
    state: AtomicU8,
    fails: AtomicU32,
    oks: AtomicU32,
    /// alg 10: calls in progress (`maxload` attribute = capacity).
    load: AtomicU32,
    maxload: u32,
    /// alg 13: round-trip times of the OPTIONS probes.
    lat: Mutex<Latency>,
}

/// Probe RTT statistics (Kamailio `ds_ping_latency_stats`), ms.
#[derive(Clone, Copy, Default, Debug)]
struct Latency {
    count: u64,
    avg: f64,
    m2: f64,
    est: f64,
    max: f64,
    timeouts: u64,
}

impl Latency {
    fn add(&mut self, ms: f64, alpha: f64) {
        self.count = self.count.saturating_add(1);
        let d = ms - self.avg;
        self.avg += d / self.count as f64;
        self.m2 += d * (ms - self.avg);
        self.est = if self.count == 1 { ms } else { alpha * self.est + (1.0 - alpha) * ms };
        self.max = self.max.max(ms);
    }

    fn std(&self) -> f64 {
        if self.count > 1 { (self.m2 / self.count.saturating_sub(1) as f64).sqrt() } else { 0.0 }
    }
}

impl Dst {
    fn active(&self) -> bool {
        self.state.load(Ordering::Relaxed) & (DS_INACTIVE | DS_DISABLED) == 0
    }
}

struct Set {
    dsts: Vec<Arc<Dst>>,
    rr: AtomicUsize,
    /// alg 9: 100 slots distributed by `weight`.
    wdist: Vec<usize>,
}

type Sets = BTreeMap<i32, Arc<Set>>;
/// ds_is_from_list([group[, mode[, uri]]])
type FromListArgs = (Option<DynInt>, Option<DynInt>, Option<DynStr>);

pub struct Dispatcher {
    list_file: Mutex<Option<String>>,
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    sets: RwLock<Arc<Sets>>,
    ping_interval: AtomicU64,
    ping_method: Mutex<String>,
    ping_from: Mutex<String>,
    probing_mode: AtomicU32,
    probing_threshold: AtomicU32,
    inactive_threshold: AtomicU32,
    reply_codes: Mutex<Vec<(u16, u16)>>,
    hash_pvar: Mutex<Option<String>>,
    setid_pvname: Mutex<Option<String>>,
    attrs_pvname: Mutex<Option<String>>,
    hash_fmt: OnceLock<sip_core::Fmt>,
    setid_pv: OnceLock<PvRef>,
    attrs_pv: OnceLock<PvRef>,
    tm: OnceLock<Arc<Tm>>,
    hub: OnceLock<Arc<RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
    /// alg 10: Call-ID → (set, destination URI) holding a unit of load.
    calls: Mutex<HashMap<String, (i32, String)>>,
    /// `ds_latency_estimator_alpha` (thousandths; weight of the old estimate).
    alpha: AtomicU32,
    latency_stats: std::sync::atomic::AtomicBool,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self {
            list_file: Mutex::new(None),
            db_url: Mutex::new(None),
            table: Mutex::new("dispatcher".into()),
            sets: RwLock::new(Arc::new(BTreeMap::new())),
            ping_interval: AtomicU64::new(0),
            ping_method: Mutex::new("OPTIONS".into()),
            ping_from: Mutex::new("sip:dispatcher@localhost".into()),
            probing_mode: AtomicU32::new(0),
            probing_threshold: AtomicU32::new(1),
            inactive_threshold: AtomicU32::new(1),
            reply_codes: Mutex::new(Vec::new()),
            hash_pvar: Mutex::new(None),
            setid_pvname: Mutex::new(None),
            attrs_pvname: Mutex::new(None),
            hash_fmt: OnceLock::new(),
            setid_pv: OnceLock::new(),
            attrs_pv: OnceLock::new(),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
            net: OnceLock::new(),
            calls: Mutex::default(),
            alpha: AtomicU32::new(900),
            latency_stats: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

/// One row: (setid, uri, flags, priority, attrs).
type Row = (i32, String, u8, i32, String);

fn parse_list(text: &str) -> Result<Vec<Row>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        let bad = || format!("dispatcher list line {}: {line:?}", n.saturating_add(1));
        let setid = f.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
        let uri = f.next().ok_or_else(bad)?.to_string();
        let flags = f.next().map_or(Ok(0), |s| s.parse()).map_err(|_| bad())?;
        let prio = f.next().map_or(Ok(0), |s| s.parse()).map_err(|_| bad())?;
        let attrs = f.collect::<Vec<_>>().join(" ").trim_matches('"').to_string();
        out.push((setid, uri, flags, prio, attrs));
    }
    Ok(out)
}

impl Dispatcher {
    fn load_rows(&self) -> Result<Vec<Row>, String> {
        if let Some(f) = lock(&self.list_file).clone() {
            let text = std::fs::read_to_string(&f).map_err(|e| format!("dispatcher list_file {f}: {e}"))?;
            return parse_list(&text);
        }
        if let Some(url) = lock(&self.db_url).clone() {
            let table = lock(&self.table).clone();
            let rows = crate::load_table(&url, &table, &["setid", "destination", "flags", "priority", "attrs"])?;
            return Ok(rows
                .into_iter()
                .filter_map(|r| {
                    let i = |k: usize| r.get(k).and_then(|v| v.int()).unwrap_or(0);
                    let dest = || r.get(1).map(|v| v.text()).unwrap_or_default();
                    let (Ok(setid), Ok(flags), Ok(prio)) = (i32::try_from(i(0)), u8::try_from(i(2)), i32::try_from(i(3))) else {
                        sip_core::log::log(
                            sip_core::log::L_ERR,
                            &format!("dispatcher: {}: setid {}, flags {} or priority {} out of range, row skipped", dest(), i(0), i(2), i(3)),
                        );
                        return None;
                    };
                    Some((setid, dest(), flags, prio, r.get(4).map(|v| v.text()).unwrap_or_default()))
                })
                .collect());
        }
        Err("dispatcher: set list_file or db_url".into())
    }

    /// (Re)load the destination sets; states of known destinations survive.
    fn reload(&self) -> Result<usize, String> {
        let rows = self.load_rows()?;
        let old = read(&self.sets).clone();
        let mut by_set: BTreeMap<i32, Vec<Arc<Dst>>> = BTreeMap::new();
        let n = rows.len();
        for (setid, uri, flags, priority, attrs) in rows {
            if parse_uri(uri.as_bytes()).is_none() {
                return Err(format!("dispatcher: bad destination URI {uri:?}"));
            }
            let prev_dst = old.get(&setid).and_then(|s| s.dsts.iter().find(|d| d.uri == uri).cloned());
            let prev = prev_dst.as_ref().map(|d| d.state.load(Ordering::Relaxed));
            let num = |k| attr(&attrs, k).and_then(|v| v.parse().ok());
            let maxload = attr(&attrs, "maxload").and_then(|v| v.parse().ok()).unwrap_or(0);
            let dst = Dst {
                setid,
                dest: uri_dest(uri.as_bytes()),
                uri,
                priority,
                weight: num("weight").unwrap_or(0),
                rweight: num("rweight").unwrap_or(0),
                attrs,
                state: AtomicU8::new(prev.unwrap_or(flags & 0x0f)),
                fails: AtomicU32::new(0),
                oks: AtomicU32::new(0),
                load: AtomicU32::new(prev_dst.as_ref().map_or(0, |d| d.load.load(Ordering::Relaxed))),
                maxload,
                lat: Mutex::new(prev_dst.as_ref().map(|d| *lock(&d.lat)).unwrap_or_default()),
            };
            by_set.entry(setid).or_default().push(Arc::new(dst));
        }
        let mut sets = BTreeMap::new();
        for (id, mut dsts) in by_set {
            dsts.sort_by_key(|d| std::cmp::Reverse(d.priority)); // stable
            let wdist = weight_dist(dsts.iter().map(|d| d.weight));
            sets.insert(id, Arc::new(Set { dsts, rr: AtomicUsize::new(0), wdist }));
        }
        *write(&self.sets) = Arc::new(sets);
        Ok(n)
    }

    fn sets(&self) -> Arc<Sets> {
        read(&self.sets).clone()
    }

    fn hash_input(&self, ctx: &mut Ctx<'_, '_>, alg: i64) -> Option<Vec<u8>> {
        let m = &mut *ctx.msg;
        m.parse_headers(HdrFlags::EOH).ok()?;
        let uri_key = |b: &[u8]| parse_uri(b).map(|u| [u.user.unwrap_or(b""), b"@", u.host].concat());
        match alg {
            0 => m.get(HdrKind::CallId).map(|h| h.body.to_vec()),
            1 => m.get(HdrKind::From).and_then(|h| uri_key(name_addr(h.body).0)),
            2 => m.get(HdrKind::To).and_then(|h| uri_key(name_addr(h.body).0)),
            3 => {
                let r = ctx.ruri().to_vec();
                uri_key(&r)
            }
            5 => {
                m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"authorization") || h.name.eq_ignore_ascii_case(b"proxy-authorization")).and_then(|h| {
                    let s = String::from_utf8_lossy(h.body);
                    let (_, v) = s.split_once("username=")?;
                    let v = v.trim_start_matches('"');
                    Some(v.split(['"', ',']).next().unwrap_or(v).as_bytes().to_vec())
                })
            }
            7 => self.hash_fmt.get().map(|f| f.eval(ctx).into_bytes()),
            _ => None,
        }
    }

    /// Destinations in failover order for `alg`; `None` = unknown set.
    fn select(&self, ctx: &mut Ctx<'_, '_>, setid: i32, alg: i64, limit: usize) -> Option<Vec<Arc<Dst>>> {
        let sets = self.sets();
        let set = sets.get(&setid)?.clone();
        let n = set.dsts.len();
        if n == 0 {
            return Some(vec![]);
        }
        let start = match alg {
            0 | 1 | 2 | 3 | 5 | 7 => match self.hash_input(ctx, alg) {
                Some(k) => index_mod(fx_hash(&k[..]), n),
                None => next_rr(&set.rr, n),
            },
            4 | 10 => next_rr(&set.rr, n),
            6 => index_mod(rand_u64(), n),
            9 if !set.wdist.is_empty() => set.wdist.get(next_rr(&set.rr, set.wdist.len())).copied().unwrap_or(0),
            11 => {
                // Relative weight among the *active* destinations: the
                // first whose running weight passes r.
                let weight = |d: &Dst| u64::from(d.rweight.max(1));
                let act = set.dsts.iter().enumerate().filter(|(_, d)| d.active());
                // At most n · u32::MAX: no overflow.
                let total: u64 = act.clone().map(|(_, d)| weight(d)).sum();
                let mut r = rand_u64().checked_rem(total).unwrap_or(0);
                let mut act = act;
                let pick = act.find(|(_, d)| match r.checked_sub(weight(d)) {
                    None => true,
                    Some(rest) => {
                        r = rest;
                        false
                    }
                });
                pick.map_or(0, |(i, _)| i)
            }
            _ => 0, // 8 (priority order), 12 (all), 13 (latency → priority)
        };
        // Every destination once, from `start` round (start < n).
        let mut out: Vec<Arc<Dst>> = set.dsts.iter().cycle().skip(start).take(n).filter(|d| d.active()).cloned().collect();
        match alg {
            // Least loaded relative to capacity (ties keep the rotation).
            10 => out.sort_by_key(|d| {
                let l = u64::from(d.load.load(Ordering::Relaxed)).saturating_mul(1_000_000);
                l.checked_div(u64::from(d.maxload)).unwrap_or(l)
            }),
            // Lowest estimated latency; never-measured ones last (priority order).
            13 => out.sort_by(|a, b| {
                let k = |d: &Dst| {
                    let l = *lock(&d.lat);
                    if l.count == 0 { f64::MAX } else { l.est }
                };
                k(a).partial_cmp(&k(b)).unwrap_or(std::cmp::Ordering::Equal)
            }),
            _ => {}
        }
        if limit > 0 {
            out.truncate(limit);
        }
        Some(out)
    }

    /// Store the failover list in `$xavp(_dsdst_)` (current first).
    fn store(ctx: &mut Ctx<'_, '_>, list: &[Arc<Dst>]) {
        let items = list
            .iter()
            .map(|d| {
                let mut m = HashMap::new();
                m.insert("uri".to_string(), Val::str(&d.uri));
                m.insert("grp".to_string(), Val::Int(i64::from(d.setid)));
                m.insert("attrs".to_string(), Val::str(&d.attrs));
                m.insert("priority".to_string(), Val::Int(i64::from(d.priority)));
                m
            })
            .collect();
        ctx.ext_mut::<TxnVars>().xavps.insert(XAVP.into(), items);
    }

    fn current_uri(ctx: &Ctx<'_, '_>) -> Option<String> {
        ctx.ext::<TxnVars>()?.xavps.get(XAVP)?.first()?.get("uri").map(|v| v.as_str().into_owned())
    }

    /// Point the request at `uri`: `$du` (dst) or the R-URI host (domain).
    fn apply(ctx: &mut Ctx<'_, '_>, uri: &str, domain: bool) -> bool {
        if domain {
            let Some(u) = parse_uri(uri.as_bytes()) else { return false };
            let host = String::from_utf8_lossy(u.host).into_owned();
            let ruri = ctx.ruri().to_vec();
            match sip_core::pvcore::rebuild_uri(&ruri, None, Some(&host), Some(u.port)) {
                Some(n) => ctx.new_ruri = Some(n),
                None => return false,
            }
            true
        } else {
            match uri_dest(uri.as_bytes()) {
                Some(d) => {
                    ctx.dst = Some(d);
                    true
                }
                None => false,
            }
        }
    }

    fn select_dst(&self, ctx: &mut Ctx<'_, '_>, a: &[DynInt], mode: u8) -> i32 {
        // set, alg[, limit]: checked at fixup.
        let [set, alg, limit @ ..] = a else { return -1 };
        let (Some(set), Some(alg)) = (set.eval(ctx), alg.eval(ctx)) else { return -1 };
        let limit = usize::try_from(limit.first().and_then(|l| l.eval(ctx)).unwrap_or(0).max(0)).unwrap_or(usize::MAX);
        let Ok(set) = i32::try_from(set) else { return -1 };
        let Some(list) = self.select(ctx, set, alg, limit) else { return -1 };
        let Some((first, others)) = list.split_first() else { return -1 };
        Self::store(ctx, &list);
        if alg == 10 && mode != 2 {
            self.load_add(ctx, set, &first.uri);
        }
        match mode {
            0 => {
                if !Self::apply(ctx, &first.uri, false) {
                    return -1;
                }
                // alg 12: parallel forking to every destination.
                if alg == 12 {
                    let ruri = ctx.ruri().to_vec();
                    for d in others {
                        ctx.branches.push(sip_core::Branch { uri: ruri.clone(), dst: d.dest, q: None, path: None, ..Default::default() });
                    }
                }
            }
            1 if !Self::apply(ctx, &first.uri, true) => return -1,
            _ => {} // ds_select(): only the list
        }
        1
    }

    /// Drop the current destination and apply the next one.
    fn next(&self, ctx: &mut Ctx<'_, '_>, domain: bool) -> i32 {
        let Some(items) = ctx.ext_get_mut::<TxnVars>().and_then(|t| t.xavps.get_mut(XAVP)) else { return -1 };
        if !items.is_empty() {
            items.remove(0);
        }
        let Some(item) = items.first() else { return -1 };
        let uri = item.get("uri").map(|v| v.as_str().into_owned()).unwrap_or_default();
        let grp = item.get("grp").and_then(Val::as_int).and_then(|g| i32::try_from(g).ok()).unwrap_or(0);
        // alg 10: the load moves to the next destination (ds_load_update).
        if let Some(cid) = Self::callid(ctx)
            && lock(&self.calls).contains_key(&cid)
        {
            self.load_add(ctx, grp, &uri);
        }
        rc(Self::apply(ctx, &uri, domain))
    }

    fn callid(ctx: &mut Ctx<'_, '_>) -> Option<String> {
        ctx.msg.parse_headers(HdrFlags::CALLID).ok()?;
        ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).trim().to_string())
    }

    fn dst_of(&self, set: i32, uri: &str) -> Option<Arc<Dst>> {
        self.sets().get(&set)?.dsts.iter().find(|d| d.uri == uri).cloned()
    }

    /// One unit of load on `uri` for this call (moved if it had one).
    fn load_add(&self, ctx: &mut Ctx<'_, '_>, set: i32, uri: &str) {
        let Some(cid) = Self::callid(ctx) else { return };
        let old = lock(&self.calls).insert(cid, (set, uri.to_string()));
        if let Some((s, u)) = old
            && let Some(d) = self.dst_of(s, &u)
        {
            let _ = d.load.try_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_sub(1));
        }
        if let Some(d) = self.dst_of(set, uri) {
            d.load.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The call ended (dialog terminated, ds_load_unset).
    fn load_unset(&self, callid: &str) -> bool {
        let Some((s, u)) = lock(&self.calls).remove(callid) else { return false };
        if let Some(d) = self.dst_of(s, &u) {
            let _ = d.load.try_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_sub(1));
        }
        true
    }

    fn find(&self, setid: Option<i32>, uri: &str) -> Vec<Arc<Dst>> {
        let sets = self.sets();
        let norm = |s: &str| s.trim_matches(|c| c == '<' || c == '>').to_ascii_lowercase();
        let want = norm(uri);
        sets.iter()
            .filter(|(id, _)| setid.is_none_or(|s| s == **id))
            .flat_map(|(_, s)| s.dsts.iter().filter(|d| norm(&d.uri) == want).cloned().collect::<Vec<_>>())
            .collect()
    }

    /// Apply a state string (`a`, `i`, `d`, `t`, `p`, combined: `ip`).
    fn set_state(&self, d: &Dst, st: &str) {
        let old = d.state.load(Ordering::Relaxed);
        let mut s = 0u8;
        for c in st.chars() {
            match c.to_ascii_lowercase() {
                'i' => s |= DS_INACTIVE,
                'd' => s |= DS_DISABLED,
                't' => s |= DS_TRYING,
                'p' => s |= DS_PROBING,
                _ => {}
            }
        }
        if self.probing_mode.load(Ordering::Relaxed) == 1 {
            s |= DS_PROBING;
        }
        d.state.store(s, Ordering::Relaxed);
        d.fails.store(0, Ordering::Relaxed);
        d.oks.store(0, Ordering::Relaxed);
        let was_up = old & (DS_INACTIVE | DS_DISABLED) == 0;
        if was_up != d.active() {
            self.event(d, d.active());
        }
    }

    fn event(&self, d: &Dst, up: bool) {
        let (Some(hub), Some(net)) = (self.hub.get(), self.net.get()) else { return };
        let name = if up { "dispatcher:dst-up" } else { "dispatcher:dst-down" };
        if !hub.has_event(name) {
            return;
        }
        let msg = format!(
            "OPTIONS {} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKdsevent\r\nFrom: <sip:dispatcher@localhost>;tag=ds\r\n\
To: <{}>\r\nCall-ID: ds-event\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
            d.uri, d.uri
        );
        hub.run_event_with(name, &**net, Some(msg.as_bytes()), |_| {});
    }

    fn probe_result(&self, d: &Dst, code: u16) {
        let ok = (200..300).contains(&code) || lock(&self.reply_codes).iter().any(|&(lo, hi)| (lo..=hi).contains(&code));
        let st = d.state.load(Ordering::Relaxed);
        if st & DS_DISABLED != 0 {
            return;
        }
        if ok {
            d.fails.store(0, Ordering::Relaxed);
            if st & DS_INACTIVE != 0 {
                let oks = d.oks.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                if oks >= self.inactive_threshold.load(Ordering::Relaxed) {
                    let keep = if self.probing_mode.load(Ordering::Relaxed) == 1 { DS_PROBING } else { 0 };
                    d.state.store(st & keep, Ordering::Relaxed);
                    d.oks.store(0, Ordering::Relaxed);
                    self.event(d, true);
                }
            } else if st & DS_TRYING != 0 {
                d.state.store(st & !DS_TRYING, Ordering::Relaxed);
            }
        } else {
            d.oks.store(0, Ordering::Relaxed);
            if st & DS_INACTIVE == 0 {
                let fails = d.fails.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                if fails >= self.probing_threshold.load(Ordering::Relaxed) {
                    d.state.store((st & !DS_TRYING) | DS_INACTIVE | DS_PROBING, Ordering::Relaxed);
                    d.fails.store(0, Ordering::Relaxed);
                    self.event(d, false);
                } else {
                    d.state.store(st | DS_TRYING, Ordering::Relaxed);
                }
            }
        }
    }

    fn ping_all(self: &Arc<Self>) {
        let Some(tm) = self.tm.get() else { return };
        let mode = self.probing_mode.load(Ordering::Relaxed);
        let method = lock(&self.ping_method).clone();
        let from = lock(&self.ping_from).clone();
        for set in self.sets().values() {
            for d in &set.dsts {
                let st = d.state.load(Ordering::Relaxed);
                if st & DS_DISABLED != 0 || (mode != 1 && st & DS_PROBING == 0) {
                    continue;
                }
                let Some(dest) = d.dest else { continue };
                let me = self.clone();
                let dd = d.clone();
                let req = UacRequest {
                    method: method.clone(),
                    ruri: d.uri.clone(),
                    dst: Some(dest),
                    from: Some(from.clone()),
                    to: Some(d.uri.clone()),
                    ..Default::default()
                };
                let sent = std::time::Instant::now();
                let alpha = f64::from(self.alpha.load(Ordering::Relaxed)) / 1000.0;
                let cb = move |code: u16, _: &[u8]| {
                    {
                        let mut l = lock(&dd.lat);
                        if code == 408 {
                            l.timeouts = l.timeouts.saturating_add(1);
                        } else {
                            l.add(sent.elapsed().as_secs_f64() * 1000.0, alpha);
                        }
                    }
                    me.probe_result(&dd, code)
                };
                if tm.t_uac(req, Some(Box::new(cb))).is_err() {
                    self.probe_result(d, 500);
                }
            }
        }
    }

    fn list_json(&self) -> Value {
        let sets: Vec<Value> = self
            .sets()
            .iter()
            .map(|(id, s)| {
                let dsts: Vec<Value> = s
                    .dsts
                    .iter()
                    .map(|d| {
                        let st = d.state.load(Ordering::Relaxed);
                        let mut f = String::new();
                        f.push(if st & DS_DISABLED != 0 {
                            'D'
                        } else if st & DS_INACTIVE != 0 {
                            'I'
                        } else if st & DS_TRYING != 0 {
                            'T'
                        } else {
                            'A'
                        });
                        f.push(if st & DS_PROBING != 0 { 'P' } else { 'X' });
                        let mut v = json!({"URI": d.uri, "FLAGS": f, "PRIORITY": d.priority, "ATTRS": d.attrs, "LOAD": d.load.load(Ordering::Relaxed)});
                        let l = *lock(&d.lat);
                        if self.latency_stats.load(Ordering::Relaxed)
                            && (l.count > 0 || l.timeouts > 0)
                            && let Some(o) = v.as_object_mut()
                        {
                            o.insert(
                                "LATENCY".into(),
                                json!({"AVG": (l.avg * 10.0).round() / 10.0, "STD": (l.std() * 10.0).round() / 10.0,
                                       "EST": (l.est * 10.0).round() / 10.0, "MAX": l.max, "TIMEOUT": l.timeouts}),
                            );
                        }
                        v
                    })
                    .collect();
                json!({"ID": id, "TARGETS": dsts})
            })
            .collect();
        json!({"RECORDS": sets})
    }

    /// ds_is_from_list([group[, mode[, uri]]]): address, port and protocol
    /// must match; mode bit 1 ignores the port, bit 2 the protocol. A match
    /// sets `setid_pvname` / `attrs_pvname`.
    fn is_from_list(&self, ctx: &mut Ctx<'_, '_>, group: i64, mode: i64, uri: Option<String>) -> i32 {
        let (ip, port, proto) = match &uri {
            Some(u) => match parse_uri(u.as_bytes()).and_then(|p| Some((parse_ip(p.host)?, p.port.unwrap_or(5060)))) {
                Some((ip, port)) => (ip, port, uri_dest(u.as_bytes()).map(|d| d.proto)),
                None => match uri_dest(u.as_bytes()) {
                    Some(d) => (d.addr.ip(), d.addr.port(), Some(d.proto)),
                    None => return -1,
                },
            },
            None => (ctx.src.addr.ip(), ctx.src.addr.port(), Some(ctx.src.proto)),
        };
        for (id, s) in self.sets().iter() {
            if group >= 0 && i64::from(*id) != group {
                continue;
            }
            for d in &s.dsts {
                let Some(dd) = d.dest else { continue };
                if dd.addr.ip() != ip || (mode & 1 == 0 && dd.addr.port() != port) || (mode & 2 == 0 && Some(dd.proto) != proto) {
                    continue;
                }
                if let Some(pv) = self.setid_pv.get() {
                    let _ = pv.set(ctx, Val::Int(i64::from(*id)));
                }
                if let Some(pv) = self.attrs_pv.get() {
                    let _ = pv.set(ctx, Val::str(&d.attrs));
                }
                return 1;
            }
        }
        -1
    }
}

impl Module for Dispatcher {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("list_file", Ty::Str, "", "Destination list file"),
            p("db_url", Ty::Str, "", "Destination list database"),
            p("table_name", Ty::Str, "dispatcher", "Table in db_url"),
            p("ds_ping_interval", Ty::Duration(Unit::Sec), "0s", "Probe interval (0: no probing)"),
            p("ds_ping_method", Ty::Str, "OPTIONS", "Probe request method"),
            p("ds_ping_from", Ty::Str, "sip:dispatcher@localhost", "From URI of probes"),
            pr(
                "ds_probing_mode",
                Ty::Enum(&[("inactive", "0"), ("all", "1"), ("only-flagged", "2"), ("all-mark-active", "3")]),
                "inactive",
                "Which destinations are probed",
            ),
            pr("ds_probing_threshold", Ty::Int { min: 1, max: 1000 }, "1", "Failed probes before a destination goes inactive"),
            pr("ds_inactive_threshold", Ty::Int { min: 1, max: 1000 }, "1", "Successful probes before it is active again"),
            p("ds_ping_reply_codes", Ty::Str, "", "Probe replies that count as up, e.g. \"class=2;code=403\""),
            p("hash_pvar", Ty::Str, "", "Variable hashed by algorithm 7"),
            p("setid_pvname", Ty::Str, "", "Variable that gets the selected set id"),
            p("attrs_pvname", Ty::Str, "", "Variable that gets the destination attributes"),
            p("ds_ping_latency_stats", Ty::Bool, "false", "Track probe latency"),
            p("ds_latency_estimator_alpha", Ty::Int { min: 0, max: 1000 }, "900", "Latency smoothing (per mille)"),
        ])
    }

    fn name(&self) -> &'static str {
        "dispatcher"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const SELECT: &[Param] = &[arg("set", Int), arg("alg", Int).eg("4"), opt("limit", Int)];
        const STATE: &[Param] = &[opt("state", Str).lit().eg("\"ip\"")];
        const FROM: &[Param] = &[opt("set", Int), opt("mode", Int).eg("0"), opt("uri", Uri)];
        const SET: &[Param] = &[arg("set", Int)];
        const ACTIVE: &[Param] = &[arg("set", Int), opt("uri", Uri)];
        Some(vec![
            sig(
                "ds_select_dst",
                "select",
                SELECT,
                Ret::Bool,
                "Pick a destination of the set by `alg` (0 Call-ID hash, 4 round robin, 9 weight, 10 load, …) into $du; the rest are kept for `next`",
            ),
            sig("ds_select_domain", "select_domain", SELECT, Ret::Bool, "Pick a destination of the set by `alg` into the R-URI host:port"),
            sig("ds_select", "select_list", SELECT, Ret::Bool, "Pick destinations of the set by `alg` for `set_dst`/`next`, without using one yet"),
            sig("ds_next_dst", "next", &[], Ret::Bool, "Use the next selected destination as $du (after a failure)"),
            sig("ds_next_domain", "next_domain", &[], Ret::Bool, "Use the next selected destination as the R-URI host:port (after a failure)"),
            sig("ds_load_unset", "load_unset", &[], Ret::Bool, "End this call's load on its destination (call-load balancing)"),
            sig("ds_load_update", "load_update", &[], Ret::Void, "A BYE or CANCEL ends this call's load on its destination"),
            sig("ds_set_dst", "set_dst", &[], Ret::Bool, "Use the current selected destination as $du"),
            sig("ds_set_domain", "set_domain", &[], Ret::Bool, "Use the current selected destination as the R-URI host:port"),
            sig(
                "ds_mark_dst",
                "mark",
                STATE,
                Ret::Bool,
                "Set the state of the current destination (`i` inactive, `a` active, `d` disabled, `p` probing; default inactive)",
            ),
            sig("ds_is_from_list", "is_from", FROM, Ret::Bool, "The source address (or `uri`) is a destination of the set (any set: -1)").allowed(ctx::ANY),
            sig("ds_list_exists", "set_exists", SET, Ret::Bool, "The destination set exists").allowed(ctx::ANY),
            sig("ds_is_active", "is_active", ACTIVE, Ret::Bool, "The set has an active destination (or this `uri` is active)").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let s = || v.str().map(String::from);
        let n = || v.int();
        match name {
            "list_file" => *lock(&self.list_file) = Some(s()?),
            "db_url" => *lock(&self.db_url) = Some(s()?),
            "table_name" => *lock(&self.table) = s()?,
            "ds_ping_interval" => self.ping_interval.store(u64::try_from(n()?).unwrap_or(0), Ordering::Relaxed),
            "ds_ping_method" => *lock(&self.ping_method) = s()?,
            "ds_ping_from" => *lock(&self.ping_from) = s()?,
            "ds_probing_mode" => self.probing_mode.store(u32::try_from(n()?.max(0)).unwrap_or(u32::MAX), Ordering::Relaxed),
            "ds_probing_threshold" => self.probing_threshold.store(u32::try_from(n()?.max(1)).unwrap_or(u32::MAX), Ordering::Relaxed),
            "ds_inactive_threshold" => self.inactive_threshold.store(u32::try_from(n()?.max(1)).unwrap_or(u32::MAX), Ordering::Relaxed),
            "ds_ping_reply_codes" => {
                // "code=404;class=3"
                let mut v = Vec::new();
                for kv in s()?.split(';').filter(|x| !x.trim().is_empty()) {
                    let (k, val) = kv.split_once('=').ok_or("ds_ping_reply_codes: expected code=N;class=N")?;
                    let x: u16 = val.trim().parse().map_err(|_| "ds_ping_reply_codes: bad number")?;
                    match k.trim() {
                        "code" => v.push((x, x)),
                        "class" => {
                            let lo = x.checked_mul(100).filter(|lo| lo.checked_add(99).is_some()).ok_or("ds_ping_reply_codes: class out of range")?;
                            v.push((lo, lo.saturating_add(99)));
                        }
                        _ => return Err("ds_ping_reply_codes: expected code=N;class=N".into()),
                    }
                }
                *lock(&self.reply_codes) = v;
            }
            "hash_pvar" => *lock(&self.hash_pvar) = Some(s()?),
            "setid_pvname" => *lock(&self.setid_pvname) = Some(s()?),
            "attrs_pvname" => *lock(&self.attrs_pvname) = Some(s()?),
            "ds_ping_latency_stats" => self.latency_stats.store(n()? != 0, Ordering::Relaxed),
            "ds_latency_estimator_alpha" => self.alpha.store(u32::try_from(n()?.clamp(0, 1000)).unwrap_or(0), Ordering::Relaxed),
            "flags" | "use_default" | "force_dst" | "xavp_dst" | "xavp_ctx" | "ds_hash_size" | "ds_timer_mode" => {}
            _ => return Err(format!("dispatcher: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let n = self.reload()?;
        sip_core::log::log(sip_core::log::L_INFO, &format!("dispatcher: loaded {n} destinations"));
        if let Some(p) = lock(&self.hash_pvar).clone() {
            let _ = self.hash_fmt.set(sip_core::pv::parse_fmt(&p, reg.pvs())?);
        }
        if let Some(p) = lock(&self.setid_pvname).clone() {
            let _ = self.setid_pv.set(sip_core::pv::parse_pv(&p, reg.pvs())?);
        }
        if let Some(p) = lock(&self.attrs_pvname).clone() {
            let _ = self.attrs_pv.set(sip_core::pv::parse_pv(&p, reg.pvs())?);
        }
        if let Some(tm) = reg.api::<Tm>() {
            let _ = self.tm.set(tm);
        } else if self.ping_interval.load(Ordering::Relaxed) > 0 {
            return Err("dispatcher: probing needs tm loaded first".into());
        }
        let _ = self.hub.set(reg.hub.clone());
        let m = "dispatcher";
        let sel_fix = |a: &[Arg]| -> Result<Vec<DynInt>, String> {
            if a.len() < 2 || a.len() > 3 {
                return Err("expected set, alg[, limit]".into());
            }
            a.iter().map(Arg::dyn_int).collect()
        };
        for (name, mode) in [("ds_select_dst", 0u8), ("ds_select_domain", 1), ("ds_select", 2)] {
            let me = self.clone();
            reg.export(m, name, sel_fix, move |ctx: &mut Ctx, a: &Vec<DynInt>| me.select_dst(ctx, a, mode));
        }
        let me = self.clone();
        reg.export(m, "ds_next_dst", |a: &[Arg]| want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.next(ctx, false));
        let me = self.clone();
        reg.export(m, "ds_next_domain", |a: &[Arg]| want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.next(ctx, true));
        let me = self.clone();
        reg.export(
            m,
            "ds_load_unset",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| match Self::callid(ctx) {
                Some(c) => rc(me.load_unset(&c)),
                None => -1,
            },
        );
        // ds_load_update(): BYE/CANCEL end the call's load; the dialog
        // module does it automatically when loaded.
        let me = self.clone();
        reg.export(
            m,
            "ds_load_update",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                if matches!(ctx.msg.method(), Some(sip_parser::Method::Bye | sip_parser::Method::Cancel))
                    && let Some(c) = Self::callid(ctx)
                {
                    me.load_unset(&c);
                }
                1
            },
        );
        if let Some(dlg) = reg.api::<mod_dialog::Dialog>() {
            let me = self.clone();
            dlg.on_state(Arc::new(move |c: &mod_dialog::DlgChange| {
                if c.state == "terminated" {
                    me.load_unset(&c.callid);
                }
            }));
        }
        reg.export(
            m,
            "ds_set_dst",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| match Dispatcher::current_uri(ctx) {
                Some(u) => rc(Dispatcher::apply(ctx, &u, false)),
                None => -1,
            },
        );
        reg.export(
            m,
            "ds_set_domain",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| match Dispatcher::current_uri(ctx) {
                Some(u) => rc(Dispatcher::apply(ctx, &u, true)),
                None => -1,
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "ds_mark_dst",
            |a: &[Arg]| -> Result<Option<String>, String> {
                match a {
                    [] => Ok(None),
                    [state] => Ok(Some(state.str()?.to_string())),
                    _ => Err("expected at most 1 argument".into()),
                }
            },
            move |ctx: &mut Ctx, st: &Option<String>| {
                let uri = Dispatcher::current_uri(ctx).or_else(|| ctx.dst.map(|d| sip_core::pvcore::dest_to_uri(&d)));
                let Some(uri) = uri else { return -1 };
                let st = st.clone().unwrap_or_else(|| if me.ping_interval.load(Ordering::Relaxed) > 0 { "ip".into() } else { "i".into() });
                let found = me.find(None, &uri);
                // Fall back to matching by address (when $du was built from it).
                let found = if found.is_empty() {
                    let d = uri_dest(uri.as_bytes());
                    me.sets()
                        .values()
                        .flat_map(|s| s.dsts.iter().filter(|x| x.dest.is_some() && x.dest.map(|y| y.addr) == d.map(|y| y.addr)).cloned().collect::<Vec<_>>())
                        .collect()
                } else {
                    found
                };
                for d in &found {
                    me.set_state(d, &st);
                }
                rc(!found.is_empty())
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "ds_is_from_list",
            |a: &[Arg]| -> Result<FromListArgs, String> {
                if a.len() > 3 {
                    return Err("expected [group[, mode[, uri]]]".into());
                }
                Ok((a.first().map(Arg::dyn_int).transpose()?, a.get(1).map(Arg::dyn_int).transpose()?, a.get(2).map(Arg::dyn_str).transpose()?))
            },
            move |ctx: &mut Ctx, (g, md, u): &FromListArgs| {
                let g = g.as_ref().and_then(|g| g.eval(ctx)).unwrap_or(-1);
                let md = md.as_ref().and_then(|x| x.eval(ctx)).unwrap_or(0);
                let u = u.as_ref().map(|u| u.eval(ctx).into_owned());
                me.is_from_list(ctx, g, md, u)
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "ds_list_exists",
            |a: &[Arg]| {
                let [s] = args(a)?;
                s.dyn_int()
            },
            move |ctx: &mut Ctx, s: &DynInt| rc(s.eval(ctx).and_then(|s| i32::try_from(s).ok()).is_some_and(|s| me.sets().contains_key(&s))),
        );
        let me = self.clone();
        reg.export(
            m,
            "ds_is_active",
            |a: &[Arg]| -> Result<(DynInt, Option<DynStr>), String> {
                let (set, uri) = match a {
                    [set] => (set, None),
                    [set, uri] => (set, Some(uri)),
                    _ => return Err("expected set[, uri]".into()),
                };
                Ok((set.dyn_int()?, uri.map(Arg::dyn_str).transpose()?))
            },
            move |ctx: &mut Ctx, (s, u): &(DynInt, Option<DynStr>)| {
                let Some(s) = s.eval(ctx).and_then(|s| i32::try_from(s).ok()) else { return -1 };
                let u = u.as_ref().map(|u| u.eval(ctx).into_owned());
                let sets = me.sets();
                let Some(set) = sets.get(&s) else { return -1 };
                rc(set.dsts.iter().any(|d| d.active() && u.as_ref().is_none_or(|u| d.uri.eq_ignore_ascii_case(u))))
            },
        );
        let me = self.clone();
        reg.rpc.add("dispatcher.reload", "Reload the destination sets", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("dispatcher.list", "List the destination sets and their state", move |_| Ok(me.list_json()));
        let me = self.clone();
        reg.rpc.add("dispatcher.set_state", "dispatcher.set_state <a|i|d|p…> <group> <uri|all>", move |p| {
            let st = sip_core::rpc::str_param(p, 0)?;
            let g = i32::try_from(sip_core::rpc::int_param(p, 1)?).map_err(|_| "group out of range".to_string())?;
            let uri = sip_core::rpc::str_param(p, 2)?;
            let found: Vec<Arc<Dst>> = if uri == "all" { me.sets().get(&g).map(|s| s.dsts.clone()).unwrap_or_default() } else { me.find(Some(g), &uri) };
            if found.is_empty() {
                return Err("destination not found".into());
            }
            for d in &found {
                me.set_state(d, &st);
            }
            Ok(json!(found.len()))
        });
        let me = self.clone();
        reg.rpc.add("dispatcher.ping_active", "dispatcher.ping_active 0|1: probe all (1) or only probing (0)", move |p| {
            let v = sip_core::rpc::int_param(p, 0)?;
            me.probing_mode.store(u32::try_from(v.max(0)).unwrap_or(u32::MAX), Ordering::Relaxed);
            Ok(json!(v))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        let every = self.ping_interval.load(Ordering::Relaxed);
        if every == 0 {
            return Ok(());
        }
        std::thread::Builder::new()
            .name("dispatcher-ping".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(every));
                    self.ping_all();
                }
            })
            .map_err(|e| format!("cannot start the dispatcher pinger thread: {e}"))?;
        Ok(())
    }
}

/// `x mod n` as an index (0 for `n` = 0); below `n`, so it always fits.
fn index_mod(x: u64, n: usize) -> usize {
    let r = x.checked_rem(u64::try_from(n).unwrap_or(u64::MAX)).unwrap_or(0);
    usize::try_from(r).unwrap_or(0)
}

/// The next round-robin index below `n` (0 for `n` = 0). The counter wraps.
fn next_rr(rr: &AtomicUsize, n: usize) -> usize {
    rr.fetch_add(1, Ordering::Relaxed).checked_rem(n).unwrap_or(0)
}

/// Algorithm 9's table: 100 slots, destination `i` in about `weight / sum
/// of weights` of them, interleaved so consecutive calls spread over the
/// destinations. Empty when every weight is 0.
fn weight_dist(weights: impl Iterator<Item = u32> + Clone) -> Vec<usize> {
    // In u64: summing config weights in u32 overflowed, and a wrapped
    // total gave a destination billions of slots.
    let total: u64 = weights.clone().map(u64::from).sum();
    let mut wdist = Vec::new();
    if total == 0 {
        return wdist;
    }
    for (i, w) in weights.enumerate() {
        let slots = u64::from(w).saturating_mul(100).div_ceil(total).min(100);
        wdist.extend(std::iter::repeat_n(i, usize::try_from(slots).unwrap_or(100)));
    }
    wdist.truncate(100);
    let mut x = 0x2545_f491u64;
    for i in (1..wdist.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        wdist.swap(i, index_mod(x, i.saturating_add(1)));
    }
    wdist
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_format() {
        let r = parse_list("# c\n1 sip:a.example:5060 0 10 weight=50;duid=a\n\n2 sip:b 8\n").unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], (1, "sip:a.example:5060".into(), 0, 10, "weight=50;duid=a".into()));
        assert_eq!(r[1].2, 8);
        assert!(parse_list("x sip:a").is_err());
    }

    #[test]
    fn weight_table() {
        let count = |w: &[usize], i: usize| w.iter().filter(|&&x| x == i).count();
        let w = weight_dist([50, 25, 25].into_iter());
        assert_eq!((w.len(), count(&w, 0), count(&w, 1), count(&w, 2)), (100, 50, 25, 25));
        assert!(weight_dist([0, 0].into_iter()).is_empty());
        // The u32 sum wrapped to 1 here: one destination got 429 billion
        // slots before the table was cut to 100 (out of memory).
        let w = weight_dist([u32::MAX, 2].into_iter());
        assert_eq!((w.len(), count(&w, 0)), (100, 100));
    }

    #[test]
    fn ping_reply_class_range() {
        let d = Dispatcher::default();
        d.set_param("ds_ping_reply_codes", &Arg::Str("class=4;code=202".into())).unwrap();
        assert_eq!(*lock(&d.reply_codes), vec![(400, 499), (202, 202)]);
        // 700 · 100 overflowed u16.
        assert!(d.set_param("ds_ping_reply_codes", &Arg::Str("class=700".into())).is_err());
        assert!(d.set_param("ds_ping_reply_codes", &Arg::Str("class=655".into())).is_err());
    }

    use crate::testutil::{FakeNet, request, udp, with_ctx};
    use sip_core::Proto;
    use sip_core::module::DynInt;

    /// A dispatcher loaded from `list` (through a temporary list file).
    fn loaded(list: &str) -> Dispatcher {
        let d = Dispatcher::default();
        reload_from(&d, list).unwrap();
        d
    }

    fn reload_from(d: &Dispatcher, list: &str) -> Result<usize, String> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!("ferrosip-ds-test-{}-{}.list", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, list).unwrap();
        *lock(&d.list_file) = Some(path.to_string_lossy().into_owned());
        let r = d.reload();
        let _ = std::fs::remove_file(&path);
        r
    }

    fn dst(d: &Dispatcher, set: i32, uri: &str) -> Arc<Dst> {
        d.dst_of(set, uri).unwrap_or_else(|| panic!("no {uri} in set {set}"))
    }

    fn uris(list: &[Arc<Dst>]) -> Vec<&str> {
        list.iter().map(|d| d.uri.as_str()).collect()
    }

    const THREE: &str = "1 sip:10.0.0.1:5060\n1 sip:10.0.0.2:5060\n1 sip:10.0.0.3:5060\n";

    fn rotated(start: usize) -> Vec<&'static str> {
        let all = ["sip:10.0.0.1:5060", "sip:10.0.0.2:5060", "sip:10.0.0.3:5060"];
        all.iter().cycle().skip(start).take(3).copied().collect()
    }

    /// The failover list `select` gives for `msg`.
    fn select_for(d: &Dispatcher, msg: &str, set: i32, alg: i64, limit: usize) -> Option<Vec<String>> {
        let net = FakeNet(vec![]);
        with_ctx(msg, udp("192.0.2.1:5060"), &net, |ctx| d.select(ctx, set, alg, limit)).map(|l| l.iter().map(|x| x.uri.clone()).collect())
    }

    fn hash_start(key: &[u8]) -> usize {
        index_mod(fx_hash(key), 3)
    }

    #[test]
    fn dispatcher_hash_algorithms_start_at_the_hashed_destination() {
        let d = loaded(THREE);
        let msg = |extra: &str| request("INVITE", "sip:carol@c.example", extra);
        // (alg, message, hashed key)
        let cases: &[(i64, String, &[u8])] = &[
            (0, msg(""), b"cid-1"),
            (1, msg(""), b"alice@a.example"),
            (2, msg(""), b"bob@b.example"),
            (3, msg(""), b"carol@c.example"),
            (5, msg("Authorization: Digest username=\"dave\", realm=\"x\"\n"), b"dave"),
            (5, msg("Proxy-Authorization: Digest realm=\"x\", username=erin, nonce=\"n\"\n"), b"erin"),
        ];
        for (alg, m, key) in cases {
            let want = rotated(hash_start(key));
            assert_eq!(select_for(&d, m, 1, *alg, 0).unwrap(), want, "alg {alg}, key {:?}", String::from_utf8_lossy(key));
            // Stable: the same input again gives the same order.
            assert_eq!(select_for(&d, m, 1, *alg, 0).unwrap(), want, "alg {alg} again");
        }
    }

    #[test]
    fn dispatcher_from_and_to_hash_ignore_display_name_and_parameters() {
        let d = loaded(THREE);
        let plain = "INVITE sip:x@h SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: <sip:alice@a.example>;tag=1\nTo: sip:bob@b.example\n\
Call-ID: one\nCSeq: 1 INVITE\nContent-Length: 0\n\n";
        let decorated = "INVITE sip:x@h SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: \"Alice\" <sip:alice@a.example;transport=tcp>;tag=2\n\
To: \"Bob\" <sip:bob@b.example:5070>;tag=9\nCall-ID: two\nCSeq: 1 INVITE\nContent-Length: 0\n\n";
        for alg in [1, 2] {
            assert_eq!(select_for(&d, plain, 1, alg, 0), select_for(&d, decorated, 1, alg, 0), "alg {alg}");
        }
    }

    #[test]
    fn dispatcher_ruri_hash_uses_the_rewritten_ruri() {
        let d = loaded(THREE);
        let net = FakeNet(vec![]);
        let got = with_ctx(&request("INVITE", "sip:carol@c.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            ctx.new_ruri = Some(b"sip:zed@z.example".to_vec());
            d.select(ctx, 1, 3, 0).unwrap()
        });
        assert_eq!(uris(&got), rotated(hash_start(b"zed@z.example")));
    }

    #[test]
    fn dispatcher_hash_without_input_falls_back_to_round_robin() {
        let d = loaded(THREE);
        let m = request("INVITE", "sip:carol@c.example", "");
        // alg 5 needs credentials: none, so each call moves one on.
        for start in [0, 1, 2, 0] {
            assert_eq!(select_for(&d, &m, 1, 5, 0).unwrap(), rotated(start));
        }
    }

    #[test]
    fn dispatcher_round_robin_rotates_and_skips_inactive() {
        let d = loaded(THREE);
        let m = request("INVITE", "sip:carol@c.example", "");
        for start in [0, 1, 2, 0, 1] {
            assert_eq!(select_for(&d, &m, 1, 4, 0).unwrap(), rotated(start));
        }
        let d = loaded("1 sip:10.0.0.1:5060\n1 sip:10.0.0.2:5060 1\n1 sip:10.0.0.3:5060 4\n1 sip:10.0.0.4:5060 2\n");
        // Inactive (1) and disabled (4) are left out; trying (2) is still used.
        assert_eq!(select_for(&d, &m, 1, 4, 0).unwrap(), ["sip:10.0.0.1:5060", "sip:10.0.0.4:5060"]);
        assert_eq!(select_for(&d, &m, 1, 4, 0).unwrap(), ["sip:10.0.0.4:5060", "sip:10.0.0.1:5060"], "start 1 is inactive: the list starts after it");
        assert_eq!(select_for(&d, &m, 1, 4, 1).unwrap().len(), 1, "limit");
        assert_eq!(select_for(&d, &m, 9, 4, 0), None, "unknown set");
    }

    #[test]
    fn dispatcher_priority_order_is_descending_and_stable() {
        let d = loaded("1 sip:10.0.0.1:5060 0 5\n1 sip:10.0.0.2:5060 0 10\n1 sip:10.0.0.3:5060 0 10\n1 sip:10.0.0.4:5060 0 -1\n");
        let m = request("INVITE", "sip:carol@c.example", "");
        let want = ["sip:10.0.0.2:5060", "sip:10.0.0.3:5060", "sip:10.0.0.1:5060", "sip:10.0.0.4:5060"];
        for alg in [8, 12, 13] {
            assert_eq!(select_for(&d, &m, 1, alg, 0).unwrap(), want, "alg {alg}");
        }
        assert_eq!(select_for(&d, &m, 1, 8, 2).unwrap(), want[..2]);
    }

    #[test]
    fn dispatcher_weight_algorithm_follows_the_weights_over_100_calls() {
        let d = loaded("1 sip:10.0.0.1:5060 0 0 weight=50\n1 sip:10.0.0.2:5060 0 0 weight=25\n1 sip:10.0.0.3:5060 0 0 weight=25\n");
        let m = request("INVITE", "sip:carol@c.example", "");
        let mut count: HashMap<String, usize> = HashMap::new();
        for _ in 0..100 {
            let l = select_for(&d, &m, 1, 9, 0).unwrap();
            assert_eq!(l.len(), 3, "every destination stays in the failover list");
            *count.entry(l[0].clone()).or_default() += 1;
        }
        assert_eq!((count["sip:10.0.0.1:5060"], count["sip:10.0.0.2:5060"], count["sip:10.0.0.3:5060"]), (50, 25, 25));
        // No weights: alg 9 starts with the first destination.
        let d = loaded(THREE);
        assert_eq!(select_for(&d, &m, 1, 9, 0).unwrap(), rotated(0));
        assert_eq!(select_for(&d, &m, 1, 9, 0).unwrap(), rotated(0));
    }

    #[test]
    fn dispatcher_relative_weight_only_picks_active_destinations() {
        let d = loaded("1 sip:10.0.0.1:5060 1 0 rweight=1000\n1 sip:10.0.0.2:5060 0 0 rweight=1\n1 sip:10.0.0.3:5060 4 0 rweight=1000\n");
        let m = request("INVITE", "sip:carol@c.example", "");
        for _ in 0..50 {
            assert_eq!(select_for(&d, &m, 1, 11, 0).unwrap(), ["sip:10.0.0.2:5060"]);
        }
        // rweight 0 or missing counts as 1: every destination gets picked.
        let d = loaded("1 sip:10.0.0.1:5060 0 0 rweight=0\n1 sip:10.0.0.2:5060\n");
        let firsts: std::collections::HashSet<String> = (0..200).map(|_| select_for(&d, &m, 1, 11, 0).unwrap()[0].clone()).collect();
        assert_eq!(firsts.len(), 2, "{firsts:?}");
    }

    #[test]
    fn dispatcher_latency_algorithm_orders_by_estimate_unmeasured_last() {
        let d = loaded("1 sip:10.0.0.1:5060 0 9\n1 sip:10.0.0.2:5060 0 8\n1 sip:10.0.0.3:5060 0 7\n1 sip:10.0.0.4:5060 0 6\n");
        lock(&dst(&d, 1, "sip:10.0.0.3:5060").lat).add(5.0, 0.9);
        lock(&dst(&d, 1, "sip:10.0.0.4:5060").lat).add(40.0, 0.9);
        let m = request("INVITE", "sip:carol@c.example", "");
        assert_eq!(select_for(&d, &m, 1, 13, 0).unwrap(), ["sip:10.0.0.3:5060", "sip:10.0.0.4:5060", "sip:10.0.0.1:5060", "sip:10.0.0.2:5060"]);
    }

    #[test]
    fn latency_statistics_arithmetic() {
        let mut l = Latency::default();
        for ms in [10.0, 20.0, 30.0] {
            l.add(ms, 0.9);
        }
        assert_eq!(l.count, 3);
        assert!((l.avg - 20.0).abs() < 1e-9, "avg {}", l.avg);
        assert!((l.std() - 10.0).abs() < 1e-9, "sample std {}", l.std());
        // est: 10, then 0.9·10 + 0.1·20 = 11, then 0.9·11 + 0.1·30 = 12.9.
        assert!((l.est - 12.9).abs() < 1e-9, "est {}", l.est);
        assert_eq!(l.max, 30.0);
        let mut one = Latency::default();
        one.add(7.0, 0.5);
        assert_eq!((one.std(), one.est), (0.0, 7.0), "one sample: no deviation, estimate = sample");
    }

    fn ints(v: &[i64]) -> Vec<DynInt> {
        v.iter().map(|&i| DynInt::Static(i)).collect()
    }

    fn call(cid: &str) -> String {
        request("INVITE", "sip:carol@c.example", "").replace("cid-1", cid)
    }

    fn load(d: &Dispatcher, uri: &str) -> u32 {
        dst(d, 1, uri).load.load(Ordering::Relaxed)
    }

    #[test]
    fn dispatcher_call_load_picks_least_loaded_relative_to_capacity() {
        let (a, b) = ("sip:10.0.0.1:5060", "sip:10.0.0.2:5060");
        let d = loaded(&format!("1 {a} 0 0 maxload=2\n1 {b} 0 0 maxload=4\n"));
        let net = FakeNet(vec![]);
        let pick = |cid: &str| {
            with_ctx(&call(cid), udp("192.0.2.1:5060"), &net, |ctx| {
                assert_eq!(d.select_dst(ctx, &ints(&[1, 10]), 0), 1);
                ctx.dst.map(|x| x.addr.to_string())
            })
        };
        // Both idle: rotation order, a first.
        assert_eq!(pick("c1").as_deref(), Some("10.0.0.1:5060"));
        // a 1/2 vs b 0/4.
        assert_eq!(pick("c2").as_deref(), Some("10.0.0.2:5060"));
        // a 1/2 vs b 1/4.
        assert_eq!(pick("c3").as_deref(), Some("10.0.0.2:5060"));
        assert_eq!((load(&d, a), load(&d, b)), (1, 2));
        // The same call again moves its unit instead of adding one.
        assert_eq!(pick("c3").as_deref(), Some("10.0.0.2:5060"));
        assert_eq!((load(&d, a), load(&d, b)), (1, 2));
        assert!(d.load_unset("c2") && d.load_unset("c3"));
        assert!(!d.load_unset("c3"), "already gone");
        assert!(!d.load_unset("never"));
        assert_eq!((load(&d, a), load(&d, b)), (1, 0));
        assert!(d.load_unset("c1"));
        assert!(!d.load_unset("c1"));
        assert_eq!(load(&d, a), 0, "never below zero");
    }

    #[test]
    fn dispatcher_next_moves_the_call_load_to_the_next_destination() {
        let (a, b) = ("sip:10.0.0.1:5060", "sip:10.0.0.2:5060");
        let d = loaded(&format!("1 {a}\n1 {b}\n"));
        let net = FakeNet(vec![]);
        with_ctx(&call("c1"), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[1, 10]), 0), 1);
            assert_eq!((load(&d, a), load(&d, b)), (1, 0));
            assert_eq!(d.next(ctx, false), 1);
            assert_eq!(ctx.dst.map(|x| x.addr.to_string()).as_deref(), Some("10.0.0.2:5060"));
            assert_eq!((load(&d, a), load(&d, b)), (0, 1));
            assert_eq!(d.next(ctx, false), -1, "list exhausted");
        });
    }

    #[test]
    fn dispatcher_select_modes() {
        let d = loaded("1 sip:10.0.0.1:5070\n1 sip:10.0.0.2:5060;transport=tcp\n");
        let net = FakeNet(vec![]);
        let m = request("INVITE", "sip:carol@c.example", "");
        // ds_select_dst: $du, failover list in the xavp.
        with_ctx(&m, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[1, 8]), 0), 1);
            assert_eq!(ctx.dst.map(|x| (x.proto, x.addr.to_string())), Some((Proto::Udp, "10.0.0.1:5070".into())));
            assert!(ctx.new_ruri.is_none());
            assert_eq!(Dispatcher::current_uri(ctx).as_deref(), Some("sip:10.0.0.1:5070"));
            assert!(ctx.branches.is_empty());
            assert_eq!(d.next(ctx, false), 1);
            assert_eq!(ctx.dst.map(|x| (x.proto, x.addr.to_string())), Some((Proto::Tcp, "10.0.0.2:5060".into())));
        });
        // ds_select_domain: the R-URI host:port.
        with_ctx(&m, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[1, 8]), 1), 1);
            assert!(ctx.dst.is_none());
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:carol@10.0.0.1:5070"[..]));
        });
        // ds_select: only the list.
        with_ctx(&m, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[1, 8, 1]), 2), 1);
            assert!(ctx.dst.is_none() && ctx.new_ruri.is_none());
            assert_eq!(Dispatcher::current_uri(ctx).as_deref(), Some("sip:10.0.0.1:5070"));
            assert_eq!(d.next(ctx, false), -1, "limit 1: nothing to fail over to");
        });
        // alg 12: one branch per other destination.
        with_ctx(&m, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[1, 12]), 0), 1);
            assert_eq!(ctx.branches.len(), 1);
            assert_eq!(ctx.branches[0].uri, b"sip:carol@c.example");
            assert_eq!(ctx.branches[0].dst.map(|x| x.addr.to_string()).as_deref(), Some("10.0.0.2:5060"));
        });
        // Unknown set, set out of i32, no args: -1.
        with_ctx(&m, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(d.select_dst(ctx, &ints(&[7, 4]), 0), -1);
            assert_eq!(d.select_dst(ctx, &ints(&[1 << 40, 4]), 0), -1);
            assert_eq!(d.select_dst(ctx, &ints(&[1]), 0), -1);
            assert_eq!(d.next(ctx, false), -1, "nothing selected");
        });
    }

    fn state(d: &Dst) -> u8 {
        d.state.load(Ordering::Relaxed)
    }

    #[test]
    fn dispatcher_probe_failures_reach_inactive_at_the_threshold() {
        let d = loaded("1 sip:10.0.0.1:5060\n");
        d.set_param("ds_probing_threshold", &Arg::Int(2)).unwrap();
        let x = dst(&d, 1, "sip:10.0.0.1:5060");
        d.probe_result(&x, 408);
        assert_eq!(state(&x), DS_TRYING, "first failure: trying");
        assert!(x.active(), "trying is still active");
        // A success in between clears trying and restarts the count.
        d.probe_result(&x, 200);
        assert_eq!(state(&x), 0);
        d.probe_result(&x, 503);
        assert_eq!(state(&x), DS_TRYING);
        d.probe_result(&x, 503);
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING, "second failure in a row");
        assert!(!x.active());
        // Inactive: more failures change nothing.
        d.probe_result(&x, 503);
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING);
    }

    #[test]
    fn dispatcher_probe_successes_reactivate_at_the_threshold() {
        let d = loaded("1 sip:10.0.0.1:5060 9\n");
        d.set_param("ds_inactive_threshold", &Arg::Int(2)).unwrap();
        let x = dst(&d, 1, "sip:10.0.0.1:5060");
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING, "flags 9 from the list");
        d.probe_result(&x, 200);
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING, "one success is not enough");
        d.probe_result(&x, 500);
        d.probe_result(&x, 200);
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING, "a failure restarts the count");
        d.probe_result(&x, 299);
        assert_eq!(state(&x), 0, "active, no longer probed");
        // probing_mode 1 (all): stays probed when it comes back.
        let d = loaded("1 sip:10.0.0.1:5060 9\n");
        d.set_param("ds_probing_mode", &Arg::Int(1)).unwrap();
        let x = dst(&d, 1, "sip:10.0.0.1:5060");
        d.probe_result(&x, 200);
        assert_eq!(state(&x), DS_PROBING);
    }

    #[test]
    fn dispatcher_probe_reply_codes_and_disabled_destinations() {
        let d = loaded("1 sip:10.0.0.1:5060 8\n1 sip:10.0.0.2:5060 4\n");
        d.set_param("ds_ping_reply_codes", &Arg::Str("class=4;code=503".into())).unwrap();
        let x = dst(&d, 1, "sip:10.0.0.1:5060");
        for code in [200, 404, 499, 503] {
            d.probe_result(&x, code);
            assert_eq!(state(&x), DS_PROBING, "{code} counts as up");
        }
        d.probe_result(&x, 502);
        assert_eq!(state(&x), DS_INACTIVE | DS_PROBING, "502 is down");
        let off = dst(&d, 1, "sip:10.0.0.2:5060");
        d.probe_result(&off, 500);
        d.probe_result(&off, 200);
        assert_eq!(state(&off), DS_DISABLED, "a disabled destination ignores probes");
    }

    #[test]
    fn dispatcher_set_state_letters() {
        let d = loaded("1 sip:10.0.0.1:5060\n");
        let x = dst(&d, 1, "sip:10.0.0.1:5060");
        for (st, want) in
            [("ip", DS_INACTIVE | DS_PROBING), ("a", 0), ("D", DS_DISABLED), ("t", DS_TRYING), ("IP", DS_INACTIVE | DS_PROBING), ("x?", 0), ("", 0)]
        {
            d.set_state(&x, st);
            assert_eq!(state(&x), want, "{st:?}");
        }
        x.fails.store(5, Ordering::Relaxed);
        d.set_param("ds_probing_mode", &Arg::Int(1)).unwrap();
        d.set_state(&x, "a");
        assert_eq!(state(&x), DS_PROBING, "probing mode 1 probes every destination");
        assert_eq!(x.fails.load(Ordering::Relaxed), 0, "counters restart");
    }

    #[test]
    fn dispatcher_list_flags_and_latency_json() {
        let d = loaded("1 sip:10.0.0.1:5060 0 3 duid=a\n1 sip:10.0.0.2:5060 9\n1 sip:10.0.0.3:5060 4\n2 sip:10.0.0.4:5060 10\n");
        let v = d.list_json();
        let flags: Vec<(i64, String)> = v["RECORDS"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|s| {
                s["TARGETS"].as_array().unwrap().iter().map(|t| (s["ID"].as_i64().unwrap(), t["FLAGS"].as_str().unwrap().to_string())).collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(flags, [(1, "AX".into()), (1, "IP".into()), (1, "DX".into()), (2, "TP".into())]);
        assert_eq!(v["RECORDS"][0]["TARGETS"][0]["ATTRS"], "duid=a");
        assert_eq!(v["RECORDS"][0]["TARGETS"][0]["PRIORITY"], 3);
        assert!(v["RECORDS"][0]["TARGETS"][0].get("LATENCY").is_none(), "latency stats off");
        d.set_param("ds_ping_latency_stats", &Arg::Int(1)).unwrap();
        {
            let x = dst(&d, 1, "sip:10.0.0.1:5060");
            let mut l = lock(&x.lat);
            l.add(10.0, 0.9);
            l.add(20.0, 0.9);
            l.timeouts = 2;
        }
        let v = d.list_json();
        let lat = &v["RECORDS"][0]["TARGETS"][0]["LATENCY"];
        assert_eq!((lat["AVG"].as_f64(), lat["EST"].as_f64(), lat["MAX"].as_f64(), lat["TIMEOUT"].as_u64()), (Some(15.0), Some(11.0), Some(20.0), Some(2)));
        assert_eq!(lat["STD"].as_f64(), Some(7.1), "sqrt(50), one decimal");
        assert!(v["RECORDS"][0]["TARGETS"][1].get("LATENCY").is_none(), "never measured");
    }

    #[test]
    fn dispatcher_list_file_edge_cases() {
        let r = parse_list("  # comment\n\n 3\tsip:10.0.0.1  2  -5  \"weight=1;duid=x y\"  \n").unwrap();
        assert_eq!(r, [(3, "sip:10.0.0.1".into(), 2, -5, "weight=1;duid=x y".into())]);
        for bad in ["1", "x sip:a", "1 sip:a 256", "1 sip:a z", "1 sip:a 0 p", "99999999999 sip:a"] {
            let e = parse_list(&format!("# ok\n{bad}\n")).unwrap_err();
            assert!(e.contains("line 2"), "{bad:?}: {e}");
        }
        assert_eq!(parse_list("").unwrap(), []);
    }

    #[test]
    fn dispatcher_reload_keeps_known_states_and_rejects_bad_uris() {
        let d = loaded("1 sip:10.0.0.1:5060\n");
        d.set_state(&dst(&d, 1, "sip:10.0.0.1:5060"), "i");
        assert_eq!(reload_from(&d, "1 sip:10.0.0.1:5060\n1 sip:10.0.0.2:5060 4\n2 sip:10.0.0.1:5060\n"), Ok(3));
        assert_eq!(state(&dst(&d, 1, "sip:10.0.0.1:5060")), DS_INACTIVE, "kept");
        assert_eq!(state(&dst(&d, 1, "sip:10.0.0.2:5060")), DS_DISABLED, "new: from the flags");
        assert_eq!(state(&dst(&d, 2, "sip:10.0.0.1:5060")), 0, "same URI in another set is another destination");
        assert!(reload_from(&d, "1 sip:10.0.0.9:5060\n1 not-a-uri\n").is_err());
        assert!(d.dst_of(1, "sip:10.0.0.2:5060").is_some(), "a failed reload keeps the old sets");
        assert!(d.dst_of(1, "sip:10.0.0.9:5060").is_none());
        // The flags column keeps only the state bits.
        assert!(reload_from(&d, "5 sip:10.0.0.5:5060 255\n").is_ok());
        assert_eq!(state(&dst(&d, 5, "sip:10.0.0.5:5060")), 0x0f);
    }

    #[test]
    fn dispatcher_find_ignores_brackets_and_case() {
        let d = loaded("1 sip:10.0.0.1:5060\n2 sip:10.0.0.1:5060\n");
        assert_eq!(d.find(None, "<SIP:10.0.0.1:5060>").len(), 2);
        assert_eq!(d.find(Some(2), "sip:10.0.0.1:5060").len(), 1);
        assert!(d.find(Some(3), "sip:10.0.0.1:5060").is_empty());
        assert!(d.find(None, "sip:10.0.0.1").is_empty(), "the port is part of the URI");
    }

    #[test]
    fn dispatcher_is_from_list_modes() {
        let d = loaded("1 sip:10.0.0.1:5060\n2 sip:10.0.0.2:5070;transport=tcp\n");
        let net = FakeNet(vec![]);
        let m = request("OPTIONS", "sip:x@y", "");
        let from = |src: Dest, group: i64, mode: i64, uri: Option<&str>| with_ctx(&m, src, &net, |ctx| d.is_from_list(ctx, group, mode, uri.map(String::from)));
        let tcp = |a: &str| Dest::new(Proto::Tcp, a.parse().unwrap());
        let cases = [
            (udp("10.0.0.1:5060"), -1, 0, None, 1),
            (udp("10.0.0.1:5060"), 1, 0, None, 1),
            (udp("10.0.0.1:5060"), 2, 0, None, -1),
            (udp("10.0.0.1:5999"), -1, 0, None, -1),
            (udp("10.0.0.1:5999"), -1, 1, None, 1),
            (tcp("10.0.0.1:5060"), -1, 0, None, -1),
            (tcp("10.0.0.1:5060"), -1, 2, None, 1),
            (tcp("10.0.0.2:5070"), -1, 0, None, 1),
            (udp("10.0.0.3:5060"), -1, 3, None, -1),
            (udp("10.0.0.9:1"), -1, 0, Some("sip:10.0.0.2:5070;transport=tcp"), 1),
            (udp("10.0.0.9:1"), -1, 0, Some("sip:10.0.0.2:5070"), -1),
            (udp("10.0.0.9:1"), -1, 0, Some("sip:10.0.0.1"), 1),
            (udp("10.0.0.9:1"), -1, 0, Some("garbage"), -1),
        ];
        for (src, group, mode, uri, want) in cases {
            assert_eq!(from(src, group, mode, uri), want, "src {:?} group {group} mode {mode} uri {uri:?}", src.addr);
        }
    }

    #[test]
    fn dispatcher_numeric_parameters_are_clamped() {
        let d = Dispatcher::default();
        d.set_param("ds_probing_threshold", &Arg::Int(0)).unwrap();
        d.set_param("ds_inactive_threshold", &Arg::Int(-5)).unwrap();
        d.set_param("ds_latency_estimator_alpha", &Arg::Int(5000)).unwrap();
        d.set_param("ds_ping_interval", &Arg::Int(-1)).unwrap();
        assert_eq!(
            (
                d.probing_threshold.load(Ordering::Relaxed),
                d.inactive_threshold.load(Ordering::Relaxed),
                d.alpha.load(Ordering::Relaxed),
                d.ping_interval.load(Ordering::Relaxed)
            ),
            (1, 1, 1000, 0)
        );
        assert!(d.set_param("ds_hash_size", &Arg::Int(9)).is_ok(), "accepted and ignored");
        assert!(d.set_param("nope", &Arg::Int(1)).is_err());
        for bad in ["code", "code=x", "status=200", "code=70000"] {
            assert!(d.set_param("ds_ping_reply_codes", &Arg::Str(bad.into())).is_err(), "{bad}");
        }
        d.set_param("ds_ping_reply_codes", &Arg::Str(" ; code = 486 ;".into())).unwrap();
        assert_eq!(*lock(&d.reply_codes), vec![(486, 486)]);
    }

    #[test]
    fn index_helpers_handle_zero() {
        assert_eq!(index_mod(12345, 0), 0);
        assert_eq!(index_mod(u64::MAX, 7), usize::try_from(u64::MAX % 7).unwrap());
        let rr = AtomicUsize::new(usize::MAX);
        assert_eq!(next_rr(&rr, 0), 0);
        assert_eq!(next_rr(&rr, 3), 0, "the counter wrapped to 0");
        assert_eq!(next_rr(&rr, 3), 1);
    }
}
