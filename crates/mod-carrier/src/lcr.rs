//! `lcr` — least cost routing over gateways and prefix rules (tables
//! `lcr_gw`, `lcr_rule`, `lcr_rule_target`), with the Sipwise patches:
//! `stopper_mode` (a stopper rule cuts the *ordered gateway list* after its
//! gateways instead of only hiding shorter prefixes), per-gateway
//! statistics (`lcr_stats`: requests/replies received from each gateway by
//! method/class) and `gw_id_avp` (the selected gateway's id).
//!
//! `load_gws(lcr_id[, uri_user[, caller_uri]])` orders matching gateways by
//! longest prefix, then priority, then randomized weight (or, with
//! `priority_ordering=1`, by priority and weight only) and keeps them in
//! `$xavp(_lcr_gws_)`, which tm carries into `failure_route`;
//! `next_gw()` takes the next one and rewrites the R-URI (strip/prefix the
//! user, gateway host/port/params/transport; with both hostname and IP the
//! hostname goes into the R-URI and the IP into `$du`).
//! `defunct_gw(period)`, `inactivate_gw()` (re-activated by OPTIONS pings
//! when `ping_interval` > 0), `from_gw`, `from_any_gw`, `to_gw`, `to_any_gw`.
//! RPC: `lcr.reload`, `lcr.dump_gws`, `lcr.dump_rules`, `lcr.defunct_gw`,
//! `lcr.load_gws`, `lcr.stats`.

use crate::{args, rand_u64};
use mod_txn::{Tm, UacRequest};
use regex::Regex;
use sip_core::module::{DynInt, DynStr, rc};
use sip_core::pv::{PvRef, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::{Value, json};
use sip_core::sig::{ArgTy, FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Proto, Registry, TxnVars};
use sip_parser::{HdrFlags, HdrKind, Method, parse_uri};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

const XAVP: &str = "_lcr_gws_";
const CUR: &str = "_lcr_cur_";
const RUSER: &str = "_lcr_ruri_user_";
const METHODS: [&str; 9] = ["INVITE", "CANCEL", "ACK", "BYE", "INFO", "REGISTER", "SUBSCRIBE", "NOTIFY", "OTHER"];

#[derive(Default)]
struct GwStats {
    reqs: AtomicU64,
    by_method: [AtomicU64; 9],
    rpl: [AtomicU64; 6],
}

struct Gw {
    id: i64,
    lcr_id: i64,
    name: String,
    ip: Option<IpAddr>,
    hostname: Option<String>,
    port: Option<u16>,
    params: String,
    scheme: i64,
    transport: i64,
    strip: usize,
    prefix: String,
    tag: String,
    flags: i64,
    defunct_until: AtomicU64,
    stats: GwStats,
}

impl Gw {
    fn active(&self, t: u64) -> bool {
        self.defunct_until.load(Ordering::Relaxed) <= t
    }
    fn proto(&self) -> Option<Proto> {
        match self.transport {
            1 => Some(Proto::Udp),
            2 => Some(Proto::Tcp),
            3 => Some(Proto::Tls),
            _ => None,
        }
    }
}

struct Rule {
    id: i64,
    lcr_id: i64,
    prefix: String,
    from_uri: Option<Regex>,
    request_uri: Option<Regex>,
    stopper: bool,
    /// (gw id, priority, weight)
    targets: Vec<(i64, i64, i64)>,
}

#[derive(Default)]
struct Data {
    gws: Vec<Arc<Gw>>,
    rules: Vec<Rule>,
}

/// One ordered candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pick {
    gw_id: i64,
    rule_id: i64,
    prefix_len: usize,
    priority: i64,
    randw: u64,
    stopper: bool,
}

#[derive(Default)]
struct AvpNames {
    tag: Option<String>,
    flags: Option<String>,
    rule_id: Option<String>,
    gw_id: Option<String>,
    lcr_id: Option<String>,
    gw_uri: Option<String>,
}

#[derive(Default)]
struct AvpRefs {
    tag: Option<PvRef>,
    flags: Option<PvRef>,
    rule_id: Option<PvRef>,
    gw_id: Option<PvRef>,
    lcr_id: Option<PvRef>,
}

pub struct Lcr {
    db_url: Mutex<Option<String>>,
    tables: Mutex<[String; 3]>,
    data: RwLock<Arc<Data>>,
    priority_ordering: AtomicBool,
    stopper_mode: AtomicU32,
    stats: AtomicBool,
    dont_strip_flag: Mutex<Option<u32>>,
    ping_interval: AtomicU64,
    ping_from: Mutex<String>,
    ping_codes: Mutex<Vec<u16>>,
    avp_names: Mutex<AvpNames>,
    avps: OnceLock<AvpRefs>,
    tm: OnceLock<Arc<Tm>>,
}

impl Default for Lcr {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            tables: Mutex::new(["lcr_gw".into(), "lcr_rule".into(), "lcr_rule_target".into()]),
            data: RwLock::new(Arc::new(Data::default())),
            priority_ordering: AtomicBool::new(false),
            stopper_mode: AtomicU32::new(0),
            stats: AtomicBool::new(false),
            dont_strip_flag: Mutex::new(None),
            ping_interval: AtomicU64::new(0),
            ping_from: Mutex::new("sip:lcr@localhost".into()),
            ping_codes: Mutex::new(Vec::new()),
            avp_names: Mutex::new(AvpNames::default()),
            avps: OnceLock::new(),
            tm: OnceLock::new(),
        }
    }
}

fn opt_re(s: String) -> Result<Option<Regex>, String> {
    if s.is_empty() { Ok(None) } else { Regex::new(&s).map(Some).map_err(|e| format!("lcr: bad pattern {s:?}: {e}")) }
}

impl Lcr {
    fn data(&self) -> Arc<Data> {
        read(&self.data).clone()
    }

    fn reload(&self) -> Result<(usize, usize), String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("lcr"));
        let db = sip_db::connect(&url)?;
        let [tg, tr, tt] = lock(&self.tables).clone();
        let old = self.data();
        let gws = db.query(
            &tg,
            &["id", "lcr_id", "gw_name", "ip_addr", "hostname", "port", "params", "uri_scheme", "transport", "strip", "prefix", "tag", "flags", "defunct"],
            &[],
        )?;
        let mut v = Vec::new();
        for r in gws.rows {
            let txt = |i: usize| r.get(i).map(sip_db::DbVal::text).unwrap_or_default();
            let int = |i: usize| r.get(i).and_then(sip_db::DbVal::int);
            let id = int(0).unwrap_or(0);
            let ip = Some(txt(3)).filter(|s| !s.is_empty()).map(|s| s.parse::<IpAddr>().map_err(|_| format!("lcr gw {id}: bad ip_addr {s:?}"))).transpose()?;
            let hostname = Some(txt(4)).filter(|s| !s.is_empty());
            if ip.is_none() && hostname.is_none() {
                return Err(format!("lcr gw {id}: needs ip_addr or hostname"));
            }
            let prev = old.gws.iter().find(|g| g.id == id).map(|g| g.defunct_until.load(Ordering::Relaxed));
            let defunct = int(13).and_then(|d| u64::try_from(d).ok()).filter(|d| *d > 0);
            let port = match int(5).filter(|p| *p > 0) {
                None => None,
                Some(p) => match u16::try_from(p) {
                    Ok(p) => Some(p),
                    Err(_) => {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("lcr gw {id}: port {p} out of range, gateway skipped"));
                        continue;
                    }
                },
            };
            v.push(Arc::new(Gw {
                id,
                lcr_id: int(1).unwrap_or(0),
                name: txt(2),
                ip,
                hostname,
                port,
                params: txt(6),
                scheme: int(7).unwrap_or(1),
                transport: int(8).unwrap_or(0),
                strip: usize::try_from(int(9).unwrap_or(0).max(0)).unwrap_or(usize::MAX),
                prefix: txt(10),
                tag: txt(11),
                flags: int(12).unwrap_or(0),
                defunct_until: AtomicU64::new(prev.or(defunct).unwrap_or(0)),
                stats: GwStats::default(),
            }));
        }
        let rules = db.query(&tr, &["id", "lcr_id", "prefix", "from_uri", "request_uri", "stopper", "enabled"], &[])?;
        let targets = db.query(&tt, &["lcr_id", "rule_id", "gw_id", "priority", "weight"], &[])?;
        let mut by_rule: HashMap<i64, Vec<(i64, i64, i64)>> = HashMap::new();
        for t in targets.rows {
            let int = |i: usize| t.get(i).and_then(sip_db::DbVal::int).unwrap_or(0);
            by_rule.entry(int(1)).or_default().push((int(2), int(3), int(4).clamp(1, 254)));
        }
        let mut rv = Vec::new();
        for r in rules.rows {
            let txt = |i: usize| r.get(i).map(sip_db::DbVal::text).unwrap_or_default();
            let int = |i: usize| r.get(i).and_then(sip_db::DbVal::int).unwrap_or(0);
            if r.get(6).and_then(sip_db::DbVal::int) == Some(0) {
                continue; // disabled
            }
            let id = int(0);
            rv.push(Rule {
                id,
                lcr_id: int(1),
                prefix: txt(2),
                from_uri: opt_re(txt(3))?,
                request_uri: opt_re(txt(4))?,
                stopper: int(5) != 0,
                targets: by_rule.remove(&id).unwrap_or_default(),
            });
        }
        let n = (v.len(), rv.len());
        *write(&self.data) = Arc::new(Data { gws: v, rules: rv });
        Ok(n)
    }

    /// Ordered gateway candidates for (lcr_id, user, caller URI, R-URI).
    fn select(&self, lcr_id: i64, user: &str, caller: &str, ruri: &str) -> Vec<Pick> {
        let d = self.data();
        let t = unix_secs();
        let mode = self.stopper_mode.load(Ordering::Relaxed);
        let mut rules: Vec<&Rule> = d
            .rules
            .iter()
            .filter(|r| r.lcr_id == lcr_id && user.starts_with(r.prefix.as_str()))
            .filter(|r| r.from_uri.as_ref().is_none_or(|re| re.is_match(caller)) && r.request_uri.as_ref().is_none_or(|re| re.is_match(ruri)))
            .collect();
        rules.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        let mut picks = Vec::new();
        let mut stop_len: Option<usize> = None;
        for r in rules {
            if stop_len.is_some_and(|l| r.prefix.len() < l) {
                break; // stock semantics: a stopper hides shorter prefixes
            }
            for &(gw_id, priority, weight) in &r.targets {
                let Some(gw) = d.gws.iter().find(|g| g.id == gw_id) else { continue };
                if (gw.lcr_id != lcr_id && gw.lcr_id != 0) || !gw.active(t) {
                    continue;
                }
                picks.push(Pick {
                    gw_id,
                    rule_id: r.id,
                    prefix_len: r.prefix.len(),
                    priority,
                    randw: (rand_u64() % 1000).saturating_mul(u64::try_from(weight).unwrap_or(0)),
                    stopper: r.stopper,
                });
            }
            if r.stopper && mode == 0 {
                stop_len = Some(r.prefix.len());
            }
        }
        if self.priority_ordering.load(Ordering::Relaxed) {
            picks.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.randw.cmp(&a.randw)));
        } else {
            picks.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len).then(a.priority.cmp(&b.priority)).then(b.randw.cmp(&a.randw)));
        }
        let mut seen = std::collections::HashSet::new();
        picks.retain(|p| seen.insert(p.gw_id));
        if mode != 0 {
            // Sipwise stopper_mode: nothing after a stopper rule's gateway.
            if let Some(i) = picks.iter().position(|p| p.stopper) {
                picks.truncate(i.saturating_add(1));
            }
        }
        picks
    }

    fn load_gws(&self, ctx: &mut Ctx<'_, '_>, lcr_id: i64, user: Option<String>, caller: Option<String>) -> i32 {
        let ruri = String::from_utf8_lossy(ctx.ruri()).into_owned();
        let user = user.unwrap_or_else(|| parse_uri(ruri.as_bytes()).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default());
        let picks = self.select(lcr_id, &user, caller.as_deref().unwrap_or(""), &ruri);
        let items = picks
            .iter()
            .map(|p| {
                let mut m = HashMap::new();
                m.insert("gw_id".to_string(), Val::Int(p.gw_id));
                m.insert("rule_id".to_string(), Val::Int(p.rule_id));
                m.insert("lcr_id".to_string(), Val::Int(lcr_id));
                m
            })
            .collect::<Vec<_>>();
        let n = items.len();
        let v = ctx.ext_mut::<TxnVars>();
        v.xavps.insert(XAVP.into(), items);
        v.avps.remove(RUSER);
        if n > 0 { 1 } else { 2 }
    }

    fn next_gw(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some(item) = ctx.ext_get_mut::<TxnVars>().and_then(|t| t.xavps.get_mut(XAVP)).and_then(|l| (!l.is_empty()).then(|| l.remove(0))) else { return -1 };
        let int = |k: &str| item.get(k).and_then(Val::as_int).unwrap_or(0);
        let (gw_id, rule_id, lcr_id) = (int("gw_id"), int("rule_id"), int("lcr_id"));
        let d = self.data();
        let Some(gw) = d.gws.iter().find(|g| g.id == gw_id).cloned() else { return self.next_gw(ctx) };
        let ruri = ctx.ruri().to_vec();
        let saved = ctx.ext::<TxnVars>().and_then(|t| t.avps.get(RUSER)).and_then(|v| v.last()).map(|v| v.as_str().into_owned());
        let user = match saved {
            Some(u) => u,
            None => {
                let u = parse_uri(&ruri).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default();
                ctx.ext_mut::<TxnVars>().avps.insert(RUSER.into(), vec![Val::str(&u)]);
                u
            }
        };
        let no_strip = lock(&self.dont_strip_flag).is_some_and(|f| ctx.ext::<TxnVars>().is_some_and(|t| t.flags & (1 << f) != 0));
        let user = if no_strip { user } else { format!("{}{}", gw.prefix, user.get(gw.strip.min(user.len())..).unwrap_or("")) };
        let scheme = if gw.scheme == 2 { "sips" } else { "sip" };
        let tparam = match gw.transport {
            1 => ";transport=udp",
            2 => ";transport=tcp",
            3 => ";transport=tls",
            4 => ";transport=sctp",
            _ => "",
        };
        let at = if user.is_empty() { String::new() } else { format!("{user}@") };
        let params = if gw.params.is_empty() || gw.params.starts_with(';') { gw.params.clone() } else { format!(";{}", gw.params) };
        let port = gw.port.map(|p| format!(":{p}")).unwrap_or_default();
        let ip = gw.ip.map(|ip| if ip.is_ipv6() { format!("[{ip}]") } else { ip.to_string() });
        match (&gw.hostname, &ip) {
            (Some(h), Some(ip)) => {
                ctx.new_ruri = Some(format!("{scheme}:{at}{h}{params}").into_bytes());
                ctx.dst = sip_core::pvcore::dest_from_uri(format!("{scheme}:{ip}{port}{tparam}").as_bytes());
            }
            (Some(h), None) => ctx.new_ruri = Some(format!("{scheme}:{at}{h}{port}{params}{tparam}").into_bytes()),
            (None, Some(ip)) => ctx.new_ruri = Some(format!("{scheme}:{at}{ip}{port}{params}{tparam}").into_bytes()),
            (None, None) => return -1,
        }
        let mut cur = HashMap::new();
        cur.insert("gw_id".to_string(), Val::Int(gw_id));
        cur.insert("lcr_id".to_string(), Val::Int(lcr_id));
        ctx.ext_mut::<TxnVars>().xavps.insert(CUR.into(), vec![cur]);
        if let Some(a) = self.avps.get() {
            let set = |ctx: &mut Ctx<'_, '_>, pv: &Option<PvRef>, v: Val| {
                if let Some(pv) = pv {
                    let _ = pv.set(ctx, v);
                }
            };
            set(ctx, &a.tag, Val::str(&gw.tag));
            set(ctx, &a.flags, Val::Int(gw.flags));
            set(ctx, &a.rule_id, Val::Int(rule_id));
            set(ctx, &a.gw_id, Val::Int(gw_id));
            set(ctx, &a.lcr_id, Val::Int(lcr_id));
        }
        1
    }

    fn current_gw(&self, ctx: &Ctx<'_, '_>) -> Option<Arc<Gw>> {
        let id = ctx.ext::<TxnVars>()?.xavps.get(CUR)?.first()?.get("gw_id")?.as_int()?;
        self.data().gws.iter().find(|g| g.id == id).cloned()
    }

    /// Gateways matching an address/proto/port (`from_gw`, `to_gw`).
    fn match_addr(&self, lcr_id: Option<i64>, ip: IpAddr, proto: Option<Proto>, port: Option<u16>) -> Option<Arc<Gw>> {
        self.data()
            .gws
            .iter()
            .find(|g| {
                lcr_id.is_none_or(|l| g.lcr_id == l)
                    && g.ip == Some(ip)
                    && (g.proto().is_none() || proto.is_none() || g.proto() == proto)
                    && port.is_none_or(|p| g.port.unwrap_or(5060) == p)
            })
            .cloned()
    }

    fn set_gw_avps(&self, ctx: &mut Ctx<'_, '_>, gw: &Gw) {
        if let Some(a) = self.avps.get() {
            if let Some(pv) = &a.tag {
                let _ = pv.set(ctx, Val::str(&gw.tag));
            }
            if let Some(pv) = &a.flags {
                let _ = pv.set(ctx, Val::Int(gw.flags));
            }
        }
    }

    fn gw_json(&self, g: &Gw) -> Value {
        let t = unix_secs();
        let du = g.defunct_until.load(Ordering::Relaxed);
        let mut v = json!({"lcr_id": g.lcr_id, "gw_id": g.id, "gw_name": g.name, "scheme": if g.scheme == 2 { "sips" } else { "sip" },
            "ip_addr": g.ip.map(|i| i.to_string()), "hostname": g.hostname, "port": g.port, "params": g.params, "transport": g.transport,
            "strip": g.strip, "prefix": g.prefix, "tag": g.tag, "flags": g.flags,
            "state": if du == u64::MAX { "inactive" } else if du > t { "defunct" } else { "active" }, "defunct_until": if du > t { du } else { 0 }});
        if self.stats.load(Ordering::Relaxed) {
            let s = &g.stats;
            let mut m = sip_core::serde_json::Map::new();
            m.insert("rcv_gw_reqs".into(), json!(s.reqs.load(Ordering::Relaxed)));
            for (name, c) in METHODS.iter().zip(&s.by_method) {
                m.insert(format!("rcv_gw_reqs_{}", name.to_ascii_lowercase()), json!(c.load(Ordering::Relaxed)));
            }
            for (class, c) in (1..=6).zip(&s.rpl) {
                m.insert(format!("rcv_gw_rpl_{class}xx"), json!(c.load(Ordering::Relaxed)));
            }
            if let Some(o) = v.as_object_mut() {
                o.insert("stats".into(), Value::Object(m));
            }
        }
        v
    }

    fn ping(self: &Arc<Self>) {
        let Some(tm) = self.tm.get() else { return };
        let from = lock(&self.ping_from).clone();
        for g in self.data().gws.iter().filter(|g| g.defunct_until.load(Ordering::Relaxed) == u64::MAX) {
            let host = g.ip.map(|i| i.to_string()).or_else(|| g.hostname.clone()).unwrap_or_default();
            let port = g.port.map(|p| format!(":{p}")).unwrap_or_default();
            let tp = match g.transport {
                2 => ";transport=tcp",
                3 => ";transport=tls",
                _ => "",
            };
            let uri = format!("sip:{host}{port}{tp}");
            let me = self.clone();
            let gw = g.clone();
            let req = UacRequest { method: "OPTIONS".into(), ruri: uri.clone(), from: Some(from.clone()), to: Some(uri), ..Default::default() };
            let _ = tm.t_uac(
                req,
                Some(Box::new(move |code, _| {
                    if (200..300).contains(&code) || lock(&me.ping_codes).contains(&code) {
                        gw.defunct_until.store(0, Ordering::Relaxed);
                    }
                })),
            );
        }
    }
}

fn proto_arg(s: &str) -> Option<Proto> {
    match s.trim() {
        "1" | "udp" => Some(Proto::Udp),
        "2" | "tcp" => Some(Proto::Tcp),
        "3" | "tls" => Some(Proto::Tls),
        _ => None,
    }
}

type AddrArgs = Vec<DynStr>;

impl Module for Lcr {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, opt, sig};
        const PROTO: ArgTy = Enum(&["udp", "tcp", "tls"]);
        const LOAD: &[Param] = &[arg("lcr_id", Int), opt("user", Str), opt("caller", Uri)];
        const FROM_AT: &[Param] = &[arg("lcr_id", Int), arg("ip", Str).eg("\"192.0.2.1\""), arg("proto", PROTO), opt("port", Int)];
        const FROM_ANY_AT: &[Param] = &[arg("ip", Str).eg("\"192.0.2.1\""), arg("proto", PROTO), opt("port", Int)];
        const TO_AT: &[Param] = &[arg("lcr_id", Int), arg("ip", Str).eg("\"192.0.2.1\""), arg("proto", PROTO)];
        const TO_ANY_AT: &[Param] = &[arg("ip", Str).eg("\"192.0.2.1\""), arg("proto", PROTO)];
        const ID: &[Param] = &[arg("lcr_id", Int)];
        const PERIOD: &[Param] = &[arg("period", Duration(Unit::Sec))];
        Some(vec![
            sig("load_gws", "load_gateways", LOAD, Ret::Bool, "Load the gateways that match the R-URI user (or `user`) in LCR instance `lcr_id`"),
            sig("next_gw", "next_gateway", &[], Ret::Bool, "Route to the next loaded gateway (false when none is left)"),
            sig("defunct_gw", "defunct_gateway", PERIOD, Ret::Bool, "Take the current gateway out of use for `period`"),
            sig("inactivate_gw", "inactivate_gateway", &[], Ret::Bool, "Take the current gateway out of use until reload"),
            sig("from_gw", "from_gateway", ID, Ret::Bool, "The request comes from a gateway of LCR instance `lcr_id`"),
            sig("from_gw", "from_gateway_at", FROM_AT, Ret::Bool, "`ip`/`proto` (and `port`) is a gateway of LCR instance `lcr_id`"),
            sig("from_any_gw", "from_any_gateway", &[], Ret::Bool, "The request comes from a gateway of any LCR instance"),
            sig("from_any_gw", "from_any_gateway_at", FROM_ANY_AT, Ret::Bool, "`ip`/`proto` (and `port`) is a gateway of any LCR instance"),
            sig("to_gw", "to_gateway", ID, Ret::Bool, "The R-URI points at a gateway of LCR instance `lcr_id`"),
            sig("to_gw", "to_gateway_at", TO_AT, Ret::Bool, "`ip`/`proto` is a gateway of LCR instance `lcr_id`"),
            sig("to_any_gw", "to_any_gateway", &[], Ret::Bool, "The R-URI points at a gateway of any LCR instance"),
            sig("to_any_gw", "to_any_gateway_at", TO_ANY_AT, Ret::Bool, "`ip`/`proto` is a gateway of any LCR instance"),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the lcr tables"),
            p("lcr_gw_table", Ty::Str, "lcr_gw", "Gateway table"),
            p("lcr_rule_table", Ty::Str, "lcr_rule", "Prefix rule table"),
            p("lcr_rule_target_table", Ty::Str, "lcr_rule_target", "Rule to gateway table"),
            p("priority_ordering", Ty::Bool, "false", "Order gateways by priority and weight only, not by prefix length"),
            p("stopper_mode", Ty::Bool, "false", "A stopper rule cuts the ordered gateway list after its gateways (Sipwise)"),
            p("lcr_stats", Ty::Bool, "false", "Count requests and replies per gateway"),
            p("dont_strip_or_prefix_flag", Ty::Int { min: 0, max: 63 }, "", "Message flag that keeps next_gw from stripping or prefixing the user"),
            p("ping_interval", Ty::Duration(Unit::Sec), "0s", "OPTIONS ping interval for inactive gateways (0: off)"),
            p("ping_from", Ty::Str, "sip:lcr@localhost", "From URI of the OPTIONS pings"),
            p("ping_valid_reply_codes", Ty::Str, "", "Comma-separated non-2xx reply codes that also count as alive"),
            p("tag_avp", Ty::Str, "", "AVP that gets the selected gateway's tag"),
            p("flags_avp", Ty::Str, "", "AVP that gets the selected gateway's flags"),
            p("rule_id_avp", Ty::Str, "", "AVP that gets the matching rule's id"),
            p("gw_id_avp", Ty::Str, "", "AVP that gets the selected gateway's id"),
            p("lcr_id_avp", Ty::Str, "", "AVP that gets the lcr id"),
            p("gw_uri_avp", Ty::Str, "", "AVP that gets the selected gateway's URI"),
        ])
    }

    fn name(&self) -> &'static str {
        "lcr"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let s = || v.str().map(|x| Some(x.to_string()));
        let mut tables = lock(&self.tables);
        let [gw_table, rule_table, target_table] = &mut *tables;
        match name {
            "db_url" => *lock(&self.db_url) = s()?,
            "lcr_gw_table" => *gw_table = v.str()?.into(),
            "lcr_rule_table" => *rule_table = v.str()?.into(),
            "lcr_rule_target_table" => *target_table = v.str()?.into(),
            "priority_ordering" => self.priority_ordering.store(v.int()? != 0, Ordering::Relaxed),
            "stopper_mode" => self.stopper_mode.store(u32::try_from(v.int()?.max(0)).unwrap_or(u32::MAX), Ordering::Relaxed),
            "lcr_stats" => self.stats.store(v.int()? != 0, Ordering::Relaxed),
            "dont_strip_or_prefix_flag" => *lock(&self.dont_strip_flag) = Some(u32::try_from(v.int()?).map_err(|_| format!("lcr: {name} out of range"))?),
            "ping_interval" => self.ping_interval.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "ping_from" => *lock(&self.ping_from) = v.str()?.into(),
            "ping_valid_reply_codes" => {
                *lock(&self.ping_codes) = v.str()?.split(',').filter_map(|c| c.trim().parse().ok()).collect();
            }
            "tag_avp" => lock(&self.avp_names).tag = s()?,
            "flags_avp" => lock(&self.avp_names).flags = s()?,
            "rule_id_avp" => lock(&self.avp_names).rule_id = s()?,
            "gw_id_avp" => lock(&self.avp_names).gw_id = s()?,
            "lcr_id_avp" => lock(&self.avp_names).lcr_id = s()?,
            "gw_uri_avp" => lock(&self.avp_names).gw_uri = s()?,
            "ruri_user_avp"
            | "defunct_gw_avp"
            | "defunct_capability"
            | "lcr_count"
            | "lcr_rule_hash_size"
            | "lcr_gw_count"
            | "fetch_rows"
            | "ping_inactivate_threshold"
            | "ping_socket"
            | "mt_pv_values"
            | "mtree" => {}
            n if n.ends_with("_column") => {}
            _ => return Err(format!("lcr: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let (g, r) = self.reload()?;
        sip_core::log::log(sip_core::log::L_INFO, &format!("lcr: loaded {g} gateways, {r} rules"));
        let names = std::mem::take(&mut *lock(&self.avp_names));
        let p = |n: &Option<String>| n.as_ref().map(|s| parse_pv(s, reg.pvs())).transpose();
        let _ = self.avps.set(AvpRefs {
            tag: p(&names.tag)?,
            flags: p(&names.flags)?,
            rule_id: p(&names.rule_id)?,
            gw_id: p(&names.gw_id)?,
            lcr_id: p(&names.lcr_id)?,
        });
        if let Some(tm) = reg.api::<Tm>() {
            let _ = self.tm.set(tm);
        } else if self.ping_interval.load(Ordering::Relaxed) > 0 {
            return Err("lcr: ping_interval needs tm loaded first".into());
        }
        let m = "lcr";
        let me = self.clone();
        reg.export(
            m,
            "load_gws",
            |a: &[Arg]| -> Result<(DynInt, Option<DynStr>, Option<DynStr>), String> {
                let [id, rest @ ..] = a else { return Err("expected lcr_id[, uri_user[, caller_uri]]".into()) };
                if rest.len() > 2 {
                    return Err("expected lcr_id[, uri_user[, caller_uri]]".into());
                }
                Ok((id.dyn_int()?, rest.first().map(Arg::dyn_str).transpose()?, rest.get(1).map(Arg::dyn_str).transpose()?))
            },
            move |ctx: &mut Ctx, (id, u, c): &(DynInt, Option<DynStr>, Option<DynStr>)| {
                let Some(id) = id.eval(ctx) else { return -1 };
                let u = u.as_ref().map(|u| u.eval(ctx).into_owned());
                let c = c.as_ref().map(|c| c.eval(ctx).into_owned());
                me.load_gws(ctx, id, u, c)
            },
        );
        let me = self.clone();
        reg.export(m, "next_gw", |a: &[Arg]| sip_core::want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.next_gw(ctx));
        let me = self.clone();
        reg.export(
            m,
            "defunct_gw",
            |a: &[Arg]| {
                let [period] = args(a)?;
                period.dyn_int()
            },
            move |ctx: &mut Ctx, p: &DynInt| {
                let (Some(p), Some(gw)) = (p.eval(ctx), me.current_gw(ctx)) else { return -1 };
                gw.defunct_until.store(unix_secs().saturating_add(u64::try_from(p).unwrap_or(0).max(1)), Ordering::Relaxed);
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "inactivate_gw",
            |a: &[Arg]| sip_core::want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| match me.current_gw(ctx) {
                Some(gw) => {
                    gw.defunct_until.store(u64::MAX, Ordering::Relaxed);
                    1
                }
                None => -1,
            },
        );
        // from_gw(lcr_id[, ip, proto[, port]]) / from_any_gw([ip, proto[, port]])
        let addr_fix = |min: usize, max: usize| {
            move |a: &[Arg]| -> Result<AddrArgs, String> {
                // `min` (the id), then none or ip, proto[, port].
                if a.len() > max || a.len().checked_sub(min).is_none_or(|addr| addr == 1) {
                    return Err("bad number of arguments".into());
                }
                a.iter().map(Arg::dyn_str).collect()
            }
        };
        let addr_of = |ctx: &mut Ctx<'_, '_>, a: &[DynStr]| -> Option<(IpAddr, Option<Proto>, Option<u16>)> {
            // None, or ip, proto[, port] (checked at fixup).
            let [ip, proto, port @ ..] = a else {
                return Some((ctx.src.addr.ip(), Some(ctx.src.proto), None));
            };
            let ip = ip.eval(ctx).trim().parse().ok()?;
            let proto = proto_arg(&proto.eval(ctx));
            let port = port.first().and_then(|p| p.eval(ctx).trim().parse().ok());
            Some((ip, proto, port))
        };
        let me = self.clone();
        reg.export(m, "from_gw", addr_fix(1, 4), move |ctx: &mut Ctx, a: &AddrArgs| {
            let [id, addr @ ..] = a.as_slice() else { return -1 };
            let Ok(id) = id.eval(ctx).trim().parse::<i64>() else { return -1 };
            let Some((ip, proto, port)) = addr_of(ctx, addr) else { return -1 };
            match me.match_addr(Some(id), ip, proto, port) {
                Some(gw) => {
                    me.set_gw_avps(ctx, &gw);
                    1
                }
                None => -1,
            }
        });
        let me = self.clone();
        reg.export(m, "from_any_gw", addr_fix(0, 3), move |ctx: &mut Ctx, a: &AddrArgs| {
            let Some((ip, proto, port)) = addr_of(ctx, a) else { return -1 };
            match me.match_addr(None, ip, proto, port) {
                Some(gw) => {
                    me.set_gw_avps(ctx, &gw);
                    lcr_rc(gw.lcr_id)
                }
                None => -1,
            }
        });
        let to_addr = |ctx: &mut Ctx<'_, '_>, a: &[DynStr]| -> Option<(IpAddr, Option<Proto>)> {
            // None, or ip, proto (checked at fixup).
            let [ip, proto, ..] = a else {
                let u = parse_uri(ctx.ruri())?;
                let ip = crate::uac::parse_ip(u.host)?;
                let proto = u.param(b"transport").and_then(|t| proto_arg(&String::from_utf8_lossy(t).to_ascii_lowercase()));
                return Some((ip, proto));
            };
            Some((ip.eval(ctx).trim().parse().ok()?, proto_arg(&proto.eval(ctx))))
        };
        let me = self.clone();
        reg.export(m, "to_gw", addr_fix(1, 3), move |ctx: &mut Ctx, a: &AddrArgs| {
            let [id, addr @ ..] = a.as_slice() else { return -1 };
            let Ok(id) = id.eval(ctx).trim().parse::<i64>() else { return -1 };
            let Some((ip, proto)) = to_addr(ctx, addr) else { return -1 };
            rc(me.match_addr(Some(id), ip, proto, None).is_some())
        });
        let me = self.clone();
        reg.export(m, "to_any_gw", addr_fix(0, 2), move |ctx: &mut Ctx, a: &AddrArgs| {
            let Some((ip, proto)) = to_addr(ctx, a) else { return -1 };
            me.match_addr(None, ip, proto, None).map_or(-1, |g| lcr_rc(g.lcr_id))
        });
        // RPC
        let me = self.clone();
        reg.rpc.add("lcr.reload", "Reload gateways and rules", move |_| me.reload().map(|(g, r)| json!({"gws": g, "rules": r})));
        let me = self.clone();
        reg.rpc.add("lcr.dump_gws", "Gateways (with statistics when lcr_stats=1)", move |_| {
            Ok(json!(me.data().gws.iter().map(|g| me.gw_json(g)).collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("lcr.stats", "Per-gateway statistics (lcr_stats)", move |_| {
            if !me.stats.load(Ordering::Relaxed) {
                return Err("lcr_stats is disabled".into());
            }
            let stats = |g| me.gw_json(g).get("stats").cloned().unwrap_or_default();
            Ok(json!(me.data().gws.iter().map(|g| json!({"gw_id": g.id, "gw_name": g.name, "stats": stats(g)})).collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("lcr.dump_rules", "Rules and their targets", move |_| {
            Ok(json!(
                me.data()
                    .rules
                    .iter()
                    .map(|r| json!({"lcr_id": r.lcr_id, "rule_id": r.id, "prefix": r.prefix, "from_uri": r.from_uri.as_ref().map(|x| x.as_str().to_string()),
                    "request_uri": r.request_uri.as_ref().map(|x| x.as_str().to_string()), "stopper": r.stopper,
                    "targets": r.targets.iter().map(|t| json!({"gw_id": t.0, "priority": t.1, "weight": t.2})).collect::<Vec<_>>()}))
                    .collect::<Vec<_>>()
            ))
        });
        let me = self.clone();
        reg.rpc.add("lcr.defunct_gw", "lcr.defunct_gw <lcr_id> <gw_id> <period>", move |p| {
            let (l, g, per) = (sip_core::rpc::int_param(p, 0)?, sip_core::rpc::int_param(p, 1)?, sip_core::rpc::int_param(p, 2)?);
            let d = me.data();
            let gw = d.gws.iter().find(|x| x.id == g && (x.lcr_id == l || x.lcr_id == 0)).ok_or("no such gateway")?;
            gw.defunct_until.store(if per <= 0 { 0 } else { unix_secs().saturating_add(u64::try_from(per).unwrap_or(0)) }, Ordering::Relaxed);
            Ok(json!(0))
        });
        let me = self.clone();
        reg.rpc.add("lcr.load_gws", "lcr.load_gws <lcr_id> <uri_user> [caller_uri] [request_uri]", move |p| {
            let l = sip_core::rpc::int_param(p, 0)?;
            let u = sip_core::rpc::str_param(p, 1)?;
            let c = sip_core::rpc::str_param(p, 2).unwrap_or_default();
            let r = sip_core::rpc::str_param(p, 3).unwrap_or_default();
            let d = me.data();
            Ok(json!(
                me.select(l, &u, &c, &r)
                    .iter()
                    .filter_map(|p| d
                        .gws
                        .iter()
                        .find(|g| g.id == p.gw_id)
                        .map(|g| json!({"gw_id": g.id, "gw_name": g.name, "rule_id": p.rule_id, "priority": p.priority})))
                    .collect::<Vec<_>>()
            ))
        });
        Ok(())
    }

    fn observes(&self) -> bool {
        self.stats.load(Ordering::Relaxed)
    }

    /// lcr_stats: requests received from a gateway.
    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        let Some(gw) = self.match_addr(None, ctx.src.addr.ip(), Some(ctx.src.proto), Some(ctx.src.addr.port())) else { return };
        gw.stats.reqs.fetch_add(1, Ordering::Relaxed);
        let i = match ctx.msg.method() {
            Some(Method::Invite) => 0,
            Some(Method::Cancel) => 1,
            Some(Method::Ack) => 2,
            Some(Method::Bye) => 3,
            Some(Method::Info) => 4,
            Some(Method::Register) => 5,
            Some(Method::Subscribe) => 6,
            Some(Method::Notify) => 7,
            _ => 8,
        };
        if let Some(c) = gw.stats.by_method.get(i) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// lcr_stats: replies received from a gateway, by class.
    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        let Some(code) = ctx.msg.status() else { return };
        let _ = ctx.msg.parse_headers(HdrFlags::EOH);
        let _ = ctx.msg.get(HdrKind::CSeq);
        // 1xx..6xx.
        let class = usize::from(code / 100).checked_sub(1);
        if let Some(gw) = self.match_addr(None, ctx.src.addr.ip(), Some(ctx.src.proto), Some(ctx.src.addr.port()))
            && let Some(c) = class.and_then(|k| gw.stats.rpl.get(k))
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        let every = self.ping_interval.load(Ordering::Relaxed);
        if every == 0 {
            return Ok(());
        }
        std::thread::Builder::new()
            .name("lcr-ping".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(every));
                    self.ping();
                }
            })
            .map_err(|e| format!("cannot start the lcr pinger thread: {e}"))?;
        Ok(())
    }
}

/// A gateway's lcr_id as a script return code (at least 1). An id beyond
/// i32 is clamped: wrapped, 4294967296 would have become 0, which ends
/// the script.
fn lcr_rc(lcr_id: i64) -> i32 {
    i32::try_from(lcr_id.max(1)).unwrap_or(i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcr_id_return_codes_never_wrap() {
        assert_eq!(lcr_rc(0), 1);
        assert_eq!(lcr_rc(5), 5);
        assert_eq!(lcr_rc(1 << 32), i32::MAX, "not 0, which would end the script");
    }

    fn lcr_with(rules: Vec<Rule>, gws: &[i64], mode: u32) -> Lcr {
        let l = Lcr::default();
        l.stopper_mode.store(mode, Ordering::Relaxed);
        let gws = gws
            .iter()
            .map(|&id| {
                Arc::new(Gw {
                    id,
                    lcr_id: 1,
                    name: format!("gw{id}"),
                    ip: Some("10.0.0.1".parse().unwrap()),
                    hostname: None,
                    port: None,
                    params: String::new(),
                    scheme: 1,
                    transport: 0,
                    strip: 0,
                    prefix: String::new(),
                    tag: String::new(),
                    flags: 0,
                    defunct_until: AtomicU64::new(0),
                    stats: GwStats::default(),
                })
            })
            .collect();
        *l.data.write().unwrap() = Arc::new(Data { gws, rules });
        l
    }

    fn rule(id: i64, prefix: &str, stopper: bool, targets: Vec<(i64, i64, i64)>) -> Rule {
        Rule { id, lcr_id: 1, prefix: prefix.into(), from_uri: None, request_uri: None, stopper, targets }
    }

    #[test]
    fn ordering_and_stoppers() {
        let rules = || vec![rule(1, "49", false, vec![(1, 1, 1)]), rule(2, "4930", true, vec![(2, 5, 1), (3, 1, 1)]), rule(3, "", false, vec![(4, 0, 1)])];
        let ids = |l: &Lcr| l.select(1, "493012", "", "").iter().map(|p| p.gw_id).collect::<Vec<_>>();
        // Stock: longest prefix first; the stopper (prefix 4930) hides 49 and "".
        assert_eq!(ids(&lcr_with(rules(), &[1, 2, 3, 4], 0)), vec![3, 2]);
        // Sipwise stopper_mode: shorter prefixes stay unless after the stopper gw.
        assert_eq!(ids(&lcr_with(rules(), &[1, 2, 3, 4], 1)), vec![3]);
        let l = lcr_with(vec![rule(1, "49", false, vec![(1, 1, 1)]), rule(2, "", false, vec![(2, 0, 1), (1, 0, 1)])], &[1, 2], 0);
        assert_eq!(ids(&l), vec![1, 2], "duplicates keep their best position");
        l.data().gws[0].defunct_until.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(ids(&l), vec![2], "inactive gateways are skipped");
    }

    use crate::testutil::{FakeNet, request, udp, with_ctx};
    use sip_core::Dest;

    /// A gateway of lcr_id 1 at 10.0.0.<id>, otherwise empty.
    fn gw(id: i64) -> Gw {
        Gw {
            id,
            lcr_id: 1,
            name: format!("gw{id}"),
            ip: Some(format!("10.0.0.{id}").parse().unwrap()),
            hostname: None,
            port: None,
            params: String::new(),
            scheme: 1,
            transport: 0,
            strip: 0,
            prefix: String::new(),
            tag: String::new(),
            flags: 0,
            defunct_until: AtomicU64::new(0),
            stats: GwStats::default(),
        }
    }

    fn lcr_of(rules: Vec<Rule>, gws: Vec<Gw>) -> Lcr {
        let l = Lcr::default();
        *l.data.write().unwrap() = Arc::new(Data { gws: gws.into_iter().map(Arc::new).collect(), rules });
        l
    }

    fn ids(l: &Lcr, user: &str) -> Vec<i64> {
        l.select(1, user, "sip:caller@c.example", &format!("sip:{user}@r.example")).iter().map(|p| p.gw_id).collect()
    }

    #[test]
    fn lcr_rules_match_by_prefix_and_order_longest_first() {
        let l = lcr_of(
            vec![
                rule(1, "", false, vec![(1, 0, 1)]),
                rule(2, "49", false, vec![(2, 0, 1)]),
                rule(3, "4930", false, vec![(3, 0, 1)]),
                rule(4, "491", false, vec![(4, 0, 1)]),
            ],
            (1..=4).map(gw).collect(),
        );
        let cases: &[(&str, &[i64])] =
            &[("493012", &[3, 2, 1]), ("4930", &[3, 2, 1]), ("4911", &[4, 2, 1]), ("49", &[2, 1]), ("4", &[1]), ("", &[1]), ("+4930", &[1])];
        for (user, want) in cases {
            assert_eq!(ids(&l, user), *want, "user {user:?}");
        }
    }

    #[test]
    fn lcr_priority_orders_within_a_prefix_and_priority_ordering_ignores_length() {
        let rules = || vec![rule(1, "49", false, vec![(1, 5, 1), (2, 1, 1)]), rule(2, "4930", false, vec![(3, 9, 1)])];
        let l = lcr_of(rules(), (1..=3).map(gw).collect());
        assert_eq!(ids(&l, "4930"), [3, 2, 1], "prefix length first, then lowest priority");
        let l = lcr_of(rules(), (1..=3).map(gw).collect());
        l.set_param("priority_ordering", &Arg::Int(1)).unwrap();
        assert_eq!(ids(&l, "4930"), [2, 1, 3], "priority only");
    }

    #[test]
    fn lcr_weight_makes_the_heavier_gateway_first_almost_always() {
        let l = lcr_of(vec![rule(1, "", false, vec![(1, 0, 1), (2, 0, 254)])], (1..=2).map(gw).collect());
        let heavy_first = (0..200).filter(|_| ids(&l, "1")[0] == 2).count();
        assert!(heavy_first >= 180, "weight 254 against 1: first {heavy_first} of 200 times");
        let p = l.select(1, "1", "", "");
        assert!(p.iter().all(|p| p.randw < 1000 * 254), "{p:?}");
    }

    #[test]
    fn lcr_instance_and_uri_patterns_filter_rules_and_gateways() {
        let mut other = rule(9, "", false, vec![(1, 0, 1)]);
        other.lcr_id = 2;
        let mut from = rule(2, "", false, vec![(2, 0, 1)]);
        from.from_uri = Some(Regex::new("^sip:caller@").unwrap());
        let mut ruri = rule(3, "", false, vec![(3, 0, 1)]);
        ruri.request_uri = Some(Regex::new("@r\\.example$").unwrap());
        let mut any_lcr = gw(4);
        any_lcr.lcr_id = 0;
        let mut foreign = gw(5);
        foreign.lcr_id = 3;
        let mut defunct = gw(6);
        defunct.defunct_until = AtomicU64::new(unix_secs() + 3600);
        let mut expired = gw(7);
        expired.defunct_until = AtomicU64::new(unix_secs().saturating_sub(1));
        let all = rule(4, "", false, vec![(4, 1, 1), (5, 1, 1), (6, 1, 1), (7, 1, 1), (99, 0, 1)]);
        let l = lcr_of(vec![other, from, ruri, all], vec![gw(1), gw(2), gw(3), any_lcr, foreign, defunct, expired]);
        let mut got = l.select(1, "1", "sip:caller@c.example", "sip:1@r.example").iter().map(|p| p.gw_id).collect::<Vec<_>>();
        got.sort_unstable();
        assert_eq!(got, [2, 3, 4, 7], "lcr 2 rule, lcr 3 gateway, defunct and unknown gateways left out");
        let mut got = l.select(1, "1", "sip:other@c.example", "sip:1@elsewhere").iter().map(|p| p.gw_id).collect::<Vec<_>>();
        got.sort_unstable();
        assert_eq!(got, [4, 7], "from_uri and request_uri patterns");
        assert!(l.select(2, "1", "", "").is_empty(), "lcr 2's gateway 1 belongs to lcr 1");
    }

    #[test]
    fn lcr_stopper_of_equal_length_keeps_its_peers() {
        let rules = || vec![rule(1, "49", true, vec![(1, 2, 1)]), rule(2, "49", false, vec![(2, 1, 1)]), rule(3, "4", false, vec![(3, 0, 1)])];
        let l = lcr_of(rules(), (1..=3).map(gw).collect());
        assert_eq!(ids(&l, "491"), [2, 1], "same prefix length as the stopper: kept; shorter: hidden");
        let l = lcr_of(rules(), (1..=3).map(gw).collect());
        l.set_param("stopper_mode", &Arg::Int(1)).unwrap();
        assert_eq!(ids(&l, "491"), [2, 1], "Sipwise mode: cut after the stopper's gateway");
        let l = lcr_of(vec![rule(1, "4", true, vec![(1, 0, 1)]), rule(2, "49", false, vec![(2, 0, 1)])], (1..=2).map(gw).collect());
        l.set_param("stopper_mode", &Arg::Int(1)).unwrap();
        assert_eq!(ids(&l, "491"), [2, 1], "a longer non-stopper rule still comes first");
    }

    type Steps = Vec<Option<(String, Option<Dest>)>>;

    /// load_gws then next_gw `n` times on an INVITE to `ruri`; the
    /// R-URIs and $du of each step (None once next_gw fails).
    fn route(l: &Lcr, ruri: &str, n: usize, flags: u64) -> (i32, Steps) {
        let net = FakeNet(None);
        with_ctx(&request("INVITE", ruri, ""), udp("192.0.2.1:5060"), &net, |ctx| {
            ctx.ext_mut::<TxnVars>().flags = flags;
            let rc = l.load_gws(ctx, 1, None, None);
            let steps = (0..n)
                .map(|_| {
                    ctx.dst = None;
                    (l.next_gw(ctx) == 1).then(|| (String::from_utf8(ctx.new_ruri.clone().unwrap()).unwrap(), ctx.dst))
                })
                .collect();
            (rc, steps)
        })
    }

    #[test]
    fn next_gw_builds_the_request_uri() {
        let mut a = gw(1);
        (a.port, a.transport, a.strip, a.prefix, a.params) = (Some(5070), 2, 2, "00".into(), "p=1".into());
        let mut b = gw(2);
        (b.hostname, b.port, b.transport, b.scheme, b.params) = (Some("gw.example".into()), Some(5061), 3, 2, ";x=y".into());
        let mut c = gw(3);
        (c.ip, c.hostname, c.port, c.transport) = (None, Some("only.example".into()), Some(5080), 4);
        let mut d = gw(4);
        (d.ip, d.strip) = (Some("2001:db8::4".parse().unwrap()), 99);
        let l = lcr_of(vec![rule(1, "49", false, vec![(1, 1, 1), (2, 2, 1), (3, 3, 1), (4, 4, 1)])], vec![a, b, c, d]);
        let (rc, steps) = route(&l, "sip:4930123@carrier.example", 5, 0);
        assert_eq!(rc, 1);
        let ruris: Vec<Option<String>> = steps.iter().map(|s| s.as_ref().map(|(u, _)| u.clone())).collect();
        assert_eq!(
            ruris,
            [
                Some("sip:0030123@10.0.0.1:5070;p=1;transport=tcp".to_string()),
                Some("sips:4930123@gw.example;x=y".to_string()),
                Some("sip:4930123@only.example:5080;transport=sctp".to_string()),
                Some("sip:[2001:db8::4]".to_string()),
                None,
            ],
            "the original user each time; strip past the end leaves no user"
        );
        let dsts: Vec<Option<(Proto, String)>> = steps.iter().take(3).map(|s| s.as_ref().unwrap().1.map(|d| (d.proto, d.addr.to_string()))).collect();
        assert_eq!(dsts, [None, Some((Proto::Tls, "10.0.0.2:5061".to_string())), None], "hostname and IP: the IP goes to $du");
    }

    #[test]
    fn next_gw_honours_the_dont_strip_flag_and_current_gateway() {
        let mut a = gw(1);
        (a.strip, a.prefix) = (2, "+".into());
        let l = lcr_of(vec![rule(1, "", false, vec![(1, 0, 1)])], vec![a]);
        assert_eq!(route(&l, "sip:0049@x", 1, 0).1[0].as_ref().unwrap().0, "sip:+49@10.0.0.1");
        l.set_param("dont_strip_or_prefix_flag", &Arg::Int(3)).unwrap();
        assert_eq!(route(&l, "sip:0049@x", 1, 1 << 3).1[0].as_ref().unwrap().0, "sip:0049@10.0.0.1");
        assert_eq!(route(&l, "sip:0049@x", 1, 1 << 2).1[0].as_ref().unwrap().0, "sip:+49@10.0.0.1", "another flag");
        assert!(l.set_param("dont_strip_or_prefix_flag", &Arg::Int(-1)).is_err());
        let net = FakeNet(None);
        with_ctx(&request("INVITE", "sip:0049@x", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert!(l.current_gw(ctx).is_none());
            assert_eq!(l.next_gw(ctx), -1, "nothing loaded");
            assert_eq!(l.load_gws(ctx, 1, Some("1".into()), None), 1);
            assert_eq!(l.next_gw(ctx), 1);
            assert_eq!(l.current_gw(ctx).map(|g| g.id), Some(1));
            assert_eq!(l.load_gws(ctx, 7, None, None), 2, "no gateway: 2");
            assert_eq!(l.next_gw(ctx), -1);
        });
    }

    #[test]
    fn lcr_gateway_address_matching() {
        let mut a = gw(1);
        (a.port, a.transport) = (Some(5070), 2);
        let mut b = gw(2);
        b.lcr_id = 2;
        let l = lcr_of(vec![], vec![a, b]);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let m = |lcr: Option<i64>, a: &str, proto: Option<Proto>, port: Option<u16>| l.match_addr(lcr, ip(a), proto, port).map(|g| g.id);
        let cases = [
            (Some(1), "10.0.0.1", Some(Proto::Tcp), Some(5070), Some(1)),
            (Some(1), "10.0.0.1", Some(Proto::Udp), None, None),
            (Some(1), "10.0.0.1", None, None, Some(1)),
            (Some(1), "10.0.0.1", Some(Proto::Tcp), Some(5060), None),
            (Some(2), "10.0.0.1", Some(Proto::Tcp), None, None),
            (None, "10.0.0.2", Some(Proto::Tls), Some(5060), Some(2)),
            (None, "10.0.0.2", Some(Proto::Udp), Some(5070), None),
            (None, "10.0.0.3", None, None, None),
        ];
        for (lcr, a, proto, port, want) in cases {
            assert_eq!(m(lcr, a, proto, port), want, "{lcr:?} {a} {proto:?} {port:?}");
        }
        for (s, want) in [("1", Some(Proto::Udp)), (" tcp ", Some(Proto::Tcp)), ("3", Some(Proto::Tls)), ("TCP", None), ("4", None), ("", None)] {
            assert_eq!(proto_arg(s), want, "{s:?}");
        }
    }

    #[test]
    fn lcr_gateway_json_state_and_statistics() {
        let mut a = gw(1);
        a.defunct_until = AtomicU64::new(u64::MAX);
        let mut b = gw(2);
        b.defunct_until = AtomicU64::new(unix_secs() + 600);
        let l = lcr_of(vec![], vec![a, b, gw(3)]);
        let states: Vec<Value> = l.data().gws.iter().map(|g| l.gw_json(g)["state"].clone()).collect();
        assert_eq!(states, ["inactive", "defunct", "active"]);
        assert_eq!(l.gw_json(&l.data().gws[2])["defunct_until"], 0);
        assert!(l.gw_json(&l.data().gws[0]).get("stats").is_none());
        l.set_param("lcr_stats", &Arg::Int(1)).unwrap();
        let net = FakeNet(None);
        for m in ["INVITE", "BYE", "MESSAGE"] {
            with_ctx(&request(m, "sip:x@y", ""), udp("10.0.0.3:5060"), &net, |ctx| l.observe_request(ctx));
        }
        with_ctx(&request("INVITE", "sip:x@y", ""), udp("10.0.0.3:5999"), &net, |ctx| l.observe_request(ctx));
        let reply = |code: u16| {
            format!(
                "SIP/2.0 {code} X
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1
From: <sip:a@x>;tag=1
To: <sip:b@x>;tag=2
Call-ID: c
CSeq: 1 INVITE
Content-Length: 0

"
            )
        };
        for code in [100, 180, 200, 486, 603] {
            with_ctx(&reply(code), udp("10.0.0.3:5060"), &net, |ctx| l.observe_reply(ctx));
        }
        let st = &l.gw_json(&l.data().gws[2])["stats"];
        assert_eq!(st["rcv_gw_reqs"], 3, "another port is another peer");
        assert_eq!((st["rcv_gw_reqs_invite"].as_u64(), st["rcv_gw_reqs_bye"].as_u64(), st["rcv_gw_reqs_other"].as_u64()), (Some(1), Some(1), Some(1)));
        let rpl: Vec<u64> = (1..=6).map(|c| st[format!("rcv_gw_rpl_{c}xx")].as_u64().unwrap()).collect();
        assert_eq!(rpl, [2, 1, 0, 1, 0, 1]);
    }

    #[test]
    fn lcr_parameters() {
        let l = Lcr::default();
        l.set_param("ping_valid_reply_codes", &Arg::Str("403, 404,x,".into())).unwrap();
        assert_eq!(*lock(&l.ping_codes), vec![403, 404]);
        assert!(l.set_param("gw_name_column", &Arg::Str("x".into())).is_ok(), "*_column accepted");
        assert!(l.set_param("mtree", &Arg::Int(1)).is_ok());
        assert!(l.set_param("bogus", &Arg::Int(1)).is_err());
        l.set_param("lcr_rule_table", &Arg::Str("r".into())).unwrap();
        assert_eq!(lock(&l.tables)[1], "r");
        assert_eq!(opt_re(String::new()).unwrap().map(|r| r.to_string()), None);
        assert!(opt_re("(".into()).is_err());
    }

    #[test]
    fn lcr_sipwise_stopper_mode_without_a_stopper_keeps_every_gateway() {
        let l = lcr_of(vec![rule(1, "49", false, vec![(1, 0, 1)]), rule(2, "", false, vec![(2, 0, 1)])], (1..=2).map(gw).collect());
        l.set_param("stopper_mode", &Arg::Int(1)).unwrap();
        assert_eq!(ids(&l, "491"), [1, 2]);
    }

    #[test]
    fn next_gw_skips_unknown_gateways_and_fails_on_one_without_an_address() {
        let mut none = gw(2);
        none.ip = None;
        let l = lcr_of(vec![rule(1, "", false, vec![(1, 0, 1), (2, 1, 1)])], vec![gw(1), none]);
        let net = FakeNet(None);
        with_ctx(&request("INVITE", "sip:1@x", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(l.load_gws(ctx, 1, None, None), 1);
            // Gateway 1 disappears (reload) between load_gws and next_gw.
            *l.data.write().unwrap() = Arc::new(Data { gws: l.data().gws.iter().skip(1).cloned().collect(), rules: vec![] });
            assert_eq!(l.next_gw(ctx), -1, "gateway 1 is skipped, gateway 2 has neither IP nor hostname");
            assert_eq!(l.next_gw(ctx), -1, "nothing left");
        });
    }

    #[test]
    fn lcr_statistics_count_every_method_class() {
        let l = lcr_of(vec![], vec![gw(3)]);
        l.set_param("lcr_stats", &Arg::Int(1)).unwrap();
        assert!(l.observes());
        let net = FakeNet(None);
        for m in ["CANCEL", "ACK", "INFO", "REGISTER", "SUBSCRIBE", "NOTIFY", "OPTIONS"] {
            with_ctx(&request(m, "sip:x@y", ""), udp("10.0.0.3:5060"), &net, |ctx| l.observe_request(ctx));
        }
        let st = &l.gw_json(&l.data().gws[0])["stats"];
        assert_eq!(st["rcv_gw_reqs"], 7);
        for m in ["cancel", "ack", "info", "register", "subscribe", "notify", "other"] {
            assert_eq!(st[format!("rcv_gw_reqs_{m}")], 1, "{m}");
        }
        assert_eq!(st["rcv_gw_reqs_invite"], 0);
    }

    use crate::testutil::{RecNet, TextDir, call, fixup_err, registry, reply_to, rpc, start_tm};
    use sip_core::serde_json::json;

    const GW_HDR: &str = "id(int) lcr_id(int) gw_name(string) ip_addr(string,null) hostname(string,null) port(int,null) params(string) \
uri_scheme(int,null) transport(int,null) strip(int,null) prefix(string) tag(string) flags(int) defunct(int,null)\n";
    const RULE_HDR: &str = "id(int) lcr_id(int) prefix(string) from_uri(string) request_uri(string) stopper(int) enabled(int,null)\n";
    const TARGET_HDR: &str = "lcr_id(int) rule_id(int) gw_id(int) priority(int) weight(int)\n";

    /// lcr_gw rows: 1 (TCP, port 5070, tag t1, flags 5), 2 (hostname only,
    /// port 0), 3 (port out of range: skipped), 4 (defunct in the table),
    /// 5 (lcr 7). Rules: "49" → 1, 2, 4; a disabled one → 5; lcr 7 "" → 5.
    fn lcr_tables() -> TextDir {
        TextDir::new(&[
            (
                "lcr_gw",
                &format!(
                    "{GW_HDR}1:1:gw1:10.0.0.1::5070::1:2:0::t1:5:\n2:1:gw2::gw2.example:0::2:::::0:\n3:1:gw3:10.0.0.3::70000:::::::0:\n\
4:1:gw4:10.0.0.4:::::::::0:99999999999\n5:7:gw5:10.0.0.5:::::1::::0:\n"
                ),
            ),
            ("lcr_rule", &format!("{RULE_HDR}1:1:49:::0:1\n2:1:4:::1:0\n3:7::^sip.*$::0:\n")),
            ("lcr_rule_target", &format!("{TARGET_HDR}1:1:1:1:1\n1:1:2:2:999\n1:1:4:3:1\n1:2:5:1:1\n7:3:5:1:0\n")),
        ])
    }

    /// An lcr on `dir` with every AVP and statistics on, registered.
    fn lcr_registered(dir: &TextDir) -> (Arc<Lcr>, Registry, Arc<Tm>) {
        let l = Arc::new(Lcr::default());
        l.set_param("db_url", &Arg::Str(dir.url())).unwrap();
        for (p, v) in
            [("tag_avp", "$avp(tag)"), ("flags_avp", "$avp(flags)"), ("rule_id_avp", "$avp(rule)"), ("gw_id_avp", "$avp(gw)"), ("lcr_id_avp", "$avp(lcr)")]
        {
            l.set_param(p, &Arg::Str(v.into())).unwrap();
        }
        let (mut reg, tm) = registry();
        reg.load(l.clone()).unwrap();
        (l, reg, tm)
    }

    fn avp(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str) -> String {
        parse_pv(&format!("$avp({name})"), reg.pvs()).unwrap().get(ctx).as_str().into_owned()
    }

    #[test]
    fn lcr_reload_reads_the_tables() {
        let dir = lcr_tables();
        let (l, reg, _) = lcr_registered(&dir);
        let d = l.data();
        assert_eq!(d.gws.iter().map(|g| g.id).collect::<Vec<_>>(), [1, 2, 4, 5], "gateway 3's port is out of range");
        assert_eq!((d.gws[0].port, d.gws[0].transport, d.gws[0].tag.as_str(), d.gws[0].flags), (Some(5070), 2, "t1", 5));
        assert_eq!((d.gws[1].ip, d.gws[1].hostname.as_deref(), d.gws[1].port, d.gws[1].scheme), (None, Some("gw2.example"), None, 2), "port 0: none");
        assert_eq!(d.gws[2].defunct_until.load(Ordering::Relaxed), 99_999_999_999);
        assert_eq!(d.rules.iter().map(|r| r.id).collect::<Vec<_>>(), [1, 3], "rule 2 is disabled");
        assert_eq!(d.rules[0].targets, [(1, 1, 1), (2, 2, 254), (4, 3, 1)], "weight clamped to 1..=254");
        assert_eq!(d.rules[1].targets, [(5, 1, 1)]);
        let rules = rpc(&reg, "lcr.dump_rules", json!([])).unwrap();
        assert_eq!(
            rules[1],
            json!({"lcr_id": 7, "rule_id": 3, "prefix": "", "from_uri": "^sip.*$", "request_uri": null, "stopper": false,
                "targets": [{"gw_id": 5, "priority": 1, "weight": 1}]})
        );
        // A gateway taken out of use keeps that state over a reload.
        l.data().gws[0].defunct_until.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(rpc(&reg, "lcr.reload", json!([])).unwrap(), json!({"gws": 4, "rules": 2}));
        assert_eq!(l.data().gws[0].defunct_until.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn lcr_reload_refuses_broken_tables_and_keeps_the_old_data() {
        let dir = lcr_tables();
        let (l, reg, _) = lcr_registered(&dir);
        let cases = [
            ("lcr_gw", format!("{GW_HDR}9:1:gw9::::::::::0:\n"), "lcr gw 9: needs ip_addr or hostname"),
            ("lcr_gw", format!("{GW_HDR}9:1:gw9:10.0.0.300:::::::::0:\n"), "lcr gw 9: bad ip_addr \"10.0.0.300\""),
            ("lcr_rule", format!("{RULE_HDR}1:1:49:(::0:1\n"), "lcr: bad pattern \"(\""),
        ];
        for (table, text, want) in cases {
            let good = std::fs::read_to_string(dir.0.join(table)).unwrap();
            dir.write(table, &text);
            let e = rpc(&reg, "lcr.reload", json!([])).unwrap_err();
            assert!(e.starts_with(want), "{e}");
            assert_eq!(l.data().gws.len(), 4, "the old data stays");
            dir.write(table, &good);
        }
    }

    #[test]
    fn lcr_register_needs_tm_for_pinging() {
        let dir = lcr_tables();
        let l = Arc::new(Lcr::default());
        l.set_param("db_url", &Arg::Str(dir.url())).unwrap();
        l.set_param("ping_interval", &Arg::Int(30)).unwrap();
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        assert_eq!(reg.load(l).unwrap_err(), "lcr: ping_interval needs tm loaded first");
        let l = Arc::new(Lcr::default());
        l.set_param("db_url", &Arg::Str(dir.url())).unwrap();
        l.set_param("tag_avp", &Arg::Str("$bogus(".into())).unwrap();
        assert!(registry().0.load(l).is_err(), "a bad AVP name");
    }

    #[test]
    fn lcr_script_functions_route_and_take_gateways_out_of_use() {
        let dir = lcr_tables();
        let (_, reg, _) = lcr_registered(&dir);
        let net = FakeNet(None);
        with_ctx(&request("INVITE", "sip:4930@x.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "load_gws", &[Arg::Int(1)]), 1);
            assert_eq!(call(&reg, ctx, "next_gw", &[]), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:4930@10.0.0.1:5070;transport=tcp"[..]));
            let avps: Vec<String> = ["tag", "flags", "rule", "gw", "lcr"].iter().map(|n| avp(&reg, ctx, n)).collect();
            assert_eq!(avps, ["t1", "5", "1", "1", "1"]);
            assert_eq!(call(&reg, ctx, "defunct_gw", &[Arg::Int(60)]), 1);
            assert_eq!(call(&reg, ctx, "next_gw", &[]), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sips:4930@gw2.example"[..]), "gateway 4 is defunct");
            assert_eq!(call(&reg, ctx, "inactivate_gw", &[]), 1);
            assert_eq!(call(&reg, ctx, "next_gw", &[]), -1);
        });
        let gws = rpc(&reg, "lcr.dump_gws", json!([])).unwrap();
        let states: Vec<&str> = gws.as_array().unwrap().iter().map(|g| g["state"].as_str().unwrap()).collect();
        assert_eq!(states, ["defunct", "inactive", "defunct", "active"]);
        let until = gws[0]["defunct_until"].as_u64().unwrap();
        assert!((unix_secs() + 59..=unix_secs() + 60).contains(&until), "{until}");
        // Both gone: nothing to load; without a current gateway nothing to take out.
        with_ctx(&request("INVITE", "sip:4930@x.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "load_gws", &[Arg::Int(1), Arg::Str("4930".into()), Arg::Str("sip:a@b".into())]), 2);
            assert_eq!(call(&reg, ctx, "defunct_gw", &[Arg::Int(60)]), -1);
            assert_eq!(call(&reg, ctx, "inactivate_gw", &[]), -1);
        });
        // lcr 7's rule matches on the caller URI.
        with_ctx(&request("INVITE", "sip:1@x.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "load_gws", &[Arg::Int(7), Arg::Str("1".into()), Arg::Str("tel:1".into())]), 2);
            assert_eq!(call(&reg, ctx, "load_gws", &[Arg::Int(7), Arg::Str("1".into()), Arg::Str("sip:a@b".into())]), 1);
        });
        let picked = rpc(&reg, "lcr.load_gws", json!([7, "1", "sip:a@b", "sip:1@x"])).unwrap();
        assert_eq!(picked, json!([{"gw_id": 5, "gw_name": "gw5", "rule_id": 3, "priority": 1}]));
        assert_eq!(rpc(&reg, "lcr.load_gws", json!([7, "1"])).unwrap(), json!([]), "no caller URI: the from_uri pattern fails");
        for args in [vec![], vec![Arg::Int(1), Arg::Str("a".into()), Arg::Str("b".into()), Arg::Str("c".into())]] {
            assert_eq!(fixup_err(&reg, "load_gws", &args).as_deref(), Some("expected lcr_id[, uri_user[, caller_uri]]"));
        }
    }

    #[test]
    fn lcr_from_and_to_gateway_checks() {
        let dir = lcr_tables();
        let (_l, reg, _) = lcr_registered(&dir);
        let net = FakeNet(None);
        let s = |v: &str| Arg::Str(v.into());
        let tcp = Dest::new(Proto::Tcp, "10.0.0.1:5070".parse().unwrap());
        // From the request's source.
        with_ctx(&request("INVITE", "sip:1@x", ""), tcp, &net, |ctx| {
            assert_eq!(call(&reg, ctx, "from_gw", &[Arg::Int(1)]), 1);
            assert_eq!((avp(&reg, ctx, "tag"), avp(&reg, ctx, "flags")), ("t1".to_string(), "5".to_string()), "from_gw sets the tag and flags");
            assert_eq!(call(&reg, ctx, "from_gw", &[Arg::Int(7)]), -1);
            assert_eq!(call(&reg, ctx, "from_any_gw", &[]), 1, "the gateway's lcr_id");
        });
        with_ctx(&request("INVITE", "sip:1@x", ""), udp("10.0.0.1:5070"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "from_gw", &[Arg::Int(1)]), -1, "gateway 1 is TCP");
            assert_eq!(call(&reg, ctx, "from_any_gw", &[]), -1);
        });
        with_ctx(&request("INVITE", "sip:1@x", ""), udp("192.0.2.1:5060"), &net, |ctx| {
            let cases: &[(&str, Vec<Arg>, i32)] = &[
                ("from_gw", vec![Arg::Int(1), s("10.0.0.1"), s("2"), s("5070")], 1),
                ("from_gw", vec![Arg::Int(1), s("10.0.0.1"), s("tcp")], 1),
                ("from_gw", vec![Arg::Int(1), s("10.0.0.1"), s("1")], -1),
                ("from_gw", vec![Arg::Int(1), s("10.0.0.1"), s("2"), s("5060")], -1),
                ("from_gw", vec![s("x"), s("10.0.0.1"), s("2")], -1),
                ("from_gw", vec![Arg::Int(1), s("not-an-ip"), s("2")], -1),
                ("from_any_gw", vec![s("10.0.0.5"), s("udp"), s("5060")], 7),
                ("from_any_gw", vec![s("10.0.0.5"), s("tcp")], -1),
                ("from_any_gw", vec![s("10.0.0.9"), s("udp")], -1),
                ("to_gw", vec![Arg::Int(1), s("10.0.0.1"), s("tcp")], 1),
                ("to_gw", vec![Arg::Int(7), s("10.0.0.1"), s("tcp")], -1),
                ("to_gw", vec![s("x"), s("10.0.0.1"), s("tcp")], -1),
                ("to_gw", vec![Arg::Int(1), s("bad"), s("tcp")], -1),
                ("to_any_gw", vec![s("10.0.0.5"), s("1")], 7),
                ("to_any_gw", vec![s("10.0.0.9"), s("1")], -1),
            ];
            for (f, args, want) in cases {
                assert_eq!(call(&reg, ctx, f, args), *want, "{f}{args:?}");
            }
        });
        // To the R-URI's host and transport.
        let to = |ruri: &str, f: &str, args: &[Arg]| with_ctx(&request("INVITE", ruri, ""), udp("192.0.2.1:5060"), &net, |ctx| call(&reg, ctx, f, args));
        assert_eq!(to("sip:1@10.0.0.1:5070;transport=TCP", "to_gw", &[Arg::Int(1)]), 1);
        assert_eq!(to("sip:1@10.0.0.1;transport=udp", "to_gw", &[Arg::Int(1)]), -1);
        assert_eq!(to("sip:1@gw2.example", "to_gw", &[Arg::Int(1)]), -1, "a host name is not matched");
        assert_eq!(to("sip:1@10.0.0.5", "to_any_gw", &[]), 7);
        assert_eq!(to("sip:1@10.0.0.9", "to_any_gw", &[]), -1);
        for (f, n) in [
            ("from_gw", 0),
            ("from_gw", 2),
            ("from_gw", 5),
            ("from_any_gw", 1),
            ("from_any_gw", 4),
            ("to_gw", 2),
            ("to_gw", 4),
            ("to_any_gw", 1),
            ("to_any_gw", 3),
        ] {
            let args = vec![Arg::Int(1); n];
            assert_eq!(fixup_err(&reg, f, &args).as_deref(), Some("bad number of arguments"), "{f} with {n} arguments");
        }
    }

    #[test]
    fn lcr_stats_rpc_needs_lcr_stats() {
        let dir = lcr_tables();
        let (l, reg, _) = lcr_registered(&dir);
        assert_eq!(rpc(&reg, "lcr.stats", json!([])).unwrap_err(), "lcr_stats is disabled");
        l.set_param("lcr_stats", &Arg::Int(1)).unwrap();
        let net = FakeNet(None);
        with_ctx(&request("BYE", "sip:x@y", ""), udp("10.0.0.5:5060"), &net, |ctx| l.observe_request(ctx));
        let st = rpc(&reg, "lcr.stats", json!([])).unwrap();
        assert_eq!(st.as_array().unwrap().len(), 4);
        assert_eq!((&st[3]["gw_id"], &st[3]["gw_name"], &st[3]["stats"]["rcv_gw_reqs_bye"]), (&json!(5), &json!("gw5"), &json!(1)));
    }

    #[test]
    fn lcr_options_ping_reactivates_answering_gateways() {
        let mut a = gw(1);
        (a.port, a.transport, a.defunct_until) = (Some(5070), 2, AtomicU64::new(u64::MAX));
        let mut b = gw(2);
        (b.transport, b.defunct_until) = (3, AtomicU64::new(u64::MAX));
        let mut c = gw(3);
        c.defunct_until = AtomicU64::new(u64::MAX);
        let mut d = gw(4);
        d.defunct_until = AtomicU64::new(unix_secs() + 600);
        let l = Arc::new(lcr_of(vec![], vec![a, b, c, d]));
        l.ping();
        l.set_param("ping_from", &Arg::Str("sip:pinger@lcr.example".into())).unwrap();
        l.set_param("ping_valid_reply_codes", &Arg::Str("403".into())).unwrap();
        let (_, tm) = registry();
        let net = Arc::new(RecNet::default());
        start_tm(&tm, &net);
        let _ = l.tm.set(tm.clone());
        l.ping();
        let sent = net.sent();
        let firsts: Vec<&str> = sent.iter().map(|(_, m)| m.split("\r\n").next().unwrap()).collect();
        assert_eq!(
            firsts,
            ["OPTIONS sip:10.0.0.1:5070;transport=tcp SIP/2.0", "OPTIONS sip:10.0.0.2;transport=tls SIP/2.0", "OPTIONS sip:10.0.0.3 SIP/2.0"],
            "only inactive gateways (not defunct ones) are pinged"
        );
        assert!(sent[0].1.contains("\r\nFrom: <sip:pinger@lcr.example>;tag="), "{}", sent[0].1);
        for ((_, req), code) in sent.iter().zip([200, 403, 404]) {
            with_ctx(&reply_to(req, code, ""), udp("10.0.0.1:5070"), &*net, |ctx| assert!(tm.on_reply(ctx)));
        }
        let du: Vec<u64> = l.data().gws.iter().map(|g| g.defunct_until.load(Ordering::Relaxed)).collect();
        assert_eq!(du[..3], [0, 0, u64::MAX], "2xx and ping_valid_reply_codes count as alive");
    }

    #[test]
    fn lcr_spawn_starts_the_pinger_only_with_an_interval() {
        let l = Arc::new(Lcr::default());
        assert!(l.clone().spawn(Arc::new(FakeNet(None))).is_ok());
        l.set_param("ping_interval", &Arg::Int(1 << 40)).unwrap();
        assert!(l.spawn(Arc::new(FakeNet(None))).is_ok());
    }
}
