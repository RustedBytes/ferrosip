//! Table-driven access control and identity lookups, data from `db_url`
//! (`text:///dir` or `sqlite:///file`), Kamailio schema:
//! * `permissions` — `address` (grp, ip_addr, mask, port, tag) and
//!   `trusted` (src_ip, proto, from_pattern, ruri_pattern, tag, priority),
//!   cached in memory, reloaded by RPC.
//! * `domain` — local domains (`domain` table), cached, reloaded by RPC.
//! * `alias_db` — `dbaliases`, queried per lookup.
//! * `group` — `grp` membership, queried per check.

use crate::{args, hdr_uri, in_subnet, parse_net, proto_from_name, user_host};
use regex::Regex;
use sip_core::module::{DynStr, rc};
use sip_core::pv::{PvRef, Val};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::{Arg, Branch, Ctx, Module, Proto, Registry, want_args};
use sip_db::DbVal;
use sip_parser::{HdrFlags, HdrKind};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

fn opt_args(a: &[Arg], max: usize) -> Result<Vec<DynStr>, String> {
    if a.len() > max {
        return Err(format!("expected at most {max} arguments"));
    }
    a.iter().map(Arg::dyn_str).collect()
}

// ------------------------------------------------------------ permissions --

#[derive(Clone, Debug)]
struct AddrRule {
    grp: i64,
    net: IpAddr,
    mask: u8,
    port: u16,
    tag: String,
}

#[derive(Clone, Debug)]
struct TrustRule {
    src: IpAddr,
    mask: u8,
    proto: Option<Proto>,
    from: Option<Regex>,
    ruri: Option<Regex>,
    tag: String,
    priority: i64,
}

/// One side of a rule in a `.allow` / `.deny` file: any of `incl`
/// matches (`ALL` = anything) and none of `excl`.
#[derive(Debug, Default)]
struct Side {
    all: bool,
    incl: Vec<Regex>,
    excl: Vec<Regex>,
}

impl Side {
    fn matches(&self, s: &str) -> bool {
        (self.all || self.incl.iter().any(|r| r.is_match(s))) && !self.excl.iter().any(|r| r.is_match(s))
    }
}

/// `from_list : request_uri_list` lines of one file.
type Rules = Vec<(Side, Side)>;

/// Kamailio `permissions.allow` / `.deny` syntax:
/// `"^sip:alice@.*" : ALL EXCEPT "^sip:900.*"` (comma-separated quoted
/// regexes, `ALL`, `EXCEPT`; `#` comments).
fn parse_rules(text: &str) -> Result<Rules, String> {
    let mut out = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = |e: &str| format!("line {}: {e}: {raw:?}", n.saturating_add(1));
        // Tokens: quoted strings, ALL, EXCEPT, ':' and ','.
        let mut toks: Vec<String> = Vec::new();
        let mut it = line.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '"' => {
                    let mut q = String::new();
                    let mut closed = false;
                    while let Some(c) = it.next() {
                        match c {
                            '\\' if it.peek() == Some(&'"') => q.push(it.next().unwrap_or('"')),
                            '"' => {
                                closed = true;
                                break;
                            }
                            c => q.push(c),
                        }
                    }
                    if !closed {
                        return Err(bad("unterminated string"));
                    }
                    toks.push(format!("\"{q}"));
                }
                ':' | ',' => toks.push(c.to_string()),
                c if c.is_whitespace() => {}
                c => {
                    let mut w = c.to_string();
                    while it.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
                        w.push(it.next().unwrap_or(' '));
                    }
                    toks.push(w.to_ascii_uppercase());
                }
            }
        }
        // Clients before the first ':', destinations after it.
        let mut halves = toks.splitn(2, |t| t == ":");
        let (Some(clients), Some(dests)) = (halves.next(), halves.next()) else { return Err(bad("missing ':'")) };
        let side = |ts: &[String]| -> Result<Side, String> {
            let mut s = Side::default();
            let mut except = false;
            for t in ts {
                match t.as_str() {
                    "ALL" if !except => s.all = true,
                    "EXCEPT" => except = true,
                    "," => {}
                    t if t.starts_with('"') => {
                        let re = Regex::new(t.strip_prefix('"').unwrap_or(t)).map_err(|e| bad(&format!("bad regex: {e}")))?;
                        if except { s.excl.push(re) } else { s.incl.push(re) }
                    }
                    t => return Err(bad(&format!("unexpected {t:?}"))),
                }
            }
            Ok(s)
        };
        out.push((side(clients)?, side(dests)?));
    }
    Ok(out)
}

/// An allow file and a deny file.
struct RuleFiles {
    allow: Rules,
    deny: Rules,
}

impl RuleFiles {
    fn load(allow: &str, deny: &str) -> Result<Self, String> {
        let read = |f: &str| -> Result<Rules, String> {
            match std::fs::read_to_string(f) {
                Ok(t) => parse_rules(&t).map_err(|e| format!("permissions {f}: {e}")),
                // Kamailio: a missing file means "no rules".
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(e) => Err(format!("permissions {f}: {e}")),
            }
        };
        Ok(Self { allow: read(allow)?, deny: read(deny)? })
    }

    /// Allow file match → yes; deny file match → no; otherwise yes.
    fn check(&self, from: &str, targets: &[String]) -> bool {
        targets.iter().all(|t| {
            if self.allow.iter().any(|(f, r)| f.matches(from) && r.matches(t)) {
                return true;
            }
            !self.deny.iter().any(|(f, r)| f.matches(from) && r.matches(t))
        })
    }
}

pub struct Permissions {
    /// `allow_routing` / `allow_register` files: (allow, deny) → rules.
    files: Mutex<std::collections::HashMap<(String, String), Arc<RuleFiles>>>,
    default_allow: Mutex<String>,
    default_deny: Mutex<String>,
    db_url: Mutex<Option<String>>,
    address_table: Mutex<String>,
    trusted_table: Mutex<String>,
    peer_tag_avp: Mutex<Option<String>>,
    tag_pv: OnceLock<PvRef>,
    address: RwLock<Arc<Vec<AddrRule>>>,
    trusted: RwLock<Arc<Vec<TrustRule>>>,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            files: Mutex::default(),
            default_allow: Mutex::new("permissions.allow".into()),
            default_deny: Mutex::new("permissions.deny".into()),
            db_url: Mutex::new(None),
            address_table: Mutex::new("address".into()),
            trusted_table: Mutex::new("trusted".into()),
            peer_tag_avp: Mutex::new(None),
            tag_pv: OnceLock::new(),
            address: RwLock::new(Arc::new(vec![])),
            trusted: RwLock::new(Arc::new(vec![])),
        }
    }
}

impl Permissions {
    fn url(&self) -> Result<String, String> {
        lock(&self.db_url).clone().ok_or_else(|| "permissions: db_url not set".into())
    }

    fn reload_address(&self) -> Result<usize, String> {
        let rows = crate::load_table(&self.url()?, &lock(&self.address_table), &["grp", "ip_addr", "mask", "port", "tag"])?;
        let mut v = Vec::with_capacity(rows.len());
        for r in rows {
            let ip = r.get(1).map(DbVal::text).unwrap_or_default();
            let (net, m) = parse_net(&ip).ok_or_else(|| format!("permissions: bad ip_addr {ip:?}"))?;
            let mask = r.get(2).and_then(DbVal::int).map_or(m, |x| u8::try_from(x.clamp(0, 128)).unwrap_or(128));
            let port = r.get(3).and_then(DbVal::int).unwrap_or(0);
            let Ok(port) = u16::try_from(port) else {
                sip_core::log::log(sip_core::log::L_ERR, &format!("permissions: {ip}: port {port} out of range, row skipped"));
                continue;
            };
            let grp = r.first().and_then(DbVal::int).unwrap_or(0);
            v.push(AddrRule { grp, net, mask, port, tag: r.get(4).map(DbVal::text).unwrap_or_default() });
        }
        let n = v.len();
        *write(&self.address) = Arc::new(v);
        Ok(n)
    }

    fn reload_trusted(&self) -> Result<usize, String> {
        let rows = crate::load_table(&self.url()?, &lock(&self.trusted_table), &["src_ip", "proto", "from_pattern", "ruri_pattern", "tag", "priority"])?;
        let mut v = Vec::with_capacity(rows.len());
        let re = |d: Option<&DbVal>| -> Result<Option<Regex>, String> {
            match d.map(DbVal::text).filter(|s| !s.is_empty()) {
                Some(p) => Regex::new(&p).map(Some).map_err(|e| format!("permissions: bad pattern {p:?}: {e}")),
                None => Ok(None),
            }
        };
        for r in rows {
            let ip = r.first().map(DbVal::text).unwrap_or_default();
            let (src, mask) = parse_net(&ip).ok_or_else(|| format!("permissions: bad src_ip {ip:?}"))?;
            let p = r.get(1).map(DbVal::text).unwrap_or_default();
            let proto = match p.to_ascii_lowercase().as_str() {
                "" | "any" => None,
                x => Some(proto_from_name(x).ok_or_else(|| format!("permissions: bad proto {x:?}"))?),
            };
            v.push(TrustRule {
                src,
                mask,
                proto,
                from: re(r.get(2))?,
                ruri: re(r.get(3))?,
                tag: r.get(4).map(DbVal::text).unwrap_or_default(),
                priority: r.get(5).and_then(DbVal::int).unwrap_or(0),
            });
        }
        v.sort_by_key(|t| std::cmp::Reverse(t.priority));
        let n = v.len();
        *write(&self.trusted) = Arc::new(v);
        Ok(n)
    }

    fn set_tag(&self, ctx: &mut Ctx<'_, '_>, tag: &str) {
        if let (Some(pv), false) = (self.tag_pv.get(), tag.is_empty()) {
            let _ = pv.set(ctx, Val::str(tag));
        }
    }

    /// First address rule matching (grp or any when `None`, ip, port).
    fn match_addr(&self, grp: Option<i64>, ip: IpAddr, port: u16) -> Option<AddrRule> {
        let rules = read(&self.address).clone();
        rules.iter().find(|r| grp.is_none_or(|g| g == r.grp) && in_subnet(ip, r.net, r.mask) && (r.port == 0 || r.port == port)).cloned()
    }

    fn allow_trusted(&self, ctx: &mut Ctx<'_, '_>, ip: IpAddr, proto: Option<Proto>, ruri: Option<String>) -> i32 {
        let rules = read(&self.trusted).clone();
        let from = hdr_uri(ctx, HdrKind::From).map(|u| String::from_utf8_lossy(&u).into_owned()).unwrap_or_default();
        let ruri = ruri.unwrap_or_else(|| String::from_utf8_lossy(ctx.ruri()).into_owned());
        for r in rules.iter() {
            if !in_subnet(ip, r.src, r.mask) || r.proto.is_some_and(|p| Some(p) != proto) {
                continue;
            }
            if r.from.as_ref().is_some_and(|re| !re.is_match(&from)) || r.ruri.as_ref().is_some_and(|re| !re.is_match(&ruri)) {
                continue;
            }
            let tag = r.tag.clone();
            self.set_tag(ctx, &tag);
            return 1;
        }
        -1
    }
}

impl Module for Permissions {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the address and trusted tables"),
            p("address_table", Ty::Str, "address", "Table for allow_source_address"),
            p("trusted_table", Ty::Str, "trusted", "Table for allow_trusted"),
            p("peer_tag_avp", Ty::Str, "", "AVP that gets the matching row's tag"),
            p("default_allow_file", Ty::Str, "permissions.allow", "allow_routing rules"),
            p("default_deny_file", Ty::Str, "permissions.deny", "allow_routing deny rules"),
        ])
    }

    fn name(&self) -> &'static str {
        "permissions"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const BASENAME: &[Param] = &[opt("basename", Str).lit().eg("\"/nonexistent/p\"")];
        const NEED_BASENAME: &[Param] = &[arg("basename", Str).lit().eg("\"/nonexistent/p\"")];
        const FILES: &[Param] = &[arg("allow_file", Str).lit().eg("\"/nonexistent/p.allow\""), arg("deny_file", Str).lit().eg("\"/nonexistent/p.deny\"")];
        const GROUP: &[Param] = &[opt("group", Int)];
        const ADDRESS: &[Param] = &[arg("group", Int), arg("ip", Str).eg("\"192.0.2.1\""), arg("port", Int).eg("5060")];
        const IP_PORT: &[Param] = &[arg("ip", Str).eg("\"192.0.2.1\""), arg("port", Int).eg("5060")];
        const TRUSTED: &[Param] = &[opt("src_ip", Str).eg("\"192.0.2.1\""), opt("proto", Str).eg("\"udp\""), opt("uri", Uri)];
        Some(vec![
            sig("allow_routing", "routing_allowed", BASENAME, Ret::Bool, "From → R-URI is allowed by basename.allow/.deny (default: permissions.allow/.deny)"),
            sig("allow_routing", "routing_allowed_by", FILES, Ret::Bool, "From → R-URI is allowed by these allow and deny files"),
            sig("allow_register", "register_allowed", NEED_BASENAME, Ret::Bool, "To → Contacts of a REGISTER are allowed by basename.allow/.deny")
                .allowed(ctx::REQUEST),
            sig("allow_register", "register_allowed_by", FILES, Ret::Bool, "To → Contacts of a REGISTER are allowed by these allow and deny files")
                .allowed(ctx::REQUEST),
            sig("allow_source_address", "source_allowed", GROUP, Ret::Bool, "The source address is in the address table's group (default 1)").allowed(ctx::ANY),
            sig("allow_address", "address_allowed", ADDRESS, Ret::Bool, "ip:port (port 0: any) is in the address table's group").allowed(ctx::ANY),
            sig("allow_source_address_group", "source_group", &[], Ret::Bool, "The source address is in some address group (its number is the return code)")
                .allowed(ctx::ANY),
            sig("allow_address_group", "address_group", IP_PORT, Ret::Bool, "ip:port is in some address group (its number is the return code)")
                .allowed(ctx::ANY),
            sig("allow_trusted", "is_trusted", TRUSTED, Ret::Bool, "The source (or src_ip, proto and uri) matches the trusted table").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "address_table" => *lock(&self.address_table) = v.str()?.into(),
            "trusted_table" => *lock(&self.trusted_table) = v.str()?.into(),
            "peer_tag_avp" => *lock(&self.peer_tag_avp) = Some(v.str()?.into()),
            "default_allow_file" => *lock(&self.default_allow) = v.str()?.into(),
            "default_deny_file" => *lock(&self.default_deny) = v.str()?.into(),
            "db_mode" | "load_backends" | "max_subnets" | "reload_delta" | "check_all_branches" | "allow_suffix" | "deny_suffix" => {}
            _ => return Err(format!("permissions: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        if lock(&self.db_url).is_some() {
            self.reload_address()?;
            self.reload_trusted()?;
        }
        if let Some(p) = lock(&self.peer_tag_avp).clone() {
            let _ = self.tag_pv.set(sip_core::pv::parse_pv(&p, reg.pvs())?);
        }
        let m = "permissions";
        // allow_routing([basename | allow_file, deny_file]) and
        // allow_register(basename | allow_file, deny_file): files are read at
        // startup and by RPC permissions.reload.
        for (name, register) in [("allow_routing", false), ("allow_register", true)] {
            let me = self.clone();
            let fix = {
                let me = self.clone();
                move |a: &[Arg]| -> Result<(String, String), String> {
                    let pair = match a {
                        [] if !register => (lock(&me.default_allow).clone(), lock(&me.default_deny).clone()),
                        [base] => (format!("{}.allow", base.str()?), format!("{}.deny", base.str()?)),
                        [allow, deny] => (allow.str()?.to_string(), deny.str()?.to_string()),
                        _ => return Err("expected [basename] or allow_file, deny_file".into()),
                    };
                    let rules = RuleFiles::load(&pair.0, &pair.1)?;
                    lock(&me.files).insert(pair.clone(), Arc::new(rules));
                    Ok(pair)
                }
            };
            reg.export(m, name, fix, move |ctx: &mut Ctx, key: &(String, String)| {
                let Some(rules) = lock(&me.files).get(key).cloned() else { return -1 };
                let s = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
                if register {
                    let Some(to) = hdr_uri(ctx, HdrKind::To) else { return -1 };
                    let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                    let contacts: Vec<String> = ctx
                        .msg
                        .headers
                        .iter()
                        .filter(|h| h.kind == HdrKind::Contact)
                        .flat_map(|h| sip_parser::uri::split_list(h.body).into_iter().map(|c| s(sip_parser::uri::name_addr(c).0.to_vec())).collect::<Vec<_>>())
                        .filter(|c| c != "*")
                        .collect();
                    rc(rules.check(&s(to), &contacts))
                } else {
                    let Some(from) = hdr_uri(ctx, HdrKind::From) else { return -1 };
                    let ruri = s(ctx.ruri().to_vec());
                    rc(rules.check(&s(from), &[ruri]))
                }
            });
        }
        let me = self.clone();
        reg.rpc.add("permissions.reload", "Re-read the allow/deny files", move |_| {
            let keys: Vec<(String, String)> = lock(&me.files).keys().cloned().collect();
            for k in &keys {
                let r = RuleFiles::load(&k.0, &k.1)?;
                lock(&me.files).insert(k.clone(), Arc::new(r));
            }
            Ok(json!(keys.len()))
        });
        // allow_source_address([grp]) — default group 1.
        let me = self.clone();
        reg.export(
            m,
            "allow_source_address",
            |a: &[Arg]| opt_args(a, 1),
            move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                let g = a.first().map_or(Some(1), |g| g.eval(ctx).trim().parse().ok());
                let Some(g) = g else { return -1 };
                match me.match_addr(Some(g), ctx.src.addr.ip(), ctx.src.addr.port()) {
                    Some(r) => {
                        me.set_tag(ctx, &r.tag);
                        1
                    }
                    None => -1,
                }
            },
        );
        // allow_address(grp, ip, port)
        let me = self.clone();
        reg.export(
            m,
            "allow_address",
            |a: &[Arg]| {
                let [g, ip, port] = args(a)?;
                Ok([g.dyn_str()?, ip.dyn_str()?, port.dyn_str()?])
            },
            move |ctx: &mut Ctx, [g, ip, port]: &[DynStr; 3]| {
                let (g, ip, port) =
                    (g.eval(ctx).trim().parse().ok(), ip.eval(ctx).trim().parse::<IpAddr>().ok(), port.eval(ctx).trim().parse::<u16>().unwrap_or(0));
                let (Some(g), Some(ip)) = (g, ip) else { return -1 };
                match me.match_addr(Some(g), ip, port) {
                    Some(r) => {
                        me.set_tag(ctx, &r.tag);
                        1
                    }
                    None => -1,
                }
            },
        );
        // allow_source_address_group() / allow_address_group(ip, port): the group.
        let me = self.clone();
        reg.export(
            m,
            "allow_source_address_group",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| match me.match_addr(None, ctx.src.addr.ip(), ctx.src.addr.port()) {
                Some(r) => {
                    me.set_tag(ctx, &r.tag);
                    grp_rc(r.grp)
                }
                None => -1,
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "allow_address_group",
            |a: &[Arg]| {
                let [ip, port] = args(a)?;
                Ok([ip.dyn_str()?, port.dyn_str()?])
            },
            move |ctx: &mut Ctx, [ip, port]: &[DynStr; 2]| {
                let Ok(ip) = ip.eval(ctx).trim().parse::<IpAddr>() else { return -1 };
                let port = port.eval(ctx).trim().parse::<u16>().unwrap_or(0);
                me.match_addr(None, ip, port).map_or(-1, |r| grp_rc(r.grp))
            },
        );
        // allow_trusted([src_ip, proto[, ruri]])
        let me = self.clone();
        reg.export(
            m,
            "allow_trusted",
            |a: &[Arg]| {
                if a.len() == 1 {
                    return Err("expected no arguments or src_ip, proto[, uri]".into());
                }
                opt_args(a, 3)
            },
            move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                // None, or 2..3: checked at fixup.
                let [ip, proto, ruri @ ..] = a.as_slice() else {
                    let (ip, proto) = (ctx.src.addr.ip(), Some(ctx.src.proto));
                    return me.allow_trusted(ctx, ip, proto, None);
                };
                let Ok(ip) = ip.eval(ctx).trim().parse::<IpAddr>() else { return -1 };
                let proto = proto_from_name(proto.eval(ctx).trim());
                let ruri = ruri.first().map(|u| u.eval(ctx).into_owned());
                me.allow_trusted(ctx, ip, proto, ruri)
            },
        );
        let me = self.clone();
        reg.rpc.add("permissions.addressReload", "Reload the address table", move |_| me.reload_address().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("permissions.trustedReload", "Reload the trusted table", move |_| me.reload_trusted().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("permissions.addressDump", "Dump the address table", move |_| {
            let v = read(&me.address).clone();
            Ok(v.iter().map(|r| json!({"grp": r.grp, "ip_addr": r.net.to_string(), "mask": r.mask, "port": r.port, "tag": r.tag})).collect())
        });
        let me = self.clone();
        reg.rpc.add("permissions.trustedDump", "Dump the trusted table", move |_| {
            let v = read(&me.trusted).clone();
            Ok(v.iter()
                .map(|r| {
                    json!({"src_ip": format!("{}/{}", r.src, r.mask), "proto": r.proto.map_or("any".to_string(), |p| p.via_name().to_ascii_lowercase()),
                    "from_pattern": r.from.as_ref().map(|x| x.as_str().to_string()), "ruri_pattern": r.ruri.as_ref().map(|x| x.as_str().to_string()),
                    "tag": r.tag, "priority": r.priority})
                })
                .collect())
        });
        Ok(())
    }
}

// ----------------------------------------------------------------- domain --

pub struct Domain {
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    register_myself: AtomicBool,
    domains: RwLock<Arc<HashSet<String>>>,
}

impl Default for Domain {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            table: Mutex::new("domain".into()),
            register_myself: AtomicBool::new(false),
            domains: RwLock::new(Arc::new(HashSet::new())),
        }
    }
}

impl Domain {
    fn reload(&self) -> Result<usize, String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("domain"));
        let rows = crate::load_table(&url, &lock(&self.table), &["domain"])?;
        let set: HashSet<String> = rows.iter().filter_map(|r| r.first()).map(|d| d.text().trim().to_ascii_lowercase()).filter(|d| !d.is_empty()).collect();
        if self.register_myself.load(Ordering::Relaxed) {
            for d in &set {
                sip_core::net::add_alias(d);
            }
        }
        let n = set.len();
        *write(&self.domains) = Arc::new(set);
        Ok(n)
    }

    fn is_local(&self, d: &str) -> bool {
        let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
        read(&self.domains).contains(&d)
    }
}

impl Module for Domain {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the domain table"),
            p("domain_table", Ty::Str, "domain", "Table of local domains"),
            p("register_myself", Ty::Bool, "false", "Also treat the loaded domains as aliases of this proxy (myself)"),
        ])
    }

    fn name(&self) -> &'static str {
        "domain"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const DOMAIN: &[Param] = &[arg("domain", Str).eg("\"example.com\"")];
        Some(vec![
            sig("is_domain_local", "is_local", DOMAIN, Ret::Bool, "The domain (or a URI's host) is in the domain table").allowed(ctx::ANY),
            sig("is_from_local", "is_from_local", &[], Ret::Bool, "The From URI's host is a local domain"),
            sig("is_uri_host_local", "is_ruri_local", &[], Ret::Bool, "The R-URI's host is a local domain"),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "domain_table" => *lock(&self.table) = v.str()?.into(),
            "register_myself" => self.register_myself.store(v.int()? != 0, Ordering::Relaxed),
            "domain_attrs_table" | "did_col" | "domain_col" | "name_col" | "type_col" | "value_col" => {}
            _ => return Err(format!("domain: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload()?;
        let m = "domain";
        let me = self.clone();
        reg.export(
            m,
            "is_domain_local",
            |a: &[Arg]| {
                let [d] = args(a)?;
                d.dyn_str()
            },
            move |ctx: &mut Ctx, d: &DynStr| {
                let d = d.eval(ctx).into_owned();
                // Accept a bare domain or a URI.
                let host = user_host(d.as_bytes()).map_or(d, |(_, h)| h);
                rc(me.is_local(&host))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "is_from_local",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| rc(hdr_uri(ctx, HdrKind::From).and_then(|u| user_host(&u)).is_some_and(|(_, h)| me.is_local(&h))),
        );
        let me = self.clone();
        reg.export(
            m,
            "is_uri_host_local",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| rc(user_host(ctx.ruri()).is_some_and(|(_, h)| me.is_local(&h))),
        );
        let me = self.clone();
        reg.rpc.add("domain.reload", "Reload the domain table", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("domain.dump", "List the local domains", move |_| {
            let mut v: Vec<String> = read(&me.domains).iter().cloned().collect();
            v.sort();
            Ok(json!(v))
        });
        Ok(())
    }
}

// --------------------------------------------------------------- alias_db --

pub struct AliasDb {
    db_url: Mutex<Option<String>>,
    use_domain: AtomicBool,
    cols: Mutex<[String; 4]>,
}

impl Default for AliasDb {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            use_domain: AtomicBool::new(false),
            cols: Mutex::new(["alias_username".into(), "alias_domain".into(), "username".into(), "domain".into()]),
        }
    }
}

impl AliasDb {
    /// alias_db_lookup(table[, flags]): flags `d` ignore the domain, `r`
    /// reverse (user → alias), `m` all matches (extra ones as branches).
    fn lookup(&self, ctx: &mut Ctx<'_, '_>, table: &str, flags: &str) -> i32 {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::DEFAULT_URL.to_string());
        let Ok(db) = sip_db::connect(&url) else { return -1 };
        let Some((user, host)) = user_host(ctx.ruri()) else { return -1 };
        let c = lock(&self.cols).clone();
        let reverse = flags.contains('r');
        let (k_user, k_dom, v_user, v_dom) = if reverse { (&c[2], &c[3], &c[0], &c[1]) } else { (&c[0], &c[1], &c[2], &c[3]) };
        let mut filter: Vec<(&str, DbVal)> = vec![(k_user.as_str(), DbVal::Str(user))];
        if self.use_domain.load(Ordering::Relaxed) && !flags.contains('d') {
            filter.push((k_dom.as_str(), DbVal::Str(host)));
        }
        let Ok(rows) = db.query(table, &[v_user.as_str(), v_dom.as_str()], &filter) else { return -1 };
        let mut it = rows.rows.into_iter();
        let Some(first) = it.next() else { return -1 };
        let mk = |r: &[DbVal]| {
            let col = |i: usize| r.get(i).map(DbVal::text).unwrap_or_default();
            format!("sip:{}@{}", col(0), col(1)).into_bytes()
        };
        ctx.new_ruri = Some(mk(&first));
        if flags.contains('m') {
            for r in it {
                ctx.branches.push(Branch { uri: mk(&r), dst: None, q: None, path: None, ..Default::default() });
            }
        }
        1
    }
}

impl Module for AliasDb {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the alias tables"),
            p("use_domain", Ty::Bool, "false", "Match the alias domain as well as the user"),
            p("alias_user_column", Ty::Str, "alias_username", "Column with the alias user"),
            p("alias_domain_column", Ty::Str, "alias_domain", "Column with the alias domain"),
            p("user_column", Ty::Str, "username", "Column with the target user"),
            p("domain_column", Ty::Str, "domain", "Column with the target domain"),
        ])
    }

    fn name(&self) -> &'static str {
        "alias_db"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, opt, sig};
        const LOOKUP: &[Param] = &[arg("table", Str).eg("\"dbaliases\""), opt("flags", Str).lit().eg("\"dm\"")];
        Some(vec![sig(
            "alias_db_lookup",
            "lookup",
            LOOKUP,
            Ret::Bool,
            "Replace the R-URI by its alias in the table; flags `d` ignore the domain, `r` reverse, `m` every match as a branch",
        )])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut cols = lock(&self.cols);
        let [alias_user, alias_domain, user, domain] = &mut *cols;
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "use_domain" => self.use_domain.store(v.int()? != 0, Ordering::Relaxed),
            "alias_user_column" => *alias_user = v.str()?.into(),
            "alias_domain_column" => *alias_domain = v.str()?.into(),
            "user_column" => *user = v.str()?.into(),
            "domain_column" => *domain = v.str()?.into(),
            "domain_prefix" | "append_branches" => {}
            _ => return Err(format!("alias_db: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        reg.export(
            "alias_db",
            "alias_db_lookup",
            |a: &[Arg]| -> Result<(DynStr, String), String> {
                let (table, flags) = match a {
                    [table] => (table, None),
                    [table, flags] => (table, Some(flags)),
                    _ => return Err("expected table[, flags]".into()),
                };
                Ok((table.dyn_str()?, flags.map(|f| f.str().map(String::from)).transpose()?.unwrap_or_default()))
            },
            move |ctx: &mut Ctx, (t, f): &(DynStr, String)| {
                let t = t.eval(ctx).into_owned();
                me.lookup(ctx, &t, f)
            },
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ group --

pub struct Group {
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    use_domain: AtomicBool,
    cols: Mutex<[String; 3]>,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            table: Mutex::new("grp".into()),
            use_domain: AtomicBool::new(false),
            cols: Mutex::new(["username".into(), "domain".into(), "grp".into()]),
        }
    }
}

/// Which user `is_user_in()` checks.
enum Who {
    Ruri,
    To,
    From,
    Credentials,
    Uri(DynStr),
}

/// An address group as a script return code. A group beyond i32 is
/// clamped: wrapped, 4294967296 would have become 0, which ends the
/// script.
fn grp_rc(g: i64) -> i32 {
    i32::try_from(g).unwrap_or(if g < 0 { i32::MIN } else { i32::MAX })
}

/// username and realm from the Authorization / Proxy-Authorization header.
fn credentials(ctx: &mut Ctx<'_, '_>) -> Option<(String, String)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let h = ctx.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"proxy-authorization") || h.name.eq_ignore_ascii_case(b"authorization"))?;
    let s = String::from_utf8_lossy(h.body).into_owned();
    let field = |k: &str| -> Option<String> {
        let (_, v) = s.split_once(&format!("{k}="))?;
        let v = v.trim_start();
        let v = match v.strip_prefix('"') {
            Some(q) => q.split('"').next().unwrap_or(q),
            None => v.split([',', ' ']).next().unwrap_or(v),
        };
        Some(v.to_string())
    };
    Some((field("username")?, field("realm").unwrap_or_default()))
}

impl Group {
    fn is_user_in(&self, ctx: &mut Ctx<'_, '_>, who: &Who, group: &str) -> i32 {
        let uh = match who {
            Who::Ruri => user_host(ctx.ruri()),
            Who::To => hdr_uri(ctx, HdrKind::To).and_then(|u| user_host(&u)),
            Who::From => hdr_uri(ctx, HdrKind::From).and_then(|u| user_host(&u)),
            Who::Credentials => credentials(ctx),
            Who::Uri(d) => {
                let s = d.eval(ctx).into_owned();
                user_host(s.as_bytes())
            }
        };
        let Some((user, host)) = uh else { return -1 };
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::DEFAULT_URL.to_string());
        let Ok(db) = sip_db::connect(&url) else { return -1 };
        let c = lock(&self.cols).clone();
        let mut filter: Vec<(&str, DbVal)> = vec![(c[0].as_str(), DbVal::Str(user)), (c[2].as_str(), DbVal::Str(group.to_string()))];
        if self.use_domain.load(Ordering::Relaxed) {
            filter.push((c[1].as_str(), DbVal::Str(host)));
        }
        rc(db.query(&lock(&self.table), &[c[2].as_str()], &filter).is_ok_and(|r| !r.rows.is_empty()))
    }
}

impl Module for Group {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the group table"),
            p("table", Ty::Str, "grp", "Table of group memberships"),
            p("use_domain", Ty::Bool, "false", "Match the user's domain as well as the user"),
            p("user_column", Ty::Str, "username", "Column with the user"),
            p("domain_column", Ty::Str, "domain", "Column with the domain"),
            p("group_column", Ty::Str, "grp", "Column with the group name"),
        ])
    }

    fn name(&self) -> &'static str {
        "group"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, sig};
        const WHO: &[Param] = &[arg("who", Enum(&["Request-URI", "To", "From", "Credentials"])), arg("group", Str)];
        const URI: &[Param] = &[arg("uri", Uri), arg("group", Str)];
        Some(vec![
            sig("is_user_in", "is_member", WHO, Ret::Bool, "The user of the R-URI, To, From or credentials is in the group"),
            sig("is_user_in", "uri_is_member", URI, Ret::Bool, "The user of this URI is in the group"),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut cols = lock(&self.cols);
        let [user, domain, group] = &mut *cols;
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "table" => *lock(&self.table) = v.str()?.into(),
            "use_domain" => self.use_domain.store(v.int()? != 0, Ordering::Relaxed),
            "user_column" => *user = v.str()?.into(),
            "domain_column" => *domain = v.str()?.into(),
            "group_column" => *group = v.str()?.into(),
            "re_table" | "re_exp_column" | "re_gid_column" | "multiple_gid" => {}
            _ => return Err(format!("group: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        reg.export(
            "group",
            "is_user_in",
            |a: &[Arg]| -> Result<(Who, DynStr), String> {
                let [who, group] = args(a)?;
                let who = match who.str() {
                    Ok("Request-URI") => Who::Ruri,
                    Ok("To") => Who::To,
                    Ok("From") => Who::From,
                    Ok("Credentials") => Who::Credentials,
                    _ => Who::Uri(who.dyn_str()?),
                };
                Ok((who, group.dyn_str()?))
            },
            move |ctx: &mut Ctx, (who, g): &(Who, DynStr)| {
                let g = g.eval(ctx).into_owned();
                me.is_user_in(ctx, who, &g)
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod rule_tests {
    #[test]
    fn allow_deny() {
        let allow = super::parse_rules("# c\n\"^sip:alice@.*\" : ALL EXCEPT \"^sip:900.*\"\n").unwrap();
        let deny = super::parse_rules("ALL : \"^sip:900\", \"^sip:premium\"\n").unwrap();
        let f = super::RuleFiles { allow, deny };
        assert!(f.check("sip:alice@x", &["sip:bob@y".into()]));
        assert!(!f.check("sip:alice@x", &["sip:900123@y".into()]), "EXCEPT, then the deny file");
        assert!(!f.check("sip:carol@x", &["sip:premium@y".into()]));
        assert!(f.check("sip:carol@x", &["sip:bob@y".into()]), "no rule: allowed");
        assert!(super::parse_rules("\"x\" \"y\"").is_err());
    }

    #[test]
    fn group_return_codes_never_wrap() {
        assert_eq!(super::grp_rc(7), 7);
        assert_eq!(super::grp_rc(-3), -3);
        assert_eq!(super::grp_rc(1 << 32), i32::MAX, "not 0, which would end the script");
        assert_eq!(super::grp_rc(i64::MIN), i32::MIN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeNet, request, udp, with_ctx};

    #[test]
    fn rule_file_syntax() {
        let r = parse_rules("all : \"^sip:a\" , \"^sip:b\" except \"^sip:bad\"  # trailing comment\n").unwrap();
        assert_eq!(r.len(), 1);
        let (from, to) = &r[0];
        assert!(from.all && from.incl.is_empty() && from.excl.is_empty(), "lower-case ALL");
        assert_eq!((to.incl.len(), to.excl.len()), (2, 1));
        assert!(to.matches("sip:a@x") && to.matches("sip:b@x") && !to.matches("sip:c@x"));
        assert!(!to.matches("sip:bad@x") && !Side { all: true, incl: vec![], excl: to.excl.clone() }.matches("sip:bad"));
        // An escaped quote inside a regex.
        let r = parse_rules(r#""^\"x\"" : ALL"#).unwrap();
        assert!(r[0].0.matches("\"x\"@h"));
        // A ':' inside a quoted regex is not the separator.
        let r = parse_rules("\"^sip:a\" : \"^sip:b\"\n").unwrap();
        assert!(r[0].0.matches("sip:a@h") && !r[0].0.matches("sip:b@h") && r[0].1.matches("sip:b@h"));
        let errors = [
            ("\"x\" ALL", "missing ':'"),
            ("\"x : ALL", "unterminated"),
            ("\"(\" : ALL", "bad regex"),
            ("FOO : ALL", "unexpected"),
            ("ALL : ALL EXCEPT ALL", "unexpected"),
            ("# ok\n\nALL : ALL\nALL ALL", "line 4"),
        ];
        for (text, want) in errors {
            let e = parse_rules(text).unwrap_err();
            assert!(e.contains(want), "{text:?}: {e}");
        }
        assert!(parse_rules("# only comments\n\n   \n").unwrap().is_empty());
    }

    #[test]
    fn allow_file_wins_then_deny_then_default_allow() {
        let f = RuleFiles { allow: parse_rules("\"^sip:boss@\" : ALL\n").unwrap(), deny: parse_rules("ALL : \"^sip:9\"\n").unwrap() };
        assert!(f.check("sip:boss@x", &["sip:900@y".into()]), "allow file first");
        assert!(!f.check("sip:joe@x", &["sip:900@y".into()]));
        assert!(f.check("sip:joe@x", &["sip:100@y".into()]));
        // Every target must pass (REGISTER Contacts).
        assert!(!f.check("sip:joe@x", &["sip:100@y".into(), "sip:999@y".into()]));
        assert!(f.check("sip:joe@x", &[]), "no targets");
        let none = RuleFiles::load("/nonexistent/ferrosip-test.allow", "/nonexistent/ferrosip-test.deny").unwrap();
        assert!(none.allow.is_empty() && none.deny.is_empty(), "missing files: no rules");
        assert!(none.check("sip:x@y", &["sip:9@z".into()]));
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(grp: i64, net: &str, port: u16, tag: &str) -> AddrRule {
        let (net, mask) = parse_net(net).unwrap();
        AddrRule { grp, net, mask, port, tag: tag.into() }
    }

    #[test]
    fn address_table_matching() {
        let p = Permissions::default();
        *write(&p.address) = Arc::new(vec![
            rule(1, "10.0.0.0/8", 0, "lan"),
            rule(2, "192.168.1.5", 5060, "pbx"),
            rule(3, "2001:db8::/32", 0, "v6"),
            rule(4, "10.1.0.0/16", 0, "shadowed"),
        ]);
        let m = |g: Option<i64>, a: &str, port: u16| p.match_addr(g, ip(a), port).map(|r| r.tag);
        let cases: &[(Option<i64>, &str, u16, Option<&str>)] = &[
            (Some(1), "10.200.0.1", 1, Some("lan")),
            (Some(1), "11.0.0.1", 1, None),
            (Some(2), "10.200.0.1", 1, None),
            (Some(2), "192.168.1.5", 5060, Some("pbx")),
            (Some(2), "192.168.1.5", 5061, None),
            (Some(2), "192.168.1.6", 5060, None),
            (Some(3), "2001:db8:1::9", 7, Some("v6")),
            (Some(3), "2001:db9::9", 7, None),
            (Some(1), "::ffff:10.1.2.3", 5, Some("lan")),
            (None, "10.1.2.3", 5, Some("lan")),
            (Some(4), "10.1.2.3", 5, Some("shadowed")),
            (None, "192.168.1.5", 5060, Some("pbx")),
            (None, "172.16.0.1", 5060, None),
        ];
        for (g, a, port, want) in cases {
            assert_eq!(m(*g, a, *port).as_deref(), *want, "group {g:?} {a}:{port}");
        }
    }

    #[test]
    fn trusted_table_matching() {
        let p = Permissions::default();
        let re = |s: &str| Some(Regex::new(s).unwrap());
        let t = |src: &str, proto: Option<Proto>, from: Option<Regex>, ruri: Option<Regex>| {
            let (src, mask) = parse_net(src).unwrap();
            TrustRule { src, mask, proto, from, ruri, tag: String::new(), priority: 0 }
        };
        *write(&p.trusted) = Arc::new(vec![
            t("198.51.100.0/24", Some(Proto::Tcp), None, None),
            t("203.0.113.5", None, re("^sip:alice@"), None),
            t("192.0.2.0/24", None, None, re("^sip:\\+1")),
        ]);
        let net = FakeNet(vec![]);
        let msg = request("INVITE", "sip:+15551234@b.example", "");
        let run = |a: &str, proto: Option<Proto>, ruri: Option<&str>| {
            with_ctx(&msg, udp("192.0.2.200:5060"), &net, |ctx| p.allow_trusted(ctx, ip(a), proto, ruri.map(String::from)))
        };
        let cases: &[(&str, Option<Proto>, Option<&str>, i32)] = &[
            ("198.51.100.9", Some(Proto::Tcp), None, 1),
            ("198.51.100.9", Some(Proto::Udp), None, -1),
            ("198.51.100.9", None, None, -1),
            ("203.0.113.5", Some(Proto::Udp), None, 1),
            ("203.0.113.6", Some(Proto::Udp), None, -1),
            ("192.0.2.1", Some(Proto::Udp), None, 1),
            ("192.0.2.1", Some(Proto::Udp), Some("sip:44@x"), -1),
            ("192.0.2.1", Some(Proto::Udp), Some("sip:+44@x"), -1),
            ("192.0.2.1", Some(Proto::Udp), Some("sip:+1@x"), 1),
        ];
        for (a, proto, ruri, want) in cases {
            assert_eq!(run(a, *proto, *ruri), *want, "{a} {proto:?} {ruri:?}");
        }
        // The From pattern sees the From URI, not the header.
        let bob = msg.replace("sip:alice@a.example", "sip:bob@a.example");
        assert_eq!(with_ctx(&bob, udp("192.0.2.200:5060"), &net, |ctx| p.allow_trusted(ctx, ip("203.0.113.5"), None, None)), -1);
    }

    #[test]
    fn credentials_username_and_realm() {
        let net = FakeNet(vec![]);
        let cases = [
            ("Authorization: Digest username=\"alice\", realm=\"a.example\", nonce=\"n\"\n", Some(("alice", "a.example"))),
            ("Proxy-Authorization: Digest realm=a.example,username=bob,nonce=\"n\"\n", Some(("bob", "a.example"))),
            ("Authorization: Digest username=\"carol\"\n", Some(("carol", ""))),
            ("Authorization: Digest  username= dave realm=r\n", Some(("dave", "r"))),
            ("Authorization: Digest realm=\"r\"\n", None),
            ("", None),
        ];
        for (hdr, want) in cases {
            let got = with_ctx(&request("INVITE", "sip:b@b.example", hdr), udp("192.0.2.1:5060"), &net, credentials);
            assert_eq!(got, want.map(|(u, r)| (u.to_string(), r.to_string())), "{hdr:?}");
        }
    }

    #[test]
    fn local_domain_lookup_is_case_and_dot_insensitive() {
        let d = Domain::default();
        *write(&d.domains) = Arc::new(["example.com".to_string(), "sip.example.org".to_string()].into_iter().collect());
        for (name, want) in [("example.com", true), ("EXAMPLE.com.", true), (" sip.example.org ", true), ("example.org", false), ("", false), ("com", false)] {
            assert_eq!(d.is_local(name), want, "{name:?}");
        }
    }

    #[test]
    fn module_parameters() {
        assert!(Permissions::default().set_param("max_subnets", &Arg::Int(1)).is_ok());
        assert!(Permissions::default().set_param("bogus", &Arg::Int(1)).is_err());
        assert!(Domain::default().set_param("bogus", &Arg::Int(1)).is_err());
        assert!(AliasDb::default().set_param("bogus", &Arg::Int(1)).is_err());
        assert!(Group::default().set_param("bogus", &Arg::Int(1)).is_err());
        assert!(opt_args(&[Arg::Int(1), Arg::Int(2)], 1).is_err());
        assert_eq!(opt_args(&[Arg::Int(1)], 1).unwrap().len(), 1);
        let g = Group::default();
        g.set_param("group_column", &Arg::Str("gid".into())).unwrap();
        assert_eq!(lock(&g.cols)[2], "gid");
        let a = AliasDb::default();
        a.set_param("alias_domain_column", &Arg::Str("ad".into())).unwrap();
        assert_eq!(lock(&a.cols)[1], "ad");
    }
}
