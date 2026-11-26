//! Request filtering from database lists:
//! * `secfilter` — block/allow lists of user agents, countries, domains,
//!   IPs and users, blocked destinations, and SQL-injection checks
//!   (table `secfilter`: action 0 blocklist / 1 allowlist / 2 destination
//!   blocklist; type 0 user-agent, 1 country, 2 domain, 3 IP, 4 user).
//!   Return codes as Kamailio: 2 allowlisted, 1 not found, -2 blocklisted.
//! * `userblocklist` — per-user and global number-prefix block/allow lists
//!   (tables `userblocklist`, `globalblocklist`), longest prefix wins.

use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sync::{lock, read, write};
use sip_core::{Arg, Ctx, Module, Registry, want_args};
use sip_db::DbVal;
use sip_parser::uri::name_addr;
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

// -------------------------------------------------------------- secfilter --

const T_UA: i64 = 0;
const T_COUNTRY: i64 = 1;
const T_DOMAIN: i64 = 2;
const T_IP: i64 = 3;
const T_USER: i64 = 4;

#[derive(Default, Clone, Debug)]
struct Lists {
    /// (action, type, data lower-cased)
    rows: Vec<(i64, i64, String)>,
}

impl Lists {
    fn has(&self, action: i64, ty: i64, f: impl Fn(&str) -> bool) -> bool {
        self.rows.iter().any(|(a, t, d)| *a == action && *t == ty && f(d))
    }
    /// 2 allowlisted, -2 blocklisted, 1 neither.
    fn verdict(&self, ty: i64, f: impl Fn(&str) -> bool) -> i32 {
        if self.has(1, ty, &f) {
            2
        } else if self.has(0, ty, &f) {
            -2
        } else {
            1
        }
    }
}

#[derive(Default)]
pub struct SecFilter {
    db_url: Mutex<Option<String>>,
    table: Mutex<Option<String>>,
    lists: RwLock<Arc<Lists>>,
    dst_exact: AtomicBool,
    blocked: AtomicI64,
}

/// Kamailio secfilter's SQL-injection markers.
fn sqli(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    ["'", "--", "#", "/*", "%27", "%24", "%60"].iter().any(|m| l.contains(m))
}

impl SecFilter {
    fn reload(&self) -> Result<usize, String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("secfilter"));
        let table = lock(&self.table).clone().unwrap_or_else(|| "secfilter".into());
        let db = sip_db::connect(&url)?;
        let rows = db.query(&table, &["action", "type", "data"], &[])?;
        let l = Lists {
            rows: rows
                .rows
                .iter()
                .filter_map(|r| match r.as_slice() {
                    [action, ty, data, ..] => Some((action.int().unwrap_or(-1), ty.int().unwrap_or(-1), data.text().trim().to_ascii_lowercase())),
                    _ => None,
                })
                .collect(),
        };
        let n = l.rows.len();
        *write(&self.lists) = Arc::new(l);
        Ok(n)
    }

    fn lists(&self) -> Arc<Lists> {
        read(&self.lists).clone()
    }

    fn count(&self, r: i32) -> i32 {
        if r == -2 {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    /// User and domain of the URI in header `kind` (or Contact).
    fn check_hdr(&self, ctx: &mut Ctx<'_, '_>, kind: HdrKind) -> i32 {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let Some(h) = ctx.msg.get(kind) else { return 1 };
        let (uri, _) = name_addr(h.body);
        let Some(u) = parse_uri(uri) else { return 1 };
        let user = String::from_utf8_lossy(u.user.unwrap_or(b"")).to_ascii_lowercase();
        let dom = String::from_utf8_lossy(u.host).to_ascii_lowercase();
        // The display name counts as a user too.
        let disp = String::from_utf8_lossy(h.body.split(|&c| c == b'<').next().unwrap_or(b"")).trim().trim_matches('"').to_ascii_lowercase();
        let l = self.lists();
        let users = |d: &str| d == user || (!disp.is_empty() && d == disp);
        let (vu, vd) = (l.verdict(T_USER, users), l.verdict(T_DOMAIN, |d| d == dom));
        self.count(if vu == 2 || vd == 2 {
            2
        } else if vu == -2 || vd == -2 {
            -2
        } else {
            1
        })
    }
}

impl Module for SecFilter {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the secfilter table"),
            p("table_name", Ty::Str, "secfilter", "Table of block/allow list entries"),
            p("dst_exact_match", Ty::Bool, "false", "secf_check_dst: match the whole destination, not a prefix"),
        ])
    }

    fn name(&self) -> &'static str {
        "secfilter"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "table_name" => *lock(&self.table) = Some(v.str()?.into()),
            "dst_exact_match" => self.dst_exact.store(v.int()? != 0, Ordering::Relaxed),
            "action_col" | "type_col" | "data_col" => {}
            _ => return Err(format!("secfilter: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, sig};
        const COUNTRY: &[Param] = &[arg("country", Str).eg("\"de\"")];
        const NUMBER: &[Param] = &[arg("number", Str)];
        const VALUE: &[Param] = &[arg("value", Str)];
        Some(
            [
                sig("secf_check_ua", "check_user_agent", &[], Ret::Bool, "The User-Agent is not blocklisted"),
                sig("secf_check_from_hdr", "check_from", &[], Ret::Bool, "The From user, domain and name are not blocklisted"),
                sig("secf_check_to_hdr", "check_to", &[], Ret::Bool, "The To user, domain and name are not blocklisted"),
                sig("secf_check_contact_hdr", "check_contact", &[], Ret::Bool, "The Contact user, domain and name are not blocklisted"),
                sig("secf_check_ip", "check_ip", &[], Ret::Bool, "The source IP is not blocklisted"),
                sig("secf_check_country", "check_country", COUNTRY, Ret::Bool, "This country code is not blocklisted"),
                sig("secf_check_dst", "check_destination", NUMBER, Ret::Bool, "This destination number is not blocked"),
                sig("secf_check_sqli_all", "check_sql_injection", &[], Ret::Bool, "No SQL injection in the R-URI user, User-Agent, From, To and Contact"),
                sig("secf_check_sqli_hdr", "check_sql_injection_in", VALUE, Ret::Bool, "No SQL injection in this value"),
            ]
            .map(|s| s.allowed(ctx::REQUEST))
            .into(),
        )
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload()?;
        let m = "secfilter";
        let me = self.clone();
        reg.export(
            m,
            "secf_check_ua",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                let ua = ctx.msg.get(HdrKind::UserAgent).map(|h| String::from_utf8_lossy(h.body).to_ascii_lowercase()).unwrap_or_default();
                if ua.is_empty() {
                    return 1;
                }
                me.count(me.lists().verdict(T_UA, |d| ua.contains(d)))
            },
        );
        for (name, kind) in [("secf_check_from_hdr", HdrKind::From), ("secf_check_to_hdr", HdrKind::To), ("secf_check_contact_hdr", HdrKind::Contact)] {
            let me = self.clone();
            reg.export(m, name, |a: &[Arg]| want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.check_hdr(ctx, kind));
        }
        let me = self.clone();
        reg.export(
            m,
            "secf_check_ip",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let ip = ctx.src.addr.ip().to_string();
                // Entries match whole addresses or prefixes ("10.0.").
                me.count(me.lists().verdict(T_IP, |d| ip == d || (d.ends_with('.') || d.ends_with(':')) && ip.starts_with(d)))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "secf_check_country",
            |a: &[Arg]| {
                let [country] = crate::fixed_args(a)?;
                country.dyn_str()
            },
            move |ctx: &mut Ctx, c: &DynStr| {
                let c = c.eval(ctx).trim().to_ascii_lowercase();
                me.count(me.lists().verdict(T_COUNTRY, |d| d == c))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "secf_check_dst",
            |a: &[Arg]| {
                let [dst] = crate::fixed_args(a)?;
                dst.dyn_str()
            },
            move |ctx: &mut Ctx, n: &DynStr| {
                let n = n.eval(ctx).trim().to_ascii_lowercase();
                let exact = me.dst_exact.load(Ordering::Relaxed);
                let hit = me.lists().rows.iter().any(|(a, _, d)| *a == 2 && if exact { n == *d } else { n.starts_with(d.as_str()) });
                me.count(if hit { -2 } else { 1 })
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "secf_check_sqli_all",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                let mut parts: Vec<String> = ctx
                    .msg
                    .headers
                    .iter()
                    .filter(|h| matches!(h.kind, HdrKind::UserAgent | HdrKind::From | HdrKind::To | HdrKind::Contact))
                    .map(|h| String::from_utf8_lossy(h.body).into_owned())
                    .collect();
                parts.push(String::from_utf8_lossy(ctx.msg.ruri_user().unwrap_or(b"")).into_owned());
                if parts.iter().any(|p| sqli(p)) {
                    me.blocked.fetch_add(1, Ordering::Relaxed);
                    -1
                } else {
                    1
                }
            },
        );
        reg.export(
            m,
            "secf_check_sqli_hdr",
            |a: &[Arg]| {
                let [hdr] = crate::fixed_args(a)?;
                hdr.dyn_str()
            },
            |ctx: &mut Ctx, h: &DynStr| rc(!sqli(&h.eval(ctx))),
        );
        let me = self.clone();
        reg.rpc.add("secfilter.reload", "Reload the lists", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("secfilter.print", "Show the lists", move |_| {
            Ok(json!(me.lists().rows.iter().map(|(a, t, d)| json!({"action": a, "type": t, "data": d})).collect::<Vec<_>>()))
        });
        for (name, action) in [("secfilter.add_bl", 0i64), ("secfilter.add_wl", 1), ("secfilter.add_dst", 2)] {
            let me = self.clone();
            reg.rpc.add(name, "secfilter.add_bl|add_wl <ua|country|domain|ip|user> <value>; add_dst <number>", move |p| {
                let (ty, data) = if action == 2 {
                    (0, sip_core::rpc::str_param(p, 0)?)
                } else {
                    let ty = match sip_core::rpc::str_param(p, 0)?.as_str() {
                        "ua" => T_UA,
                        "country" => T_COUNTRY,
                        "domain" => T_DOMAIN,
                        "ip" => T_IP,
                        "user" => T_USER,
                        t => return Err(format!("unknown type {t:?}")),
                    };
                    (ty, sip_core::rpc::str_param(p, 1)?)
                };
                let mut l = (*me.lists()).clone();
                l.rows.push((action, ty, data.to_ascii_lowercase()));
                *write(&me.lists) = Arc::new(l);
                Ok(json!(0))
            });
        }
        let me = self.clone();
        reg.rpc.add("secfilter.stats", "Blocked requests", move |_| Ok(json!({"blocked": me.blocked.load(Ordering::Relaxed)})));
        Ok(())
    }
}

// ---------------------------------------------------------- userblocklist --

pub struct UserBlocklist {
    db_url: Mutex<Option<String>>,
    use_domain: AtomicBool,
    table: Mutex<String>,
    global: RwLock<Arc<Vec<(String, bool)>>>,
    global_table: Mutex<String>,
}

impl Default for UserBlocklist {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            use_domain: AtomicBool::new(false),
            table: Mutex::new("userblocklist".into()),
            global: RwLock::new(Arc::new(Vec::new())),
            global_table: Mutex::new("globalblocklist".into()),
        }
    }
}

/// Longest prefix of `number` among (prefix, allowlist) entries.
fn longest(entries: &[(String, bool)], number: &str) -> Option<bool> {
    let n = number.trim_start_matches('+');
    entries.iter().filter(|(p, _)| n.starts_with(p.trim_start_matches('+'))).max_by_key(|(p, _)| p.trim_start_matches('+').len()).map(|e| e.1)
}

impl UserBlocklist {
    fn db(&self) -> Result<Arc<dyn sip_db::DbConn>, sip_db::DbError> {
        sip_db::connect(&lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("userblocklist")))
    }

    fn reload_global(&self) -> Result<usize, String> {
        let rows = self.db()?.query(&lock(&self.global_table), &["prefix", "allowlist"], &[])?;
        let v: Vec<(String, bool)> = rows.rows.iter().filter_map(|r| prefix_entry(r)).collect();
        let n = v.len();
        *write(&self.global) = Arc::new(v);
        Ok(n)
    }

    fn user_entries(&self, table: &str, user: &str, domain: &str) -> Vec<(String, bool)> {
        let db = match self.db() {
            Ok(db) => db,
            Err(e) => return entries(table, Err(e)),
        };
        let mut f: Vec<(&str, DbVal)> = vec![("username", DbVal::Str(user.into()))];
        if self.use_domain.load(Ordering::Relaxed) {
            f.push(("domain", DbVal::Str(domain.into())));
        }
        entries(table, db.query(table, &["prefix", "allowlist"], &f))
    }

    fn global_table_entries(&self, table: &str) -> Vec<(String, bool)> {
        if *table == *lock(&self.global_table) {
            return (*read(&self.global).clone()).clone();
        }
        let db = match self.db() {
            Ok(db) => db,
            Err(e) => return entries(table, Err(e)),
        };
        entries(table, db.query(table, &["prefix", "allowlist"], &[]))
    }
}

/// A (prefix, allowlist) row.
fn prefix_entry(r: &[sip_db::DbVal]) -> Option<(String, bool)> {
    match r {
        [prefix, allow, ..] => Some((prefix.text(), allow.int().unwrap_or(0) != 0)),
        _ => None,
    }
}

/// The (prefix, allowlist) rows of a query. A failed query counts as an
/// empty list (fail open: the number is not blocked), and is logged.
fn entries(table: &str, rows: Result<sip_db::Rows, sip_db::DbError>) -> Vec<(String, bool)> {
    match rows {
        Ok(r) => r.rows.iter().filter_map(|r| prefix_entry(r)).collect(),
        Err(e) => {
            // Counted apart: a database that is down vs. a bad table/query.
            sip_core::stats::inc(sip_core::stats::counter("userblocklist", if e.is_conn() { "db_unreachable" } else { "db_errors" }));
            sip_core::log::log(sip_core::log::L_ERR, &format!("userblocklist: query of {table} failed, treated as empty: {e}"));
            Vec::new()
        }
    }
}

fn ruri_user(ctx: &Ctx<'_, '_>) -> String {
    parse_uri(ctx.ruri()).and_then(|u| u.user).map(|u| String::from_utf8_lossy(u).into_owned()).unwrap_or_default()
}

impl Module for UserBlocklist {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the blocklist tables"),
            p("use_domain", Ty::Bool, "false", "Match the user's domain as well as the user"),
            p("db_table", Ty::Str, "userblocklist", "Per-user prefix table"),
            p("userblocklist_table", Ty::Str, "userblocklist", "Same as db_table"),
            p("globalblocklist_table", Ty::Str, "globalblocklist", "Global prefix table"),
        ])
    }

    fn name(&self) -> &'static str {
        "userblocklist"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "use_domain" => self.use_domain.store(v.int()? != 0, Ordering::Relaxed),
            "db_table" | "userblocklist_table" => *lock(&self.table) = v.str()?.into(),
            "globalblocklist_table" => *lock(&self.global_table) = v.str()?.into(),
            "match_mode" => {}
            _ => return Err(format!("userblocklist: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, opt, sig};
        const USER: &[Param] = &[arg("user", Str), arg("domain", Str), opt("number", Str), opt("table", Str)];
        const TABLE: &[Param] = &[opt("table", Str).lit().eg("\"globalblocklist\"")];
        Some(
            [
                sig("check_user_blocklist", "check_user", USER, Ret::Bool, "The number (default: R-URI user) is not on the user's blocklist"),
                sig("check_user_allowlist", "user_allowlisted", USER, Ret::Bool, "The number (default: R-URI user) is on the user's allowlist"),
                sig("check_blocklist", "check_global", TABLE, Ret::Bool, "The R-URI user is not on the global blocklist"),
                sig("check_allowlist", "global_allowlisted", TABLE, Ret::Bool, "The R-URI user is on the global allowlist"),
            ]
            .map(|s| s.allowed(ctx::REQUEST))
            .into(),
        )
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload_global()?;
        let m = "userblocklist";
        // check_user_blocklist(user, domain[, number[, table]]) / check_user_allowlist(…)
        for (name, allow) in [("check_user_blocklist", false), ("check_user_allowlist", true)] {
            let me = self.clone();
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    if a.len() < 2 || a.len() > 4 {
                        return Err("expected user, domain[, number[, table]]".into());
                    }
                    a.iter().map(Arg::dyn_str).collect::<Result<Vec<_>, _>>()
                },
                move |ctx: &mut Ctx, a: &Vec<DynStr>| {
                    let [user, dom, rest @ ..] = a.as_slice() else { return -1 };
                    let (user, dom) = (user.eval(ctx).into_owned(), dom.eval(ctx).into_owned());
                    let num = rest.first().map(|n| n.eval(ctx).into_owned()).unwrap_or_else(|| ruri_user(ctx));
                    let table = rest.get(1).map(|t| t.eval(ctx).into_owned()).unwrap_or_else(|| lock(&me.table).clone());
                    let r = longest(&me.user_entries(&table, &user, &dom), &num);
                    if allow { rc(r == Some(true)) } else { rc(r != Some(false)) }
                },
            );
        }
        // check_blocklist([table]) / check_allowlist(table): global lists on the R-URI user.
        for (name, allow) in [("check_blocklist", false), ("check_allowlist", true)] {
            let me = self.clone();
            reg.export(
                m,
                name,
                |a: &[Arg]| -> Result<Option<String>, String> {
                    match a {
                        [] => Ok(None),
                        [table] => Ok(Some(table.str()?.to_string())),
                        _ => Err("expected [table]".into()),
                    }
                },
                move |ctx: &mut Ctx, t: &Option<String>| {
                    let table = t.clone().unwrap_or_else(|| lock(&me.global_table).clone());
                    let r = longest(&me.global_table_entries(&table), &ruri_user(ctx));
                    if allow { rc(r == Some(true)) } else { rc(r != Some(false)) }
                },
            );
        }
        let me = self.clone();
        reg.rpc.add("userblocklist.reload_blocklist", "Reload the global list", move |_| me.reload_global().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("userblocklist.dump_blocklist", "Show the global list", move |_| {
            let g = read(&me.global).clone();
            Ok(json!(g.iter().map(|(p, a)| json!({"prefix": p, "allowlist": a})).collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("userblocklist.check_blocklist", "userblocklist.check_blocklist <number>", move |p| {
            let n = sip_core::rpc::str_param(p, 0)?;
            let g = read(&me.global).clone();
            Ok(json!(longest(&g, &n).map_or("not found", |a| if a { "allowlisted" } else { "blocklisted" })))
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix() {
        let e = vec![("49".to_string(), false), ("4930".to_string(), true), ("+1".to_string(), false)];
        assert_eq!(longest(&e, "+49301234"), Some(true));
        assert_eq!(longest(&e, "4940"), Some(false));
        assert_eq!(longest(&e, "15550100"), Some(false));
        assert_eq!(longest(&e, "33"), None);
        assert!(sqli("1' or '1'='1") && !sqli("alice"));
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use sip_core::{Dest, Outbound, Proto};

    fn lists(rows: &[(i64, i64, &str)]) -> Lists {
        Lists { rows: rows.iter().map(|&(a, t, d)| (a, t, d.to_string())).collect() }
    }

    #[test]
    fn verdict_prefers_the_allowlist() {
        let l = lists(&[(0, T_UA, "friendly-scanner"), (1, T_UA, "good"), (0, T_UA, "good"), (0, T_COUNTRY, "xx"), (2, T_UA, "dst")]);
        let ua = |s: &'static str| move |d: &str| s.contains(d);
        assert_eq!(l.verdict(T_UA, ua("friendly-scanner 1.0")), -2);
        assert_eq!(l.verdict(T_UA, ua("good phone")), 2, "on both lists: allowed");
        assert_eq!(l.verdict(T_UA, ua("other")), 1);
        assert_eq!(l.verdict(T_UA, ua("dst")), 1, "destination entries are not UA entries");
        assert_eq!(l.verdict(T_COUNTRY, |d| d == "xx"), -2);
        assert_eq!(l.verdict(T_DOMAIN, |_| true), 1, "no entries of that type");
    }

    #[test]
    fn sqli_markers() {
        let cases: &[(&str, bool)] = &[
            ("alice", false),
            ("+4930123", false),
            ("sip:alice@example.com;tag=1", false),
            ("1' or '1'='1", true),
            ("x--", true),
            ("a#b", true),
            ("/* c */", true),
            ("%27", true),
            ("%24x", true),
            ("%60", true),
            ("%2A", false),
            ("", false),
        ];
        for &(s, want) in cases {
            assert_eq!(sqli(s), want, "{s:?}");
        }
    }

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    /// An event route that runs `check_hdr(From)` and keeps its result.
    struct CheckFrom(Arc<SecFilter>, Mutex<i32>);
    impl sip_core::RouteRunner for CheckFrom {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            *lock(&self.1) = self.0.check_hdr(ctx, HdrKind::From);
            true
        }
    }

    /// `check_hdr(From)` on a request with this From header value.
    fn check_from(sf: &Arc<SecFilter>, from: &str) -> i32 {
        let req = format!("INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nFrom: {from}\r\nTo: <sip:b@x>\r\nCall-ID: c\r\n\r\n");
        let runner = Arc::new(CheckFrom(sf.clone(), Mutex::new(i32::MIN)));
        let hub = sip_core::RouteHub::default();
        hub.set_names(sip_core::RouteNames { event: vec!["e".into()], ..Default::default() });
        hub.set_runner(runner.clone());
        hub.run_event_with("e", &NoNet, Some(req.as_bytes()), |_| {});
        *lock(&runner.1)
    }

    #[test]
    fn header_check_matches_user_domain_and_display_name() {
        let sf = Arc::new(SecFilter::default());
        *write(&sf.lists) = Arc::new(lists(&[(0, T_USER, "mallory"), (0, T_DOMAIN, "evil.example"), (1, T_USER, "boss"), (0, T_USER, "spam bot")]));
        let cases: &[(&str, i32)] = &[
            ("<sip:alice@example.com>;tag=1", 1),
            ("<sip:Mallory@example.com>;tag=1", -2),
            ("<sip:alice@EVIL.example>;tag=1", -2),
            ("\"Spam Bot\" <sip:alice@example.com>;tag=1", -2),
            ("<sip:boss@evil.example>;tag=1", 2),
            ("Boss <sip:x@example.com>", 2),
            ("<nonsense>", 1),
        ];
        for &(from, want) in cases {
            assert_eq!(check_from(&sf, from), want, "{from}");
        }
        assert_eq!(sf.blocked.load(Ordering::Relaxed), 3, "blocklist hits are counted");
    }

    #[test]
    fn longest_prefix_wins_and_plus_is_ignored() {
        let e = |v: &[(&str, bool)]| v.iter().map(|&(p, a)| (p.to_string(), a)).collect::<Vec<_>>();
        let list = e(&[("", true), ("49", false), ("+4930", true), ("493012", false), ("1", false)]);
        let cases: &[(&str, Option<bool>)] = &[
            ("+4930123", Some(false)),
            ("4930999", Some(true)),
            ("4940", Some(false)),
            ("+49", Some(false)),
            ("4", Some(true)),
            ("33", Some(true)),
            ("", Some(true)),
            ("15550100", Some(false)),
        ];
        for &(n, want) in cases {
            assert_eq!(longest(&list, n), want, "{n:?}");
        }
        let no_default = e(&[("49", false)]);
        assert_eq!(longest(&no_default, "33"), None);
        assert_eq!(longest(&[], "49"), None);
    }

    #[test]
    fn prefix_entry_reads_prefix_and_allowlist_flag() {
        assert_eq!(prefix_entry(&[DbVal::Str("49".into()), DbVal::Int(1)]), Some(("49".into(), true)));
        assert_eq!(prefix_entry(&[DbVal::Str("49".into()), DbVal::Int(0), DbVal::Int(9)]), Some(("49".into(), false)));
        assert_eq!(prefix_entry(&[DbVal::Str("49".into()), DbVal::Str("x".into())]), Some(("49".into(), false)));
        assert_eq!(prefix_entry(&[DbVal::Str("49".into())]), None);
        assert_eq!(entries("t", Err(sip_db::DbError::Config("down".into()))), vec![], "a failed query: an empty list");
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::testutil::{TextDb, call, call_from, request, request_with, rpc};
    use sip_core::serde_json::json;
    use sip_core::{Dest, Proto};

    fn s(v: &str) -> Arg {
        Arg::Str(v.into())
    }

    /// A request whose headers do not parse (a line without a colon).
    const BROKEN: &str = "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nno colon here\r\n\r\n";

    const SECF: &str = "action(int) type(int) data(string)\n\
0:0:friendly-scanner\n1:0:Good Phone\n0:1:XX\n0:3:10.0.\n0:3:192.0.2.1\n1:3:2001\\:db8\\:\n2:0:0900\n";

    fn secfilter(db: &TextDb, exact: bool) -> (Arc<SecFilter>, Registry) {
        let sf = Arc::new(SecFilter::default());
        sf.set_param("db_url", &s(&db.url())).unwrap();
        sf.set_param("table_name", &s("sf")).unwrap();
        sf.set_param("dst_exact_match", &Arg::Int(i64::from(exact))).unwrap();
        let mut reg = Registry::default();
        reg.load(sf.clone()).unwrap();
        (sf, reg)
    }

    #[test]
    fn secfilter_params() {
        let sf = SecFilter::default();
        for name in ["action_col", "type_col", "data_col"] {
            assert!(sf.set_param(name, &s("x")).is_ok(), "{name}");
        }
        assert!(sf.set_param("nope", &s("x")).is_err());
    }

    #[test]
    fn secf_check_ua() {
        let db = TextDb::new(&[("sf", SECF)]);
        let (sf, reg) = secfilter(&db, false);
        let ua = |v: &str| call(&reg, "secf_check_ua", &[], &request_with("INVITE", "sip:b@x", &format!("User-Agent: {v}\r\n"))).0;
        assert_eq!(ua("Friendly-Scanner 1.0"), -2);
        assert_eq!(ua("good phone 2"), 2, "case-insensitive");
        assert_eq!(ua("other"), 1);
        assert_eq!(call(&reg, "secf_check_ua", &[], &request("INVITE")).0, 1, "no User-Agent");
        assert_eq!(call(&reg, "secf_check_ua", &[], BROKEN).0, -1, "headers that do not parse");
        assert_eq!(sf.blocked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn secf_check_ip_matches_addresses_and_prefixes() {
        let db = TextDb::new(&[("sf", SECF)]);
        let (_, reg) = secfilter(&db, false);
        let req = request("INVITE");
        let cases: &[(&str, i32)] = &[
            ("10.0.0.5:5060", -2),
            ("10.1.0.5:5060", 1),
            ("192.0.2.1:5060", -2),
            ("192.0.2.10:5060", 1),
            ("[2001:db8::1]:5060", 2),
            ("[2001:db9::1]:5060", 1),
        ];
        for &(src, want) in cases {
            let d = Dest::new(Proto::Udp, src.parse().unwrap());
            assert_eq!(call_from(&reg, "secf_check_ip", &[], &req, Some(d)).0, want, "{src}");
        }
    }

    #[test]
    fn secf_check_country_dst_and_sqli() {
        let db = TextDb::new(&[("sf", SECF)]);
        let (_, reg) = secfilter(&db, false);
        let req = request("INVITE");
        let one = |f: &str, v: &str| call(&reg, f, &[s(v)], &req).0;
        assert_eq!(one("secf_check_country", " xx "), -2);
        assert_eq!(one("secf_check_country", "de"), 1);
        assert_eq!(one("secf_check_dst", "0900123"), -2, "prefix match");
        assert_eq!(one("secf_check_dst", "0900"), -2);
        assert_eq!(one("secf_check_dst", "0800"), 1);
        assert_eq!(one("secf_check_sqli_hdr", "alice"), 1);
        assert_eq!(one("secf_check_sqli_hdr", "a' or 1=1"), -1);
        assert!((reg.get("secf_check_country").unwrap().fixup)(&[]).is_err());

        let (_, exact) = secfilter(&db, true);
        assert_eq!(call(&exact, "secf_check_dst", &[s("0900123")], &req).0, 1, "dst_exact_match: whole number only");
        assert_eq!(call(&exact, "secf_check_dst", &[s("0900")], &req).0, -2);
    }

    #[test]
    fn secf_check_sqli_all_looks_at_ruri_user_and_headers() {
        let db = TextDb::new(&[("sf", SECF)]);
        let (sf, reg) = secfilter(&db, false);
        let all = |ruri: &str, extra: &str| call(&reg, "secf_check_sqli_all", &[], &request_with("INVITE", ruri, extra)).0;
        assert_eq!(all("sip:b@x", "User-Agent: phone\r\nContact: <sip:a@1.2.3.4>\r\n"), 1);
        assert_eq!(all("sip:b'--@x", ""), -1, "R-URI user");
        assert_eq!(all("sip:b@x", "User-Agent: x/*y\r\n"), -1);
        assert_eq!(all("sip:b@x", "Contact: <sip:a%27@1.2.3.4>\r\n"), -1);
        assert_eq!(all("sip:b@x", "Subject: it's fine\r\n"), 1, "other headers are not checked");
        assert_eq!(sf.blocked.load(Ordering::Relaxed), 3);
        assert_eq!(call(&reg, "secf_check_sqli_all", &[], BROKEN).0, -1);
        for f in ["secf_check_from_hdr", "secf_check_to_hdr", "secf_check_contact_hdr"] {
            assert_eq!(call(&reg, f, &[], BROKEN).0, -1, "{f}: headers that do not parse");
        }
        assert_eq!(call(&reg, "secf_check_contact_hdr", &[], &request("INVITE")).0, 1, "no Contact");
    }

    #[test]
    fn secfilter_rpc_adds_prints_counts_and_reloads() {
        let db = TextDb::new(&[("sf", "action(int) type(int) data(string)\n0:2:Evil.Example\n")]);
        let (_, reg) = secfilter(&db, false);
        assert_eq!(rpc(&reg, "secfilter.print", json!([])), Ok(json!([{"action": 0, "type": 2, "data": "evil.example"}])));
        for (cmd, params) in [
            ("secfilter.add_bl", json!(["ua", "BadUA"])),
            ("secfilter.add_bl", json!(["country", "xx"])),
            ("secfilter.add_wl", json!(["domain", "good.example"])),
            ("secfilter.add_wl", json!(["ip", "10.0.0.1"])),
            ("secfilter.add_bl", json!(["user", "mallory"])),
            ("secfilter.add_dst", json!(["0900"])),
        ] {
            assert_eq!(rpc(&reg, cmd, params.clone()), Ok(json!(0)), "{cmd} {params}");
        }
        assert!(rpc(&reg, "secfilter.add_bl", json!(["phone", "x"])).unwrap_err().contains("unknown type"));
        assert!(rpc(&reg, "secfilter.add_wl", json!(["ua"])).is_err(), "missing value");
        let rows = rpc(&reg, "secfilter.print", json!([])).unwrap();
        let rows: Vec<(i64, i64, &str)> =
            rows.as_array().unwrap().iter().map(|r| (r["action"].as_i64().unwrap(), r["type"].as_i64().unwrap(), r["data"].as_str().unwrap())).collect();
        assert_eq!(
            rows,
            [
                (0, T_DOMAIN, "evil.example"),
                (0, T_UA, "badua"),
                (0, T_COUNTRY, "xx"),
                (1, T_DOMAIN, "good.example"),
                (1, T_IP, "10.0.0.1"),
                (0, T_USER, "mallory"),
                (2, 0, "0900")
            ]
        );
        let req = request_with("INVITE", "sip:b@x", "User-Agent: BADUA\r\n");
        assert_eq!(call(&reg, "secf_check_ua", &[], &req).0, -2, "an added entry is used at once");
        assert_eq!(rpc(&reg, "secfilter.stats", json!([])), Ok(json!({"blocked": 1})));
        assert_eq!(rpc(&reg, "secfilter.reload", json!([])), Ok(json!(1)), "RPC additions are not kept");
        assert_eq!(call(&reg, "secf_check_ua", &[], &req).0, 1);
    }

    #[test]
    fn secfilter_without_its_table_fails_to_load() {
        let db = TextDb::new(&[]);
        let sf = Arc::new(SecFilter::default());
        sf.set_param("db_url", &s(&db.url())).unwrap();
        assert!(Registry::default().load(sf).is_err());
    }

    const USERS: &str = "username(string) domain(string) prefix(string) allowlist(int)\n\
alice:a.example:49:0\nalice:a.example:4930:1\nalice:b.example:33:0\nbob:a.example:1:0\n";
    const GLOBAL: &str = "prefix(string) allowlist(int)\n0900:0\n+0800:1\n";

    fn userblocklist(db: &TextDb, use_domain: bool) -> (Arc<UserBlocklist>, Registry) {
        let ub = Arc::new(UserBlocklist::default());
        ub.set_param("db_url", &s(&db.url())).unwrap();
        ub.set_param("use_domain", &Arg::Int(i64::from(use_domain))).unwrap();
        let mut reg = Registry::default();
        reg.load(ub.clone()).unwrap();
        (ub, reg)
    }

    fn tables() -> TextDb {
        TextDb::new(&[
            ("userblocklist", USERS),
            ("globalblocklist", GLOBAL),
            ("other", "prefix(string) allowlist(int)\n44:0\n4420:1\n"),
            ("mine", "username(string) domain(string) prefix(string) allowlist(int)\nalice:a.example:7:0\n"),
        ])
    }

    #[test]
    fn userblocklist_params() {
        let ub = UserBlocklist::default();
        assert!(ub.set_param("match_mode", &Arg::Int(128)).is_ok());
        assert!(ub.set_param("nope", &Arg::Int(1)).is_err());
        ub.set_param("userblocklist_table", &s("t1")).unwrap();
        ub.set_param("globalblocklist_table", &s("g1")).unwrap();
        assert_eq!((lock(&ub.table).as_str(), lock(&ub.global_table).as_str()), ("t1", "g1"));
    }

    #[test]
    fn check_user_lists() {
        let db = tables();
        let (_, reg) = userblocklist(&db, false);
        // (function, args, R-URI, rc)
        let cases: &[(&str, &[&str], &str, i32)] = &[
            ("check_user_blocklist", &["alice", "a.example"], "sip:4940@x", -1),
            ("check_user_blocklist", &["alice", "a.example"], "sip:4930123@x", 1),
            ("check_user_blocklist", &["alice", "a.example"], "sip:+33123@x", -1),
            ("check_user_blocklist", &["alice", "a.example", "+4940"], "sip:4930123@x", -1),
            ("check_user_blocklist", &["carol", "a.example", "4940"], "sip:b@x", 1),
            ("check_user_blocklist", &["alice", "a.example", "777", "mine"], "sip:b@x", -1),
            ("check_user_allowlist", &["alice", "a.example"], "sip:4930123@x", 1),
            ("check_user_allowlist", &["alice", "a.example"], "sip:4940@x", -1),
            ("check_user_allowlist", &["alice", "a.example", "555"], "sip:b@x", -1),
        ];
        for &(f, args, ruri, want) in cases {
            let a: Vec<Arg> = args.iter().map(|v| s(v)).collect();
            assert_eq!(call(&reg, f, &a, &request_with("INVITE", ruri, "")).0, want, "{f}{args:?} on {ruri}");
        }
        let fixup = &reg.get("check_user_blocklist").unwrap().fixup;
        assert!(fixup(&[s("alice")]).is_err());
        assert!(fixup(&[s("a"), s("b"), s("c"), s("d"), s("e")]).is_err());
    }

    #[test]
    fn use_domain_also_matches_the_domain() {
        let db = tables();
        let (_, reg) = userblocklist(&db, true);
        let block = |dom: &str, n: &str| call(&reg, "check_user_blocklist", &[s("alice"), s(dom), s(n)], &request("INVITE")).0;
        assert_eq!(block("a.example", "33"), 1, "the 33 entry is for b.example");
        assert_eq!(block("b.example", "33"), -1);
        assert_eq!(block("b.example", "4940"), 1);
    }

    #[test]
    fn check_global_lists() {
        let db = tables();
        let (_, reg) = userblocklist(&db, false);
        let cases: &[(&str, &[&str], &str, i32)] = &[
            ("check_blocklist", &[], "sip:0900123@x", -1),
            ("check_blocklist", &[], "sip:+0800123@x", 1),
            ("check_blocklist", &[], "sip:alice@x", 1),
            ("check_allowlist", &[], "sip:0800123@x", 1),
            ("check_allowlist", &[], "sip:0900123@x", -1),
            ("check_allowlist", &["globalblocklist"], "sip:0800@x", 1),
            ("check_blocklist", &["other"], "sip:44123@x", -1),
            ("check_blocklist", &["other"], "sip:0900123@x", 1),
            ("check_allowlist", &["other"], "sip:442012@x", 1),
            ("check_blocklist", &["missing"], "sip:0900@x", 1),
        ];
        for &(f, args, ruri, want) in cases {
            let a: Vec<Arg> = args.iter().map(|v| s(v)).collect();
            assert_eq!(call(&reg, f, &a, &request_with("INVITE", ruri, "")).0, want, "{f}{args:?} on {ruri}");
        }
        assert!((reg.get("check_blocklist").unwrap().fixup)(&[s("a"), s("b")]).is_err());
    }

    #[test]
    fn a_database_that_went_away_fails_blocklists_open_and_allowlists_closed() {
        let db = tables();
        let (_, reg) = userblocklist(&db, false);
        drop(db);
        let req = request_with("INVITE", "sip:0900@x", "");
        let user = [s("alice"), s("a.example"), s("4940")];
        assert_eq!(call(&reg, "check_user_blocklist", &user, &req).0, 1);
        assert_eq!(call(&reg, "check_user_allowlist", &[s("alice"), s("a.example"), s("4930")], &req).0, -1);
        assert_eq!(call(&reg, "check_blocklist", &[s("other")], &req).0, 1);
        assert_eq!(call(&reg, "check_blocklist", &[], &req).0, -1, "the cached global list still applies");
        assert!(rpc(&reg, "userblocklist.reload_blocklist", json!([])).is_err());
        assert_eq!(rpc(&reg, "userblocklist.check_blocklist", json!(["0900"])), Ok(json!("blocklisted")), "the cache is kept");
    }

    #[test]
    fn userblocklist_rpc() {
        let db = tables();
        let (_, reg) = userblocklist(&db, false);
        assert_eq!(
            rpc(&reg, "userblocklist.dump_blocklist", json!([])),
            Ok(json!([{"prefix": "0900", "allowlist": false}, {"prefix": "+0800", "allowlist": true}]))
        );
        for (n, want) in [("0900555", "blocklisted"), ("0800", "allowlisted"), ("+49", "not found")] {
            assert_eq!(rpc(&reg, "userblocklist.check_blocklist", json!([n])), Ok(json!(want)), "{n}");
        }
        assert!(rpc(&reg, "userblocklist.check_blocklist", json!([])).is_err());
        db.write("globalblocklist", "prefix(string) allowlist(int)\n49:0\n");
        assert_eq!(rpc(&reg, "userblocklist.reload_blocklist", json!([])), Ok(json!(1)));
        assert_eq!(rpc(&reg, "userblocklist.check_blocklist", json!(["0900"])), Ok(json!("not found")));
    }
}
