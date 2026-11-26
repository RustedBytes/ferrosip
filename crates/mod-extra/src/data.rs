//! Data-driven modules:
//! * `avpops` — AVPs from/to the `usr_preferences` table and AVP
//!   operations: `avp_db_load(source, name)`, `avp_db_store(source, name)`,
//!   `avp_db_delete(source, name)` (source: a URI variable like `$fu`;
//!   name: `$avp(x)` or `*`), `avp_delete(name)`, `avp_copy(src, dst)`,
//!   `avp_pushto("$ru"|"$du"|"$ru/username"|"$ru/domain", $avp(x))`,
//!   `avp_check($avp(x), "op/value")` (eq ne lt le gt ge re), `avp_print()`.
//! * `sqlops` — raw SQL (SQLite connections): `sql_query(con, query[,
//!   res])`, `sql_xquery(con, query, xavp)`, `sql_pvquery(con, query,
//!   "$var(a),$avp(b)")`, `sql_result_free(res)`, `$dbr(res=>rows|cols|
//!   [r,c]|colname[c])`; connections `modparam("sqlops", "sqlcon",
//!   "name=>sqlite:///file")`.
//! * `mtree` — prefix trees from tables (`tprefix`, `tvalue`):
//!   `modparam("mtree", "mtree", "name=gw;dbtable=mtree")`,
//!   `mt_match(tree, pv, mode)` (0 longest prefix, 1 all prefixes) into
//!   `pv_value` (`$avp(tvalue)`); RPC `mtree.reload`, `mtree.list`.
//! * `prefix_route` — `prefix_route([user])`: run `route[name]` of the
//!   longest matching prefix (table `prefix_route`: prefix, route); RPC
//!   `prefix_route.reload`, `prefix_route.dump`.
//! * `speeddial` — `sd_lookup(table[, owner])`: R-URI user is a speed-dial
//!   short code of the caller (`speed_dial`: username, domain,
//!   sd_username, sd_domain, new_uri) → new R-URI.

use crate::ruri_user;
use sip_core::module::{DynStr, rc};
use sip_core::pv::{FmtPart, PvRef, PvSpec, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::{Arg, Ctx, Module, Registry, RouteHub, TxnVars};
use sip_db::{DbConn, DbVal, Rows};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

fn db(url: &Mutex<Option<String>>, m: &str) -> Result<Arc<dyn DbConn>, String> {
    Ok(sip_db::connect(&lock(url).clone().unwrap_or_else(|| sip_db::default_url(m)))?)
}

/// `$avp(name)` → name; `*` stays.
fn avp_name(a: &Arg) -> Result<String, String> {
    let s = match a {
        Arg::Str(s) => s.clone(),
        Arg::Fmt(f) => f.single_pv().map(|p| format!("$avp({})", p.param.name)).ok_or("expected $avp(name)")?,
        Arg::Int(_) => return Err("expected $avp(name)".into()),
    };
    let s = s.trim();
    if s == "*" {
        return Ok("*".into());
    }
    let n = s.strip_prefix("$avp(").and_then(|x| x.strip_suffix(')')).ok_or_else(|| format!("expected $avp(name), got {s:?}"))?;
    Ok(n.trim_start_matches("s:").trim_start_matches("i:").to_string())
}

fn uri_parts(uri: &str) -> Option<(String, String)> {
    let u = sip_parser::parse_uri(uri.as_bytes())?;
    Some((String::from_utf8_lossy(u.user.unwrap_or(b"")).into_owned(), String::from_utf8_lossy(u.host).to_ascii_lowercase()))
}

// ------------------------------------------------------------------ avpops --

pub struct AvpOps {
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    use_domain: std::sync::atomic::AtomicBool,
}

impl Default for AvpOps {
    fn default() -> Self {
        Self { db_url: Mutex::new(None), table: Mutex::new("usr_preferences".into()), use_domain: std::sync::atomic::AtomicBool::new(false) }
    }
}

impl AvpOps {
    fn filter(&self, src: &str) -> Option<Vec<(&'static str, DbVal)>> {
        let (u, d) = uri_parts(src).or_else(|| Some((src.to_string(), String::new())))?;
        let mut f = vec![("username", DbVal::Str(u))];
        if self.use_domain.load(std::sync::atomic::Ordering::Relaxed) {
            f.push(("domain", DbVal::Str(d)));
        }
        Some(f)
    }

    fn load(&self, ctx: &mut Ctx<'_, '_>, src: &str, name: &str) -> i32 {
        let (Ok(db), Some(mut f)) = (db(&self.db_url, "avpops"), self.filter(src)) else { return -1 };
        if name != "*" {
            f.push(("attribute", DbVal::Str(name.into())));
        }
        let fr: Vec<(&str, DbVal)> = f.iter().map(|(k, v)| (*k, v.clone())).collect();
        let Ok(rows) = db.query(&lock(&self.table), &["attribute", "type", "value"], &fr) else { return -1 };
        if rows.rows.is_empty() {
            return -1;
        }
        let avps = &mut ctx.ext_mut::<TxnVars>().avps;
        for r in rows.rows {
            let [name, ty, value, ..] = r.as_slice() else { continue };
            // `type` is avpops' bit field (avpops_impl.c dbrow2avp): bit 0 an
            // integer value, bit 1 an integer name.
            let v = if ty.int().is_some_and(|t| t & 1 != 0) { Val::Int(value.int().unwrap_or(0)) } else { Val::Str(value.text()) };
            avps.entry(name.text()).or_default().push(v);
        }
        1
    }

    fn store(&self, ctx: &mut Ctx<'_, '_>, src: &str, name: &str) -> i32 {
        let Ok(db) = db(&self.db_url, "avpops") else { return -1 };
        let vals: Vec<(String, Val)> = match ctx.ext::<TxnVars>() {
            Some(t) => t.avps.iter().filter(|(k, _)| name == "*" || *k == name).flat_map(|(k, v)| v.iter().map(move |x| (k.clone(), x.clone()))).collect(),
            None => vec![],
        };
        if vals.is_empty() {
            return -1;
        }
        let table = lock(&self.table).clone();
        // Not a URI: the whole source is the user name (as in filter()).
        let (user, dom) = uri_parts(src).unwrap_or_else(|| (src.to_string(), String::new()));
        for (k, v) in vals {
            let (ty, val) = match v {
                Val::Int(i) => (1, i.to_string()),
                v => (0, v.as_str().into_owned()),
            };
            if db
                .insert(
                    &table,
                    &["uuid", "username", "domain", "attribute", "type", "value"],
                    &[DbVal::Str(String::new()), DbVal::Str(user.clone()), DbVal::Str(dom.clone()), DbVal::Str(k), DbVal::Int(ty), DbVal::Str(val)],
                )
                .is_err()
            {
                return -1;
            }
        }
        1
    }

    fn delete(&self, src: &str, name: &str) -> i32 {
        let (Ok(db), Some(mut f)) = (db(&self.db_url, "avpops"), self.filter(src)) else { return -1 };
        if name != "*" {
            f.push(("attribute", DbVal::Str(name.into())));
        }
        let fr: Vec<(&str, DbVal)> = f.iter().map(|(k, v)| (*k, v.clone())).collect();
        rc(db.delete(&lock(&self.table), &fr).is_ok_and(|n| n > 0))
    }
}

/// `avp_copy`'s flags.
#[derive(Clone, Copy, Default, Debug, PartialEq)]
struct CopyFlags {
    all: bool,
    delete: bool,
    to_int: bool,
    to_str: bool,
}

/// `avp_check`'s `op/value[/flags]` (Kamailio avpops parse_check_value):
/// the flags are the part after the last `/` when it is made of `g` (every
/// value, not just the newest) and `i` (case-insensitive `eq`/`ne`/`fm`),
/// so a regex value may itself contain `/`.
fn parse_check(spec: &str) -> Option<(&str, &str, bool, bool)> {
    let (op, rest) = spec.split_once('/')?;
    let (value, flags) = match rest.rsplit_once('/') {
        Some((v, f)) if !f.is_empty() && f.chars().all(|c| matches!(c, 'g' | 'G' | 'i' | 'I')) => (v, f),
        _ => (rest, ""),
    };
    let has = |c: char| flags.chars().any(|f| f.eq_ignore_ascii_case(&c));
    Some((op, value, has('g'), has('i')))
}

/// One avp_check comparison (Kamailio avpops_impl.c ops_check_avp): numbers
/// compare as numbers (`band`/`bor`/`bxor`: the bitwise result is non-zero);
/// strings with `eq`/`ne` case-sensitively unless `ci`, with `lt`…`ge`
/// always case-insensitively (strncasecmp), `re` always case-insensitively
/// (REG_ICASE), and `fm` as a glob, case-insensitive with `ci`.
fn check(v: &Val, op: &str, rhs: &str, ci: bool) -> bool {
    let a = v.as_str();
    let num = |s: &str| s.trim().parse::<i64>().ok();
    if let (Some(x), Some(y)) = (v.as_int().or_else(|| num(&a)), num(rhs)) {
        return match op {
            "eq" => x == y,
            "ne" => x != y,
            "lt" => x < y,
            "le" => x <= y,
            "gt" => x > y,
            "ge" => x >= y,
            "band" => x & y != 0,
            "bor" => x | y != 0,
            "bxor" => x ^ y != 0,
            _ => false,
        };
    }
    let fold = |s: &str| s.to_ascii_lowercase();
    match op {
        "eq" if ci => a.eq_ignore_ascii_case(rhs),
        "eq" => a == rhs,
        "ne" if ci => !a.eq_ignore_ascii_case(rhs),
        "ne" => a != rhs,
        "lt" => fold(&a) < fold(rhs),
        "le" => fold(&a) <= fold(rhs),
        "gt" => fold(&a) > fold(rhs),
        "ge" => fold(&a) >= fold(rhs),
        "re" => regex::RegexBuilder::new(rhs).case_insensitive(true).build().is_ok_and(|r| r.is_match(&a)),
        "fm" => glob(rhs.as_bytes(), a.as_bytes(), ci),
        _ => false,
    }
}

/// fnmatch(3) without flags: `*`, `?`, `[set]` / `[!set]` with ranges, and
/// `\` escaping the next character. Iterative (backtracks only to the last
/// `*`), so no input can recurse deeply or take exponential time.
fn glob(p: &[u8], s: &[u8], ci: bool) -> bool {
    let same = |a: u8, b: u8| if ci { a.eq_ignore_ascii_case(&b) } else { a == b };
    // One pattern element at `p[pi..]` against `c`: Some(width) when it matches.
    let one = |pi: usize, c: u8| -> Option<usize> {
        match p.get(pi..)? {
            [b'?', ..] => Some(1),
            [b'\\', e, ..] => same(*e, c).then_some(2),
            [b'[', rest @ ..] => {
                let (neg, body) = match rest {
                    [b'!' | b'^', tail @ ..] => (true, tail),
                    _ => (false, rest),
                };
                // `]` right after `[` or `[!` is a member, not the end.
                let close = body.iter().skip(1).position(|&b| b == b']').map(|i| i.saturating_add(1))?;
                let set = body.get(..close)?;
                let mut hit = false;
                let mut i = 0;
                while let Some(&lo) = set.get(i) {
                    if let (Some(b'-'), Some(&hi)) = (set.get(i.saturating_add(1)), set.get(i.saturating_add(2))) {
                        let (l, h, x) = if ci { (lo.to_ascii_lowercase(), hi.to_ascii_lowercase(), c.to_ascii_lowercase()) } else { (lo, hi, c) };
                        hit |= (l..=h).contains(&x);
                        i = i.saturating_add(3);
                    } else {
                        hit |= same(lo, c);
                        i = i.saturating_add(1);
                    }
                }
                // `[`, the optional `!`, the set, `]`.
                let width = close.saturating_add(usize::from(neg)).saturating_add(2);
                (hit != neg).then_some(width)
            }
            [x, ..] => same(*x, c).then_some(1),
            [] => None,
        }
    };
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (p.get(pi), s.get(si)) {
            (Some(b'*'), _) => {
                pi = pi.saturating_add(1);
                star = Some((pi, si));
            }
            (Some(_), Some(&c)) if let Some(w) = one(pi, c) => {
                pi = pi.saturating_add(w);
                si = si.saturating_add(1);
            }
            (None, None) => return true,
            _ => match star {
                Some((sp, ss)) if ss < s.len() => {
                    star = Some((sp, ss.saturating_add(1)));
                    pi = sp;
                    si = ss.saturating_add(1);
                }
                _ => return false,
            },
        }
    }
}

impl Module for AvpOps {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the AVP table (default: the module's default database)"),
            p("avp_table", Ty::Str, "usr_preferences", "Table AVPs are loaded from and stored to"),
            p("use_domain", Ty::Bool, "false", "Match the domain as well as the username"),
        ])
    }

    fn name(&self) -> &'static str {
        "avpops"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "avp_table" => *lock(&self.table) = v.str()?.into(),
            "use_domain" => self.use_domain.store(v.int()? != 0, std::sync::atomic::Ordering::Relaxed),
            "uuid_column" | "username_column" | "domain_column" | "attribute_column" | "value_column" | "type_column" | "db_scheme" => {}
            _ => return Err(format!("avpops: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{Ret, ctx, hidden, sig};
        const NO_AVPS: &str = "`.fsr` has no AVPs (its variables are typed locals): read usr_preferences with sql.query_value";
        Some(vec![
            hidden("avp_db_load", NO_AVPS),
            hidden("avp_db_store", NO_AVPS),
            hidden("avp_db_delete", NO_AVPS),
            hidden("avp_delete", "`.fsr` has no AVPs: assign the variable instead"),
            hidden("avp_copy", "`.fsr` has no AVPs: `let b = a`"),
            hidden("avp_pushto", "`.fsr` has no AVPs: assign msg.ruri / msg.duri"),
            hidden("avp_check", "`.fsr` has no AVPs: compare the variable (==, <, =~ …)"),
            sig("avp_print", "print", &[], Ret::Void, "Log every AVP of the message (debugging; `.fsr` locals included)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "avpops";
        let src_name = |a: &[Arg]| -> Result<(DynStr, String), String> {
            match a {
                [src, name] | [src, name, _] => Ok((src.dyn_str()?, avp_name(name)?)),
                _ => Err("expected source, name".into()),
            }
        };
        let me = self.clone();
        reg.export(m, "avp_db_load", src_name, move |ctx: &mut Ctx, (s, n): &(DynStr, String)| {
            let s = s.eval(ctx).into_owned();
            me.load(ctx, &s, n)
        });
        let me = self.clone();
        reg.export(m, "avp_db_store", src_name, move |ctx: &mut Ctx, (s, n): &(DynStr, String)| {
            let s = s.eval(ctx).into_owned();
            me.store(ctx, &s, n)
        });
        let me = self.clone();
        reg.export(m, "avp_db_delete", src_name, move |ctx: &mut Ctx, (s, n): &(DynStr, String)| {
            let s = s.eval(ctx).into_owned();
            me.delete(&s, n)
        });
        reg.export(
            m,
            "avp_delete",
            |a: &[Arg]| {
                let [name] = crate::fixed_args(a)?;
                avp_name(name)
            },
            |ctx: &mut Ctx, n: &String| {
                let avps = &mut ctx.ext_mut::<TxnVars>().avps;
                if n == "*" {
                    avps.clear();
                    1
                } else {
                    rc(avps.remove(n).is_some())
                }
            },
        );
        reg.export(
            m,
            "avp_copy",
            |a: &[Arg]| {
                let [src, dst_spec] = crate::fixed_args(a)?;
                // A script string with a variable (`"$avp(dst)/d"`) arrives
                // as a format: the variable, then the flags as a literal.
                let (dst, spec) = match dst_spec {
                    Arg::Str(s) => (s.split('/').next().unwrap_or("").to_string(), s.clone()),
                    Arg::Fmt(f) => match f.0.first() {
                        Some(FmtPart::Pv(p)) => (format!("$avp({})", p.param.name), f.literal()),
                        _ => return Err("expected \"$avp(dst)[/flags]\"".into()),
                    },
                    Arg::Int(_) => return Err("expected \"$avp(dst)[/flags]\"".into()),
                };
                // Flags after the `/` (Kamailio avpops.c fixup_copy_avp): g
                // every value, d delete what was copied, n/s cast to int/string.
                let mut f = CopyFlags::default();
                for c in spec.split_once('/').map_or("", |(_, fl)| fl).chars() {
                    match c.to_ascii_lowercase() {
                        'g' => f.all = true,
                        'd' => f.delete = true,
                        'n' => f.to_int = true,
                        's' => f.to_str = true,
                        _ => return Err(format!("avp_copy: bad flag {c:?} (g, d, n, s)")),
                    }
                }
                Ok((avp_name(src)?, avp_name(&Arg::Str(dst))?, f))
            },
            |ctx: &mut Ctx, (src, dst, f): &(String, String, CopyFlags)| {
                let avps = &mut ctx.ext_mut::<TxnVars>().avps;
                let Some(list) = avps.get_mut(src) else { return -1 };
                // Kamailio (avpops_impl.c ops_copy_avp): the newest value, or
                // with `g` all of them; `d` removes what was copied.
                let copied: Vec<Val> = match (f.all, f.delete) {
                    (true, true) => std::mem::take(list),
                    (true, false) => list.clone(),
                    (false, true) => list.pop().into_iter().collect(),
                    (false, false) => list.last().cloned().into_iter().collect(),
                };
                if list.is_empty() {
                    avps.remove(src);
                }
                if copied.is_empty() {
                    return -1;
                }
                let cast = |v: Val| match v {
                    Val::Str(s) if f.to_int => s.trim().parse::<i64>().map_or(Val::Str(s), Val::Int),
                    Val::Int(i) if f.to_str => Val::Str(i.to_string()),
                    v => v,
                };
                avps.entry(dst.clone()).or_default().extend(copied.into_iter().map(cast));
                1
            },
        );
        reg.export(
            m,
            "avp_pushto",
            |a: &[Arg]| {
                let [dest, src] = crate::fixed_args(a)?;
                let dest = match dest {
                    Arg::Str(s) => s.clone(),
                    // `"$ru/username"`: the variable, then the part as a literal.
                    Arg::Fmt(f) => match f.0.first() {
                        Some(FmtPart::Pv(p)) => format!("${}", p.name) + &f.literal(),
                        _ => String::new(),
                    },
                    Arg::Int(_) => String::new(),
                };
                Ok((dest, avp_name(src)?))
            },
            |ctx: &mut Ctx, (dest, n): &(String, String)| {
                let Some(v) = ctx.ext::<TxnVars>().and_then(|t| t.avps.get(n)).and_then(|l| l.last()).map(|v| v.as_str().into_owned()) else { return -1 };
                let ruri = String::from_utf8_lossy(ctx.ruri()).into_owned();
                match dest.as_str() {
                    "$ru" => ctx.new_ruri = Some(v.into_bytes()),
                    "$du" => match sip_core::pvcore::dest_from_uri(v.as_bytes()) {
                        Some(d) => ctx.dst = Some(d),
                        None => return -1,
                    },
                    "$ru/username" => match sip_core::pvcore::rebuild_uri(ruri.as_bytes(), Some(Some(&v)), None, None) {
                        Some(u) => ctx.new_ruri = Some(u),
                        None => return -1,
                    },
                    "$ru/domain" => match sip_core::pvcore::rebuild_uri(ruri.as_bytes(), None, Some(&v), None) {
                        Some(u) => ctx.new_ruri = Some(u),
                        None => return -1,
                    },
                    _ => return -1,
                }
                1
            },
        );
        reg.export(
            m,
            "avp_check",
            |a: &[Arg]| {
                let [name, spec] = crate::fixed_args(a)?;
                let spec = spec.dyn_str()?;
                Ok((avp_name(name)?, spec))
            },
            |ctx: &mut Ctx, (n, spec): &(String, DynStr)| {
                let spec = spec.eval(ctx).into_owned();
                let Some((op, rhs, all, ci)) = parse_check(&spec) else { return -1 };
                let Some(vals) = ctx.ext::<TxnVars>().and_then(|t| t.avps.get(n)) else { return -1 };
                // The newest value only (Kamailio's AVP lists are newest
                // first), or with `g` any of them.
                if all { rc(vals.iter().any(|v| check(v, op, rhs, ci))) } else { rc(vals.last().is_some_and(|v| check(v, op, rhs, ci))) }
            },
        );
        reg.export(
            m,
            "avp_print",
            |a: &[Arg]| sip_core::want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if let Some(t) = ctx.ext::<TxnVars>() {
                    for (k, v) in &t.avps {
                        sip_core::log::log(sip_core::log::L_INFO, &format!("avp {k} = {v:?}"));
                    }
                }
                1
            },
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ sqlops --

/// A statement for the `sql_query_async` thread.
type SqlJob = (Arc<dyn DbConn>, String);

/// Results of `sql_query()` for this message.
#[derive(Default)]
struct Results(HashMap<String, Rows>);

#[derive(Default)]
pub struct SqlOps {
    specs: Mutex<Vec<String>>,
    cons: OnceLock<HashMap<String, Arc<dyn DbConn>>>,
    /// `sql_query_async`: statements run on a background thread, in order.
    bg: OnceLock<Mutex<std::sync::mpsc::Sender<SqlJob>>>,
}

fn dbval(v: &DbVal) -> Val {
    match v {
        DbVal::Null => Val::Null,
        DbVal::Int(i) => Val::Int(*i),
        v => Val::Str(v.text()),
    }
}

impl SqlOps {
    fn con(&self, name: &str) -> Option<Arc<dyn DbConn>> {
        self.cons.get()?.get(name).cloned()
    }
}

impl Module for SqlOps {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("sqlcon", Ty::List(&Ty::Str), "", "Database connections, each \"name=>url\"")])
    }

    fn name(&self) -> &'static str {
        "sqlops"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "sqlcon" => lock(&self.specs).push(v.str()?.into()),
            "sqlres" | "tr_buf_size" | "connect_mode" | "results_maxsize" => {}
            _ => return Err(format!("sqlops: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const QUERY: &[Param] = &[arg("connection", Str).lit(), arg("query", Str), opt("result", Str).lit()];
        const ASYNC: &[Param] = &[arg("connection", Str).lit(), arg("query", Str)];
        const XQUERY: &[Param] = &[arg("connection", Str).lit(), arg("query", Str), arg("xavp", Str).lit()];
        const VALUE: &[Param] = &[arg("connection", Str).lit(), arg("query", Str), arg("into", Var)];
        const RESULT: &[Param] = &[arg("result", Str).lit()];
        Some(vec![
            sig("sql_query", "query", QUERY, Ret::Bool, "Run a statement on a `sqlcon` connection (rows kept as `result` for $dbr); false on error")
                .allowed(ctx::ANY),
            sig("sql_query_async", "query_async", ASYNC, Ret::Bool, "Queue a statement to run in the background (no result)").allowed(ctx::ANY),
            sig("sql_xquery", "xquery", XQUERY, Ret::Bool, "Run a query; its rows become items of $xavp(`xavp`)").allowed(ctx::ANY),
            sig("sql_pvquery", "query_value", VALUE, Ret::Bool, "Run a query; the first column of the first row goes into `into` (unchanged when no row)")
                .allowed(ctx::ANY),
            sig("sql_result_free", "free_result", RESULT, Ret::Void, "Drop the rows kept by sql.query(…, result)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let mut cons = HashMap::new();
        for s in lock(&self.specs).iter() {
            let (n, url) = s.split_once("=>").ok_or_else(|| format!("sqlops sqlcon {s:?}: expected name=>url"))?;
            cons.insert(n.trim().to_string(), sip_db::connect(url.trim())?);
        }
        let _ = self.cons.set(cons);
        let m = "sqlops";
        let me = self.clone();
        reg.export(
            m,
            "sql_query",
            |a: &[Arg]| -> Result<(String, DynStr, Option<String>), String> {
                let ([con, query] | [con, query, _]) = a else { return Err("expected con, query[, result]".into()) };
                Ok((con.str()?.to_string(), query.dyn_str()?, a.get(2).map(|r| r.str().map(String::from)).transpose()?))
            },
            move |ctx: &mut Ctx, (c, q, res): &(String, DynStr, Option<String>)| {
                let Some(con) = me.con(c) else { return -1 };
                let q = q.eval(ctx).into_owned();
                match con.raw(&q) {
                    Ok(rows) => {
                        let n = rows.rows.len();
                        if let Some(r) = res {
                            ctx.ext_mut::<Results>().0.insert(r.clone(), rows);
                        }
                        if n > 0 || !q.trim_start().to_ascii_lowercase().starts_with("select") { 1 } else { 2 }
                    }
                    Err(e) => {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("sql_query: {e}"));
                        -1
                    }
                }
            },
        );
        // sql_query_async(con, query): fire and forget (no result), e.g. CDR
        // or presence inserts off the SIP path.
        let me = self.clone();
        reg.export(
            m,
            "sql_query_async",
            |a: &[Arg]| {
                let [con, query] = crate::fixed_args(a)?;
                Ok((con.str()?.to_string(), query.dyn_str()?))
            },
            move |ctx: &mut Ctx, (c, q): &(String, DynStr)| {
                let Some(con) = me.con(c) else { return -1 };
                let q = q.eval(ctx).into_owned();
                let tx = me.bg.get_or_init(|| {
                    let (tx, rx) = std::sync::mpsc::channel::<SqlJob>();
                    // Without the thread, every send fails (-1).
                    let spawned = std::thread::Builder::new().name("sqlops-async".into()).spawn(move || {
                        for (con, q) in rx {
                            if let Err(e) = con.raw(&q) {
                                sip_core::log::log(sip_core::log::L_ERR, &format!("sql_query_async: {e}"));
                            }
                        }
                    });
                    if let Err(e) = spawned {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("sql_query_async: cannot start its thread: {e}"));
                    }
                    Mutex::new(tx)
                });
                if lock(tx).send((con, q)).is_ok() { 1 } else { -1 }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "sql_xquery",
            |a: &[Arg]| {
                let [con, query, xavp] = crate::fixed_args(a)?;
                Ok((con.str()?.to_string(), query.dyn_str()?, xavp.str()?.to_string()))
            },
            move |ctx: &mut Ctx, (c, q, x): &(String, DynStr, String)| {
                let Some(con) = me.con(c) else { return -1 };
                let q = q.eval(ctx).into_owned();
                let Ok(rows) = con.raw(&q) else { return -1 };
                let items: Vec<HashMap<String, Val>> = rows.rows.iter().map(|r| rows.cols.iter().cloned().zip(r.iter().map(dbval)).collect()).collect();
                let n = items.len();
                ctx.ext_mut::<TxnVars>().xavps.insert(x.clone(), items);
                if n > 0 { 1 } else { 2 }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "sql_pvquery",
            |a: &[Arg]| -> Result<(String, DynStr, Vec<PvRef>), String> {
                let [con, query, outs] = crate::fixed_args(a)?;
                // "$var(a),$avp(b)" arrives as a template: take its variables.
                let outs = match outs {
                    Arg::Fmt(f) => f.0.iter().filter_map(|p| if let sip_core::pv::FmtPart::Pv(r) = p { Some(r.clone()) } else { None }).collect(),
                    _ => return Err("expected a list of variables".into()),
                };
                Ok((con.str()?.to_string(), query.dyn_str()?, outs))
            },
            move |ctx: &mut Ctx, (c, q, outs): &(String, DynStr, Vec<PvRef>)| {
                let Some(con) = me.con(c) else { return -1 };
                let q = q.eval(ctx).into_owned();
                let Ok(rows) = con.raw(&q) else { return -1 };
                let Some(row) = rows.rows.first() else { return 2 };
                for (pv, v) in outs.iter().zip(row) {
                    let _ = pv.set(ctx, dbval(v));
                }
                1
            },
        );
        reg.export(
            m,
            "sql_result_free",
            |a: &[Arg]| {
                let [res] = crate::fixed_args(a)?;
                Ok(res.str()?.to_string())
            },
            |ctx: &mut Ctx, r: &String| {
                if let Some(x) = ctx.ext_get_mut::<Results>() {
                    x.0.remove(r);
                }
                1
            },
        );
        reg.pv(
            "dbr",
            PvSpec::ro(|ctx, p| {
                let Some((res, key)) = p.name.split_once("=>") else { return Val::Null };
                let Some(rows) = ctx.ext::<Results>().and_then(|r| r.0.get(res.trim())) else { return Val::Null };
                let key = key.trim();
                if key == "rows" {
                    return Val::Int(i64::try_from(rows.rows.len()).unwrap_or(i64::MAX));
                }
                if key == "cols" {
                    return Val::Int(i64::try_from(rows.cols.len()).unwrap_or(i64::MAX));
                }
                if let Some(i) = key.strip_prefix("colname[").and_then(|x| x.strip_suffix(']')) {
                    return i.trim().parse::<usize>().ok().and_then(|i| rows.cols.get(i)).map_or(Val::Null, Val::str);
                }
                if let Some(rc) = key.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                    let mut it = rc.split(',').map(|x| x.trim().parse::<usize>().ok());
                    if let (Some(Some(r)), Some(Some(c))) = (it.next(), it.next()) {
                        return rows.rows.get(r).and_then(|row| row.get(c)).map_or(Val::Null, dbval);
                    }
                }
                Val::Null
            })
            .with_param(),
        );
        Ok(())
    }
}

// ------------------------------------------------------------------- mtree --

/// (table, prefix → values)
type Tree = (String, BTreeMap<String, Vec<String>>);

#[derive(Default)]
pub struct MTree {
    db_url: Mutex<Option<String>>,
    specs: Mutex<Vec<String>>,
    pv_value: Mutex<String>,
    out: OnceLock<PvRef>,
    trees: RwLock<HashMap<String, Tree>>,
}

impl MTree {
    fn reload(&self) -> Result<usize, String> {
        let db = db(&self.db_url, "mtree")?;
        let mut trees = write(&self.trees);
        let mut n: usize = 0;
        for (table, map) in trees.values_mut() {
            map.clear();
            for r in db.query(table, &["tprefix", "tvalue"], &[])?.rows {
                let [prefix, value, ..] = r.as_slice() else { continue };
                map.entry(prefix.text()).or_default().push(value.text());
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    fn matches(&self, tree: &str, s: &str, all: bool) -> Vec<String> {
        let trees = read(&self.trees);
        let Some((_, map)) = trees.get(tree) else { return vec![] };
        let mut hits: Vec<(usize, Vec<String>)> = (1..=s.len()).filter_map(|l| s.get(..l)).filter_map(|p| map.get(p).map(|v| (p.len(), v.clone()))).collect();
        hits.sort_by_key(|h| std::cmp::Reverse(h.0));
        if all { hits.into_iter().flat_map(|h| h.1).collect() } else { hits.into_iter().next().map(|h| h.1).unwrap_or_default() }
    }
}

impl Module for MTree {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the tree tables (default: the module's default database)"),
            p("mtree", Ty::List(&Ty::Str), "", "Trees, each \"name=gw;dbtable=mtree\""),
            p("pv_value", Ty::Str, "$avp(tvalue)", "Variable mt_match() writes the matched values to"),
        ])
    }

    fn name(&self) -> &'static str {
        "mtree"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "mtree" => lock(&self.specs).push(v.str()?.into()),
            "pv_value" => *lock(&self.pv_value) = v.str()?.into(),
            "db_table"
            | "char_list"
            | "fetch_rows"
            | "pv_dstid"
            | "pv_weight"
            | "pv_count"
            | "mt_tree_type"
            | "mt_ignore_duplicates"
            | "mt_allow_duplicates"
            | "tprefix_column"
            | "tvalue_column" => {}
            _ => return Err(format!("mtree: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt_or, sig};
        const MATCH: &[Param] = &[arg("tree", Str), arg("value", Str), opt_or("mode", Int, "0").lit()];
        Some(vec![
            sig("mt_match", "lookup", MATCH, Ret::Bool, "Look `value` up in the tree (mode 0: longest prefix, 1: all prefixes); values into `pv_value`")
                .allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        {
            let mut t = write(&self.trees);
            for s in lock(&self.specs).iter() {
                let kv = crate::kv_list(s);
                let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
                let name = get("name").ok_or_else(|| format!("mtree {s:?}: name= is required"))?;
                t.insert(name, (get("dbtable").unwrap_or_else(|| "mtree".into()), BTreeMap::new()));
            }
        }
        self.reload()?;
        let pv = lock(&self.pv_value).clone();
        let _ = self.out.set(parse_pv(if pv.is_empty() { "$avp(tvalue)" } else { &pv }, reg.pvs())?);
        let me = self.clone();
        reg.export(
            "mtree",
            "mt_match",
            |a: &[Arg]| {
                let [tmpl, val, mode] = crate::fixed_args(a)?;
                Ok((tmpl.dyn_str()?, val.dyn_str()?, mode.int()?))
            },
            move |ctx: &mut Ctx, (t, v, mode): &(DynStr, DynStr, i64)| {
                let (t, v) = (t.eval(ctx).into_owned(), v.eval(ctx).into_owned());
                let hits = me.matches(&t, &v, *mode == 1);
                let Some(out) = me.out.get() else { return -1 };
                if hits.is_empty() {
                    return -1;
                }
                let _ = out.set(ctx, Val::Null);
                for h in hits.iter().rev() {
                    let _ = out.set(ctx, Val::Str(h.clone()));
                }
                1
            },
        );
        let me = self.clone();
        reg.rpc.add("mtree.reload", "Reload the trees", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("mtree.list", "mtree.list [tree]", move |p| {
            let want = sip_core::rpc::str_param(p, 0).ok();
            let t = read(&me.trees);
            Ok(json!(
                t.iter()
                    .filter(|(n, _)| want.as_ref().is_none_or(|w| w == *n))
                    .flat_map(|(n, (_, m))| m.iter().map(move |(p, v)| json!({"tree": n, "tprefix": p, "tvalue": v})))
                    .collect::<Vec<_>>()
            ))
        });
        let me = self.clone();
        reg.rpc.add("mtree.match", "mtree.match <tree> <value> [mode]", move |p| {
            let t = sip_core::rpc::str_param(p, 0)?;
            let v = sip_core::rpc::str_param(p, 1)?;
            Ok(json!(me.matches(&t, &v, sip_core::rpc::int_param(p, 2).unwrap_or(0) == 1)))
        });
        Ok(())
    }
}

// ------------------------------------------------------------ prefix_route --

#[derive(Default)]
pub struct PrefixRoute {
    db_url: Mutex<Option<String>>,
    table: Mutex<Option<String>>,
    map: RwLock<BTreeMap<String, String>>,
    hub: OnceLock<Arc<RouteHub>>,
}

impl PrefixRoute {
    fn reload(&self) -> Result<usize, String> {
        let db = db(&self.db_url, "prefix_route")?;
        let table = lock(&self.table).clone().unwrap_or_else(|| "prefix_route".into());
        let rows = db.query(&table, &["prefix", "route"], &[])?;
        let m: BTreeMap<String, String> = rows
            .rows
            .iter()
            .filter_map(|r| match r.as_slice() {
                [prefix, route, ..] => Some((prefix.text(), route.text())),
                _ => None,
            })
            .collect();
        let n = m.len();
        *write(&self.map) = m;
        Ok(n)
    }
}

impl Module for PrefixRoute {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the prefix table (default: the module's default database)"),
            p("db_table", Ty::Str, "prefix_route", "Table of prefixes and route names"),
        ])
    }

    fn name(&self) -> &'static str {
        "prefix_route"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "db_table" => *lock(&self.table) = Some(v.str()?.into()),
            "exit" => {}
            _ => return Err(format!("prefix_route: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, opt, sig};
        const USER: &[Param] = &[opt("user", Str)];
        Some(vec![sig("prefix_route", "run", USER, Ret::Bool, "Run the route of the longest prefix of `user` (default: the R-URI user) in the prefix table")])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.reload()?;
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        reg.export(
            "prefix_route",
            "prefix_route",
            |a: &[Arg]| -> Result<Option<DynStr>, String> {
                match a {
                    [] => Ok(None),
                    [user] => Ok(Some(user.dyn_str()?)),
                    _ => Err("expected [user]".into()),
                }
            },
            move |ctx: &mut Ctx, u: &Option<DynStr>| {
                let user = match u {
                    Some(u) => u.eval(ctx).into_owned(),
                    None => ruri_user(ctx),
                };
                let route = {
                    let m = read(&me.map);
                    (0..=user.len()).rev().filter_map(|l| user.get(..l)).find_map(|p| m.get(p).cloned())
                };
                let Some(route) = route else { return -1 };
                let Some(runner) = me.hub.get().and_then(|h| h.runner()) else { return -1 };
                match runner.route_index(&route) {
                    Some(i) => runner.run_route(i, ctx),
                    None => {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("prefix_route: no route[{route}] in the script"));
                        -1
                    }
                }
            },
        );
        let me = self.clone();
        reg.rpc.add("prefix_route.reload", "Reload the prefix table", move |_| me.reload().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("prefix_route.dump", "Prefixes and routes", move |_| Ok(json!(*read(&me.map))));
        Ok(())
    }
}

// --------------------------------------------------------------- speeddial --

#[derive(Default)]
pub struct SpeedDial {
    db_url: Mutex<Option<String>>,
    use_domain: std::sync::atomic::AtomicBool,
}

impl Module for SpeedDial {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the speed-dial tables (default: the module's default database)"),
            p("use_domain", Ty::Bool, "false", "Match the caller's domain as well as the username"),
        ])
    }

    fn name(&self) -> &'static str {
        "speeddial"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "use_domain" => self.use_domain.store(v.int()? != 0, std::sync::atomic::Ordering::Relaxed),
            "user_column" | "domain_column" | "sd_user_column" | "sd_domain_column" | "new_uri_column" | "domain_prefix" => {}
            _ => return Err(format!("speeddial: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, ctx, opt, opt_or, sig};
        const LOOKUP: &[Param] = &[opt_or("table", Str, "speed_dial"), opt("owner", Uri)];
        Some(vec![
            sig("sd_lookup", "lookup", LOOKUP, Ret::Bool, "The R-URI user is a speed-dial code of `owner` (default: the caller): rewrite the R-URI")
                .allowed(ctx::REQUEST),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        db(&self.db_url, "speeddial")?;
        let me = self.clone();
        reg.export(
            "speeddial",
            "sd_lookup",
            |a: &[Arg]| match a {
                [table] => Ok((table.dyn_str()?, None)),
                [table, owner] => Ok((table.dyn_str()?, Some(owner.dyn_str()?))),
                _ => Err("expected table[, owner]".into()),
            },
            move |ctx: &mut Ctx, (t, owner): &(DynStr, Option<DynStr>)| {
                let Ok(db) = db(&me.db_url, "speeddial") else { return -1 };
                let table = t.eval(ctx).into_owned();
                let owner = match owner {
                    Some(o) => o.eval(ctx).into_owned(),
                    None => {
                        let _ = ctx.msg.parse_headers(sip_parser::HdrFlags::EOH);
                        ctx.msg
                            .get(sip_parser::HdrKind::From)
                            .map(|h| String::from_utf8_lossy(sip_parser::uri::name_addr(h.body).0).into_owned())
                            .unwrap_or_default()
                    }
                };
                let Some((ou, od)) = uri_parts(&owner) else { return -1 };
                let sd = ruri_user(ctx);
                let mut f = vec![("username", DbVal::Str(ou)), ("sd_username", DbVal::Str(sd))];
                if me.use_domain.load(std::sync::atomic::Ordering::Relaxed) {
                    f.push(("domain", DbVal::Str(od)));
                }
                let fr: Vec<(&str, DbVal)> = f.iter().map(|(k, v)| (*k, v.clone())).collect();
                match db.query(&table, &["new_uri"], &fr).ok().and_then(|r| r.rows.into_iter().next()).and_then(|r| r.into_iter().next()) {
                    Some(new_uri) => {
                        ctx.new_ruri = Some(new_uri.text().into_bytes());
                        1
                    }
                    None => -1,
                }
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{Dest, Lumps, Outbound, Proto};

    fn tree(entries: &[(&str, &[&str])]) -> MTree {
        let t = MTree::default();
        let map = entries.iter().map(|(p, v)| (p.to_string(), v.iter().map(|x| x.to_string()).collect())).collect();
        write(&t.trees).insert("gw".into(), ("mtree".into(), map));
        t
    }

    #[test]
    fn mtree_longest_prefix_and_all_prefixes() {
        let t = tree(&[("4", &["any"]), ("49", &["de"]), ("4930", &["berlin", "berlin2"]), ("1", &["us"])]);
        let cases: &[(&str, bool, &[&str])] = &[
            ("4930123", false, &["berlin", "berlin2"]),
            ("4930123", true, &["berlin", "berlin2", "de", "any"]),
            ("4989", false, &["de"]),
            ("4989", true, &["de", "any"]),
            ("49", false, &["de"]),
            ("4", false, &["any"]),
            ("1", true, &["us"]),
            ("2", false, &[]),
            ("2", true, &[]),
            ("", false, &[]),
            ("+4930", false, &[]),
        ];
        for &(s, all, want) in cases {
            assert_eq!(t.matches("gw", s, all), want, "{s:?} all={all}");
        }
        assert!(t.matches("nope", "4930", false).is_empty(), "unknown tree");
    }

    #[test]
    fn mtree_prefix_matching_is_byte_exact_and_utf8_safe() {
        let t = tree(&[("ab", &["x"]), ("é", &["e-acute"])]);
        assert!(t.matches("gw", "AB", false).is_empty(), "case-sensitive");
        assert_eq!(t.matches("gw", "éa", false), ["e-acute"]);
        assert_eq!(t.matches("gw", "abé", false), ["x"]);
    }

    #[test]
    fn avp_name_accepts_avp_specs_and_star() {
        let cases: &[(&str, Option<&str>)] = &[
            ("$avp(x)", Some("x")),
            ("  $avp(s:name) ", Some("name")),
            ("$avp(i:5)", Some("5")),
            ("*", Some("*")),
            (" * ", Some("*")),
            ("$var(x)", None),
            ("x", None),
            ("$avp(x", None),
        ];
        for &(s, want) in cases {
            assert_eq!(avp_name(&Arg::Str(s.into())).ok().as_deref(), want, "{s:?}");
        }
        assert!(avp_name(&Arg::Int(1)).is_err());
    }

    #[test]
    fn uri_parts_lowercases_the_domain_only() {
        let cases: &[(&str, Option<(&str, &str)>)] = &[
            ("sip:Alice@Example.COM", Some(("Alice", "example.com"))),
            ("sip:example.com", Some(("", "example.com"))),
            ("sips:bob@h:5061;transport=tls", Some(("bob", "h"))),
            ("alice", None),
        ];
        for &(s, want) in cases {
            let got = uri_parts(s);
            assert_eq!(got.as_ref().map(|(u, d)| (u.as_str(), d.as_str())), want, "{s:?}");
        }
    }

    #[test]
    fn avp_check_operators() {
        let i = Val::Int;
        let s = |x: &str| Val::Str(x.into());
        let cases: &[(Val, &str, &str, bool)] = &[
            (i(5), "eq", "5", true),
            (i(5), "ne", "5", false),
            (i(5), "gt", "3", true),
            (i(5), "gt", "5", false),
            (i(5), "ge", "5", true),
            (i(5), "lt", "10", true),
            (i(5), "le", "4", false),
            (s("10"), "gt", "9", true),
            (s(" 7 "), "eq", "7", true),
            (s("abc"), "lt", "abd", true),
            (s("10"), "lt", "9x", true),
            (s("abc"), "eq", "abc", true),
            (s("abc"), "eq", "ABC", false),
            (s("sip:alice@x"), "re", "^sip:al", true),
            (s("sip:alice@x"), "re", "^tel:", false),
            (s("x"), "re", "(", false),
            (i(5), "xx", "5", false),
            (Val::Null, "eq", "", true),
            // Kamailio: ordering and regexes ignore case; eq/ne only with `i`.
            (s("ABC"), "lt", "abd", true),
            (s("Sip:Alice@X"), "re", "^sip:al", true),
            // Bitwise ops on numbers: true when the result is non-zero.
            (i(6), "band", "2", true),
            (i(4), "band", "2", false),
            (i(0), "bor", "0", false),
            (i(5), "bxor", "5", false),
            (i(5), "bxor", "4", true),
            // fm: a glob.
            (s("sip:alice@x"), "fm", "sip:*@?", true),
            (s("sip:alice@x"), "fm", "sip:[a-c]lice@x", true),
            (s("sip:alice@x"), "fm", "sip:[!a]lice@x", false),
            (s("SIP:alice@x"), "fm", "sip:*", false),
        ];
        for (v, op, rhs, want) in cases {
            assert_eq!(check(v, op, rhs, false), *want, "{v:?} {op} {rhs:?}");
        }
        // `i`: eq/ne and fm become case-insensitive.
        assert!(check(&s("abc"), "eq", "ABC", true));
        assert!(!check(&s("abc"), "ne", "ABC", true));
        assert!(check(&s("SIP:alice@x"), "fm", "sip:*", true));
    }

    #[test]
    fn avp_check_flags_follow_the_last_slash() {
        assert_eq!(parse_check("eq/5"), Some(("eq", "5", false, false)));
        assert_eq!(parse_check("eq/abc/gi"), Some(("eq", "abc", true, true)));
        assert_eq!(parse_check("re/^a/b$/I"), Some(("re", "^a/b$", false, true)), "a / inside the regex");
        assert_eq!(parse_check("re/^a/b$"), Some(("re", "^a/b$", false, false)), "b$ isn't flags");
        assert_eq!(parse_check("nonsense"), None);
    }

    #[test]
    fn glob_is_iterative_and_handles_classes() {
        assert!(glob(b"*", b"", false));
        assert!(glob(b"a*b*c", b"aXXbYYc", false));
        assert!(!glob(b"a*b*c", b"aXXbYY", false));
        assert!(glob(b"[]x]", b"]", false), "] first in a class is a member");
        assert!(glob(b"\\*", b"*", false) && !glob(b"\\*", b"x", false));
        assert!(!glob(b"[abc", b"a", false), "an unclosed class matches nothing");
        // Pathological for a backtracking matcher: stays fast.
        let pat = [b"*a".repeat(30), b"b".to_vec()].concat();
        assert!(!glob(&pat, &b"a".repeat(5000), false));
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

    fn registry() -> Registry {
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        reg.load(Arc::new(AvpOps::default())).unwrap();
        reg
    }

    /// A script argument as the script compiler builds it.
    fn arg(reg: &Registry, s: &str) -> Arg {
        let f = sip_core::pv::parse_fmt(s, reg.pvs()).unwrap();
        if f.has_pv() { Arg::Fmt(Arc::new(f)) } else { Arg::Str(f.literal()) }
    }

    /// Runs the exported function `name` with `args` on a request whose
    /// AVPs are `avps`; returns its result, the AVPs and the new R-URI.
    /// (return code, AVPs after the call, new R-URI)
    type Outcome = (i32, BTreeMap<String, Vec<Val>>, Option<String>);

    fn run(name: &str, args: &[&str], avps: &[(&str, &[Val])]) -> Result<Outcome, String> {
        let reg = registry();
        let e = reg.get(name).unwrap();
        let args: Vec<Arg> = args.iter().map(|a| arg(&reg, a)).collect();
        let fixed = (e.fixup)(&args)?;
        let req = b"INVITE sip:bob@example.com;transport=tcp SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nCall-ID: c\r\n\r\n";
        let arena = bumpalo::Bump::new();
        let mut msg = sip_parser::Msg::parse(req, &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, std::net::SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        for (k, v) in avps {
            ctx.ext_mut::<TxnVars>().avps.insert(k.to_string(), v.to_vec());
        }
        let rc = (e.func)(&mut ctx, &*fixed);
        let avps =
            ctx.ext::<TxnVars>().map(|t| t.avps.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default();
        Ok((rc, avps, ctx.new_ruri.map(|u| String::from_utf8_lossy(&u).into_owned())))
    }

    fn map(entries: &[(&str, &[Val])]) -> BTreeMap<String, Vec<Val>> {
        entries.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()
    }

    #[test]
    fn avp_copy_flags_follow_kamailio() {
        let two = || Val::Str("two".into());
        let a: &[Val] = &[Val::Int(1), two()]; // "two" is the newest
        let b: &[Val] = &[Val::Int(0)];
        // No flags: only the newest value.
        let (rc, avps, _) = run("avp_copy", &["$avp(a)", "$avp(b)"], &[("a", a), ("b", b)]).unwrap();
        assert_eq!((rc, avps), (1, map(&[("a", a), ("b", &[Val::Int(0), two()])])));
        // g: every value.
        let (_, avps, _) = run("avp_copy", &["$avp(a)", "$avp(b)/g"], &[("a", a)]).unwrap();
        assert_eq!(avps, map(&[("a", a), ("b", a)]));
        // d: the copied (newest) value leaves the source.
        let (_, avps, _) = run("avp_copy", &["$avp(a)", "$avp(b)/d"], &[("a", a)]).unwrap();
        assert_eq!(avps, map(&[("a", &[Val::Int(1)]), ("b", &[two()])]));
        // gd (any order, any case): all copied, the source gone.
        for f in ["gd", "DG"] {
            let (_, avps, _) = run("avp_copy", &["$avp(a)", &format!("$avp(b)/{f}")], &[("a", a)]).unwrap();
            assert_eq!(avps, map(&[("b", a)]), "{f}");
        }
        // n / s: casts.
        let nums: &[Val] = &[Val::Str("42".into())];
        let (_, avps, _) = run("avp_copy", &["$avp(a)", "$avp(b)/n"], &[("a", nums)]).unwrap();
        assert_eq!(avps.get("b"), Some(&vec![Val::Int(42)]));
        let (_, avps, _) = run("avp_copy", &["$avp(a)", "$avp(b)/s"], &[("a", &[Val::Int(7)])]).unwrap();
        assert_eq!(avps.get("b"), Some(&vec![Val::Str("7".into())]));
        // Errors.
        assert_eq!(run("avp_copy", &["$avp(none)", "$avp(b)"], &[]).unwrap().0, -1, "a missing source");
        assert!(run("avp_copy", &["$avp(a)", "$avp(b)/x"], &[]).is_err(), "unknown flag");
        assert!(run("avp_copy", &["$avp(a)", "nonsense"], &[]).is_err());
    }

    #[test]
    fn avp_delete_one_or_all() {
        let v: &[Val] = &[Val::Int(1)];
        let (rc, avps, _) = run("avp_delete", &["$avp(a)"], &[("a", v), ("b", v)]).unwrap();
        assert_eq!((rc, avps), (1, map(&[("b", v)])));
        let (rc, avps, _) = run("avp_delete", &["*"], &[("a", v), ("b", v)]).unwrap();
        assert_eq!((rc, avps), (1, map(&[])));
        let (rc, _, _) = run("avp_delete", &["$avp(none)"], &[("a", v)]).unwrap();
        assert_eq!(rc, -1);
    }

    #[test]
    fn avp_check_checks_the_newest_value_or_all_with_g() {
        // Values in insertion order: 7 is the newest (Kamailio's "first").
        let v: &[Val] = &[Val::Int(2), Val::Int(7)];
        let cases: &[(&str, i32)] =
            &[("gt/5", 1), ("eq/2", -1), ("eq/2/g", 1), ("gt/7/g", -1), ("re/^7$", 1), ("re/^2$", -1), ("re/^2$/g", 1), ("re/^x/i", -1), ("nonsense", -1)];
        for &(spec, want) in cases {
            assert_eq!(run("avp_check", &["$avp(n)", spec], &[("n", v)]).unwrap().0, want, "{spec}");
        }
        assert_eq!(run("avp_check", &["$avp(none)", "eq/2"], &[("n", v)]).unwrap().0, -1);
    }

    #[test]
    fn avp_pushto_rewrites_the_request_uri_or_its_parts() {
        let uri: &[Val] = &[Val::Str("sip:first@a".into()), Val::Str("sip:carol@c.example".into())];
        let user: &[Val] = &[Val::Str("dave".into())];
        let host: &[Val] = &[Val::Str("d.example".into())];
        let cases: &[(&str, &[Val], Option<&str>)] = &[
            ("$ru", uri, Some("sip:carol@c.example")),
            ("$ru/username", user, Some("sip:dave@example.com;transport=tcp")),
            ("$ru/domain", host, Some("sip:bob@d.example;transport=tcp")),
        ];
        for &(dest, v, want) in cases {
            let (rc, _, ruri) = run("avp_pushto", &[dest, "$avp(x)"], &[("x", v)]).unwrap();
            assert_eq!((rc, ruri.as_deref()), (1, want), "{dest}");
        }
        assert_eq!(run("avp_pushto", &["$ru", "$avp(none)"], &[]).unwrap().0, -1);
        assert_eq!(run("avp_pushto", &["$fu", "$avp(x)"], &[("x", user)]).unwrap().0, -1, "not a destination");
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::testutil::{FakeNet, TempFile, arg, call, call_args, fixup, invite, pv, registry, rpc, with_ctx};
    use sip_core::RouteRunner;
    use sip_core::serde_json::json;

    const PREFS: &str = "CREATE TABLE usr_preferences (uuid TEXT, username TEXT, domain TEXT, attribute TEXT, type INTEGER, value TEXT)";

    /// An avpops registry on a fresh database with the usr_preferences table.
    fn avpops(use_domain: bool) -> (TempFile, Registry) {
        let f = TempFile::new("avp");
        f.sql(PREFS);
        let m = AvpOps::default();
        m.set_param("db_url", &Arg::Str(f.url())).unwrap();
        m.set_param("use_domain", &Arg::Int(i64::from(use_domain))).unwrap();
        (f, registry(vec![Arc::new(m)]))
    }

    fn set_avps(ctx: &mut Ctx<'_, '_>, avps: &[(&str, &[Val])]) {
        for (k, v) in avps {
            ctx.ext_mut::<TxnVars>().avps.insert(k.to_string(), v.to_vec());
        }
    }

    fn avps(ctx: &Ctx<'_, '_>) -> BTreeMap<String, Vec<Val>> {
        ctx.ext::<TxnVars>().map(|t| t.avps.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default()
    }

    /// The table's rows as text, sorted.
    fn rows(f: &TempFile) -> Vec<String> {
        let mut v: Vec<String> = f
            .sql("SELECT username, domain, attribute, type, value FROM usr_preferences")
            .rows
            .iter()
            .map(|r| r.iter().map(DbVal::text).collect::<Vec<_>>().join("|"))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn avp_check_string_ordering_ignores_case() {
        let s = |x: &str| Val::Str(x.into());
        let cases: &[(&str, &str, &str, bool, bool)] = &[
            ("abc", "ne", "ABC", true, false),
            ("abc", "ne", "abd", true, true),
            ("ABC", "le", "abc", false, true),
            ("abd", "le", "ABC", false, false),
            ("B", "gt", "a", false, true),
            ("a", "gt", "B", false, false),
            ("Abc", "ge", "abc", false, true),
            ("abc", "ge", "abd", false, false),
            ("abc", "band", "1", false, false),
            ("abc", "", "abc", false, false),
        ];
        for &(v, op, rhs, ci, want) in cases {
            assert_eq!(check(&s(v), op, rhs, ci), want, "{v:?} {op} {rhs:?} ci={ci}");
        }
    }

    #[test]
    fn avpops_parameters() {
        let m = AvpOps::default();
        for ok in ["uuid_column", "db_scheme", "avp_table"] {
            assert!(m.set_param(ok, &Arg::Str("x".into())).is_ok(), "{ok}");
        }
        assert!(m.set_param("nope", &Arg::Str("x".into())).is_err());
    }

    #[test]
    fn avp_db_store_writes_typed_rows_for_the_uri_owner() {
        let (f, reg) = avpops(false);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "avp_db_store", &["sip:Alice@Example.COM", "$avp(x)"]).unwrap(), -1, "no AVPs at all");
            set_avps(ctx, &[("x", &[Val::Int(5), Val::Str("a".into())]), ("y", &[Val::Str("b".into())])]);
            assert_eq!(call(&reg, ctx, "avp_db_store", &["sip:Alice@Example.COM", "$avp(x)"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "avp_db_store", &["sip:Alice@Example.COM", "$avp(none)"]).unwrap(), -1);
            assert_eq!(call(&reg, ctx, "avp_db_store", &["carol", "*"]).unwrap(), 1, "not a URI: the whole source is the user");
        });
        assert_eq!(rows(&f), ["Alice|example.com|x|0|a", "Alice|example.com|x|1|5", "carol||x|0|a", "carol||x|1|5", "carol||y|0|b"]);
    }

    #[test]
    fn avp_db_store_fails_when_the_insert_fails() {
        let (f, reg) = avpops(false);
        f.sql("DROP TABLE usr_preferences");
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            set_avps(ctx, &[("x", &[Val::Int(1)])]);
            assert_eq!(call(&reg, ctx, "avp_db_store", &["sip:a@b", "$avp(x)"]).unwrap(), -1);
            assert_eq!(call(&reg, ctx, "avp_db_load", &["sip:a@b", "$avp(x)"]).unwrap(), -1, "the query fails too");
        });
    }

    #[test]
    fn avp_db_load_reads_one_or_all_attributes() {
        let (f, reg) = avpops(false);
        f.sql(
            "INSERT INTO usr_preferences VALUES ('', 'alice', 'a.example', 'x', 1, '42'), ('', 'alice', 'b.example', 'y', 0, 'str'), \
             ('', 'alice', 'a.example', 'n', 1, 'NaN'), ('', 'bob', 'a.example', 'x', 1, '7'), \
             ('', 'carol', 'a.example', 'i', 3, '9'), ('', 'carol', 'a.example', 's', 2, '9')",
        );
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "avp_db_load", &["sip:alice@a.example", "$avp(x)"]).unwrap(), 1);
            assert_eq!(avps(ctx), BTreeMap::from([("x".to_string(), vec![Val::Int(42)])]));
            assert_eq!(call(&reg, ctx, "avp_db_load", &["sip:alice@a.example", "$avp(none)"]).unwrap(), -1, "no row");
            assert_eq!(call(&reg, ctx, "avp_db_load", &["alice", "*"]).unwrap(), 1, "a bare user name, every attribute");
            let got = avps(ctx);
            assert_eq!(got["x"], [Val::Int(42), Val::Int(42)]);
            assert_eq!(got["y"], [Val::Str("str".into())]);
            assert_eq!(got["n"], [Val::Int(0)], "an int-typed value that isn't a number reads 0");
            // type is a bit field: 3 (int name, int value) is an integer, 2 (int name) a string.
            assert_eq!(call(&reg, ctx, "avp_db_load", &["carol", "*"]).unwrap(), 1);
            let got = avps(ctx);
            assert_eq!((&got["i"], &got["s"]), (&vec![Val::Int(9)], &vec![Val::Str("9".into())]));
        });
    }

    #[test]
    fn avp_db_load_and_delete_match_the_domain_with_use_domain() {
        let (f, reg) = avpops(true);
        f.sql("INSERT INTO usr_preferences VALUES ('', 'alice', 'a.example', 'x', 0, 'a'), ('', 'alice', 'b.example', 'x', 0, 'b')");
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "avp_db_load", &["sip:alice@B.example", "$avp(x)"]).unwrap(), 1);
            assert_eq!(avps(ctx)["x"], [Val::Str("b".into())]);
            assert_eq!(call(&reg, ctx, "avp_db_delete", &["sip:alice@b.example", "*"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "avp_db_delete", &["sip:alice@b.example", "*"]).unwrap(), -1, "nothing left to delete");
        });
        assert_eq!(rows(&f), ["alice|a.example|x|0|a"]);
    }

    #[test]
    fn avp_db_delete_removes_one_attribute() {
        let (f, reg) = avpops(false);
        f.sql("INSERT INTO usr_preferences VALUES ('', 'alice', '', 'x', 0, 'a'), ('', 'alice', '', 'y', 0, 'b')");
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "avp_db_delete", &["sip:alice@h", "$avp(x)"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "avp_db_delete", &["sip:alice@h", "$avp(x)"]).unwrap(), -1);
        });
        assert_eq!(rows(&f), ["alice||y|0|b"]);
    }

    #[test]
    fn avp_db_functions_need_a_source_and_a_name() {
        let reg = registry(vec![Arc::new(AvpOps::default())]);
        let s = |x: &str| Arg::Str(x.into());
        assert!(fixup(&reg, "avp_db_load", &[s("$fu")]).is_err());
        assert!(fixup(&reg, "avp_db_load", &[s("$fu"), s("$avp(x)"), s("x"), s("y")]).is_err());
        assert!(fixup(&reg, "avp_db_load", &[s("$fu"), s("$avp(x)"), s("ignored")]).is_ok());
        assert!(fixup(&reg, "avp_db_store", &[s("$fu"), s("x")]).is_err(), "not an AVP");
    }

    #[test]
    fn avp_copy_and_pushto_refuse_bad_arguments() {
        let reg = registry(vec![Arc::new(AvpOps::default())]);
        let a = arg(&reg, "$avp(a)");
        assert!(fixup(&reg, "avp_copy", &[a.clone(), Arg::Int(1)]).is_err());
        assert!(fixup(&reg, "avp_copy", &[a.clone(), arg(&reg, "x$avp(b)")]).is_err(), "the variable must come first");
        // A destination that is no variable: accepted, the call fails.
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            set_avps(ctx, &[("x", &[Val::Str("sip:c@d".into())])]);
            let x = arg(&reg, "$avp(x)");
            for dest in [Arg::Int(1), arg(&reg, "x$ru"), Arg::Str("$tu".into())] {
                assert_eq!(call_args(&reg, ctx, "avp_pushto", &[dest.clone(), x.clone()]).unwrap(), -1, "{dest:?}");
            }
            assert_eq!(call_args(&reg, ctx, "avp_pushto", &[Arg::Str("$ru".into()), x]).unwrap(), 1, "a plain string destination");
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:c@d"[..]));
        });
    }

    #[test]
    fn avp_copy_of_an_empty_list_fails_and_drops_it() {
        let reg = registry(vec![Arc::new(AvpOps::default())]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            set_avps(ctx, &[("a", &[])]);
            assert_eq!(call(&reg, ctx, "avp_copy", &["$avp(a)", "$avp(b)"]).unwrap(), -1);
            assert!(avps(ctx).is_empty());
        });
    }

    #[test]
    fn avp_pushto_du_sets_the_destination() {
        let reg = registry(vec![Arc::new(AvpOps::default())]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            set_avps(ctx, &[("d", &[Val::Str("sip:192.0.2.9:5080;transport=tcp".into())]), ("bad", &[Val::Str("nonsense".into())])]);
            assert_eq!(call(&reg, ctx, "avp_pushto", &["$du", "$avp(bad)"]).unwrap(), -1);
            assert!(ctx.dst.is_none());
            assert_eq!(call(&reg, ctx, "avp_pushto", &["$du", "$avp(d)"]).unwrap(), 1);
            let d = ctx.dst.unwrap();
            assert_eq!((d.proto, d.addr), (sip_core::Proto::Tcp, "192.0.2.9:5080".parse().unwrap()));
        });
    }

    #[test]
    fn avp_print_is_always_true() {
        let reg = registry(vec![Arc::new(AvpOps::default())]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "avp_print", &[]).unwrap(), 1, "no AVPs");
            set_avps(ctx, &[("a", &[Val::Int(1)])]);
            assert_eq!(call(&reg, ctx, "avp_print", &[]).unwrap(), 1);
            assert!(call(&reg, ctx, "avp_print", &["x"]).is_err());
        });
    }

    // ------------------------------------------------------------ sqlops --

    fn sqlops() -> Registry {
        let m = SqlOps::default();
        m.set_param("sqlcon", &Arg::Str("c => sqlite::memory:".into())).unwrap();
        let reg = registry(vec![Arc::new(m)]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sql_query", &["c", "CREATE TABLE t (id INTEGER, name TEXT, n INTEGER)"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "sql_query", &["c", "INSERT INTO t VALUES (1, 'one', NULL), (2, 'two', 7)"]).unwrap(), 1);
        });
        reg
    }

    #[test]
    fn sqlops_parameters_and_connection_specs() {
        let m = SqlOps::default();
        assert!(m.set_param("sqlres", &Arg::Str("r".into())).is_ok());
        assert!(m.set_param("results_maxsize", &Arg::Int(1)).is_ok());
        assert!(m.set_param("nope", &Arg::Str("x".into())).is_err());
        m.set_param("sqlcon", &Arg::Str("no-arrow".into())).unwrap();
        let mut reg = Registry::default();
        let err = Arc::new(m).register(&mut reg).err().unwrap();
        assert!(err.contains("name=>url"), "{err}");
    }

    #[test]
    fn sql_query_return_codes_and_dbr() {
        let reg = sqlops();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sql_query", &["c", "SELECT id, name, n FROM t ORDER BY id", "r"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "sql_query", &["c", "SELECT id FROM t WHERE id = 9", "empty"]).unwrap(), 2, "no rows");
            assert_eq!(call(&reg, ctx, "sql_query", &["c", "SELEC nonsense"]).unwrap(), -1, "an SQL error");
            assert_eq!(call(&reg, ctx, "sql_query", &["none", "SELECT 1"]).unwrap(), -1, "unknown connection");
            let cases: &[(&str, Val)] = &[
                ("$dbr(r=>rows)", Val::Int(2)),
                ("$dbr(r=>cols)", Val::Int(3)),
                ("$dbr(r=>colname[1])", Val::Str("name".into())),
                ("$dbr(r=>colname[3])", Val::Null),
                ("$dbr(r=>colname[x])", Val::Null),
                ("$dbr(r=>[0,0])", Val::Int(1)),
                ("$dbr(r => [1, 1])", Val::Str("two".into())),
                ("$dbr(r=>[0,2])", Val::Null),
                ("$dbr(r=>[1,2])", Val::Int(7)),
                ("$dbr(r=>[5,0])", Val::Null),
                ("$dbr(r=>[0])", Val::Null),
                ("$dbr(r=>[a,b])", Val::Null),
                ("$dbr(r=>other)", Val::Null),
                ("$dbr(empty=>rows)", Val::Int(0)),
                ("$dbr(nores=>rows)", Val::Null),
                ("$dbr(r)", Val::Null),
            ];
            for (spec, want) in cases {
                assert_eq!(&pv(&reg, ctx, spec), want, "{spec}");
            }
            assert_eq!(call(&reg, ctx, "sql_result_free", &["r"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$dbr(r=>rows)"), Val::Null, "freed");
            assert_eq!(pv(&reg, ctx, "$dbr(empty=>rows)"), Val::Int(0), "other results stay");
        });
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sql_result_free", &["r"]).unwrap(), 1, "nothing to free");
        });
    }

    #[test]
    fn sql_xquery_turns_rows_into_xavp_items() {
        let reg = sqlops();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sql_xquery", &["c", "SELECT id, name, n FROM t ORDER BY id", "row"]).unwrap(), 1);
            let items = ctx.ext::<TxnVars>().unwrap().xavps["row"].clone();
            assert_eq!(items.len(), 2);
            assert_eq!(items[0]["name"], Val::Str("one".into()));
            assert_eq!(items[0]["n"], Val::Null);
            assert_eq!(items[1]["n"], Val::Int(7));
            assert_eq!(call(&reg, ctx, "sql_xquery", &["c", "SELECT id FROM t WHERE id = 9", "row"]).unwrap(), 2);
            assert!(ctx.ext::<TxnVars>().unwrap().xavps["row"].is_empty());
            assert_eq!(call(&reg, ctx, "sql_xquery", &["c", "SELEC x", "row"]).unwrap(), -1);
            assert_eq!(call(&reg, ctx, "sql_xquery", &["none", "SELECT 1", "row"]).unwrap(), -1);
        });
    }

    #[test]
    fn sql_pvquery_fills_the_variables_from_the_first_row() {
        let reg = sqlops();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sql_pvquery", &["c", "SELECT name, id FROM t ORDER BY id DESC", "$var(a),$var(b)"]).unwrap(), 1);
            assert_eq!((pv(&reg, ctx, "$var(a)"), pv(&reg, ctx, "$var(b)")), (Val::Str("two".into()), Val::Int(2)));
            assert_eq!(call(&reg, ctx, "sql_pvquery", &["c", "SELECT name FROM t WHERE id = 9", "$var(a)"]).unwrap(), 2);
            assert_eq!(pv(&reg, ctx, "$var(a)"), Val::Str("two".into()), "unchanged without a row");
            assert_eq!(call(&reg, ctx, "sql_pvquery", &["c", "SELEC x", "$var(a)"]).unwrap(), -1);
            assert_eq!(call(&reg, ctx, "sql_pvquery", &["none", "SELECT 1", "$var(a)"]).unwrap(), -1);
        });
        assert!(fixup(&reg, "sql_pvquery", &[Arg::Str("c".into()), Arg::Str("SELECT 1".into()), Arg::Str("a".into())]).is_err(), "no variables");
    }

    // ------------------------------------------- mtree, prefix_route, speeddial --

    #[test]
    fn mtree_parameters_and_specs() {
        let m = MTree::default();
        for ok in ["db_table", "char_list", "tvalue_column"] {
            assert!(m.set_param(ok, &Arg::Str("x".into())).is_ok(), "{ok}");
        }
        assert!(m.set_param("nope", &Arg::Str("x".into())).is_err());
        let f = TempFile::new("mt");
        m.set_param("db_url", &Arg::Str(f.url())).unwrap();
        m.set_param("mtree", &Arg::Str("dbtable=mtree".into())).unwrap();
        let err = Arc::new(m).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("name= is required"), "{err}");
    }

    /// An mtree registry with trees `gw` (table mtree) and `alt` (table mt2).
    fn mtree() -> (TempFile, Registry) {
        let f = TempFile::new("mt");
        f.sql("CREATE TABLE mtree (tprefix TEXT, tvalue TEXT); CREATE TABLE mt2 (tprefix TEXT, tvalue TEXT)");
        f.sql("INSERT INTO mtree VALUES ('49', 'de'), ('4930', 'berlin'); INSERT INTO mt2 VALUES ('1', 'us')");
        let m = MTree::default();
        m.set_param("db_url", &Arg::Str(f.url())).unwrap();
        m.set_param("mtree", &Arg::Str("name=gw".into())).unwrap();
        m.set_param("mtree", &Arg::Str("name=alt;dbtable=mt2".into())).unwrap();
        m.set_param("pv_value", &Arg::Str("$var(out)".into())).unwrap();
        (f, registry(vec![Arc::new(m)]))
    }

    #[test]
    fn mt_match_writes_the_matches_to_pv_value() {
        let (_f, reg) = mtree();
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "mt_match", &["gw", "493012", "0"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$var(out)"), Val::Str("berlin".into()));
            assert_eq!(call(&reg, ctx, "mt_match", &["gw", "493012", "1"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$var(out)"), Val::Str("berlin".into()), "$var keeps the last value written: the longest");
            assert_eq!(call(&reg, ctx, "mt_match", &["gw", "1", "0"]).unwrap(), -1, "not in this tree");
            assert_eq!(call(&reg, ctx, "mt_match", &["alt", "1555", "0"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$var(out)"), Val::Str("us".into()));
        });
    }

    #[test]
    fn mtree_rpcs_list_match_and_reload() {
        let (f, reg) = mtree();
        let all = rpc(&reg, "mtree.list", json!([])).unwrap();
        assert_eq!(all.as_array().unwrap().len(), 3);
        assert_eq!(rpc(&reg, "mtree.list", json!(["alt"])).unwrap(), json!([{"tree": "alt", "tprefix": "1", "tvalue": ["us"]}]));
        assert_eq!(rpc(&reg, "mtree.match", json!(["gw", "4930", 1])).unwrap(), json!(["berlin", "de"]));
        assert_eq!(rpc(&reg, "mtree.match", json!(["gw", "4930"])).unwrap(), json!(["berlin"]), "mode 0 by default");
        assert!(rpc(&reg, "mtree.match", json!(["gw"])).is_err(), "no value");
        f.sql("INSERT INTO mtree VALUES ('4', 'any')");
        assert_eq!(rpc(&reg, "mtree.reload", json!([])).unwrap(), json!(4));
        assert_eq!(rpc(&reg, "mtree.match", json!(["gw", "4", 0])).unwrap(), json!(["any"]));
    }

    /// Runs `route[r1]` (returning 7) and knows no other route.
    struct Routes;
    impl RouteRunner for Routes {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn route_index(&self, name: &str) -> Option<usize> {
            (name == "r1").then_some(0)
        }
        fn run_route(&self, idx: usize, _: &mut Ctx<'_, '_>) -> i32 {
            if idx == 0 { 7 } else { -1 }
        }
    }

    #[test]
    fn prefix_route_runs_the_route_of_the_longest_prefix() {
        let f = TempFile::new("pr");
        f.sql("CREATE TABLE routes (prefix TEXT, route TEXT); INSERT INTO routes VALUES ('49', 'r1'), ('4930', 'missing'), ('bo', 'r1')");
        let m = PrefixRoute::default();
        m.set_param("db_url", &Arg::Str(f.url())).unwrap();
        m.set_param("db_table", &Arg::Str("routes".into())).unwrap();
        assert!(m.set_param("exit", &Arg::Int(0)).is_ok());
        assert!(m.set_param("nope", &Arg::Int(0)).is_err());
        let reg = registry(vec![Arc::new(m)]);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "prefix_route", &["4989"]).unwrap(), -1, "no script runner yet");
        });
        reg.hub.set_runner(Arc::new(Routes));
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "prefix_route", &["4989"]).unwrap(), 7);
            assert_eq!(call(&reg, ctx, "prefix_route", &["49301"]).unwrap(), -1, "the route isn't in the script");
            assert_eq!(call(&reg, ctx, "prefix_route", &["1"]).unwrap(), -1, "no prefix");
            assert_eq!(call(&reg, ctx, "prefix_route", &[]).unwrap(), 7, "the R-URI user, bob");
        });
        assert!(fixup(&reg, "prefix_route", &[Arg::Str("a".into()), Arg::Str("b".into())]).is_err());
        assert_eq!(rpc(&reg, "prefix_route.dump", json!([])).unwrap(), json!({"49": "r1", "4930": "missing", "bo": "r1"}));
        f.sql("DELETE FROM routes WHERE prefix = 'bo'");
        assert_eq!(rpc(&reg, "prefix_route.reload", json!([])).unwrap(), json!(2));
    }

    fn speeddial(use_domain: bool) -> (TempFile, Registry) {
        let f = TempFile::new("sd");
        f.sql("CREATE TABLE speed_dial (username TEXT, domain TEXT, sd_username TEXT, sd_domain TEXT, new_uri TEXT)");
        f.sql("INSERT INTO speed_dial VALUES ('alice', 'a.example', 'bob', '', 'sip:bob@far.example'), ('carol', 'c.example', 'bob', '', 'sip:carols-bob@x')");
        let m = SpeedDial::default();
        m.set_param("db_url", &Arg::Str(f.url())).unwrap();
        m.set_param("use_domain", &Arg::Int(i64::from(use_domain))).unwrap();
        (f, registry(vec![Arc::new(m)]))
    }

    #[test]
    fn sd_lookup_rewrites_the_request_uri() {
        let (_f, reg) = speeddial(false);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial"]).unwrap(), 1, "owner: the caller (From)");
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:bob@far.example"[..]));
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial", "sip:carol@elsewhere"]).unwrap(), 1, "no domain check");
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:carols-bob@x"[..]));
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial", "sip:dave@d.example"]).unwrap(), -1, "no entry");
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial", "dave"]).unwrap(), -1, "not a URI");
            assert_eq!(call(&reg, ctx, "sd_lookup", &["no_table"]).unwrap(), -1);
        });
        assert!(fixup(&reg, "sd_lookup", &[]).is_err());
    }

    #[test]
    fn sd_lookup_with_use_domain_matches_the_owner_domain() {
        let (_f, reg) = speeddial(true);
        with_ctx(&invite(""), &FakeNet(None), |ctx| {
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial", "sip:carol@elsewhere"]).unwrap(), -1);
            assert_eq!(call(&reg, ctx, "sd_lookup", &["speed_dial", "sip:carol@C.example"]).unwrap(), 1);
        });
        let m = SpeedDial::default();
        assert!(m.set_param("new_uri_column", &Arg::Str("x".into())).is_ok());
        assert!(m.set_param("nope", &Arg::Str("x".into())).is_err());
    }
}
