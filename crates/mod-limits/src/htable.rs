//! `htable` — named shared hash tables of strings/integers with optional
//! auto-expiry, usable from the script as `$sht(table=>key)`.
//!
//! ```text
//! modparam("htable", "htable", "ipban=>size=8;autoexpire=300;")
//! modparam("htable", "htable", "acc=>autoexpire=0;dbtable=htable;dbmode=1;")
//! ```
//! Table options: `autoexpire` (s, 0 = never), `initval` (value of unset
//! keys), `updateexpire` (1: refresh expiry on update), `dbtable` +
//! `dbmode` (load from `db_url` at start; with dbmode=1 the table is
//! written back every `timer_interval` when it changed, and on
//! `htable.store`). `size` is accepted (the table is a sharded map).
//!
//! Variables: `$sht(t=>k)` (assign `$null` to delete), `$shtex(t=>k)`
//! (seconds to expiry), `$shtcn(t=>pattern)` / `$shtcv(t=>pattern)` (count
//! of names / values matching: `~~re`, `~%suffix`, `%~prefix`, `==str`, or a
//! regex), `$shtinc(t=>k)` / `$shtdec(t=>k)` (atomic ±1, new value),
//! `$shtrecord(key|value)` (in `event_route[htable:expired:<t>]`).

use crate::kv_list;
use regex::Regex;
use sip_core::module::{DynStr, rc};
use sip_core::pv::{Fmt, PvParam, PvSpec, Val, parse_fmt};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::{Value, json};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, RouteHub, ShardedMap};
use sip_db::DbVal;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Debug)]
struct Item {
    val: Val,
    /// Unix seconds; 0 = never.
    expires: u64,
}

pub struct Table {
    name: String,
    autoexpire: u64,
    initval: Option<i64>,
    updateexpire: bool,
    dbtable: Option<String>,
    dbmode: u8,
    map: ShardedMap<String, Item>,
    dirty: AtomicBool,
}

impl Table {
    fn get(&self, k: &str) -> Val {
        let now = unix_secs();
        match self.map.get_cloned(k) {
            Some(i) if i.expires == 0 || i.expires >= now => i.val,
            _ => self.initval.map_or(Val::Null, Val::Int),
        }
    }

    fn set(&self, k: &str, v: Val, expires: Option<u64>) {
        self.dirty.store(true, Ordering::Relaxed);
        if v.is_null() {
            self.map.remove(k);
            return;
        }
        let now = unix_secs();
        let auto = if self.autoexpire > 0 { now.saturating_add(self.autoexpire) } else { 0 };
        self.map.alter(k.to_string(), |cur| {
            let exp = match (expires, cur) {
                (Some(e), _) => {
                    if e > 0 {
                        // A huge script value means "practically never".
                        now.saturating_add(e)
                    } else {
                        0
                    }
                }
                (None, Some(c)) if !self.updateexpire && (c.expires == 0 || c.expires >= now) => c.expires,
                _ => auto,
            };
            (Some(Item { val: v, expires: exp }), ())
        })
    }

    /// Atomic add (`$shtinc`): returns the new value.
    fn add(&self, k: &str, d: i64) -> i64 {
        self.dirty.store(true, Ordering::Relaxed);
        let now = unix_secs();
        let auto = if self.autoexpire > 0 { now.saturating_add(self.autoexpire) } else { 0 };
        let init = self.initval.unwrap_or(0);
        self.map.alter(k.to_string(), |cur| {
            let (base, exp) = match cur {
                Some(c) if c.expires == 0 || c.expires >= now => (c.val.as_int().unwrap_or(0), if self.updateexpire { auto } else { c.expires }),
                _ => (init, auto),
            };
            // Counters saturate: wrapping would turn a high count into a low one.
            let n = base.saturating_add(d);
            (Some(Item { val: Val::Int(n), expires: exp }), n)
        })
    }

    fn expire_in(&self, k: &str) -> Val {
        let now = unix_secs();
        match self.map.get_cloned(k) {
            Some(i) if i.expires == 0 => Val::Int(0),
            Some(i) if i.expires >= now => Val::Int(i64::try_from(i.expires.saturating_sub(now)).unwrap_or(i64::MAX)),
            _ => Val::Null,
        }
    }

    fn set_expire(&self, k: &str, secs: u64) {
        let now = unix_secs();
        self.map.with(k, |i| i.expires = if secs == 0 { 0 } else { now.saturating_add(secs) });
    }

    /// Unexpired items.
    fn items(&self) -> Vec<(String, Item)> {
        let now = unix_secs();
        let mut v = Vec::new();
        self.map.for_each_mut(|k, i| {
            if i.expires == 0 || i.expires >= now {
                v.push((k.clone(), i.clone()));
            }
        });
        v
    }

    fn remove_where(&self, f: impl Fn(&str, &Item) -> bool) -> usize {
        let mut n: usize = 0;
        self.map.retain(|k, i| {
            let rm = f(k, i);
            n = n.saturating_add(usize::from(rm));
            !rm
        });
        if n > 0 {
            self.dirty.store(true, Ordering::Relaxed);
        }
        n
    }
}

/// How a name/value is compared: `op` as in `sht_rm_name(t, op, val)`.
#[derive(Clone, Debug)]
enum Matcher {
    Re(Regex),
    Prefix(String),
    Suffix(String),
    Eq(String),
    Contains(String),
}

impl Matcher {
    fn new(op: &str, v: &str) -> Result<Self, String> {
        Ok(match op {
            "re" => Matcher::Re(Regex::new(v).map_err(|e| format!("bad regex {v:?}: {e}"))?),
            "sw" => Matcher::Prefix(v.into()),
            "ew" => Matcher::Suffix(v.into()),
            "eq" => Matcher::Eq(v.into()),
            "in" => Matcher::Contains(v.into()),
            _ => return Err(format!("unknown match operator {op:?} (re, sw, ew, eq, in)")),
        })
    }
    /// `$shtcn` pattern syntax.
    fn pattern(p: &str) -> Result<Self, String> {
        if let Some(r) = p.strip_prefix("~~") {
            Self::new("re", r)
        } else if let Some(s) = p.strip_prefix("~%") {
            Ok(Matcher::Suffix(s.into()))
        } else if let Some(s) = p.strip_prefix("%~") {
            Ok(Matcher::Prefix(s.into()))
        } else if let Some(s) = p.strip_prefix("==") {
            Ok(Matcher::Eq(s.into()))
        } else {
            Self::new("re", p)
        }
    }
    fn is_match(&self, s: &str) -> bool {
        match self {
            Matcher::Re(r) => r.is_match(s),
            Matcher::Prefix(p) => s.starts_with(p.as_str()),
            Matcher::Suffix(p) => s.ends_with(p.as_str()),
            Matcher::Eq(p) => s == p,
            Matcher::Contains(p) => s.contains(p.as_str()),
        }
    }
}

/// The record an `htable:expired:<t>` event route sees.
#[derive(Clone)]
struct ExpiredRecord(String, Val);

/// A `t=>key` parameter: table + key template.
struct TKey {
    t: Arc<Table>,
    key: Fmt,
}

#[derive(Default)]
pub struct Htable {
    specs: Mutex<Vec<String>>,
    db_url: Mutex<Option<String>>,
    timer_interval: AtomicU64,
    tables: OnceLock<HashMap<String, Arc<Table>>>,
    hub: OnceLock<Arc<RouteHub>>,
    locks: (Mutex<HashSet<String>>, Condvar),
}

impl Htable {
    fn table(&self, name: &str) -> Result<Arc<Table>, String> {
        self.tables.get().and_then(|t| t.get(name)).cloned().ok_or_else(|| format!("htable: no table {name:?}"))
    }

    fn parse_spec(spec: &str) -> Result<Table, String> {
        let (name, opts) = spec.split_once("=>").ok_or_else(|| format!("htable: expected name=>options, got {spec:?}"))?;
        let mut t = Table {
            name: name.trim().to_string(),
            autoexpire: 0,
            initval: None,
            updateexpire: true,
            dbtable: None,
            dbmode: 0,
            map: ShardedMap::new(64),
            dirty: AtomicBool::new(false),
        };
        for (k, v) in kv_list(opts) {
            let n = || v.parse::<i64>().map_err(|_| format!("htable {}: {k} must be a number", t.name));
            match k.as_str() {
                "autoexpire" => t.autoexpire = u64::try_from(n()?).unwrap_or(0),
                "initval" => t.initval = Some(n()?),
                "updateexpire" => t.updateexpire = n()? != 0,
                "dbtable" => t.dbtable = Some(v.clone()),
                "dbmode" => t.dbmode = u8::try_from(n()?).map_err(|_| format!("htable {}: dbmode {v:?} is out of range", t.name))?,
                "size" | "array" | "dmqreplicate" | "coldelim" | "colnull" => {}
                _ => return Err(format!("htable {}: unknown option {k:?}", t.name)),
            }
        }
        Ok(t)
    }

    fn load_db(&self, t: &Table) -> Result<usize, String> {
        let (Some(dbt), Some(url)) = (&t.dbtable, lock(&self.db_url).clone()) else { return Ok(0) };
        let db = sip_db::connect(&url)?;
        let rows = db.query(dbt, &["key_name", "key_type", "value_type", "key_value", "expires"], &[])?;
        let now = unix_secs();
        let mut n: usize = 0;
        t.map.retain(|_, _| false);
        for r in rows.rows {
            let exp = r.get(4).and_then(DbVal::int).and_then(|e| u64::try_from(e).ok()).unwrap_or(0);
            if exp != 0 && exp <= now {
                continue;
            }
            let raw = r.get(3).map(DbVal::text).unwrap_or_default();
            let val = if r.get(2).and_then(DbVal::int) == Some(1) { Val::Int(raw.trim().parse().unwrap_or(0)) } else { Val::Str(raw) };
            let Some(name) = r.first() else { continue };
            t.map.insert(name.text(), Item { val, expires: exp });
            n = n.saturating_add(1);
        }
        t.dirty.store(false, Ordering::Relaxed);
        Ok(n)
    }

    fn store_db(&self, t: &Table) -> Result<usize, String> {
        let (Some(dbt), Some(url)) = (&t.dbtable, lock(&self.db_url).clone()) else { return Err(format!("htable {}: no dbtable/db_url", t.name)) };
        let db = sip_db::connect(&url)?;
        db.delete(dbt, &[])?;
        let items = t.items();
        for (k, i) in &items {
            let (vt, v) = match &i.val {
                Val::Int(n) => (1, n.to_string()),
                v => (0, v.as_str().into_owned()),
            };
            db.insert(
                dbt,
                &["key_name", "key_type", "value_type", "key_value", "expires"],
                &[DbVal::Str(k.clone()), DbVal::Int(0), DbVal::Int(vt), DbVal::Str(v), DbVal::Int(i64::try_from(i.expires).unwrap_or(i64::MAX))],
            )?;
        }
        t.dirty.store(false, Ordering::Relaxed);
        Ok(items.len())
    }

    /// Sweep expired items (raising `htable:expired:<t>`), write back dbmode=1 tables.
    fn tick(&self, net: &dyn Outbound) {
        let Some(tables) = self.tables.get() else { return };
        let now = unix_secs();
        for t in tables.values() {
            let mut gone = Vec::new();
            t.map.retain(|k, i| {
                let keep = i.expires == 0 || i.expires >= now;
                if !keep {
                    gone.push(ExpiredRecord(k.clone(), i.val.clone()));
                }
                keep
            });
            if !gone.is_empty() {
                t.dirty.store(true, Ordering::Relaxed);
                let ev = format!("htable:expired:{}", t.name);
                if let Some(hub) = self.hub.get().filter(|h| h.has_event(&ev)) {
                    for r in gone {
                        hub.run_event_with(&ev, net, None, |ctx| ctx.ext.push(Box::new(r)));
                    }
                }
            }
            if t.dbmode == 1
                && t.dirty.load(Ordering::Relaxed)
                && let Err(e) = self.store_db(t)
            {
                sip_core::log::log(sip_core::log::L_ERR, &format!("htable: {e}"));
            }
        }
    }

    fn lock_key(&self, k: String) {
        let (m, cv) = &self.locks;
        let mut held = lock(m);
        while held.contains(&k) {
            held = cv.wait(held).unwrap_or_else(|e| e.into_inner());
        }
        held.insert(k);
    }

    fn unlock_key(&self, k: &str) {
        let (m, cv) = &self.locks;
        lock(m).remove(k);
        cv.notify_all();
    }

    fn tkey(self: &Arc<Self>, s: &str, table: &sip_core::pv::PvTable) -> Result<TKey, String> {
        let (t, k) = s.split_once("=>").ok_or_else(|| format!("expected table=>key, got {s:?}"))?;
        Ok(TKey { t: self.table(t.trim())?, key: parse_fmt(k, table)? })
    }

    fn dump(t: &Table) -> Value {
        let now = unix_secs();
        t.items()
            .into_iter()
            .map(|(k, i)| {
                let v = match i.val {
                    Val::Int(n) => json!(n),
                    v => json!(v.as_str()),
                };
                json!({"name": k, "value": v, "expires": if i.expires == 0 { 0 } else { i.expires.saturating_sub(now) }})
            })
            .collect()
    }
}

/// The key the fixup stored; `None` only if the variable skipped its fixup.
fn tk(p: &PvParam) -> Option<&TKey> {
    p.fixed::<TKey>()
}

/// Fixup for `sht_xxx("t=>k")`-style and `(table, key)`-style arguments.
fn dyn_strs<const N: usize>(a: &[Arg]) -> Result<[DynStr; N], String> {
    let a: &[Arg; N] = crate::fixed_args(a)?;
    let v: Vec<DynStr> = a.iter().map(Arg::dyn_str).collect::<Result<_, _>>()?;
    v.try_into().map_err(|_| format!("expected {N} argument(s)"))
}

impl Module for Htable {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("htable", Ty::List(&Ty::Str), "", "Tables, \"name=>size=8;autoexpire=300;dbtable=…\""),
            p("db_url", Ty::Str, "", "Database for tables with dbtable"),
            p("timer_interval", Ty::Duration(Unit::Sec), "20s", "Expiry check interval"),
        ])
    }

    fn name(&self) -> &'static str {
        "htable"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "htable" => lock(&self.specs).push(v.str()?.to_string()),
            "db_url" => *lock(&self.db_url) = Some(v.str()?.to_string()),
            "timer_interval" => self.timer_interval.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "key_name_column" | "key_type_column" | "value_type_column" | "key_value_column" | "expires_column" | "array_size_suffix" | "fetch_rows"
            | "timer_procs" | "event_callback" | "enable_dmq" | "db_expires" => {}
            _ => return Err(format!("htable: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, sig};
        const KEY: &[Param] = &[arg("table", Str), arg("key", Str)];
        const SPEC_RE: &[Param] = &[arg("table_and_regex", Str).lit().eg("\"t=>^a\"")];
        const MATCH: &[Param] = &[arg("table", Str).lit(), arg("op", Enum(&["re", "sw", "ew", "eq", "in"])).lit(), arg("value", Str)];
        const TABLE: &[Param] = &[arg("table", Str)];
        const SETS: &[Param] = &[arg("table", Str), arg("key", Str), arg("value", Str), arg("expires", Duration(Unit::Sec))];
        const SETI: &[Param] = &[arg("table", Str), arg("key", Str), arg("value", Int), arg("expires", Duration(Unit::Sec))];
        const SPEC_KEY: &[Param] = &[arg("table_and_key", Str).lit().eg("\"t=>k\"")];
        const LOCK: &[Param] = &[arg("table_and_key", Str).eg("\"t=>k\"")];
        Some(
            [
                sig("sht_rm", "remove", KEY, Ret::Bool, "Remove a key from a table (false: it wasn't there)"),
                sig("sht_rm_name_re", "remove_matching", SPEC_RE, Ret::Bool, "Remove the keys matching a regex (\"table=>regex\")"),
                sig("sht_rm_value_re", "remove_matching_values", SPEC_RE, Ret::Bool, "Remove the items whose value matches a regex (\"table=>regex\")"),
                sig("sht_rm_name", "remove_keys", MATCH, Ret::Bool, "Remove the keys matching value by op (re, sw, ew, eq, in)"),
                sig("sht_rm_value", "remove_values", MATCH, Ret::Bool, "Remove the items whose value matches by op (re, sw, ew, eq, in)"),
                sig("sht_has_name", "has_key", MATCH, Ret::Bool, "Some key matches value by op (re, sw, ew, eq, in)"),
                sig("sht_has_str_value", "has_value", MATCH, Ret::Bool, "Some item's value matches by op (re, sw, ew, eq, in)"),
                sig("sht_reset", "clear", TABLE, Ret::Bool, "Remove every item of a table"),
                sig("sht_setxs", "set_expiring", SETS, Ret::Bool, "Set a string item that expires after `expires`"),
                sig("sht_setxi", "set_int_expiring", SETI, Ret::Bool, "Set an integer item that expires after `expires`"),
                sig("sht_is_null", "is_null", SPEC_KEY, Ret::Bool, "The item (\"table=>key\") is not set"),
                sig("sht_lock", "lock", LOCK, Ret::Void, "Lock a key (\"table=>key\") for an atomic read-modify-write"),
                sig("sht_unlock", "unlock", LOCK, Ret::Void, "Unlock a key locked with lock"),
            ]
            .map(|s| s.allowed(ctx::ANY))
            .into(),
        )
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let mut tables = HashMap::new();
        for spec in lock(&self.specs).iter() {
            let t = Self::parse_spec(spec)?;
            if t.dbtable.is_some() && lock(&self.db_url).is_none() {
                return Err(format!("htable {}: dbtable needs modparam(\"htable\", \"db_url\", …)", t.name));
            }
            tables.insert(t.name.clone(), Arc::new(t));
        }
        let _ = self.tables.set(tables);
        for t in self.tables.get().ok_or("htable: tables not initialised")?.values() {
            self.load_db(t)?;
        }
        let _ = self.hub.set(reg.hub.clone());
        if self.timer_interval.load(Ordering::Relaxed) == 0 {
            self.timer_interval.store(20, Ordering::Relaxed);
        }

        // ------------------------------------------------------ variables
        let fix = {
            let me = self.clone();
            move |p: &mut PvParam, table: &sip_core::pv::PvTable| -> Result<(), String> {
                p.fixed = Some(Arc::new(me.tkey(&p.name, table)?));
                Ok(())
            }
        };
        reg.pv(
            "sht",
            PvSpec::rw(
                |c, p| {
                    let Some(k) = tk(p) else { return Val::Null };
                    let key = k.key.eval(c);
                    k.t.get(&key)
                },
                |c, p, v| {
                    let k = tk(p).ok_or("htable key not fixed up")?;
                    let key = k.key.eval(c);
                    k.t.set(&key, v, None);
                    Ok(())
                },
            )
            .with_param()
            .with_fix(fix.clone()),
        );
        reg.pv(
            "shtex",
            PvSpec::rw(
                |c, p| {
                    let Some(k) = tk(p) else { return Val::Null };
                    let key = k.key.eval(c);
                    k.t.expire_in(&key)
                },
                |c, p, v| {
                    let k = tk(p).ok_or("htable key not fixed up")?;
                    let key = k.key.eval(c);
                    k.t.set_expire(&key, v.as_int().and_then(|e| u64::try_from(e).ok()).unwrap_or(0));
                    Ok(())
                },
            )
            .with_param()
            .with_fix(fix.clone()),
        );
        for (name, d) in [("shtinc", 1i64), ("shtdec", -1)] {
            reg.pv(
                name,
                PvSpec::ro(move |c, p| {
                    let Some(k) = tk(p) else { return Val::Null };
                    let key = k.key.eval(c);
                    Val::Int(k.t.add(&key, d))
                })
                .with_param()
                .with_fix(fix.clone()),
            );
        }
        for (name, values) in [("shtcn", false), ("shtcv", true)] {
            let me = self.clone();
            reg.pv(
                name,
                PvSpec::ro(move |_, p| {
                    let Some((t, m)) = p.fixed::<(Arc<Table>, Matcher)>() else { return Val::Null };
                    let n = t.items().iter().filter(|(k, i)| if values { m.is_match(&i.val.as_str()) } else { m.is_match(k) }).count();
                    Val::Int(i64::try_from(n).unwrap_or(i64::MAX))
                })
                .with_param()
                .with_fix(move |p, _| {
                    let (t, pat) = p.name.split_once("=>").ok_or("expected table=>pattern")?;
                    p.fixed = Some(Arc::new((me.table(t.trim())?, Matcher::pattern(pat)?)));
                    Ok(())
                }),
            );
        }
        reg.pv(
            "shtrecord",
            PvSpec::ro(|c, p| match c.ext::<ExpiredRecord>() {
                Some(r) if p.name == "key" => Val::str(&r.0),
                Some(r) if p.name == "value" => r.1.clone(),
                _ => Val::Null,
            })
            .with_param(),
        );

        // ------------------------------------------------------ functions
        let m = "htable";
        let me = self.clone();
        let tbl = move |c: &mut Ctx, d: &DynStr| -> Option<Arc<Table>> {
            let n = d.eval(c).into_owned();
            me.table(&n).ok()
        };
        let t2 = tbl.clone();
        reg.export(
            m,
            "sht_rm",
            |a: &[Arg]| dyn_strs(a),
            move |c: &mut Ctx, [table, key]: &[DynStr; 2]| {
                let Some(t) = t2(c, table) else { return -1 };
                let k = key.eval(c).into_owned();
                let had = t.map.get_cloned(k.as_str()).is_some();
                t.set(&k, Val::Null, None);
                rc(had)
            },
        );
        for (fname, values) in [("sht_rm_name_re", false), ("sht_rm_value_re", true)] {
            let me = self.clone();
            reg.export(
                m,
                fname,
                |a: &[Arg]| {
                    let [spec] = crate::fixed_args(a)?;
                    Ok(spec.str()?.to_string())
                },
                move |_: &mut Ctx, s: &String| {
                    let Some((t, re)) = s.split_once("=>") else { return -1 };
                    let (Ok(t), Ok(re)) = (me.table(t.trim()), Regex::new(re)) else { return -1 };
                    t.remove_where(|k, i| if values { re.is_match(&i.val.as_str()) } else { re.is_match(k) });
                    1
                },
            );
        }
        for (fname, values, remove) in
            [("sht_rm_name", false, true), ("sht_rm_value", true, true), ("sht_has_name", false, false), ("sht_has_str_value", true, false)]
        {
            let me = self.clone();
            reg.export(
                m,
                fname,
                |a: &[Arg]| {
                    let [table, op, val] = crate::fixed_args(a)?;
                    Ok((table.str()?.to_string(), op.str()?.to_string(), val.dyn_str()?))
                },
                move |c: &mut Ctx, (t, op, v): &(String, String, DynStr)| {
                    let Ok(t) = me.table(t) else { return -1 };
                    let v = v.eval(c).into_owned();
                    let Ok(mt) = Matcher::new(op, &v) else { return -1 };
                    let hit = |k: &str, i: &Item| if values { mt.is_match(&i.val.as_str()) } else { mt.is_match(k) };
                    if remove {
                        t.remove_where(hit);
                        1
                    } else {
                        rc(t.items().iter().any(|(k, i)| hit(k, i)))
                    }
                },
            );
        }
        let t2 = tbl.clone();
        reg.export(
            m,
            "sht_reset",
            |a: &[Arg]| dyn_strs(a),
            move |c: &mut Ctx, [table]: &[DynStr; 1]| {
                let Some(t) = t2(c, table) else { return -1 };
                t.remove_where(|_, _| true);
                1
            },
        );
        for (fname, int) in [("sht_setxs", false), ("sht_setxi", true)] {
            let t2 = tbl.clone();
            reg.export(
                m,
                fname,
                |a: &[Arg]| dyn_strs(a),
                move |c: &mut Ctx, [table, key, val, exp]: &[DynStr; 4]| {
                    let Some(t) = t2(c, table) else { return -1 };
                    let k = key.eval(c).into_owned();
                    let v = val.eval(c).into_owned();
                    let v = if int { Val::Int(v.trim().parse().unwrap_or(0)) } else { Val::Str(v) };
                    let exp = exp.eval(c).trim().parse::<u64>().unwrap_or(0);
                    t.set(&k, v, Some(exp));
                    1
                },
            );
        }
        let me = self.clone();
        reg.export(
            m,
            "sht_is_null",
            |a: &[Arg]| {
                let [spec] = crate::fixed_args(a)?;
                Ok(spec.str()?.to_string())
            },
            move |c: &mut Ctx, s: &String| {
                let Some((t, k)) = s.split_once("=>") else { return -1 };
                let Ok(t) = me.table(t.trim()) else { return -1 };
                let _ = c;
                rc(t.get(k).is_null())
            },
        );
        for (fname, lk) in [("sht_lock", true), ("sht_unlock", false)] {
            let me = self.clone();
            reg.export(
                m,
                fname,
                |a: &[Arg]| {
                    let [key] = crate::fixed_args(a)?;
                    key.dyn_str()
                },
                move |c: &mut Ctx, d: &DynStr| {
                    let k = d.eval(c).into_owned();
                    if lk {
                        me.lock_key(k);
                    } else {
                        me.unlock_key(&k);
                    }
                    1
                },
            );
        }

        // ------------------------------------------------------------ RPC
        let me = self.clone();
        let tparam = move |p: &[Value], i: usize| -> Result<Arc<Table>, String> { me.table(&sip_core::rpc::str_param(p, i)?) };
        let tp = tparam.clone();
        reg.rpc.add("htable.get", "htable.get <table> <key>", move |p| {
            let t = tp(p, 0)?;
            match t.get(&sip_core::rpc::str_param(p, 1)?) {
                Val::Null => Err("key not found".into()),
                Val::Int(n) => Ok(json!(n)),
                v => Ok(json!(v.as_str())),
            }
        });
        for (name, int) in [("htable.sets", false), ("htable.seti", true)] {
            let tp = tparam.clone();
            reg.rpc.add(name, "htable.sets|seti <table> <key> <value>", move |p| {
                let t = tp(p, 0)?;
                let k = sip_core::rpc::str_param(p, 1)?;
                let v = if int { Val::Int(sip_core::rpc::int_param(p, 2)?) } else { Val::Str(sip_core::rpc::str_param(p, 2)?) };
                t.set(&k, v, None);
                Ok(json!(0))
            });
        }
        let tp = tparam.clone();
        reg.rpc.add("htable.delete", "htable.delete <table> <key>", move |p| {
            let t = tp(p, 0)?;
            t.set(&sip_core::rpc::str_param(p, 1)?, Val::Null, None);
            Ok(json!(0))
        });
        let tp = tparam.clone();
        reg.rpc.add("htable.dump", "htable.dump <table>", move |p| Ok(Htable::dump(&*tp(p, 0)?)));
        let tp = tparam.clone();
        reg.rpc.add("htable.flush", "htable.flush <table>", move |p| Ok(json!(tp(p, 0)?.remove_where(|_, _| true))));
        let (tp, me) = (tparam.clone(), self.clone());
        reg.rpc.add("htable.reload", "htable.reload <table>: reload from the database", move |p| me.load_db(&*tp(p, 0)?).map(|n| json!(n)));
        let (tp, me) = (tparam, self.clone());
        reg.rpc.add("htable.store", "htable.store <table>: write to the database", move |p| me.store_db(&*tp(p, 0)?).map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("htable.listTables", "List the hash tables", move |_| {
            let mut v: Vec<Value> = me
                .tables
                .get()
                .map(|t| {
                    t.values()
                        .map(|t| json!({"name": t.name, "autoexpire": t.autoexpire, "dbtable": t.dbtable, "dbmode": t.dbmode, "items": t.items().len()}))
                        .collect()
                })
                .unwrap_or_default();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            Ok(json!(v))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        // event_route[htable:mod-init]: once, at startup.
        if let Some(hub) = self.hub.get() {
            hub.run_event_with("htable:mod-init", &*net, None, |_| {});
        }
        let every = self.timer_interval.load(Ordering::Relaxed).max(1);
        std::thread::Builder::new()
            .name("htable-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(every));
                    self.tick(&*net);
                }
            })
            .map_err(|e| format!("cannot start the htable timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_semantics() {
        let t = Htable::parse_spec("t=>size=4;initval=0;autoexpire=0").unwrap();
        assert_eq!(t.get("x"), Val::Int(0), "initval for unset keys");
        assert_eq!(t.add("x", 1), 1);
        assert_eq!(t.add("x", 1), 2);
        t.set("s", Val::Str("v".into()), None);
        assert_eq!(t.get("s"), Val::Str("v".into()));
        t.set("s", Val::Null, None);
        assert_eq!(t.get("s"), Val::Int(0));
        t.set("e", Val::Int(1), Some(100));
        assert!(matches!(t.expire_in("e"), Val::Int(n) if (99..=100).contains(&n)));
        assert!(Matcher::pattern("%~ab").unwrap().is_match("abc"));
        assert!(Matcher::pattern("~%bc").unwrap().is_match("abc"));
        assert!(Matcher::pattern("~~^a.c$").unwrap().is_match("abc"));
        assert!(Htable::parse_spec("bad").is_err());
        assert!(Htable::parse_spec("t=>nope=1").is_err());
    }

    #[test]
    fn huge_script_values_saturate() {
        let t = Htable::parse_spec("t=>size=4;autoexpire=0").unwrap();
        // sht_setxi(..., "18446744073709551615"): expired at once (wrapped) or panicked.
        t.set("e", Val::Int(1), Some(u64::MAX));
        assert_eq!(t.get("e"), Val::Int(1));
        t.set_expire("e", u64::MAX);
        assert_eq!(t.get("e"), Val::Int(1));
        assert_eq!(t.expire_in("e"), Val::Int(i64::MAX));
        // $shtinc on a counter at i64::MAX stays there instead of wrapping negative.
        t.set("c", Val::Int(i64::MAX), None);
        assert_eq!(t.add("c", 1), i64::MAX);
        assert_eq!(t.add("c", -1), i64::MAX - 1);
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;

    fn table(spec: &str) -> Table {
        Htable::parse_spec(&format!("t=>{spec}")).unwrap()
    }

    fn item(t: &Table, k: &str) -> Option<Item> {
        t.map.get_cloned(k)
    }

    #[test]
    fn parse_spec_options() {
        let t = table("");
        assert_eq!((t.name.as_str(), t.autoexpire, t.initval, t.updateexpire, t.dbtable.as_deref(), t.dbmode), ("t", 0, None, true, None, 0));
        let t = Htable::parse_spec(" ipban =>size=8;autoexpire=300;initval=-1;updateexpire=0;dbtable=ht;dbmode=1;").unwrap();
        assert_eq!((t.name.as_str(), t.autoexpire, t.initval, t.updateexpire, t.dbtable.as_deref(), t.dbmode), ("ipban", 300, Some(-1), false, Some("ht"), 1));
        assert_eq!(table("autoexpire=-5").autoexpire, 0, "a negative expiry is none");
        for bad in ["t", "t=>autoexpire=x", "t=>dbmode=300", "t=>dbmode=-1", "t=>initval=", "t=>colour=1"] {
            assert!(Htable::parse_spec(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn get_returns_initval_for_missing_and_expired_keys() {
        let now = unix_secs();
        for (initval, missing) in [("", Val::Null), ("initval=7", Val::Int(7))] {
            let t = table(initval);
            t.map.insert("old".into(), Item { val: Val::Int(1), expires: now - 10 });
            t.map.insert("live".into(), Item { val: Val::Int(2), expires: now + 1000 });
            t.map.insert("forever".into(), Item { val: Val::str("f"), expires: 0 });
            assert_eq!(t.get("missing"), missing);
            assert_eq!(t.get("old"), missing, "expired");
            assert_eq!(t.get("live"), Val::Int(2));
            assert_eq!(t.get("forever"), Val::str("f"));
        }
    }

    #[test]
    fn set_expiry_rules() {
        let now = unix_secs();
        let t = table("autoexpire=60");
        t.set("a", Val::Int(1), None);
        let e = item(&t, "a").unwrap().expires;
        assert!((now + 60..=unix_secs() + 60).contains(&e), "autoexpire from now");
        t.set("b", Val::Int(1), Some(0));
        assert_eq!(item(&t, "b").unwrap().expires, 0, "an explicit 0 never expires");
        t.set("c", Val::Int(1), Some(5));
        assert!((now + 5..=unix_secs() + 5).contains(&item(&t, "c").unwrap().expires));

        // updateexpire=1 (default): an update restarts the expiry.
        t.map.insert("u".into(), Item { val: Val::Int(1), expires: now + 5 });
        t.set("u", Val::Int(2), None);
        assert!(item(&t, "u").unwrap().expires >= now + 60);

        // updateexpire=0: an update keeps a live item's expiry ...
        let k = table("autoexpire=60;updateexpire=0");
        k.map.insert("u".into(), Item { val: Val::Int(1), expires: now + 5 });
        k.set("u", Val::Int(2), None);
        let u = item(&k, "u").unwrap();
        assert_eq!((u.val, u.expires), (Val::Int(2), now + 5));
        k.map.insert("never".into(), Item { val: Val::Int(1), expires: 0 });
        k.set("never", Val::Int(2), None);
        assert_eq!(item(&k, "never").unwrap().expires, 0);
        // ... but an expired one starts over.
        k.map.insert("old".into(), Item { val: Val::Int(1), expires: now - 5 });
        k.set("old", Val::Int(2), None);
        assert!(item(&k, "old").unwrap().expires >= now + 60);

        t.set("a", Val::Null, None);
        assert!(item(&t, "a").is_none(), "$null deletes");
        assert!(t.dirty.load(Ordering::Relaxed));
    }

    #[test]
    fn add_counts_from_initval_and_saturates() {
        let now = unix_secs();
        let t = table("initval=10");
        assert_eq!(t.add("n", 1), 11);
        assert_eq!(t.add("n", -3), 8);
        t.map.insert("old".into(), Item { val: Val::Int(100), expires: now - 1 });
        assert_eq!(t.add("old", 1), 11, "an expired counter restarts from initval");
        t.set("s", Val::str("abc"), None);
        assert_eq!(t.add("s", 1), 1, "a non-number counts as 0");
        t.set("s", Val::str("41"), None);
        assert_eq!(t.add("s", 1), 42);
        t.set("min", Val::Int(i64::MIN), None);
        assert_eq!(t.add("min", -1), i64::MIN);
        let z = table("");
        assert_eq!(z.add("n", -1), -1, "no initval: from 0");
    }

    #[test]
    fn add_keeps_or_refreshes_the_expiry() {
        let now = unix_secs();
        let keep = table("autoexpire=60;updateexpire=0");
        keep.map.insert("n".into(), Item { val: Val::Int(1), expires: now + 5 });
        keep.add("n", 1);
        assert_eq!(item(&keep, "n").unwrap().expires, now + 5);
        let refresh = table("autoexpire=60");
        refresh.map.insert("n".into(), Item { val: Val::Int(1), expires: now + 5 });
        refresh.add("n", 1);
        assert!(item(&refresh, "n").unwrap().expires >= now + 60);
    }

    #[test]
    fn expire_in_and_set_expire() {
        let now = unix_secs();
        let t = table("");
        t.map.insert("never".into(), Item { val: Val::Int(1), expires: 0 });
        t.map.insert("live".into(), Item { val: Val::Int(1), expires: now + 1000 });
        t.map.insert("old".into(), Item { val: Val::Int(1), expires: now - 1 });
        assert_eq!(t.expire_in("never"), Val::Int(0));
        assert!(matches!(t.expire_in("live"), Val::Int(n) if (999..=1000).contains(&n)));
        assert_eq!(t.expire_in("old"), Val::Null);
        assert_eq!(t.expire_in("missing"), Val::Null);
        t.set_expire("live", 0);
        assert_eq!(item(&t, "live").unwrap().expires, 0);
        t.set_expire("never", 30);
        assert!(item(&t, "never").unwrap().expires >= now + 30);
        t.set_expire("missing", 30);
        assert!(item(&t, "missing").is_none(), "no item is created");
    }

    #[test]
    fn items_skip_expired_and_remove_where_counts() {
        let now = unix_secs();
        let t = table("");
        t.map.insert("a1".into(), Item { val: Val::str("x"), expires: 0 });
        t.map.insert("a2".into(), Item { val: Val::str("y"), expires: now + 100 });
        t.map.insert("b1".into(), Item { val: Val::str("x"), expires: now - 100 });
        let mut keys: Vec<String> = t.items().into_iter().map(|(k, _)| k).collect();
        keys.sort();
        assert_eq!(keys, ["a1", "a2"]);
        assert!(!t.dirty.load(Ordering::Relaxed));
        assert_eq!(t.remove_where(|_, _| false), 0);
        assert!(!t.dirty.load(Ordering::Relaxed), "nothing removed: not dirty");
        assert_eq!(t.remove_where(|_, i| i.val == Val::str("x")), 2, "expired items are matched too");
        assert!(t.dirty.load(Ordering::Relaxed));
        assert_eq!(t.items().len(), 1);
    }

    #[test]
    fn matcher_operators() {
        let cases: &[(&str, &str, &str, bool)] = &[
            ("re", "^ab", "abc", true),
            ("re", "^b", "abc", false),
            ("sw", "ab", "abc", true),
            ("sw", "bc", "abc", false),
            ("ew", "bc", "abc", true),
            ("ew", "ab", "abc", false),
            ("eq", "abc", "abc", true),
            ("eq", "ab", "abc", false),
            ("in", "b", "abc", true),
            ("in", "x", "abc", false),
            ("sw", "", "abc", true),
        ];
        for &(op, v, s, want) in cases {
            assert_eq!(Matcher::new(op, v).unwrap().is_match(s), want, "{op} {v:?} on {s:?}");
        }
        assert!(Matcher::new("re", "(").is_err());
        assert!(Matcher::new("like", "x").is_err());
    }

    #[test]
    fn shtcn_pattern_prefixes() {
        // (pattern, name, matches)
        let cases: &[(&str, &str, bool)] = &[
            ("~~^a.c$", "abc", true),
            ("~~^a.c$", "abcd", false),
            ("%~ab", "abc", true),
            ("%~bc", "abc", false),
            ("~%bc", "abc", true),
            ("~%ab", "abc", false),
            ("==abc", "abc", true),
            ("==ab", "abc", false),
            ("b", "abc", true),
            ("^b", "abc", false),
            ("%~", "abc", true),
        ];
        for &(p, s, want) in cases {
            assert_eq!(Matcher::pattern(p).unwrap().is_match(s), want, "{p:?} on {s:?}");
        }
        assert!(Matcher::pattern("~~(").is_err());
        assert!(Matcher::pattern("(").is_err());
    }

    #[test]
    fn dump_reports_remaining_seconds() {
        let now = unix_secs();
        let t = table("");
        t.map.insert("i".into(), Item { val: Val::Int(5), expires: 0 });
        t.map.insert("s".into(), Item { val: Val::str("v"), expires: now + 1000 });
        let mut v = Htable::dump(&t).as_array().unwrap().clone();
        v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        assert_eq!(v[0], json!({"name": "i", "value": 5, "expires": 0}));
        assert_eq!((v[1]["name"].clone(), v[1]["value"].clone()), (json!("s"), json!("v")));
        assert!((999..=1000).contains(&v[1]["expires"].as_u64().unwrap()));
    }

    #[test]
    fn register_builds_tables_and_needs_db_url_for_dbtable() {
        let h = Arc::new(Htable::default());
        h.set_param("htable", &Arg::Str("a=>autoexpire=5".into())).unwrap();
        h.set_param("htable", &Arg::Str("b=>".into())).unwrap();
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        reg.load(h.clone()).unwrap();
        assert_eq!(h.table("a").unwrap().autoexpire, 5);
        assert!(h.table("b").is_ok());
        assert!(h.table("c").is_err());
        assert!(h.tkey("a=>k$ci", reg.pvs()).is_ok());
        assert!(h.tkey("c=>k", reg.pvs()).is_err());
        assert!(h.tkey("a", reg.pvs()).is_err());

        let d = Arc::new(Htable::default());
        d.set_param("htable", &Arg::Str("x=>dbtable=htable".into())).unwrap();
        let err = d.register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("db_url"), "{err}");
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::testutil::{Sent, TextDb, call, request, rpc, with_ctx};
    use sip_core::pv::parse_pv;

    const HEADER: &str = "key_name(string) key_type(int) value_type(int) key_value(string) expires(int)\n";

    /// A registry with htable loaded from these table specs (and `db_url`).
    fn load(specs: &[&str], db_url: Option<&str>) -> (Arc<Htable>, Registry) {
        let h = Arc::new(Htable::default());
        for s in specs {
            h.set_param("htable", &Arg::Str((*s).into())).unwrap();
        }
        if let Some(u) = db_url {
            h.set_param("db_url", &Arg::Str(u.into())).unwrap();
        }
        let mut reg = Registry::default();
        reg.load(h.clone()).unwrap();
        (h, reg)
    }

    fn s(v: &str) -> Arg {
        Arg::Str(v.into())
    }

    fn keys(t: &Table) -> Vec<String> {
        let mut k: Vec<String> = t.items().into_iter().map(|(k, _)| k).collect();
        k.sort();
        k
    }

    #[test]
    fn ignored_and_unknown_params() {
        let h = Htable::default();
        for name in [
            "key_name_column",
            "key_type_column",
            "value_type_column",
            "key_value_column",
            "expires_column",
            "array_size_suffix",
            "fetch_rows",
            "timer_procs",
            "event_callback",
            "enable_dmq",
            "db_expires",
        ] {
            assert!(h.set_param(name, &s("x")).is_ok(), "{name} is accepted");
        }
        assert!(h.set_param("no_such_param", &s("x")).is_err());
        h.set_param("timer_interval", &Arg::Int(0)).unwrap();
        assert_eq!(h.timer_interval.load(Ordering::Relaxed), 1, "at least one second");
    }

    #[test]
    fn load_db_reads_ints_strings_and_skips_expired_rows() {
        let live = unix_secs() + 1000;
        let db = TextDb::new(&[("ht", &format!("{HEADER}a:0:1:42:0\nb:0:0:hello:0\nold:0:0:x:1\nlive:0:0:y:{live}\nbad:0:1:nan:0\n"))]);
        let (h, reg) = load(&["t=>dbtable=ht"], Some(&db.url()));
        let t = h.table("t").unwrap();
        assert_eq!(keys(&t), ["a", "b", "bad", "live"], "the row that expired in 1970 is skipped");
        assert_eq!(t.get("a"), Val::Int(42));
        assert_eq!(t.get("b"), Val::str("hello"));
        assert_eq!(t.get("bad"), Val::Int(0), "an integer row that is not a number reads as 0");
        assert_eq!(item_expires(&t, "live"), live);
        assert!(!t.dirty.load(Ordering::Relaxed), "a fresh load is clean");

        // htable.reload replaces the contents.
        t.set("extra", Val::Int(1), None);
        db.write("ht", &format!("{HEADER}z:0:0:zz:0\n"));
        assert_eq!(rpc(&reg, "htable.reload", json!(["t"])), Ok(json!(1)));
        assert_eq!(keys(&t), ["z"]);
    }

    fn item_expires(t: &Table, k: &str) -> u64 {
        t.map.get_cloned(k).unwrap().expires
    }

    #[test]
    fn store_db_writes_ints_and_strings_back() {
        let db = TextDb::new(&[("ht", HEADER)]);
        let (h, reg) = load(&["t=>dbtable=ht;dbmode=1", "plain=>"], Some(&db.url()));
        let t = h.table("t").unwrap();
        t.set("n", Val::Int(7), None);
        t.set("s", Val::str("v:w"), Some(1000));
        assert_eq!(rpc(&reg, "htable.store", json!(["t"])), Ok(json!(2)));
        assert!(!t.dirty.load(Ordering::Relaxed));
        let text = db.read("ht");
        assert!(text.contains("n:0:1:7:0\n"), "{text}");
        assert!(text.contains("s:0:0:v\\:w:"), "{text}");

        t.remove_where(|_, _| true);
        assert_eq!(rpc(&reg, "htable.reload", json!(["t"])), Ok(json!(2)));
        assert_eq!((t.get("n"), t.get("s")), (Val::Int(7), Val::str("v:w")), "round trip");
        assert!(item_expires(&t, "s") > unix_secs());

        let err = rpc(&reg, "htable.store", json!(["plain"])).unwrap_err();
        assert!(err.contains("no dbtable"), "{err}");
        assert_eq!(rpc(&reg, "htable.reload", json!(["plain"])), Ok(json!(0)), "nothing to load");
    }

    /// An event route that records `$shtrecord(key)` / `$shtrecord(value)`.
    struct Expired(sip_core::pv::PvRef, sip_core::pv::PvRef, Mutex<Vec<(Val, Val)>>);
    impl sip_core::RouteRunner for Expired {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            let r = (self.0.get(ctx), self.1.get(ctx));
            lock(&self.2).push(r);
            true
        }
    }

    #[test]
    fn tick_sweeps_expired_items_and_raises_the_event() {
        let (h, reg) = load(&["t=>", "quiet=>"], None);
        let rec = Arc::new(Expired(parse_pv("$shtrecord(key)", reg.pvs()).unwrap(), parse_pv("$shtrecord(value)", reg.pvs()).unwrap(), Mutex::new(Vec::new())));
        reg.hub.set_names(sip_core::RouteNames { event: vec!["htable:expired:t".into()], ..Default::default() });
        reg.hub.set_runner(rec.clone());
        let now = unix_secs();
        let (t, q) = (h.table("t").unwrap(), h.table("quiet").unwrap());
        t.map.insert("gone".into(), Item { val: Val::Int(5), expires: now - 10 });
        t.map.insert("kept".into(), Item { val: Val::Int(6), expires: now + 1000 });
        t.map.insert("forever".into(), Item { val: Val::Int(7), expires: 0 });
        q.map.insert("gone".into(), Item { val: Val::Int(1), expires: now - 10 });
        h.tick(&Sent::default());
        assert_eq!(*lock(&rec.2), [(Val::str("gone"), Val::Int(5))], "one event, for table t only");
        assert_eq!(keys(&t), ["forever", "kept"]);
        assert!(q.map.get_cloned("gone").is_none(), "swept without an event route too");
        assert!(t.dirty.load(Ordering::Relaxed));
        h.tick(&Sent::default());
        assert_eq!(lock(&rec.2).len(), 1, "nothing more expired");

        let (r, _) = with_ctx(&request("OPTIONS"), |c| parse_pv("$shtrecord(key)", reg.pvs()).unwrap().get(c));
        assert_eq!(r, Val::Null, "outside the event route");
    }

    #[test]
    fn tick_writes_back_dbmode_1_tables_and_survives_a_failed_write() {
        let db = TextDb::new(&[("ht", HEADER)]);
        let (h, _reg) = load(&["t=>dbtable=ht;dbmode=1", "ro=>dbtable=ht"], Some(&db.url()));
        let t = h.table("t").unwrap();
        h.tick(&Sent::default());
        assert_eq!(db.read("ht"), HEADER, "clean: not written");
        t.set("k", Val::Int(3), None);
        h.tick(&Sent::default());
        assert!(db.read("ht").contains("k:0:1:3:0"));
        assert!(!t.dirty.load(Ordering::Relaxed));

        std::fs::remove_file(db.0.join("ht")).unwrap();
        t.set("k", Val::Int(4), None);
        h.tick(&Sent::default());
        assert!(t.dirty.load(Ordering::Relaxed), "the write failed: still dirty, retried next time");
    }

    #[test]
    fn variables_read_write_count_and_expire() {
        let (h, reg) = load(&["t=>"], None);
        let pv = |s: &str| parse_pv(s, reg.pvs()).unwrap();
        let req = request("OPTIONS");
        with_ctx(&req, |c| {
            pv("$sht(t=>a1)").set(c, Val::str("x")).unwrap();
            pv("$sht(t=>a2)").set(c, Val::str("y")).unwrap();
            pv("$sht(t=>b1)").set(c, Val::str("x")).unwrap();
            assert_eq!(pv("$sht(t=>a1)").get(c), Val::str("x"));
            assert_eq!(pv("$shtinc(t=>n)").get(c), Val::Int(1));
            assert_eq!(pv("$shtinc(t=>n)").get(c), Val::Int(2));
            assert_eq!(pv("$shtdec(t=>n)").get(c), Val::Int(1));
            assert_eq!(pv("$shtcn(t=>%~a)").get(c), Val::Int(2));
            assert_eq!(pv("$shtcn(t=>==b1)").get(c), Val::Int(1));
            assert_eq!(pv("$shtcv(t=>==x)").get(c), Val::Int(2));
            assert_eq!(pv("$shtcv(t=>~~^[xy]$)").get(c), Val::Int(3));

            let ex = pv("$shtex(t=>a1)");
            assert_eq!(ex.get(c), Val::Int(0), "no expiry");
            ex.set(c, Val::Int(100)).unwrap();
            assert!(matches!(ex.get(c), Val::Int(99..=100)), "{:?}", ex.get(c));
            ex.set(c, Val::Int(-5)).unwrap();
            assert_eq!(ex.get(c), Val::Int(0), "a negative expiry is none");
            ex.set(c, Val::str("soon")).unwrap();
            assert_eq!(ex.get(c), Val::Int(0), "not a number: none");
            assert_eq!(pv("$shtex(t=>missing)").get(c), Val::Null);

            pv("$sht(t=>a1)").set(c, Val::Null).unwrap();
            assert_eq!(pv("$sht(t=>a1)").get(c), Val::Null, "$null deletes");
        });
        assert_eq!(keys(&h.table("t").unwrap()), ["a2", "b1", "n"]);
        for bad in ["$sht(nope=>k)", "$shtex(t)", "$shtcn(t)", "$shtcn(nope=>x)", "$shtcv(t=>~~()"] {
            assert!(parse_pv(bad, reg.pvs()).is_err(), "{bad}");
        }
    }

    /// Table `t` holding a1=x, a2=y, b1=x.
    fn abc() -> (Arc<Htable>, Registry, Arc<Table>) {
        let (h, reg) = load(&["t=>"], None);
        let t = h.table("t").unwrap();
        for (k, v) in [("a1", "x"), ("a2", "y"), ("b1", "x")] {
            t.set(k, Val::str(v), None);
        }
        (h, reg, t)
    }

    #[test]
    fn sht_rm_name_re_and_value_re() {
        let req = request("OPTIONS");
        // (function, spec, rc, keys left)
        let cases: &[(&str, &str, i32, &[&str])] = &[
            ("sht_rm_name_re", "t=>^a", 1, &["b1"]),
            ("sht_rm_name_re", "t=>^z", 1, &["a1", "a2", "b1"]),
            ("sht_rm_value_re", "t=>^x$", 1, &["a2"]),
            ("sht_rm_name_re", "t=>(", -1, &["a1", "a2", "b1"]),
            ("sht_rm_name_re", "nope=>^a", -1, &["a1", "a2", "b1"]),
            ("sht_rm_value_re", "t", -1, &["a1", "a2", "b1"]),
        ];
        for &(f, spec, want, left) in cases {
            let (_, reg, t) = abc();
            assert_eq!(call(&reg, f, &[s(spec)], &req).0, want, "{f}({spec:?})");
            assert_eq!(keys(&t), left, "{f}({spec:?})");
        }
    }

    #[test]
    fn sht_rm_and_has_by_operator() {
        let req = request("OPTIONS");
        // (function, op, value, rc, keys left)
        let cases: &[(&str, &str, &str, i32, &[&str])] = &[
            ("sht_rm_name", "sw", "a", 1, &["b1"]),
            ("sht_rm_name", "ew", "1", 1, &["a2"]),
            ("sht_rm_name", "eq", "a2", 1, &["a1", "b1"]),
            ("sht_rm_name", "in", "2", 1, &["a1", "b1"]),
            ("sht_rm_name", "re", "^b", 1, &["a1", "a2"]),
            ("sht_rm_value", "eq", "x", 1, &["a2"]),
            ("sht_rm_name", "re", "(", -1, &["a1", "a2", "b1"]),
            ("sht_rm_name", "like", "a", -1, &["a1", "a2", "b1"]),
            ("sht_has_name", "sw", "b", 1, &["a1", "a2", "b1"]),
            ("sht_has_name", "eq", "c", -1, &["a1", "a2", "b1"]),
            ("sht_has_str_value", "eq", "y", 1, &["a1", "a2", "b1"]),
            ("sht_has_str_value", "sw", "z", -1, &["a1", "a2", "b1"]),
            ("sht_has_str_value", "bogus", "y", -1, &["a1", "a2", "b1"]),
        ];
        for &(f, op, v, want, left) in cases {
            let (_, reg, t) = abc();
            assert_eq!(call(&reg, f, &[s("t"), s(op), s(v)], &req).0, want, "{f}(t, {op}, {v:?})");
            assert_eq!(keys(&t), left, "{f}(t, {op}, {v:?})");
        }
        let (_, reg, _) = abc();
        assert_eq!(call(&reg, "sht_has_name", &[s("nope"), s("sw"), s("a")], &req).0, -1, "no such table");
        assert!((reg.get("sht_has_name").unwrap().fixup)(&[s("t"), s("sw")]).is_err());
    }

    #[test]
    fn sht_is_null_takes_the_key_literally() {
        let (_, reg, _) = abc();
        let req = request("OPTIONS");
        let is_null = |spec: &str| call(&reg, "sht_is_null", &[s(spec)], &req).0;
        assert_eq!(is_null("t=>a1"), -1);
        assert_eq!(is_null("t=>zz"), 1);
        assert_eq!(is_null("t=>$var(x)"), 1, "not evaluated");
        assert_eq!(is_null("nope=>a1"), -1, "no such table");
        assert_eq!(is_null("t"), -1, "no =>");
    }

    #[test]
    fn sht_lock_and_unlock() {
        let (h, reg, _) = abc();
        let req = request("OPTIONS");
        assert_eq!(call(&reg, "sht_lock", &[s("t=>a1")], &req).0, 1);
        assert!(lock(&h.locks.0).contains("t=>a1"));
        assert_eq!(call(&reg, "sht_unlock", &[s("t=>a1")], &req).0, 1);
        assert!(lock(&h.locks.0).is_empty());
        assert_eq!(call(&reg, "sht_lock", &[s("t=>a1")], &req).0, 1, "free again: does not block");
        assert_eq!(call(&reg, "sht_unlock", &[s("t=>a1")], &req).0, 1);
        assert_eq!(call(&reg, "sht_unlock", &[s("never=>locked")], &req).0, 1, "unlocking a free key is harmless");

        // A second holder waits until the first unlocks.
        h.lock_key("k".into());
        let h2 = h.clone();
        let waiter = std::thread::spawn(move || {
            h2.lock_key("k".into());
            h2.unlock_key("k");
        });
        h.unlock_key("k");
        waiter.join().unwrap();
        assert!(lock(&h.locks.0).is_empty());
    }

    #[test]
    fn rpc_commands() {
        let (_, reg, t) = abc();
        assert_eq!(rpc(&reg, "htable.get", json!(["t", "a1"])), Ok(json!("x")));
        assert_eq!(rpc(&reg, "htable.get", json!(["t", "zz"])), Err("key not found".into()));
        assert!(rpc(&reg, "htable.get", json!(["nope", "a1"])).unwrap_err().contains("no table"));
        assert_eq!(rpc(&reg, "htable.seti", json!(["t", "n", 5])), Ok(json!(0)));
        assert_eq!(rpc(&reg, "htable.get", json!(["t", "n"])), Ok(json!(5)));
        assert!(rpc(&reg, "htable.seti", json!(["t", "n", "five"])).is_err());
        assert_eq!(rpc(&reg, "htable.sets", json!(["t", "s", "str"])), Ok(json!(0)));
        assert_eq!(t.get("s"), Val::str("str"));
        assert_eq!(rpc(&reg, "htable.delete", json!(["t", "s"])), Ok(json!(0)));
        assert_eq!(t.get("s"), Val::Null);
        assert!(rpc(&reg, "htable.delete", json!(["t"])).is_err(), "missing key");
        assert_eq!(rpc(&reg, "htable.dump", json!(["t"])).unwrap().as_array().unwrap().len(), 4);
        assert_eq!(rpc(&reg, "htable.flush", json!(["t"])), Ok(json!(4)));
        assert_eq!(rpc(&reg, "htable.dump", json!(["t"])), Ok(json!([])));
    }

    #[test]
    fn list_tables_is_sorted_by_name() {
        let db = TextDb::new(&[("ht", &format!("{HEADER}k:0:0:v:0\n"))]);
        let (_, reg) = load(&["zeta=>autoexpire=5", "alpha=>dbtable=ht;dbmode=1"], Some(&db.url()));
        assert_eq!(
            rpc(&reg, "htable.listTables", json!([])),
            Ok(json!([
                {"name": "alpha", "autoexpire": 0, "dbtable": "ht", "dbmode": 1, "items": 1},
                {"name": "zeta", "autoexpire": 5, "dbtable": null, "dbmode": 0, "items": 0},
            ]))
        );
    }
}
