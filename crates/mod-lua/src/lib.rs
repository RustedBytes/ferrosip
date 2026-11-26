//! `app_lua` — Lua routing logic (Lua 5.4, built in) with a KEMI-style
//! API: `KSR.<module>.<function>(…)` calls any exported script function
//! by name (`KSR.sl.sl_send_reply(404, "Not here")`, `KSR.tm.t_relay()`,
//! `KSR.registrar.save("location")`), plus `KSR.pv.get/sets/seti/unset/
//! is_null`, `KSR.hdr.append/remove/is_present`, `KSR.info/dbg/warn/err/
//! notice/crit`, `KSR.x.exit()` / `KSR.x.drop()`.
//!
//! Script functions: `lua_dofile(path)`, `lua_runstring(code)`,
//! `lua_run(function[, p1[, p2[, p3]]])` (returns what the Lua function
//! returns when it's a number, else 1). `modparam("app_lua", "load",
//! "/path/script.lua")` loads a file into every worker's Lua state; RPC
//! `app_lua.reload` re-reads and checks it; each worker switches before its
//! next call (a broken file is refused and the old script stays).
//!
//! Each worker thread has its own Lua state; arguments given to `KSR`
//! functions are fixed up once per distinct call and cached.

use mlua::{Lua, MultiValue, Value};
use sip_core::module::Fixed;
use sip_core::pv::{PvRef, Val, parse_fmt, parse_pv};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry, RouteHub};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["app_lua"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    match name {
        "app_lua" => Some(Arc::new(AppLua::default())),
        _ => None,
    }
}

const PRELUDE: &str = r#"
local function logger(level) return function(msg) __ksr_log(level, tostring(msg)) end end
local alias = {
  hdr = { append = "append_hf", remove = "remove_hf", is_present = "is_present_hf", insert = "insert_hf" },
}
KSR = {
  info = logger(3), dbg = logger(4), notice = logger(2), warn = logger(1), err = logger(0), crit = logger(-2),
  x = { exit = function() error("__ksr_exit__", 0) end, drop = function() error("__ksr_drop__", 0) end },
  pv = {
    get = function(n) return __ksr_pv_get(n) end,
    gete = function(n) local v = __ksr_pv_get(n); if v == nil then return "" end; return v end,
    sets = function(n, v) return __ksr_pv_set(n, tostring(v)) end,
    seti = function(n, v) return __ksr_pv_set(n, math.tointeger(v) or 0) end,
    unset = function(n) return __ksr_pv_set(n, nil) end,
    is_null = function(n) return __ksr_pv_get(n) == nil end,
  },
}
setmetatable(KSR, { __index = function(_, mod)
  local m = setmetatable({}, { __index = function(_, fname)
    local real = (alias[mod] and alias[mod][fname]) or fname
    return function(...) return __ksr_call(real, ...) end
  end })
  rawset(KSR, mod, m)
  return m
end })
"#;

#[derive(Default)]
pub struct AppLua {
    load: Mutex<Option<String>>,
    /// Bumped by `app_lua.reload`.
    generation: AtomicU64,
    /// The script as read and checked at startup or by the last
    /// `app_lua.reload`: what every worker's state runs (later edits to the
    /// file wait for a reload, as in Kamailio).
    code: Mutex<Option<(String, Arc<str>)>>,
    hub: OnceLock<Arc<RouteHub>>,
}

struct State {
    lua: Lua,
    generation: u64,
    fixups: HashMap<String, Arc<Fixed>>,
    pvs: HashMap<String, Option<PvRef>>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// Why a Lua call ended.
enum End {
    Ret(i32),
    Exit,
}

/// A Lua float where an integer is wanted: truncated toward zero,
/// saturating at the ends, NaN as 0.
#[allow(clippy::cast_possible_truncation, reason = "float to int: `as` truncates toward zero and saturates, the conversion wanted")]
fn num_to_int(n: f64) -> i64 {
    n.trunc() as i64
}

/// A Lua return value as a route return code (a C `int` in Kamailio): out of
/// range saturates, keeping the sign (true / false), instead of wrapping.
fn ret_code(i: i64) -> i32 {
    i32::try_from(i).unwrap_or(if i < 0 { i32::MIN } else { i32::MAX })
}

fn lua_to_val(v: &Value) -> Val {
    match v {
        Value::Integer(i) => Val::Int(*i),
        Value::Number(n) => Val::Int(num_to_int(*n)),
        Value::String(s) => Val::Str(s.to_string_lossy()),
        Value::Boolean(b) => Val::Int(i64::from(*b)),
        _ => Val::Null,
    }
}

impl AppLua {
    /// A Lua state running `code` (path, source).
    fn state_with(&self, code: Option<&(String, Arc<str>)>) -> Result<State, String> {
        let lua = Lua::new();
        lua.load(PRELUDE).exec().map_err(|e| format!("app_lua prelude: {e}"))?;
        if let Some((path, src)) = code {
            lua.load(&**src).set_name(path.as_str()).exec().map_err(|e| format!("app_lua {path}: {e}"))?;
        }
        Ok(State { lua, generation: self.generation.load(Ordering::Relaxed), fixups: HashMap::new(), pvs: HashMap::new() })
    }

    /// A state for this worker, from the checked copy of the script.
    fn new_state(&self) -> Result<State, String> {
        let code = lock(&self.code).clone();
        self.state_with(code.as_ref())
    }

    /// Read and check the script file; on success it becomes what workers run.
    fn load_file(&self) -> Result<(), String> {
        let Some(path) = lock(&self.load).clone() else { return Ok(()) };
        let src = std::fs::read_to_string(&path).map_err(|e| format!("app_lua {path}: {e}"))?;
        let code = (path, Arc::<str>::from(src));
        self.state_with(Some(&code))?;
        *lock(&self.code) = Some(code);
        Ok(())
    }

    /// Run `f` (which gets the Lua state) with the KSR bridge bound to `ctx`.
    fn with_ctx(&self, ctx: &mut Ctx<'_, '_>, f: impl FnOnce(&Lua) -> mlua::Result<MultiValue>) -> End {
        let runner = self.hub.get().and_then(|h| h.runner()).cloned();
        STATE.with(|st| {
            let mut st = st.borrow_mut();
            let stale = st.as_ref().is_none_or(|s| s.generation != self.generation.load(Ordering::Relaxed));
            let state = match &mut *st {
                Some(s) if !stale => s,
                _ => match self.new_state() {
                    Ok(s) => st.insert(s),
                    Err(e) => {
                        sip_core::log::log(sip_core::log::L_ERR, &e);
                        return End::Ret(-1);
                    }
                },
            };
            let (lua, fixups_cell, pvs_cell) = (&state.lua, RefCell::new(&mut state.fixups), RefCell::new(&mut state.pvs));
            let (fixups, pvs) = (&fixups_cell, &pvs_cell);
            let ctx_cell = RefCell::new(ctx);
            let ctx = &ctx_cell;
            let Some(runner) = runner else { return End::Ret(-1) };
            let runner = &runner;
            let table = runner.pv_table();
            let pvref = |name: &str| -> Option<PvRef> {
                let mut c = pvs.borrow_mut();
                c.entry(name.to_string()).or_insert_with(|| table.and_then(|t| parse_pv(name, t).ok())).clone()
            };
            let pvref = &pvref;
            let res = lua.scope(|scope| {
                let g = lua.globals();
                g.set(
                    "__ksr_log",
                    scope.create_function(|_, (lvl, msg): (i32, String)| {
                        sip_core::log::log(lvl, &msg);
                        Ok(())
                    })?,
                )?;
                g.set(
                    "__ksr_pv_get",
                    scope.create_function(move |lua, name: String| {
                        let Some(pv) = pvref(&name) else { return Ok(Value::Nil) };
                        let v = pv.get(&mut ctx.borrow_mut());
                        Ok(match v {
                            Val::Null => Value::Nil,
                            Val::Int(i) => Value::Integer(i),
                            Val::Str(s) => Value::String(lua.create_string(&s)?),
                        })
                    })?,
                )?;
                g.set(
                    "__ksr_pv_set",
                    scope.create_function(move |_, (name, v): (String, Value)| {
                        let Some(pv) = pvref(&name) else { return Ok(-1) };
                        Ok(if pv.set(&mut ctx.borrow_mut(), lua_to_val(&v)).is_ok() { 1 } else { -1 })
                    })?,
                )?;
                g.set(
                    "__ksr_call",
                    scope.create_function(move |_, args: MultiValue| {
                        let mut it = args.into_iter();
                        let Some(Value::String(fname)) = it.next() else { return Err(mlua::Error::RuntimeError("KSR: missing function name".into())) };
                        let fname = fname.to_string_lossy();
                        let Some(ex) = runner.export(&fname) else { return Err(mlua::Error::RuntimeError(format!("KSR: no function {fname}"))) };
                        let rest: Vec<Value> = it.collect();
                        let key = fixup_key(&fname, &rest);
                        let fixed = {
                            let mut c = fixups.borrow_mut();
                            match c.get(&key) {
                                Some(f) => f.clone(),
                                None => {
                                    let mut args = Vec::with_capacity(rest.len());
                                    for v in &rest {
                                        args.push(match v {
                                            Value::Integer(i) => Arg::Int(*i),
                                            Value::Number(n) => Arg::Int(num_to_int(*n)),
                                            Value::Boolean(b) => Arg::Int(i64::from(*b)),
                                            Value::String(s) => {
                                                let s = s.to_string_lossy();
                                                match table.filter(|_| s.contains('$')).map(|t| parse_fmt(&s, t)) {
                                                    Some(Ok(f)) => Arg::Fmt(Arc::new(f)),
                                                    _ => Arg::Str(s),
                                                }
                                            }
                                            _ => Arg::Str(String::new()),
                                        });
                                    }
                                    let f: Arc<Fixed> = Arc::new((ex.fixup)(&args).map_err(|e| mlua::Error::RuntimeError(format!("KSR.{fname}: {e}")))?);
                                    c.insert(key, f.clone());
                                    f
                                }
                            }
                        };
                        let rc = (ex.func)(&mut ctx.borrow_mut(), &**fixed);
                        ctx.borrow_mut().rc = rc;
                        if rc == 0 {
                            return Err(mlua::Error::RuntimeError("__ksr_exit__".into()));
                        }
                        Ok(rc)
                    })?,
                )?;
                f(lua)
            });
            match res {
                Ok(v) => End::Ret(match v.into_iter().next() {
                    Some(Value::Integer(i)) => ret_code(i),
                    Some(Value::Number(n)) => ret_code(num_to_int(n)),
                    Some(Value::Boolean(false)) => -1,
                    _ => 1,
                }),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("__ksr_exit__") || msg.contains("__ksr_drop__") {
                        End::Exit
                    } else {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("app_lua: {msg}"));
                        End::Ret(-1)
                    }
                }
            }
        })
    }

    fn rc(e: End) -> i32 {
        match e {
            End::Ret(0) => -1,
            End::Ret(n) => n,
            End::Exit => 0,
        }
    }
}

/// The fixup cache key of a `KSR` call. Arguments that fix up to an empty
/// string (tables, functions, nil…) share one key: their `Debug` form holds
/// an address, which would add a cache entry per call.
fn fixup_key(fname: &str, args: &[Value]) -> String {
    let mut key = fname.to_string();
    for v in args {
        key.push('\u{0}');
        match v {
            Value::Integer(_) | Value::Number(_) | Value::Boolean(_) | Value::String(_) => key.push_str(&format!("{v:?}")),
            _ => key.push('_'),
        }
    }
    key
}

fn dyn_args(a: &[Arg], min: usize, max: usize) -> Result<Vec<sip_core::module::DynStr>, String> {
    if a.len() < min || a.len() > max {
        return Err(format!("expected {min}..{max} arguments"));
    }
    a.iter().map(Arg::dyn_str).collect()
}

impl Module for AppLua {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("load", Ty::Str, "", "Lua script loaded into every worker's Lua state")])
    }

    fn name(&self) -> &'static str {
        "app_lua"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "load" => *lock(&self.load) = Some(v.str()?.into()),
            "reload" | "log_mode" => {}
            _ => return Err(format!("app_lua: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const RUN: &[Param] = &[arg("function", Str).eg("\"route\""), opt("p1", Str), opt("p2", Str), opt("p3", Str)];
        const CODE: &[Param] = &[arg("code", Str).eg("\"return 1\"")];
        const PATH: &[Param] = &[arg("path", Str).eg("\"/etc/ferrosip/route.lua\"")];
        Some(vec![
            sig(
                "lua_run",
                "run",
                RUN,
                Ret::Bool,
                "Call a function of the loaded Lua script with up to three string arguments; false when it fails or returns < 0",
            )
            .allowed(ctx::ANY),
            sig("lua_runstring", "run_string", CODE, Ret::Bool, "Run a piece of Lua code").allowed(ctx::ANY),
            sig("lua_dofile", "run_file", PATH, Ret::Bool, "Run a Lua file").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        // Read and check the script at startup.
        self.load_file()?;
        let _ = self.hub.set(reg.hub.clone());
        let m = "app_lua";
        let me = self.clone();
        reg.export(
            m,
            "lua_run",
            |a: &[Arg]| dyn_args(a, 1, 4),
            move |ctx: &mut Ctx, a: &Vec<sip_core::module::DynStr>| {
                let v: Vec<String> = a.iter().map(|x| x.eval(ctx).into_owned()).collect();
                // The fixup takes 1 to 4 arguments: the function, then its own.
                let Some((name, rest)) = v.split_first() else { return -1 };
                AppLua::rc(me.with_ctx(ctx, |lua| {
                    let f: mlua::Function = lua.globals().get(name.as_str())?;
                    let args = rest.iter().map(|s| lua.create_string(s).map(Value::String)).collect::<mlua::Result<MultiValue>>()?;
                    f.call::<MultiValue>(args)
                }))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "lua_runstring",
            |a: &[Arg]| dyn_args(a, 1, 1),
            move |ctx: &mut Ctx, a: &Vec<sip_core::module::DynStr>| {
                let Some(code) = a.first() else { return -1 };
                let code = code.eval(ctx).into_owned();
                AppLua::rc(me.with_ctx(ctx, |lua| lua.load(&code).eval::<MultiValue>()))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "lua_dofile",
            |a: &[Arg]| dyn_args(a, 1, 1),
            move |ctx: &mut Ctx, a: &Vec<sip_core::module::DynStr>| {
                let Some(path) = a.first() else { return -1 };
                let path = path.eval(ctx).into_owned();
                let Ok(code) = std::fs::read_to_string(&path) else { return -1 };
                AppLua::rc(me.with_ctx(ctx, |lua| lua.load(&code).set_name(path.as_str()).eval::<MultiValue>()))
            },
        );
        let me = self.clone();
        reg.rpc.add("app_lua.reload", "Reload the Lua script in every worker", move |_| {
            // A broken script is refused and the workers keep the old one.
            me.load_file()?;
            // The new generation (fetch_add wraps; so does this).
            Ok(json!(me.generation.fetch_add(1, Ordering::Relaxed).wrapping_add(1)))
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_to_ints() {
        assert_eq!(num_to_int(2.9), 2);
        assert_eq!(num_to_int(-2.9), -2);
        assert_eq!(num_to_int(f64::NAN), 0);
        assert_eq!(num_to_int(1e300), i64::MAX);
        assert_eq!(ret_code(-1), -1);
        // 2^32 saturates; wrapping would give 0, which a route reads as exit.
        assert_eq!(ret_code(1 << 32), i32::MAX);
        assert_eq!(ret_code(i64::MIN), i32::MIN);
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;
    use sip_core::{Dest, Outbound, Proto, RouteNames, RouteRunner};

    #[test]
    fn num_to_int_truncates_and_saturates() {
        let cases = [
            (0.0, 0),
            (-0.0, 0),
            (0.999, 0),
            (-0.999, 0),
            (7.5, 7),
            (-7.5, -7),
            (9.007_199_254_740_993e15, 9_007_199_254_740_992),
            (9.3e18, i64::MAX),
            (-9.3e18, i64::MIN),
            (f64::INFINITY, i64::MAX),
            (f64::NEG_INFINITY, i64::MIN),
            (f64::NAN, 0),
        ];
        for (n, want) in cases {
            assert_eq!(num_to_int(n), want, "{n}");
        }
    }

    #[test]
    fn ret_code_saturates_keeping_the_sign() {
        let cases = [
            (0, 0),
            (1, 1),
            (-1, -1),
            (i64::from(i32::MAX), i32::MAX),
            (i64::from(i32::MAX) + 1, i32::MAX),
            (i64::from(i32::MIN), i32::MIN),
            (i64::from(i32::MIN) - 1, i32::MIN),
            (1 << 32, i32::MAX),
            (-(1 << 32), i32::MIN),
            (i64::MAX, i32::MAX),
            (i64::MIN, i32::MIN),
        ];
        for (i, want) in cases {
            assert_eq!(ret_code(i), want, "{i}");
        }
    }

    #[test]
    fn lua_values_to_script_values() {
        let lua = Lua::new();
        let cases = [
            (Value::Integer(-3), Val::Int(-3)),
            (Value::Number(2.9), Val::Int(2)),
            (Value::Number(f64::NAN), Val::Int(0)),
            (Value::Boolean(true), Val::Int(1)),
            (Value::Boolean(false), Val::Int(0)),
            (Value::String(lua.create_string("abc").unwrap()), Val::Str("abc".into())),
            (Value::String(lua.create_string(b"\xff").unwrap()), Val::Str("\u{fffd}".into())),
            (Value::Nil, Val::Null),
            (Value::Table(lua.create_table().unwrap()), Val::Null),
        ];
        for (v, want) in cases {
            assert_eq!(lua_to_val(&v), want, "{v:?}");
        }
    }

    #[test]
    fn end_to_route_code() {
        assert_eq!(AppLua::rc(End::Ret(5)), 5);
        assert_eq!(AppLua::rc(End::Ret(-2)), -2);
        assert_eq!(AppLua::rc(End::Ret(0)), -1, "0 would end the route: false instead");
        assert_eq!(AppLua::rc(End::Exit), 0);
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

    /// The script runner: one event route that calls `lua_runstring(code)`.
    struct Runner {
        call: OnceLock<(sip_core::ExportFn, Fixed)>,
        rc: Mutex<i32>,
    }
    impl RouteRunner for Runner {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            if let Some((f, fixed)) = self.call.get() {
                *lock(&self.rc) = f(ctx, &**fixed);
            }
            true
        }
    }

    /// The route return code of `lua_runstring(code)`.
    fn runstring(code: &str) -> i32 {
        let mut reg = Registry::default();
        let runner = Arc::new(Runner { call: OnceLock::new(), rc: Mutex::new(i32::MIN) });
        reg.hub.set_names(RouteNames { event: vec!["e".into()], ..Default::default() });
        reg.hub.set_runner(runner.clone());
        reg.load(Arc::new(AppLua::default())).unwrap();
        let e = reg.get("lua_runstring").unwrap();
        let _ = runner.call.set((e.func.clone(), (e.fixup)(&[Arg::Str(code.into())]).unwrap()));
        reg.hub.run_event_with("e", &NoNet, None, |_| {});
        *lock(&runner.rc)
    }

    #[test]
    fn lua_return_values_become_route_codes() {
        let cases: &[(&str, i32)] = &[
            ("return 5", 5),
            ("return -3", -3),
            ("return 0", -1),
            ("return 2.9", 2),
            ("return -2.9", -2),
            ("return 0.5", -1),
            ("return 0/0", -1),
            ("return 1 << 40", i32::MAX),
            ("return 2^40", i32::MAX),
            ("return -(2^40)", i32::MIN),
            ("return math.mininteger", i32::MIN),
            ("return true", 1),
            ("return false", -1),
            ("return nil", 1),
            ("return 'text'", 1),
            ("return {}", 1),
            ("return 7, -1", 7),
            ("local x = 1", 1),
            ("KSR.x.exit()", 0),
            ("KSR.x.drop()", 0),
            ("error('boom')", -1),
            ("this is not lua", -1),
            ("KSR.nomodule.nofunction()", -1),
        ];
        for &(code, want) in cases {
            assert_eq!(runstring(code), want, "{code:?}");
        }
    }

    #[test]
    fn params_and_arguments() {
        let a = AppLua::default();
        a.set_param("load", &Arg::Str("/x.lua".into())).unwrap();
        assert_eq!(lock(&a.load).as_deref(), Some("/x.lua"));
        assert!(a.set_param("nope", &Arg::Int(1)).is_err());
        assert!(a.load_file().is_err(), "a missing file is refused");
        assert!(dyn_args(&[], 1, 4).is_err());
        assert_eq!(dyn_args(&[Arg::Str("f".into()), Arg::Int(2)], 1, 4).unwrap().len(), 2);
        assert!(dyn_args(&[Arg::Int(1), Arg::Int(2)], 1, 1).is_err());
    }
}

#[cfg(test)]
mod ksr_tests {
    use super::*;
    use sip_core::ExportFn;
    use sip_core::module::Export;
    use sip_core::pv::{PvSpec, PvTable};
    use sip_core::{Dest, Outbound, Proto, RouteNames, RouteRunner};
    use std::sync::atomic::AtomicUsize;

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    /// One event route that calls a single exported function; `$var(name)`
    /// (read-write) and `$ro` (read-only, 7) as variables, and the
    /// registry's exports reachable from `KSR`.
    struct Runner {
        call: OnceLock<(ExportFn, Fixed)>,
        rc: Mutex<i32>,
        table: PvTable,
        exports: OnceLock<HashMap<String, Export>>,
    }
    impl RouteRunner for Runner {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            if let Some((f, fixed)) = self.call.get() {
                *lock(&self.rc) = f(ctx, &**fixed);
            }
            true
        }
        fn export(&self, name: &str) -> Option<Export> {
            self.exports.get()?.get(name).cloned()
        }
        fn pv_table(&self) -> Option<&PvTable> {
            Some(&self.table)
        }
    }

    /// What the test exports saw.
    #[derive(Default)]
    struct Seen {
        /// `t_args` calls: their arguments as fixed up.
        args: Mutex<Vec<String>>,
        /// How many times `t_args` was fixed up.
        fixups: AtomicUsize,
        vars: Arc<Mutex<HashMap<String, Val>>>,
    }

    fn describe(a: &[Arg]) -> String {
        a.iter()
            .map(|x| match x {
                Arg::Int(i) => format!("i:{i}"),
                Arg::Str(s) => format!("s:{s}"),
                Arg::Fmt(_) => "fmt".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A generation no Lua state of this thread has: the run gets a fresh one.
    fn fresh_generation(app: &AppLua) {
        static NEXT: AtomicU64 = AtomicU64::new(1 << 40);
        app.generation.store(NEXT.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
    }

    /// The route return code of `func(args)` (an app_lua export), with the
    /// test exports `t_args(…)` (records its arguments, returns 1) and
    /// `t_rc(n)` (returns n) callable from Lua.
    fn run_with(app: Arc<AppLua>, func: &str, args: &[Arg], seen: &Arc<Seen>) -> i32 {
        let mut reg = Registry::default();
        let vars = seen.vars.clone();
        let vars2 = seen.vars.clone();
        let mut table = PvTable::new();
        table.insert(
            "var".into(),
            PvSpec::rw(
                move |_, p| lock(&vars).get(&p.name).cloned().unwrap_or(Val::Null),
                move |_, p, v| {
                    let mut g = lock(&vars2);
                    if v == Val::Null {
                        g.remove(&p.name);
                    } else {
                        g.insert(p.name.clone(), v);
                    }
                    Ok(())
                },
            )
            .with_param(),
        );
        table.insert("ro".into(), PvSpec::ro(|_, _| Val::Int(7)));
        let runner = Arc::new(Runner { call: OnceLock::new(), rc: Mutex::new(i32::MIN), table, exports: OnceLock::new() });
        reg.hub.set_names(RouteNames { event: vec!["e".into()], ..Default::default() });
        reg.hub.set_runner(runner.clone());
        reg.load(app.clone()).unwrap();
        let (s1, s2) = (seen.clone(), seen.clone());
        reg.export(
            "t",
            "t_args",
            move |a: &[Arg]| {
                s1.fixups.fetch_add(1, Ordering::Relaxed);
                Ok(describe(a))
            },
            move |_: &mut Ctx, d: &String| {
                lock(&s2.args).push(d.clone());
                1
            },
        );
        reg.export(
            "t",
            "t_rc",
            |a: &[Arg]| match a {
                [Arg::Int(i)] => i32::try_from(*i).map_err(|e| e.to_string()),
                _ => Err("t_rc: one integer".to_string()),
            },
            |_: &mut Ctx, rc: &i32| *rc,
        );
        let exports = ["t_args", "t_rc", "lua_runstring", "lua_run", "lua_dofile"].iter().map(|n| (n.to_string(), reg.get(n).unwrap().clone())).collect();
        let _ = runner.exports.set(exports);
        let e = reg.get(func).unwrap();
        let _ = runner.call.set((e.func.clone(), (e.fixup)(args).unwrap()));
        fresh_generation(&app);
        reg.hub.run_event_with("e", &NoNet, None, |_| {});
        *lock(&runner.rc)
    }

    fn runstring(code: &str, seen: &Arc<Seen>) -> i32 {
        run_with(Arc::new(AppLua::default()), "lua_runstring", &[Arg::Str(code.into())], seen)
    }

    #[test]
    fn ksr_calls_convert_lua_arguments_once() {
        let seen = Arc::new(Seen::default());
        let code = r#"for _ = 1, 3 do KSR.t.t_args(1, 2.7, -2.7, true, false, "plain", "$var(x)@h", {}) end"#;
        assert_eq!(runstring(code, &seen), 1);
        assert_eq!(*lock(&seen.args), vec!["i:1 i:2 i:-2 i:1 i:0 s:plain fmt s:".to_string(); 3]);
        assert_eq!(seen.fixups.load(Ordering::Relaxed), 1, "the same call is fixed up once and cached");
        assert_eq!(runstring(r#"KSR.t.t_args("$nope")"#, &seen), 1);
        assert_eq!(lock(&seen.args).last().map(String::as_str), Some("s:$nope"), "a string with an unknown variable stays a string");
    }

    #[test]
    fn ksr_call_return_codes() {
        let seen = Arc::new(Seen::default());
        let cases: &[(&str, i32)] = &[
            ("return KSR.t.t_rc(5)", 5),
            ("return KSR.t.t_rc(-2)", -2),
            ("if KSR.t.t_rc(-2) < 0 then return 9 end", 9),
            ("KSR.t.t_rc(0); return 5", 0),
            ("KSR.t.t_rc('x'); return 5", -1),
            ("KSR.t.t_rc(1 << 40); return 5", -1),
            ("local ok = pcall(KSR.t.t_rc, 'x'); return ok and 1 or 3", 3),
        ];
        for &(code, want) in cases {
            assert_eq!(runstring(code, &seen), want, "{code:?}");
        }
    }

    #[test]
    fn ksr_pv_reads_and_writes_variables() {
        let seen = Arc::new(Seen::default());
        let cases: &[(&str, i32)] = &[
            (r#"KSR.pv.seti("$var(n)", 42); return KSR.pv.get("$var(n)")"#, 42),
            (r#"KSR.pv.seti("$var(n)", 2.9); return KSR.pv.get("$var(n)") + 10"#, 10),
            (r#"KSR.pv.seti("$var(n)", "x"); return KSR.pv.get("$var(n)") + 10"#, 10),
            (r#"KSR.pv.sets("$var(s)", 12); return KSR.pv.get("$var(s)") == "12" and 1 or 2"#, 1),
            (r#"KSR.pv.unset("$var(s)"); return KSR.pv.is_null("$var(s)") and 1 or 2"#, 1),
            (r#"return KSR.pv.gete("$var(none)") == "" and 1 or 2"#, 1),
            (r#"return KSR.pv.get("$var(none)") == nil and 1 or 2"#, 1),
            (r#"return KSR.pv.get("$ro")"#, 7),
            (r#"return KSR.pv.sets("$ro", "x")"#, -1),
            (r#"return KSR.pv.sets("$nope", "x")"#, -1),
            (r#"return KSR.pv.get("$nope") == nil and 1 or 2"#, 1),
        ];
        for &(code, want) in cases {
            assert_eq!(runstring(code, &seen), want, "{code:?}");
        }
        assert_eq!(lock(&seen.vars).get("n"), Some(&Val::Int(0)), "seti of a non-number sets 0");
    }

    #[test]
    fn ksr_log_functions_return_normally() {
        let seen = Arc::new(Seen::default());
        let code = "KSR.info('i'); KSR.dbg('d'); KSR.notice('n'); KSR.warn('w'); KSR.err('e'); KSR.crit({}); return 4";
        assert_eq!(runstring(code, &seen), 4);
    }

    #[test]
    fn a_script_that_fails_to_load_in_a_worker_fails_the_call() {
        let app = Arc::new(AppLua::default());
        let mut reg = Registry::default();
        reg.load(app.clone()).unwrap();
        // load_file refuses such a script; set it directly so the worker's state fails to build.
        *lock(&app.code) = Some(("broken.lua".into(), Arc::from("error('at load')")));
        fresh_generation(&app);
        let e = reg.get("lua_runstring").unwrap();
        let runner = Arc::new(Runner { call: OnceLock::new(), rc: Mutex::new(i32::MIN), table: PvTable::new(), exports: OnceLock::new() });
        let _ = runner.call.set((e.func.clone(), (e.fixup)(&[Arg::Str("return 5".into())]).unwrap()));
        reg.hub.set_names(RouteNames { event: vec!["e".into()], ..Default::default() });
        reg.hub.set_runner(runner.clone());
        reg.hub.run_event_with("e", &NoNet, None, |_| {});
        assert_eq!(*lock(&runner.rc), -1);
    }

    #[test]
    fn lua_dofile_runs_a_file() {
        let dir = std::env::temp_dir().join(format!("ferrosip-mod-lua-dofile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ok = dir.join("ok.lua");
        let bad = dir.join("bad.lua");
        std::fs::write(&ok, "local x = 6\nreturn x + 1\n").unwrap();
        std::fs::write(&bad, "return (\n").unwrap();
        let seen = Arc::new(Seen::default());
        let dofile = |p: &std::path::Path| run_with(Arc::new(AppLua::default()), "lua_dofile", &[Arg::Str(p.display().to_string())], &seen);
        assert_eq!(dofile(&ok), 7);
        assert_eq!(dofile(&bad), -1, "a syntax error");
        assert_eq!(dofile(&dir.join("missing.lua")), -1, "a file that can't be read");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lua_run_calls_a_global_function_with_string_arguments() {
        let seen = Arc::new(Seen::default());
        let dir = std::env::temp_dir().join(format!("ferrosip-mod-lua-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.lua");
        std::fs::write(&path, "function f(a, b, c) return #(a .. b .. c) end\nfunction g() return nil end\n").unwrap();
        let app = || {
            let a = AppLua::default();
            a.set_param("load", &Arg::Str(path.display().to_string())).unwrap();
            Arc::new(a)
        };
        let s = |v: &str| Arg::Str(v.into());
        assert_eq!(run_with(app(), "lua_run", &[s("f"), s("ab"), s("c"), s("def")], &seen), 6);
        assert_eq!(run_with(app(), "lua_run", &[s("g")], &seen), 1);
        assert_eq!(run_with(app(), "lua_run", &[s("nofunc")], &seen), -1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ignored_kamailio_parameters_are_accepted() {
        let a = AppLua::default();
        for name in ["reload", "log_mode"] {
            a.set_param(name, &Arg::Int(1)).unwrap();
        }
        assert!(lock(&a.load).is_none(), "they change nothing");
    }
}
