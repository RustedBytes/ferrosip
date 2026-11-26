//! `xlog`, `cfgutils`, `corex`, `kex`, `statistics`, `pv`, `ipops`.

use crate::{args, dyn_args, dyn_arr, pv_arg};
use sip_core::log;
use sip_core::module::{Branch, DynInt, DynStr, FakedMsg, rc};
use sip_core::pv::{PvRef, PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry, TxnVars, want_args};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
    (h.finish() >> 32) as u32
}

// ---------------------------------------------------------------- xlog ---

pub struct Xlog;

#[derive(Clone)]
enum Level {
    Fixed(i32),
    Dyn(DynStr),
}

impl Module for Xlog {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "xlog"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const LEVEL_TEXT: &[Param] = &[arg("level", Enum(&["error", "warn", "notice", "info", "debug", "alert", "critical", "bug"])).lit(), arg("text", Str)];
        const TEXT: &[Param] = &[arg("text", Str)];
        let at = |name, fsr, doc| sig(name, fsr, TEXT, Ret::Void, doc).ns("log").allowed(ctx::ANY);
        Some(vec![
            sig("xlog", "write", LEVEL_TEXT, Ret::Void, "Log the text (variables expanded) at this level").ns("log").allowed(ctx::ANY),
            sig("xlogl", "write_line", LEVEL_TEXT, Ret::Void, "Log the text at this level (Kamailio adds the config line)").ns("log").allowed(ctx::ANY),
            at("xalert", "alert", "Log the text at level alert"),
            at("xcrit", "critical", "Log the text at level critical"),
            at("xerr", "error", "Log the text at level error"),
            at("xwarn", "warn", "Log the text at level warning"),
            at("xnotice", "notice", "Log the text at level notice"),
            at("xinfo", "info", "Log the text at level info"),
            at("xdbg", "debug", "Log the text at level debug"),
            at("xbug", "bug", "Log the text at level bug"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let fix = |a: &[Arg]| -> Result<(Level, DynStr), String> {
            match a {
                [fmt] => Ok((Level::Fixed(log::L_ERR), fmt.dyn_str()?)),
                [level, fmt] => {
                    let l = match level {
                        Arg::Str(s) => Level::Fixed(log::parse(s).ok_or_else(|| format!("unknown log level {s:?}"))?),
                        Arg::Int(i) => Level::Fixed(i32::try_from(*i).map_err(|_| format!("log level {i} out of range"))?),
                        x => Level::Dyn(x.dyn_str()?),
                    };
                    Ok((l, fmt.dyn_str()?))
                }
                _ => Err("xlog([level,] format)".into()),
            }
        };
        let run = |ctx: &mut Ctx, (l, f): &(Level, DynStr)| {
            let lvl = match l {
                Level::Fixed(l) => *l,
                Level::Dyn(d) => log::parse(&d.eval(ctx)).unwrap_or(log::L_ERR),
            };
            if lvl <= log::level() {
                let msg = f.eval(ctx).into_owned();
                log::log(lvl, &msg);
            }
            1
        };
        reg.export("xlog", "xlog", fix, run);
        reg.export("xlog", "xlogl", fix, run);
        for (name, lvl) in [
            ("xalert", log::L_ALERT),
            ("xcrit", log::L_CRIT),
            ("xerr", log::L_ERR),
            ("xwarn", log::L_WARN),
            ("xnotice", log::L_NOTICE),
            ("xinfo", log::L_INFO),
            ("xdbg", log::L_DBG),
            ("xbug", log::L_BUG),
        ] {
            reg.export(
                "xlog",
                name,
                |a: &[Arg]| {
                    let [f] = args(a)?;
                    f.dyn_str()
                },
                move |ctx: &mut Ctx, f: &DynStr| {
                    if lvl <= log::level() {
                        let msg = f.eval(ctx).into_owned();
                        log::log(lvl, &msg);
                    }
                    1
                },
            );
        }
        Ok(())
    }
}

// ------------------------------------------------------------ cfgutils ---

pub struct CfgUtils {
    prob: AtomicU32,
    initial: AtomicU32,
    gflags: AtomicU64,
    locks: Mutex<HashSet<String>>,
    unlocked: Condvar,
}

impl Default for CfgUtils {
    fn default() -> Self {
        Self { prob: AtomicU32::new(10), initial: AtomicU32::new(10), gflags: AtomicU64::new(0), locks: Mutex::default(), unlocked: Condvar::new() }
    }
}

fn flag_bit(a: &[Arg]) -> Result<u64, String> {
    let [n] = args(a)?;
    let n = n.int()?;
    if !(0..64).contains(&n) {
        return Err(format!("flag {n} out of range 0..63"));
    }
    Ok(1u64 << n)
}

impl Module for CfgUtils {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("initial_probability", Ty::Int { min: 0, max: 100 }, "10", "Initial rand_event() probability in percent"),
            p("initial_gflags", UINT, "0", "Initial value of the global flags bitmask"),
        ])
    }

    fn name(&self) -> &'static str {
        "cfgutils"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const PERCENT: &[Param] = &[arg("percent", Int).lit().eg("50")];
        const SECS: &[Param] = &[arg("time", Duration(Unit::Sec))];
        const MICROS: &[Param] = &[arg("microseconds", Int)];
        const KEY: &[Param] = &[arg("key", Str)];
        const GFLAG: &[Param] = &[arg("flag", Int).lit()];
        Some(vec![
            sig("rand_event", "random_event", &[], Ret::Bool, "True with the current probability (percent)").allowed(ctx::ANY),
            sig("rand_set_prob", "set_probability", PERCENT, Ret::Void, "Set the random_event probability (0 to 100 percent)").allowed(ctx::ANY),
            sig("rand_reset_prob", "reset_probability", &[], Ret::Void, "Reset the random_event probability to its initial value").allowed(ctx::ANY),
            sig("rand_get_prob", "probability", &[], Ret::Void, "The random_event probability, as the return code").allowed(ctx::ANY),
            sig("sleep", "sleep", SECS, Ret::Void, "Block this worker for whole seconds").allowed(ctx::ANY),
            sig("usleep", "sleep_us", MICROS, Ret::Void, "Block this worker for microseconds").allowed(ctx::ANY),
            sig("lock", "lock", KEY, Ret::Void, "Take the named global lock (waits for it)").allowed(ctx::ANY),
            sig("trylock", "try_lock", KEY, Ret::Bool, "Take the named global lock if it is free").allowed(ctx::ANY),
            sig("unlock", "unlock", KEY, Ret::Bool, "Release the named global lock").allowed(ctx::ANY),
            sig("set_gflag", "set_global_flag", GFLAG, Ret::Void, "Set global flag 0..63 (shared by all processes)").allowed(ctx::ANY),
            sig("reset_gflag", "reset_global_flag", GFLAG, Ret::Void, "Clear global flag 0..63").allowed(ctx::ANY),
            sig("is_gflag", "has_global_flag", GFLAG, Ret::Bool, "Global flag 0..63 is set").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "initial_probability" => {
                let p = u32::try_from(v.int()?.clamp(0, 100)).unwrap_or(0);
                self.initial.store(p, Ordering::Relaxed);
                self.prob.store(p, Ordering::Relaxed);
            }
            // A bit mask: the i64 is taken bit for bit.
            "initial_gflags" => self.gflags.store(v.int()?.cast_unsigned(), Ordering::Relaxed),
            _ => return Err(format!("cfgutils: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "cfgutils";
        let me = self.clone();
        reg.export(m, "rand_event", |a: &[Arg]| want_args(a, 0), move |_: &mut Ctx, _: &()| rc(rand_u32() % 100 < me.prob.load(Ordering::Relaxed)));
        let me = self.clone();
        reg.export(
            m,
            "rand_set_prob",
            |a: &[Arg]| {
                let [p] = args(a)?;
                Ok(u32::try_from(p.int()?.clamp(0, 100)).unwrap_or(0))
            },
            move |_: &mut Ctx, p: &u32| {
                me.prob.store(*p, Ordering::Relaxed);
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "rand_reset_prob",
            |a: &[Arg]| want_args(a, 0),
            move |_: &mut Ctx, _: &()| {
                me.prob.store(me.initial.load(Ordering::Relaxed), Ordering::Relaxed);
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "rand_get_prob",
            |a: &[Arg]| want_args(a, 0),
            move |_: &mut Ctx, _: &()| i32::try_from(me.prob.load(Ordering::Relaxed)).unwrap_or(i32::MAX),
        );
        for (name, scale) in [("sleep", 1_000_000u64), ("usleep", 1)] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [d] = args(a)?;
                    d.dyn_int()
                },
                move |ctx: &mut Ctx, d: &DynInt| {
                    let n = d.eval(ctx).and_then(|n| u64::try_from(n).ok()).unwrap_or(0);
                    std::thread::sleep(std::time::Duration::from_micros(n.saturating_mul(scale)));
                    1
                },
            );
        }
        // lock(key) / trylock(key) / unlock(key): named global locks.
        let me = self.clone();
        reg.export(
            m,
            "lock",
            |a: &[Arg]| {
                let [k] = args(a)?;
                k.dyn_str()
            },
            move |ctx: &mut Ctx, k: &DynStr| {
                let k = k.eval(ctx).into_owned();
                let mut l = lock(&me.locks);
                while l.contains(&k) {
                    l = me.unlocked.wait(l).unwrap_or_else(|e| e.into_inner());
                }
                l.insert(k);
                1
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "trylock",
            |a: &[Arg]| {
                let [k] = args(a)?;
                k.dyn_str()
            },
            move |ctx: &mut Ctx, k: &DynStr| {
                let k = k.eval(ctx).into_owned();
                rc(lock(&me.locks).insert(k))
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "unlock",
            |a: &[Arg]| {
                let [k] = args(a)?;
                k.dyn_str()
            },
            move |ctx: &mut Ctx, k: &DynStr| {
                let k = k.eval(ctx).into_owned();
                let removed = lock(&me.locks).remove(&k);
                me.unlocked.notify_all();
                rc(removed)
            },
        );
        let me = self.clone();
        reg.export(m, "set_gflag", flag_bit, move |_: &mut Ctx, b: &u64| {
            me.gflags.fetch_or(*b, Ordering::Relaxed);
            1
        });
        let me = self.clone();
        reg.export(m, "reset_gflag", flag_bit, move |_: &mut Ctx, b: &u64| {
            me.gflags.fetch_and(!*b, Ordering::Relaxed);
            1
        });
        let me = self.clone();
        reg.export(m, "is_gflag", flag_bit, move |_: &mut Ctx, b: &u64| rc(me.gflags.load(Ordering::Relaxed) & b != 0));
        let me = self.clone();
        reg.rpc.add("cfgutils.get_prob", "Current rand_event probability (%)", move |_| Ok(sip_core::serde_json::json!(me.prob.load(Ordering::Relaxed))));
        let me = self.clone();
        reg.rpc.add("cfgutils.set_gflag", "Set global flag bits (mask)", move |p| {
            // A bit mask: the i64 is taken bit for bit.
            me.gflags.fetch_or(sip_core::rpc::int_param(p, 0)?.cast_unsigned(), Ordering::Relaxed);
            Ok(sip_core::serde_json::json!(me.gflags.load(Ordering::Relaxed)))
        });
        let me = self.clone();
        reg.rpc.add("cfgutils.get_gflags", "Global flags", move |_| Ok(sip_core::serde_json::json!(me.gflags.load(Ordering::Relaxed))));
        Ok(())
    }
}

// --------------------------------------------------------------- corex ---

pub struct Corex;

#[derive(Default)]
struct XFlags(u64);

impl Module for Corex {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "corex"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const DATA: &[Param] = &[arg("to", Uri), arg("data", Str)];
        const TO: &[Param] = &[opt("to", Uri)];
        const XFLAG: &[Param] = &[arg("flag", Int).lit()];
        const READ: &[Param] = &[arg("path", Str), arg("into", Var)];
        const WRITE: &[Param] = &[arg("path", Str), arg("content", Str)];
        Some(vec![
            sig("send_data", "send_data", DATA, Ret::Bool, "Send raw data to the URI's address").allowed(ctx::ANY),
            sig("send", "send", TO, Ret::Bool, "Forward the message as it is, statelessly (to `to`, or $du / the R-URI)"),
            sig("setxflag", "set_xflag", XFLAG, Ret::Void, "Set extended message flag 0..63"),
            sig("resetxflag", "reset_xflag", XFLAG, Ret::Void, "Clear extended message flag 0..63"),
            sig("isxflagset", "has_xflag", XFLAG, Ret::Bool, "Extended message flag 0..63 is set"),
            sig("is_faked_msg", "is_faked", &[], Ret::Bool, "The message is a faked one (built internally, e.g. for a local timeout)").allowed(ctx::ANY),
            sig("has_ruri_user", "ruri_has_user", &[], Ret::Bool, "The R-URI has a user part"),
            sig("file_read", "read_file", READ, Ret::Bool, "Read a file's contents into `into`").allowed(ctx::ANY),
            sig("file_write", "write_file", WRITE, Ret::Bool, "Write the text to a file (replacing it)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "corex";
        // send_data(uri, data): raw datagram/stream payload.
        reg.export(
            m,
            "send_data",
            |a: &[Arg]| {
                let [u, d] = dyn_arr(a)?;
                Ok((u, d))
            },
            |ctx: &mut Ctx, (u, d): &(DynStr, DynStr)| {
                let (u, d) = (u.eval(ctx).into_owned(), d.eval(ctx).into_owned());
                let Some(dst) = sip_core::pvcore::dest_from_uri(u.as_bytes()) else { return -1 };
                rc(ctx.send(&dst, d.as_bytes()).is_ok())
            },
        );
        // send([uri]): forward the message as it is (stateless, no Via).
        reg.export(
            m,
            "send",
            |a: &[Arg]| Ok(dyn_args(a, 0, 1)?.into_iter().next()),
            |ctx: &mut Ctx, u: &Option<DynStr>| {
                let dst = match u {
                    Some(u) => {
                        let u = u.eval(ctx).into_owned();
                        sip_core::pvcore::dest_from_uri(u.as_bytes())
                    }
                    None => ctx.dst.or_else(|| sip_core::pvcore::dest_from_uri(ctx.ruri())),
                };
                let Some(dst) = dst else { return -1 };
                rc(ctx.send_rendered(&dst).is_ok())
            },
        );
        reg.export(m, "setxflag", flag_bit, |ctx: &mut Ctx, b: &u64| {
            ctx.ext_mut::<XFlags>().0 |= b;
            1
        });
        reg.export(m, "resetxflag", flag_bit, |ctx: &mut Ctx, b: &u64| {
            ctx.ext_mut::<XFlags>().0 &= !b;
            1
        });
        reg.export(m, "isxflagset", flag_bit, |ctx: &mut Ctx, b: &u64| rc(ctx.ext::<XFlags>().is_some_and(|x| x.0 & b != 0)));
        reg.export(m, "is_faked_msg", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(ctx.ext::<FakedMsg>().is_some()));
        reg.export(
            m,
            "has_ruri_user",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| rc(sip_parser::parse_uri(ctx.ruri()).and_then(|u| u.user).is_some_and(|u| !u.is_empty())),
        );
        reg.export(
            m,
            "file_read",
            |a: &[Arg]| {
                let [p, out] = args(a)?;
                Ok((p.dyn_str()?, pv_arg(out)?))
            },
            |ctx: &mut Ctx, (p, out): &(DynStr, PvRef)| {
                let p = p.eval(ctx).into_owned();
                match std::fs::read_to_string(&p) {
                    Ok(s) => rc(out.set(ctx, Val::Str(s)).is_ok()),
                    Err(_) => -1,
                }
            },
        );
        reg.export(
            m,
            "file_write",
            |a: &[Arg]| {
                let [p, s] = dyn_arr(a)?;
                Ok((p, s))
            },
            |ctx: &mut Ctx, (p, s): &(DynStr, DynStr)| {
                let (p, s) = (p.eval(ctx).into_owned(), s.eval(ctx).into_owned());
                rc(std::fs::write(p, s).is_ok())
            },
        );
        Ok(())
    }
}

// ----------------------------------------------------------------- kex ---

pub struct Kex;

#[derive(Default)]
struct SFlags(u64);

impl Module for Kex {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "kex"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const SFLAG: &[Param] = &[arg("flag", Int).lit()];
        const URI: &[Param] = &[arg("uri", Uri)];
        const PRINTF: &[Param] = &[arg("into", Var), arg("text", Str)];
        const BRANCH: &[Param] = &[opt("uri", Uri)];
        const LEVEL: &[Param] = &[arg("level", Int)];
        Some(vec![
            sig("setsflag", "set_sflag", SFLAG, Ret::Void, "Set script flag 0..63 (kept for the transaction)"),
            sig("resetsflag", "reset_sflag", SFLAG, Ret::Void, "Clear script flag 0..63"),
            sig("issflagset", "has_sflag", SFLAG, Ret::Bool, "Script flag 0..63 is set"),
            sig("setdsturi", "set_dst", URI, Ret::Bool, "Set the destination URI ($du): where the request is sent"),
            sig("resetdsturi", "reset_dst", &[], Ret::Void, "Clear the destination URI ($du)"),
            sig("isdsturiset", "has_dst", &[], Ret::Bool, "A destination URI ($du) is set"),
            sig("pv_printf", "printf", PRINTF, Ret::Bool, "Store the text (variables expanded) in `into`").allowed(ctx::ANY),
            sig("km_append_branch", "append_branch", BRANCH, Ret::Void, "Add a branch for this URI (default: the R-URI and $du)"),
            sig("setdebug", "set_debug", LEVEL, Ret::Void, "Set the log level (number) for this process").allowed(ctx::ANY),
            sig("resetdebug", "reset_debug", &[], Ret::Void, "Reset the log level").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "kex";
        reg.export(m, "setsflag", flag_bit, |ctx: &mut Ctx, b: &u64| {
            ctx.ext_mut::<SFlags>().0 |= b;
            1
        });
        reg.export(m, "resetsflag", flag_bit, |ctx: &mut Ctx, b: &u64| {
            ctx.ext_mut::<SFlags>().0 &= !b;
            1
        });
        reg.export(m, "issflagset", flag_bit, |ctx: &mut Ctx, b: &u64| rc(ctx.ext::<SFlags>().is_some_and(|x| x.0 & b != 0)));
        reg.export(
            m,
            "setdsturi",
            |a: &[Arg]| {
                let [u] = args(a)?;
                u.dyn_str()
            },
            |ctx: &mut Ctx, u: &DynStr| {
                let u = u.eval(ctx).into_owned();
                match sip_core::pvcore::dest_from_uri(u.as_bytes()) {
                    Some(d) => {
                        ctx.dst = Some(d);
                        1
                    }
                    None => -1,
                }
            },
        );
        reg.export(
            m,
            "resetdsturi",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                ctx.dst = None;
                1
            },
        );
        reg.export(m, "isdsturiset", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(ctx.dst.is_some()));
        reg.export(
            m,
            "pv_printf",
            |a: &[Arg]| {
                let [out, f] = args(a)?;
                Ok((pv_arg(out)?, f.dyn_str()?))
            },
            |ctx: &mut Ctx, (out, f): &(PvRef, DynStr)| {
                let s = f.eval(ctx).into_owned();
                rc(out.set(ctx, Val::Str(s)).is_ok())
            },
        );
        reg.export(
            m,
            "km_append_branch",
            |a: &[Arg]| Ok(dyn_args(a, 0, 1)?.into_iter().next()),
            |ctx: &mut Ctx, u: &Option<DynStr>| {
                let uri = match u {
                    Some(u) => u.eval(ctx).into_owned().into_bytes(),
                    None => ctx.ruri().to_vec(),
                };
                let dst = if u.is_none() { ctx.dst } else { None };
                if ctx.append_branch(Branch { uri, dst, q: None, path: None, ..Default::default() }) { 1 } else { -1 }
            },
        );
        reg.export(
            m,
            "setdebug",
            |a: &[Arg]| {
                let [l] = args(a)?;
                l.dyn_int()
            },
            |ctx: &mut Ctx, l: &DynInt| {
                let l = l.eval(ctx).unwrap_or(i64::from(log::L_INFO));
                // Out of i32 range: the most or least verbose level, not a wrapped one.
                log::set_level(i32::try_from(l).unwrap_or(if l < 0 { i32::MIN } else { i32::MAX }));
                1
            },
        );
        reg.export(
            m,
            "resetdebug",
            |a: &[Arg]| want_args(a, 0),
            |_: &mut Ctx, _: &()| {
                log::set_level(log::L_INFO);
                1
            },
        );
        reg.rpc.add("corex.debug", "Get/set the log level: corex.debug [level]", |p| {
            if let Ok(l) = sip_core::rpc::str_param(p, 0) {
                log::set_level(log::parse(&l).ok_or("bad level")?);
            }
            Ok(sip_core::serde_json::json!(log::level()))
        });
        Ok(())
    }
}

// ---------------------------------------------------------- statistics ---

pub struct Statistics;

/// `group:name` (or `name` → group "script").
fn stat_name(s: &str) -> (String, String) {
    match s.split_once(':') {
        Some((g, n)) => (g.to_string(), n.to_string()),
        None => ("script".into(), s.to_string()),
    }
}

impl Module for Statistics {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("variable", Ty::List(&Ty::Str), "", "Statistics to declare up front, as \"group:name\" (one per entry)")])
    }

    fn name(&self) -> &'static str {
        "statistics"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const UPDATE: &[Param] = &[arg("name", Str).eg("\"calls:active\""), arg("by", Int)];
        const NAME: &[Param] = &[arg("name", Str).eg("\"calls:active\"")];
        Some(vec![
            sig("update_stat", "update", UPDATE, Ret::Void, "Add `by` to the statistic `group:name` (may be negative)").allowed(ctx::ANY),
            sig("reset_stat", "reset", NAME, Ret::Void, "Set the statistic `group:name` to 0").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "variable" => {
                let (g, n) = stat_name(v.str()?.split('/').next().unwrap_or(""));
                sip_core::stats::counter(&g, &n);
                Ok(())
            }
            _ => Err(format!("statistics: unknown parameter {name:?}")),
        }
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        reg.export(
            "statistics",
            "update_stat",
            |a: &[Arg]| {
                let [name, value] = args(a)?;
                Ok((name.dyn_str()?, value.dyn_int()?))
            },
            |ctx: &mut Ctx, (n, v): &(DynStr, DynInt)| {
                let (g, n) = stat_name(&n.eval(ctx));
                let v = v.eval(ctx).unwrap_or(0);
                sip_core::stats::counter(&g, &n).fetch_add(v, Ordering::Relaxed);
                1
            },
        );
        reg.export(
            "statistics",
            "reset_stat",
            |a: &[Arg]| {
                let [n] = args(a)?;
                n.dyn_str()
            },
            |ctx: &mut Ctx, n: &DynStr| {
                let (g, n) = stat_name(&n.eval(ctx));
                sip_core::stats::counter(&g, &n).store(0, Ordering::Relaxed);
                1
            },
        );
        Ok(())
    }
}

// ------------------------------------------------------------ counters ---

/// Kamailio `counters`: named script counters (`group.name`, group
/// `script` by default) on the same statistics as everything else, so they
/// show in `stats.get_statistics` and the Prometheus export.
pub struct Counters;

/// `grp.name` (or `name` → group "script").
fn counter_name(s: &str) -> (String, String) {
    match s.split_once('.') {
        Some((g, n)) if !g.is_empty() && !n.is_empty() => (g.to_string(), n.to_string()),
        _ => ("script".into(), s.to_string()),
    }
}

impl Module for Counters {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("script_counter", Ty::List(&Ty::Str), "", "Counters to declare up front, as \"group.name [description]\" (one per entry)")])
    }

    fn name(&self) -> &'static str {
        "counters"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const NAME: &[Param] = &[arg("name", Str).eg("\"calls.failed\"")];
        const ADD: &[Param] = &[arg("name", Str).eg("\"calls.failed\""), arg("by", Int)];
        Some(vec![
            sig("cnt_inc", "inc", NAME, Ret::Void, "Add 1 to the counter `group.name`").allowed(ctx::ANY),
            sig("cnt_add", "add", ADD, Ret::Void, "Add `by` to the counter `group.name`").allowed(ctx::ANY),
            sig("cnt_reset", "reset", NAME, Ret::Void, "Set the counter `group.name` to 0").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            // "name [description]" declares a counter up front.
            "script_counter" => {
                let s = v.str()?;
                let (g, n) = counter_name(s.split_whitespace().next().unwrap_or(""));
                sip_core::stats::counter(&g, &n);
                Ok(())
            }
            "script_counter_group" => Ok(()),
            _ => Err(format!("counters: unknown parameter {name:?}")),
        }
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let one = |a: &[Arg]| {
            let [name] = args(a)?;
            name.dyn_str()
        };
        reg.export("counters", "cnt_inc", one, |ctx: &mut Ctx, n: &DynStr| {
            let (g, n) = counter_name(&n.eval(ctx));
            sip_core::stats::counter(&g, &n).fetch_add(1, Ordering::Relaxed);
            1
        });
        reg.export(
            "counters",
            "cnt_add",
            |a: &[Arg]| {
                let [name, value] = args(a)?;
                Ok((name.dyn_str()?, value.dyn_int()?))
            },
            |ctx: &mut Ctx, (n, v): &(DynStr, DynInt)| {
                let (g, n) = counter_name(&n.eval(ctx));
                sip_core::stats::counter(&g, &n).fetch_add(v.eval(ctx).unwrap_or(0), Ordering::Relaxed);
                1
            },
        );
        reg.export("counters", "cnt_reset", one, |ctx: &mut Ctx, n: &DynStr| {
            let (g, n) = counter_name(&n.eval(ctx));
            sip_core::stats::counter(&g, &n).store(0, Ordering::Relaxed);
            1
        });
        Ok(())
    }
}

// ------------------------------------------------------------------ pv ---

pub struct PvMod;

impl Module for PvMod {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "pv"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const VAR: &[Param] = &[arg("var", Var)];
        const TYPE: &[Param] = &[arg("var", Var), arg("type", Enum(&["int", "str", "null"])).lit()];
        const EXPLODE: &[Param] = &[arg("params", Str).eg("\"a=1;b=2\""), arg("xavp", Str)];
        Some(vec![
            sig("pv_isset", "is_set", VAR, Ret::Bool, "The variable has a value").allowed(ctx::ANY),
            sig("pv_unset", "unset", VAR, Ret::Bool, "Clear the variable").allowed(ctx::ANY),
            sig("is_int", "is_int", VAR, Ret::Bool, "The variable holds an integer").allowed(ctx::ANY),
            sig("not_empty", "not_empty", VAR, Ret::Bool, "The variable holds a non-empty, non-zero value").allowed(ctx::ANY),
            sig("typeof", "is_type", TYPE, Ret::Bool, "The variable's value is of this type").allowed(ctx::ANY),
            sig("xavp_params_explode", "explode_params", EXPLODE, Ret::Void, "Split `a=1;b=2` into the fields of a new $xavp(xavp) item").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "pv";
        let one = |a: &[Arg]| -> Result<PvRef, String> {
            let [p] = args(a)?;
            pv_arg(p)
        };
        reg.export(m, "pv_isset", one, |ctx: &mut Ctx, p: &PvRef| rc(!p.get(ctx).is_null()));
        reg.export(m, "pv_unset", one, |ctx: &mut Ctx, p: &PvRef| rc(p.set(ctx, Val::Null).is_ok()));
        reg.export(m, "is_int", one, |ctx: &mut Ctx, p: &PvRef| rc(matches!(p.get(ctx), Val::Int(_))));
        reg.export(m, "not_empty", one, |ctx: &mut Ctx, p: &PvRef| rc(p.get(ctx).truthy()));
        reg.export(
            m,
            "typeof",
            |a: &[Arg]| {
                let [p, t] = args(a)?;
                Ok((pv_arg(p)?, t.str()?.to_ascii_lowercase()))
            },
            |ctx: &mut Ctx, (p, t): &(PvRef, String)| {
                let v = p.get(ctx);
                rc(match t.as_str() {
                    "int" => matches!(v, Val::Int(_)),
                    "str" => matches!(v, Val::Str(_)),
                    "null" => v.is_null(),
                    _ => false,
                })
            },
        );
        // xavp_params_explode("a=1;b=2", "x") → $xavp(x=>a), $xavp(x=>b)
        reg.export(
            m,
            "xavp_params_explode",
            |a: &[Arg]| {
                let [p, x] = dyn_arr(a)?;
                Ok((p, x))
            },
            |ctx: &mut Ctx, (p, x): &(DynStr, DynStr)| {
                let (p, x) = (p.eval(ctx).into_owned(), x.eval(ctx).into_owned());
                let mut item = HashMap::new();
                for kv in p.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    item.insert(k.trim().to_string(), Val::Str(v.trim().to_string()));
                }
                ctx.ext_mut::<TxnVars>().xavps.entry(x).or_default().insert(0, item);
                1
            },
        );
        Ok(())
    }
}

// --------------------------------------------------------------- ipops ---

pub struct IpOps;

fn ip(s: &str) -> Option<IpAddr> {
    s.trim().trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// `10.0.0.0/8`, `2001:db8::/32`, or a single address.
fn in_subnet(addr: IpAddr, net: &str) -> bool {
    let (n, bits) = match net.trim().split_once('/') {
        Some((n, b)) => (n, b.trim().parse::<u32>().ok()),
        None => (net.trim(), None),
    };
    let Some(n) = ip(n) else { return false };
    match (addr, n) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let b = bits.unwrap_or(32).min(32);
            // The top `b` bits (all of them for 32: the shift fails).
            let mask = u32::MAX.checked_shr(b).map_or(u32::MAX, |low| !low);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let b = bits.unwrap_or(128).min(128);
            let mask = u128::MAX.checked_shr(b).map_or(u128::MAX, |low| !low);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Results of `dns_query(host, id)`, read via `$dns(id=>addr[i])`.
#[derive(Default)]
struct DnsResults(HashMap<String, Vec<IpAddr>>);

impl Module for IpOps {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "ipops"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const IP: &[Param] = &[arg("ip", Str).eg("\"10.0.0.1\"")];
        const TWO: &[Param] = &[arg("a", Str).eg("\"10.0.0.1\""), arg("b", Str).eg("\"10.0.0.1\"")];
        const SUBNET: &[Param] = &[arg("ip", Str).eg("\"10.0.0.1\""), arg("subnets", Str).eg("\"10.0.0.0/8,192.168.0.0/16\"")];
        const HOST_IP: &[Param] = &[arg("host", Str).eg("\"localhost\""), arg("ip", Str).eg("\"127.0.0.1\"")];
        const QUERY: &[Param] = &[arg("host", Str).eg("\"localhost\""), arg("id", Str)];
        let any = |name, fsr, p, doc| sig(name, fsr, p, Ret::Bool, doc).allowed(ctx::ANY);
        Some(vec![
            any("is_ip", "is_ip", IP, "The string is an IPv4 or IPv6 address (IPv6 may be in brackets)"),
            any("is_ipv4", "is_ipv4", IP, "The string is an IPv4 address"),
            any("is_ipv6", "is_ipv6", IP, "The string is an IPv6 address (may be in brackets)"),
            any("is_pure_ip", "is_pure_ip", IP, "The string is an IP address without brackets"),
            any("is_ipv6_reference", "is_ipv6_reference", IP, "The string is a bracketed IPv6 address (`[::1]`)"),
            any("ip_type", "ip_type", IP, "The string is an IP (the return code: 1 IPv4, 2 IPv6, 3 IPv6 reference)"),
            any("compare_ips", "same_ip", TWO, "The two strings are the same IP address"),
            any("ip_is_in_subnet", "in_subnet", SUBNET, "The IP is in one of the subnets (comma-separated, `10.0.0.0/8`)"),
            any("is_in_subnet", "is_in_subnet", SUBNET, "Same as in_subnet"),
            any("is_ip_rfc1918", "is_private", IP, "The IP is in an RFC 1918 private range"),
            any("dns_sys_match_ip", "host_has_ip", HOST_IP, "The host name resolves (system resolver) to this IP"),
            any("dns_query", "resolve", QUERY, "Resolve the host; results in $dns(id=>addr[i]), $dns(id=>count)"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "ipops";
        let one = |a: &[Arg]| -> Result<DynStr, String> {
            let [s] = args(a)?;
            s.dyn_str()
        };
        reg.export(m, "is_ip", one, |ctx: &mut Ctx, s: &DynStr| rc(ip(&s.eval(ctx)).is_some()));
        reg.export(m, "is_ipv4", one, |ctx: &mut Ctx, s: &DynStr| rc(s.eval(ctx).trim().parse::<std::net::Ipv4Addr>().is_ok()));
        reg.export(m, "is_ipv6", one, |ctx: &mut Ctx, s: &DynStr| rc(matches!(ip(&s.eval(ctx)), Some(IpAddr::V6(_)))));
        reg.export(m, "is_pure_ip", one, |ctx: &mut Ctx, s: &DynStr| rc(s.eval(ctx).trim().parse::<IpAddr>().is_ok()));
        reg.export(m, "is_ipv6_reference", one, |ctx: &mut Ctx, s: &DynStr| {
            let s = s.eval(ctx);
            rc(s.starts_with('[') && s.ends_with(']') && matches!(ip(&s), Some(IpAddr::V6(_))))
        });
        reg.export(m, "ip_type", one, |ctx: &mut Ctx, s: &DynStr| {
            let s = s.eval(ctx).into_owned();
            match ip(&s) {
                Some(IpAddr::V4(_)) => 1,
                Some(IpAddr::V6(_)) if s.trim().starts_with('[') => 3,
                Some(IpAddr::V6(_)) => 2,
                None => -1,
            }
        });
        reg.export(
            m,
            "compare_ips",
            |a: &[Arg]| {
                let [x, y] = dyn_arr(a)?;
                Ok((x, y))
            },
            |ctx: &mut Ctx, (x, y): &(DynStr, DynStr)| {
                let (x, y) = (ip(&x.eval(ctx)), ip(&y.eval(ctx)));
                rc(x.is_some() && x == y)
            },
        );
        for name in ["ip_is_in_subnet", "is_in_subnet"] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [x, nets] = dyn_arr(a)?;
                    Ok((x, nets))
                },
                |ctx: &mut Ctx, (x, nets): &(DynStr, DynStr)| {
                    let Some(addr) = ip(&x.eval(ctx)) else { return -1 };
                    let nets = nets.eval(ctx).into_owned();
                    rc(nets.split(',').any(|n| in_subnet(addr, n)))
                },
            );
        }
        reg.export(m, "is_ip_rfc1918", one, |ctx: &mut Ctx, s: &DynStr| {
            let Some(addr) = ip(&s.eval(ctx)) else { return -1 };
            rc(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].iter().any(|n| in_subnet(addr, n)))
        });
        reg.export(
            m,
            "dns_sys_match_ip",
            |a: &[Arg]| {
                let [h, x] = dyn_arr(a)?;
                Ok((h, x))
            },
            |ctx: &mut Ctx, (h, x): &(DynStr, DynStr)| {
                let (h, x) = (h.eval(ctx).into_owned(), ip(&x.eval(ctx)));
                let Some(x) = x else { return -1 };
                rc((h.as_str(), 0).to_socket_addrs().is_ok_and(|mut it| it.any(|a| a.ip() == x)))
            },
        );
        reg.export(
            m,
            "dns_query",
            |a: &[Arg]| {
                let [h, id] = dyn_arr(a)?;
                Ok((h, id))
            },
            |ctx: &mut Ctx, (h, id): &(DynStr, DynStr)| {
                let (h, id) = (h.eval(ctx).into_owned(), id.eval(ctx).into_owned());
                let addrs: Vec<IpAddr> = match (h.as_str(), 0).to_socket_addrs() {
                    Ok(it) => {
                        let mut v: Vec<IpAddr> = Vec::new();
                        for a in it {
                            if !v.contains(&a.ip()) {
                                v.push(a.ip());
                            }
                        }
                        v
                    }
                    Err(_) => vec![],
                };
                let found = !addrs.is_empty();
                ctx.ext_mut::<DnsResults>().0.insert(id, addrs);
                rc(found)
            },
        );
        // $dns(id=>addr[i]) | count | ipv4 | ipv6 | type[i]
        reg.pv(
            "dns",
            PvSpec::ro(|ctx, p| {
                let (id, key) = p.name.split_once("=>").map_or((p.name.as_str(), "addr"), |(a, b)| (a.trim(), b.trim()));
                let (key, idx) = match key.split_once('[') {
                    Some((k, i)) => (k, i.trim_end_matches(']').trim().parse::<usize>().unwrap_or(0)),
                    None => (key, 0),
                };
                let Some(v) = ctx.ext::<DnsResults>().and_then(|d| d.0.get(id)) else { return Val::Null };
                match key {
                    "count" => Val::Int(i64::try_from(v.len()).unwrap_or(i64::MAX)),
                    "ipv4" => Val::Int(i64::from(v.iter().any(IpAddr::is_ipv4))),
                    "ipv6" => Val::Int(i64::from(v.iter().any(IpAddr::is_ipv6))),
                    "type" => v.get(idx).map_or(Val::Null, |a| Val::Int(if a.is_ipv4() { 4 } else { 6 })),
                    _ => v.get(idx).map_or(Val::Null, |a| Val::Str(a.to_string())),
                }
            })
            .with_param(),
        );
        Ok(())
    }
}

// ------------------------------------------------------------------ blst ---

/// Kamailio `blst`: the destination blocklist from the script, for the
/// current next hop (`$du`, else the R-URI). `blst_add([secs])`,
/// `blst_add_retry_after(min, max)` (the reply's Retry-After, clamped;
/// `min` when absent), `blst_del()`, `blst_is_blocklisted()`.
pub struct Blst;

fn blst_target(ctx: &Ctx<'_, '_>) -> Option<sip_core::Dest> {
    ctx.dst.or_else(|| sip_core::pvcore::dest_from_uri(ctx.ruri()))
}

impl Module for Blst {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "blst"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const SECS: &[Param] = &[opt("time", Duration(Unit::Sec))];
        const RANGE: &[Param] = &[arg("min", Duration(Unit::Sec)), arg("max", Duration(Unit::Sec))];
        Some(vec![
            sig("blst_add", "add", SECS, Ret::Bool, "Block the next hop ($du, else the R-URI) for `time` (default: the module setting)"),
            sig("blst_add_retry_after", "add_retry_after", RANGE, Ret::Bool, "Block the next hop for the reply's Retry-After, clamped to min..max")
                .allowed(ctx::FAILURE | ctx::REPLY),
            sig("blst_del", "remove", &[], Ret::Bool, "Unblock the next hop ($du, else the R-URI)"),
            sig("blst_is_blocklisted", "is_blocked", &[], Ret::Bool, "The next hop ($du, else the R-URI) is blocked"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        use sip_core::blst::blocklist;
        reg.export(
            "blst",
            "blst_add",
            |a: &[Arg]| {
                if a.len() > 1 {
                    return Err("blst_add([seconds])".into());
                }
                a.first().map(Arg::dyn_int).transpose()
            },
            |ctx: &mut Ctx, secs: &Option<DynInt>| {
                let secs = secs.as_ref().and_then(|s| s.eval(ctx)).map(|s| u64::try_from(s).unwrap_or(0).max(1));
                let Some(d) = blst_target(ctx) else { return -1 };
                blocklist().add(&d, secs);
                1
            },
        );
        reg.export(
            "blst",
            "blst_add_retry_after",
            |a: &[Arg]| {
                let [min, max] = args(a)?;
                Ok((min.dyn_int()?, max.dyn_int()?))
            },
            |ctx: &mut Ctx, (min, max): &(DynInt, DynInt)| {
                let secs = |d: &DynInt, ctx: &mut Ctx| d.eval(ctx).and_then(|s| u64::try_from(s).ok()).unwrap_or(0).max(1);
                let (min, max) = (secs(min, ctx), secs(max, ctx));
                // The reply: this message in a reply route, the winning reply in a failure route.
                let raw = match ctx.ext::<sip_core::module::FailureReply>() {
                    Some(r) if !r.0.is_empty() => r.0.clone(),
                    _ => ctx.msg.buf.to_vec(),
                };
                let ra = String::from_utf8_lossy(&raw)
                    .split("\r\n\r\n")
                    .next()
                    .unwrap_or("")
                    .lines()
                    .find_map(|l| l.split_once(':').filter(|(n, _)| n.trim().eq_ignore_ascii_case("retry-after")).map(|(_, v)| v.to_string()))
                    .and_then(|v| v.trim().split([' ', ';', '(']).next()?.parse::<u64>().ok());
                let Some(d) = blst_target(ctx) else { return -1 };
                blocklist().add(&d, Some(ra.unwrap_or(min).clamp(min, max.max(min))));
                1
            },
        );
        reg.export(
            "blst",
            "blst_del",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| match blst_target(ctx) {
                Some(d) => rc(sip_core::blst::blocklist().del(&d)),
                None => -1,
            },
        );
        reg.export(
            "blst",
            "blst_is_blocklisted",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| match blst_target(ctx) {
                Some(d) => rc(sip_core::blst::blocklist().is_blocked(&d)),
                None => -1,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn subnets() {
        use super::{in_subnet, ip};
        let a = ip("192.168.1.20").unwrap();
        assert!(in_subnet(a, "192.168.0.0/16"));
        assert!(!in_subnet(a, "10.0.0.0/8"));
        assert!(in_subnet(a, "192.168.1.20"));
        assert!(in_subnet(ip("[2001:db8::5]").unwrap(), "2001:db8::/32"));
        assert!(in_subnet(a, "0.0.0.0/0"));
    }
}
