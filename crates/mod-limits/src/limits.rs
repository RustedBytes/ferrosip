//! Flood detection and rate limiting:
//! * `pike` — per source IP request density (`pike_check_req()`), with
//!   `event_route[pike:blocked]` when an address starts flooding.
//! * `ratelimit` — static pipes (`modparam("ratelimit", "pipe", "id:ALG:limit")`)
//!   fed by method queues (`"queue", "id:METHOD"`), `rl_check([pipe])`.
//! * `pipelimit` — named pipes from the db (`pl_pipes`) or created by
//!   `pl_check(name, alg, limit)`, `pl_check(name)`, `pl_drop([retry[, lo, hi]])`.
//!
//! Limits are requests per `timer_interval` (seconds). Algorithms:
//! `TAILDROP` (drop above the limit), `RED` (also drops early, randomly,
//! from 3/4 of the limit up); `NETWORK` / `FEEDBACK` (load-driven in
//! Kamailio) are accepted and behave as `TAILDROP`.

use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p, pr};
use sip_core::serde_json::{Value, json};
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, RouteHub, ShardedMap, want_args};
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

// ------------------------------------------------------------------- pike --

#[derive(Clone, Debug, Default)]
struct Hits {
    win: u64,
    cnt: u32,
    prev: u32,
    blocked: bool,
    last: u64,
}

pub struct Pike {
    unit: AtomicU64,
    density: AtomicU64,
    remove_latency: AtomicU64,
    ips: ShardedMap<IpAddr, Hits>,
    hub: OnceLock<Arc<RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for Pike {
    fn default() -> Self {
        Self {
            unit: AtomicU64::new(2),
            density: AtomicU64::new(30),
            remove_latency: AtomicU64::new(120),
            ips: ShardedMap::new(64),
            hub: OnceLock::new(),
            net: OnceLock::new(),
        }
    }
}

impl Pike {
    /// Count one request from `ip`; true if the address is (now) blocked.
    fn hit(&self, ip: IpAddr) -> (bool, bool) {
        let now = unix_secs();
        let unit = NonZeroU64::new(self.unit.load(Ordering::Relaxed)).unwrap_or(NonZeroU64::MIN);
        let density = u32::try_from(self.density.load(Ordering::Relaxed)).unwrap_or(u32::MAX);
        let win = now / unit;
        self.ips.alter(ip, |cur| {
            let mut e = cur.unwrap_or(Hits { win, ..Default::default() });
            if e.win != win {
                e.prev = if win.checked_sub(e.win) == Some(1) { e.cnt } else { 0 };
                e.cnt = 0;
                e.win = win;
                if e.blocked && e.prev <= density {
                    e.blocked = false;
                }
            }
            // Saturates: a flood must not wrap back under the density.
            e.cnt = e.cnt.saturating_add(1);
            e.last = now;
            let newly = !e.blocked && e.cnt > density;
            if newly {
                e.blocked = true;
            }
            let b = e.blocked;
            (Some(e), (b, newly))
        })
    }
}

impl Module for Pike {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            pr("sampling_time_unit", Ty::Duration(Unit::Sec), "2s", "Length of one sampling window"),
            pr("reqs_density_per_unit", UINT, "30", "More requests than this per window from one IP: blocked"),
            pr("remove_latency", Ty::Duration(Unit::Sec), "120s", "Forget an idle IP after this"),
        ])
    }

    fn name(&self) -> &'static str {
        "pike"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = u64::try_from(v.int()?).unwrap_or(0);
        match name {
            "sampling_time_unit" => self.unit.store(n.max(1), Ordering::Relaxed),
            "reqs_density_per_unit" => self.density.store(n, Ordering::Relaxed),
            "remove_latency" => self.remove_latency.store(n, Ordering::Relaxed),
            "pike_log_level" => {}
            _ => return Err(format!("pike: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, sig};
        const IP: &[Param] = &[arg("ip", Str).eg("\"10.0.0.1\"")];
        Some(vec![
            sig("pike_check_req", "check_flood", &[], Ret::Bool, "Count this request against its source IP: false when the IP is flooding")
                .allowed(sip_core::sig::ctx::REQUEST),
            sig("pike_check_ip", "check_flood_ip", IP, Ret::Bool, "Count a hit for this IP: false when it is flooding (or not an IP)"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        reg.export(
            "pike",
            "pike_check_req",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let ip = ctx.src.addr.ip();
                let (blocked, newly) = me.hit(ip);
                if newly {
                    sip_core::log::log(sip_core::log::L_WARN, &format!("pike: {ip} is flooding, blocked"));
                    if let (Some(hub), Some(net)) = (me.hub.get(), me.net.get())
                        && hub.has_event("pike:blocked")
                    {
                        let src = ctx.src;
                        hub.run_event_with("pike:blocked", &**net, None, |c| c.src = src);
                    }
                }
                if blocked { -1 } else { 1 }
            },
        );
        let me = self.clone();
        reg.export(
            "pike",
            "pike_check_ip",
            |a: &[Arg]| {
                let [ip] = crate::fixed_args(a)?;
                ip.dyn_str()
            },
            move |ctx: &mut Ctx, ip: &DynStr| match ip.eval(ctx).trim().parse::<IpAddr>() {
                Ok(ip) => rc(!me.hit(ip).0),
                Err(_) => -1,
            },
        );
        let me = self.clone();
        reg.rpc.add("pike.top", "pike.top [ALL|HOT]: tracked addresses", move |p| {
            let all = sip_core::rpc::str_param(p, 0).is_ok_and(|s| s.eq_ignore_ascii_case("all"));
            let mut v = Vec::new();
            me.ips.for_each_mut(|ip, h| {
                if all || h.blocked {
                    v.push(json!({"ip": ip.to_string(), "blocked": h.blocked, "hits": h.cnt, "prev": h.prev}));
                }
            });
            Ok(json!(v))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        std::thread::Builder::new()
            .name("pike-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let idle = self.remove_latency.load(Ordering::Relaxed);
                    let now = unix_secs();
                    self.ips.retain(|_, h| h.blocked || now.saturating_sub(h.last) < idle.max(self.unit.load(Ordering::Relaxed).saturating_mul(2)));
                }
            })
            .map_err(|e| format!("cannot start the pike timer thread: {e}"))?;
        Ok(())
    }
}

// ------------------------------------------------------------------ pipes --

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    TailDrop,
    Red,
    Network,
    Feedback,
}

impl Alg {
    fn parse(s: &str) -> Result<Self, String> {
        Ok(match s.trim().to_ascii_uppercase().as_str() {
            "TAILDROP" => Alg::TailDrop,
            "RED" => Alg::Red,
            "NETWORK" => Alg::Network,
            "FEEDBACK" => Alg::Feedback,
            a => return Err(format!("unknown algorithm {a:?} (TAILDROP, RED, NETWORK, FEEDBACK)")),
        })
    }
    fn name(self) -> &'static str {
        match self {
            Alg::TailDrop => "TAILDROP",
            Alg::Red => "RED",
            Alg::Network => "NETWORK",
            Alg::Feedback => "FEEDBACK",
        }
    }
}

struct Pipe {
    alg: Mutex<Alg>,
    limit: AtomicI64,
    counter: AtomicI64,
    /// Requests in the last full interval.
    last: AtomicI64,
    dropped: AtomicI64,
}

/// ⌊3·limit/4⌋ without the overflow of `limit * 3` for a huge limit.
#[allow(clippy::arithmetic_side_effects, reason = "|limit / 4 * 3| <= |limit| and |limit % 4 * 3 / 4| <= 2: no term overflows")]
fn three_quarters(limit: i64) -> i64 {
    limit / 4 * 3 + limit % 4 * 3 / 4
}

impl Pipe {
    fn new(alg: Alg, limit: i64) -> Self {
        Self { alg: Mutex::new(alg), limit: AtomicI64::new(limit), counter: AtomicI64::new(0), last: AtomicI64::new(0), dropped: AtomicI64::new(0) }
    }

    /// Count a request; true = accept.
    fn check(&self) -> bool {
        let n = self.counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let limit = self.limit.load(Ordering::Relaxed);
        let ok = match *lock(&self.alg) {
            Alg::Red if limit > 0 && n > three_quarters(limit) => {
                // Early drop probability grows linearly from 0 at 3/4 of the limit.
                let q = three_quarters(limit);
                // 0 <= q < limit and q < n here, so p is in 1..=1000.
                let span = limit.saturating_sub(q).max(1);
                let p = u64::try_from(n.saturating_sub(q).saturating_mul(1000).checked_div(span).unwrap_or(1000).min(1000)).unwrap_or(0);
                n <= limit && (rand() % 4000) >= p
            }
            _ => n <= limit,
        };
        if !ok {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    fn json(&self, id: &str) -> Value {
        json!({"pipe": id, "algorithm": lock(&self.alg).name(), "limit": self.limit.load(Ordering::Relaxed),
               "counter": self.counter.load(Ordering::Relaxed), "last_counter": self.last.load(Ordering::Relaxed),
               "dropped": self.dropped.load(Ordering::Relaxed)})
    }
}

fn rand() -> u64 {
    static S: AtomicU64 = AtomicU64::new(0x853c_49e6_748f_ea9b);
    let mut x = S.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^ (x >> 31)
}

type Pipes = RwLock<HashMap<String, Arc<Pipe>>>;

fn reset_loop(name: &str, pipes: Arc<Pipes>, every: u64) -> Result<(), String> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(every.max(1)));
                for p in read(&pipes).values() {
                    p.last.store(p.counter.swap(0, Ordering::Relaxed), Ordering::Relaxed);
                }
            }
        })
        .map(|_| ())
        .map_err(|e| format!("cannot start the {name} thread: {e}"))
}

fn pipes_json(pipes: &Pipes) -> Value {
    let mut v: Vec<(String, Value)> = read(pipes).iter().map(|(k, p)| (k.clone(), p.json(k))).collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    json!(v.into_iter().map(|x| x.1).collect::<Vec<_>>())
}

fn set_pipe_rpc(pipes: Arc<Pipes>, create: bool) -> impl Fn(&[Value]) -> Result<Value, String> + Send + Sync + 'static {
    move |p| {
        let id = sip_core::rpc::str_param(p, 0)?;
        let alg = Alg::parse(&sip_core::rpc::str_param(p, 1)?)?;
        let limit = sip_core::rpc::int_param(p, 2)?;
        let mut w = write(&pipes);
        match w.get(&id) {
            Some(pp) => {
                *lock(&pp.alg) = alg;
                pp.limit.store(limit, Ordering::Relaxed);
            }
            None if create => {
                w.insert(id, Arc::new(Pipe::new(alg, limit)));
            }
            None => return Err("no such pipe".into()),
        }
        Ok(json!(0))
    }
}

// -------------------------------------------------------------- ratelimit --

pub struct RateLimit {
    pipes: Arc<Pipes>,
    /// (pipe id, method or "*").
    queues: Mutex<Vec<(String, String)>>,
    timer_interval: AtomicU64,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self { pipes: Arc::new(RwLock::new(HashMap::new())), queues: Mutex::new(Vec::new()), timer_interval: AtomicU64::new(10) }
    }
}

impl RateLimit {
    fn pipe(&self, id: &str) -> Option<Arc<Pipe>> {
        read(&self.pipes).get(id).cloned()
    }
}

impl Module for RateLimit {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("pipe", Ty::List(&Ty::Str), "", "Pipes, \"id:algorithm:limit\" (TAILDROP, RED, NETWORK, FEEDBACK)"),
            p("queue", Ty::List(&Ty::Str), "", "Queues, \"pipe:method\""),
            p("timer_interval", Ty::Duration(Unit::Sec), "10s", "Rate window"),
        ])
    }

    fn name(&self) -> &'static str {
        "ratelimit"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "pipe" => {
                let s = v.str()?;
                let f: Vec<&str> = s.split(':').collect();
                let [id, alg, limit] = f[..] else { return Err(format!("ratelimit pipe: expected id:ALGORITHM:limit, got {s:?}")) };
                let limit = limit.trim().parse().map_err(|_| format!("ratelimit pipe {id}: bad limit"))?;
                let p = Pipe::new(Alg::parse(alg).map_err(|e| format!("ratelimit pipe {id}: {e}"))?, limit);
                write(&self.pipes).insert(id.trim().to_string(), Arc::new(p));
            }
            "queue" => {
                let s = v.str()?;
                let (id, m) = s.split_once(':').ok_or_else(|| format!("ratelimit queue: expected pipe:METHOD, got {s:?}"))?;
                lock(&self.queues).push((id.trim().to_string(), m.trim().to_ascii_uppercase()));
            }
            "timer_interval" => self.timer_interval.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "reply_code" | "reply_reason" | "hash_size" | "load_source" | "limit_hash_size" => {}
            _ => return Err(format!("ratelimit: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, opt, sig};
        const PIPE: &[Param] = &[opt("pipe", Str)];
        Some(vec![sig("rl_check", "check_rate", PIPE, Ret::Bool, "Count against a pipe (default: the queue for this method): false when over its limit")])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        for (id, _) in lock(&self.queues).iter() {
            if self.pipe(id).is_none() {
                return Err(format!("ratelimit: queue refers to unknown pipe {id:?}"));
            }
        }
        let me = self.clone();
        reg.export(
            "ratelimit",
            "rl_check",
            |a: &[Arg]| -> Result<Option<DynStr>, String> {
                match a {
                    [] => Ok(None),
                    [pipe] => Ok(Some(pipe.dyn_str()?)),
                    _ => Err("expected at most 1 argument".into()),
                }
            },
            move |ctx: &mut Ctx, p: &Option<DynStr>| {
                let id = match p {
                    Some(p) => p.eval(ctx).into_owned(),
                    None => {
                        let m = match ctx.msg.first {
                            sip_parser::FirstLine::Request { method_raw, .. } => String::from_utf8_lossy(method_raw).to_ascii_uppercase(),
                            _ => return -1,
                        };
                        match lock(&me.queues).iter().find(|(_, q)| q == "*" || *q == m) {
                            Some((id, _)) => id.clone(),
                            None => return 1, // no queue for this method: not limited
                        }
                    }
                };
                match me.pipe(&id) {
                    Some(p) => rc(p.check()),
                    None => -2,
                }
            },
        );
        let me = self.clone();
        reg.rpc.add("rl.stats", "Pipe counters", move |_| Ok(pipes_json(&me.pipes)));
        let me = self.clone();
        reg.rpc.add("rl.get_pipes", "Pipe definitions and counters", move |_| Ok(pipes_json(&me.pipes)));
        reg.rpc.add("rl.set_pipe", "rl.set_pipe <id> <ALGORITHM> <limit>", set_pipe_rpc(self.pipes.clone(), false));
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        reset_loop("ratelimit-timer", self.pipes.clone(), self.timer_interval.load(Ordering::Relaxed))
    }
}

// -------------------------------------------------------------- pipelimit --

pub struct PipeLimit {
    pipes: Arc<Pipes>,
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    timer_interval: AtomicU64,
    reply: Mutex<(u16, String)>,
}

impl Default for PipeLimit {
    fn default() -> Self {
        Self {
            pipes: Arc::new(RwLock::new(HashMap::new())),
            db_url: Mutex::new(None),
            table: Mutex::new("pl_pipes".into()),
            timer_interval: AtomicU64::new(10),
            reply: Mutex::new((503, "Server Unavailable".into())),
        }
    }
}

impl PipeLimit {
    fn load(&self) -> Result<usize, String> {
        let Some(url) = lock(&self.db_url).clone() else { return Ok(0) };
        let db = sip_db::connect(&url)?;
        let rows = db.query(&lock(&self.table), &["pipeid", "algorithm", "plimit"], &[])?;
        let mut w = write(&self.pipes);
        for r in &rows.rows {
            let [id, alg, limit, ..] = r.as_slice() else { continue };
            let (alg, limit) = (Alg::parse(&alg.text())?, limit.int().unwrap_or(0));
            match w.get(&id.text()) {
                Some(p) => {
                    *lock(&p.alg) = alg;
                    p.limit.store(limit, Ordering::Relaxed);
                }
                None => {
                    w.insert(id.text(), Arc::new(Pipe::new(alg, limit)));
                }
            }
        }
        Ok(rows.rows.len())
    }
}

impl Module for PipeLimit {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database with the pipe definitions (none: pipes come from pl_check)"),
            p("plp_table_name", Ty::Str, "pl_pipes", "Table of pipe definitions"),
            p("table_name", Ty::Str, "pl_pipes", "Same as plp_table_name"),
            p("timer_interval", Ty::Duration(Unit::Sec), "10s", "Rate window"),
            p("reply_code", Ty::Int { min: 100, max: 699 }, "503", "Reply code of pl_drop"),
            p("reply_reason", Ty::Str, "Server Unavailable", "Reply reason of pl_drop"),
        ])
    }

    fn name(&self) -> &'static str {
        "pipelimit"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "plp_table_name" | "table_name" => *lock(&self.table) = v.str()?.into(),
            "timer_interval" => self.timer_interval.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "reply_code" => {
                let c = v.int()?;
                lock(&self.reply).0 =
                    u16::try_from(c).ok().filter(|c| (100..=699).contains(c)).ok_or_else(|| format!("pipelimit: reply_code must be 100..699, not {c}"))?
            }
            "reply_reason" => lock(&self.reply).1 = v.str()?.into(),
            "hash_size" | "load_source" | "clean_unused" => {}
            "plp_pipeid_column" | "plp_limit_column" | "plp_algorithm_column" => {}
            _ => return Err(format!("pipelimit: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, opt, sig};
        const PIPE: &[Param] = &[arg("pipe", Str)];
        const CREATE: &[Param] = &[arg("pipe", Str), arg("algorithm", Enum(&["TAILDROP", "RED", "NETWORK", "FEEDBACK"])).lit(), arg("limit", Int)];
        const RETRY: &[Param] = &[opt("retry_after", Duration(Unit::Sec)).lit()];
        const RANDOM: &[Param] = &[arg("low", Duration(Unit::Sec)).lit(), arg("high", Duration(Unit::Sec)).lit().eg("5s")];
        Some(vec![
            sig("pl_check", "check", PIPE, Ret::Bool, "Count against a pipe: false when over its limit (or no such pipe)"),
            sig("pl_check", "check_or_create", CREATE, Ret::Bool, "Count against a pipe, creating it with this algorithm and limit: false when over"),
            sig("pl_drop", "reject", RETRY, Ret::Action, "Reject with the configured reply (503), with Retry-After if given"),
            sig("pl_drop", "reject_random", RANDOM, Ret::Action, "Reject with the configured reply and a random Retry-After between low and high")
                .fixed(&["0"]),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        self.load()?;
        let me = self.clone();
        reg.export(
            "pipelimit",
            "pl_check",
            |a: &[Arg]| -> Result<(DynStr, Option<(Alg, DynStr)>), String> {
                match a {
                    [pipe] => Ok((pipe.dyn_str()?, None)),
                    [pipe, alg, limit] => Ok((pipe.dyn_str()?, Some((Alg::parse(alg.str()?)?, limit.dyn_str()?)))),
                    _ => Err("expected pipe or pipe, algorithm, limit".into()),
                }
            },
            move |ctx: &mut Ctx, (id, create): &(DynStr, Option<(Alg, DynStr)>)| {
                let id = id.eval(ctx).into_owned();
                let p = read(&me.pipes).get(&id).cloned();
                let p = match (p, create) {
                    (Some(p), _) => p,
                    (None, Some((alg, limit))) => {
                        let limit = limit.eval(ctx).trim().parse().unwrap_or(0);
                        let mut w = write(&me.pipes);
                        w.entry(id).or_insert_with(|| Arc::new(Pipe::new(*alg, limit))).clone()
                    }
                    (None, None) => return -2,
                };
                rc(p.check())
            },
        );
        let me = self.clone();
        reg.export(
            "pipelimit",
            "pl_drop",
            |a: &[Arg]| -> Result<Vec<i64>, String> {
                if a.len() > 3 || a.len() == 2 {
                    return Err("expected [retry_after] or [retry_after, low, high]".into());
                }
                a.iter().map(Arg::int).collect()
            },
            move |ctx: &mut Ctx, a: &Vec<i64>| {
                let (code, reason) = lock(&me.reply).clone();
                let retry = match a[..] {
                    [r] => Some(r),
                    // Uniform in lo..=hi; the offset is at most hi - lo, so the sum stays in range.
                    [_, lo, hi] if hi >= lo => Some(lo.saturating_add_unsigned(rand().checked_rem(hi.abs_diff(lo).saturating_add(1)).unwrap_or(0))),
                    _ => None,
                };
                let extra = retry.map(|r| format!("Retry-After: {r}\r\n")).unwrap_or_default();
                rc(ctx.reply_with(code, &reason, extra.as_bytes()).is_ok())
            },
        );
        let me = self.clone();
        reg.rpc.add("pl.stats", "Pipe counters", move |_| Ok(pipes_json(&me.pipes)));
        let me = self.clone();
        reg.rpc.add("pl.list", "Pipes", move |_| Ok(pipes_json(&me.pipes)));
        reg.rpc.add("pl.set_pipe", "pl.set_pipe <name> <ALGORITHM> <limit> (creates it)", set_pipe_rpc(self.pipes.clone(), true));
        let me = self.clone();
        reg.rpc.add("pl.reload", "Reload pipes from the database", move |_| me.load().map(|n| json!(n)));
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        reset_loop("pipelimit-timer", self.pipes.clone(), self.timer_interval.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn red_with_a_huge_limit() {
        for l in [1, 4, 5, 7, 100, 1001] {
            assert_eq!(three_quarters(l), l * 3 / 4);
        }
        assert_eq!(three_quarters(i64::MAX), i64::MAX / 4 * 3 + 2);
        let p = Pipe::new(Alg::Red, i64::MAX);
        // In the early-drop band, near the top of i64: `limit * 3` used to
        // overflow here (a panic in debug builds). The verdict itself is random.
        p.counter.store(i64::MAX - 1, Ordering::Relaxed);
        let _accepted = p.check();
    }

    #[test]
    fn taildrop_and_pike() {
        let p = Pipe::new(Alg::TailDrop, 3);
        assert_eq!((0..5).map(|_| p.check()).collect::<Vec<_>>(), [true, true, true, false, false]);
        let pk = Pike::default();
        pk.density.store(2, Ordering::Relaxed);
        pk.unit.store(1000, Ordering::Relaxed);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(pk.hit(ip), (false, false));
        assert_eq!(pk.hit(ip), (false, false));
        assert_eq!(pk.hit(ip), (true, true));
        assert_eq!(pk.hit(ip), (true, false));
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use crate::testutil::{call, request};

    /// A sampling unit so long that the current window never changes
    /// during a test.
    const UNIT: u64 = 1 << 28;

    fn pike(density: u64) -> (Pike, u64) {
        let pk = Pike::default();
        pk.unit.store(UNIT, Ordering::Relaxed);
        pk.density.store(density, Ordering::Relaxed);
        (pk, unix_secs() / UNIT)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pike_blocks_once_the_density_is_exceeded_in_a_window() {
        let (pk, _) = pike(3);
        let a = ip("192.0.2.1");
        let got: Vec<_> = (0..6).map(|_| pk.hit(a)).collect();
        assert_eq!(got, [(false, false), (false, false), (false, false), (true, true), (true, false), (true, false)]);
        assert_eq!(pk.hit(ip("192.0.2.2")), (false, false), "addresses are counted apart");
        assert_eq!(pk.hit(ip("2001:db8::1")), (false, false));
        let (pk, _) = pike(0);
        assert_eq!(pk.hit(a), (true, true), "density 0: the first request floods");
    }

    #[test]
    fn pike_window_changes_carry_or_clear_the_block() {
        // (window offset of the stored entry, its count, blocked) → result of the next hit
        let cases: &[(u64, u32, bool, (bool, bool))] = &[
            (1, 11, true, (true, false)),
            (1, 10, true, (false, false)),
            (1, 2, true, (false, false)),
            (2, 500, true, (false, false)),
            (1, 500, false, (false, false)),
            (0, 10, false, (true, true)),
            (0, 9, false, (false, false)),
            (0, u32::MAX, true, (true, false)),
        ];
        for &(back, cnt, blocked, want) in cases {
            let (pk, win) = pike(10);
            let a = ip("198.51.100.1");
            pk.ips.insert(a, Hits { win: win - back, cnt, prev: 0, blocked, last: 0 });
            assert_eq!(pk.hit(a), want, "entry {back} window(s) back, count {cnt}, blocked {blocked}");
            let h = pk.ips.get_cloned(&a).unwrap();
            assert_eq!(h.win, win);
            match back {
                0 => assert_eq!(h.cnt, cnt.saturating_add(1)),
                1 => assert_eq!((h.prev, h.cnt), (cnt, 1)),
                _ => assert_eq!((h.prev, h.cnt), (0, 1)),
            }
        }
    }

    #[test]
    fn pike_params_clamp() {
        let pk = Pike::default();
        pk.set_param("sampling_time_unit", &Arg::Int(0)).unwrap();
        assert_eq!(pk.unit.load(Ordering::Relaxed), 1, "a zero window would divide by zero");
        pk.set_param("reqs_density_per_unit", &Arg::Int(-5)).unwrap();
        assert_eq!(pk.density.load(Ordering::Relaxed), 0);
        assert!(pk.set_param("nope", &Arg::Int(1)).is_err());
    }

    #[test]
    fn algorithm_names() {
        let cases: &[(&str, Option<Alg>)] = &[
            ("TAILDROP", Some(Alg::TailDrop)),
            ("taildrop", Some(Alg::TailDrop)),
            (" RED ", Some(Alg::Red)),
            ("Network", Some(Alg::Network)),
            ("FEEDBACK", Some(Alg::Feedback)),
            ("", None),
            ("REDX", None),
        ];
        for &(s, want) in cases {
            assert_eq!(Alg::parse(s).ok(), want, "{s:?}");
        }
        for a in [Alg::TailDrop, Alg::Red, Alg::Network, Alg::Feedback] {
            assert_eq!(Alg::parse(a.name()), Ok(a));
        }
    }

    /// Accepted requests out of `n` on a fresh pipe.
    fn accepted(alg: Alg, limit: i64, n: usize) -> Vec<bool> {
        let p = Pipe::new(alg, limit);
        (0..n).map(|_| p.check()).collect()
    }

    #[test]
    fn taildrop_network_and_feedback_drop_above_the_limit() {
        for alg in [Alg::TailDrop, Alg::Network, Alg::Feedback] {
            for (limit, n) in [(0i64, 3usize), (1, 3), (2, 4), (5, 8), (-1, 2)] {
                let got = accepted(alg, limit, n);
                let want: Vec<bool> = (1..=n).map(|i| i64::try_from(i).unwrap() <= limit).collect();
                assert_eq!(got, want, "{alg:?} limit {limit}");
            }
        }
        let p = Pipe::new(Alg::TailDrop, 2);
        (0..5).for_each(|_| {
            p.check();
        });
        assert_eq!((p.counter.load(Ordering::Relaxed), p.dropped.load(Ordering::Relaxed)), (5, 3));
    }

    #[test]
    fn red_never_drops_below_three_quarters_and_always_above_the_limit() {
        for limit in [1i64, 4, 8, 100, 1001] {
            let got = accepted(Alg::Red, limit, usize::try_from(limit).unwrap() + 5);
            let q = usize::try_from(three_quarters(limit)).unwrap();
            assert!(got[..q].iter().all(|&a| a), "limit {limit}: the first {q} are always accepted");
            assert!(got[usize::try_from(limit).unwrap()..].iter().all(|&a| !a), "limit {limit}: over the limit");
        }
        assert_eq!(accepted(Alg::Red, 0, 2), [false, false]);
        assert_eq!(accepted(Alg::Red, -3, 1), [false]);
    }

    #[test]
    fn red_drops_some_at_the_top_of_the_band() {
        // limit 4: 3/4 is 3, so the 4th request is in the band with the
        // highest early-drop probability (1000/4000).
        let p = Pipe::new(Alg::Red, 4);
        let trials = 4000;
        let ok = (0..trials)
            .filter(|_| {
                p.counter.store(3, Ordering::Relaxed);
                p.check()
            })
            .count();
        assert!((2400..=3600).contains(&ok), "about 3 in 4 accepted, got {ok} of {trials}");
        assert_eq!(p.dropped.load(Ordering::Relaxed), i64::try_from(trials - ok).unwrap());
    }

    #[test]
    fn three_quarters_rounds_down() {
        let cases = [(0, 0), (1, 0), (2, 1), (3, 2), (4, 3), (5, 3), (6, 4), (7, 5), (-4, -3), (i64::MAX, 6_917_529_027_641_081_855)];
        for (l, want) in cases {
            assert_eq!(three_quarters(l), want, "{l}");
        }
    }

    #[test]
    fn ratelimit_pipe_and_queue_params() {
        let rl = RateLimit::default();
        let cases: &[(&str, bool)] = &[
            ("p1:TAILDROP:10", true),
            (" p2 : red : 5 ", true),
            ("p3:NETWORK:0", true),
            ("p4:TAILDROP", false),
            ("p5:FOO:1", false),
            ("p6:RED:x", false),
            ("a:b:c:d", false),
        ];
        for &(s, ok) in cases {
            assert_eq!(rl.set_param("pipe", &Arg::Str(s.into())).is_ok(), ok, "{s:?}");
        }
        let p2 = rl.pipe("p2").unwrap();
        assert_eq!((*lock(&p2.alg), p2.limit.load(Ordering::Relaxed)), (Alg::Red, 5));
        rl.set_param("queue", &Arg::Str("p1: invite ".into())).unwrap();
        assert!(rl.set_param("queue", &Arg::Str("p1".into())).is_err());
        assert_eq!(*lock(&rl.queues), [("p1".to_string(), "INVITE".to_string())]);
        rl.set_param("timer_interval", &Arg::Int(0)).unwrap();
        assert_eq!(rl.timer_interval.load(Ordering::Relaxed), 1);
        rl.set_param("queue", &Arg::Str("missing:BYE".into())).unwrap();
        let err = Arc::new(rl).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn set_pipe_rpc_updates_or_creates() {
        let pipes: Arc<Pipes> = Arc::new(RwLock::new(HashMap::new()));
        write(&pipes).insert("a".into(), Arc::new(Pipe::new(Alg::TailDrop, 1)));
        let update = set_pipe_rpc(pipes.clone(), false);
        assert!(update(&[json!("a"), json!("RED"), json!(7)]).is_ok());
        let a = read(&pipes)["a"].clone();
        assert_eq!((*lock(&a.alg), a.limit.load(Ordering::Relaxed)), (Alg::Red, 7));
        assert_eq!(update(&[json!("b"), json!("RED"), json!(7)]).err().as_deref(), Some("no such pipe"));
        assert!(update(&[json!("a"), json!("BAD"), json!(7)]).is_err());
        assert!(update(&[json!("a"), json!("RED")]).is_err());
        let create = set_pipe_rpc(pipes.clone(), true);
        create(&[json!("b"), json!("TAILDROP"), json!("3")]).unwrap();
        let v = pipes_json(&pipes);
        let names: Vec<&str> = v.as_array().unwrap().iter().map(|p| p["pipe"].as_str().unwrap()).collect();
        assert_eq!(names, ["a", "b"], "sorted by name");
        assert_eq!(v[1]["limit"], json!(3));
        assert_eq!(v[1]["algorithm"], json!("TAILDROP"));
    }

    #[test]
    fn rl_check_uses_the_queue_of_the_method() {
        let rl = Arc::new(RateLimit::default());
        for s in ["inv:TAILDROP:1", "all:TAILDROP:2"] {
            rl.set_param("pipe", &Arg::Str(s.into())).unwrap();
        }
        for s in ["inv:INVITE", "all:*", "inv:BYE"] {
            rl.set_param("queue", &Arg::Str(s.into())).unwrap();
        }
        let mut reg = Registry::default();
        reg.load(rl.clone()).unwrap();
        let rl_check = |args: &[Arg], method: &str| call(&reg, "rl_check", args, &request(method)).0;
        assert_eq!(rl_check(&[], "INVITE"), 1);
        assert_eq!(rl_check(&[], "INVITE"), -1, "pipe inv holds 1");
        assert_eq!(rl_check(&[], "BYE"), 1, "the earlier `*` queue wins over inv:BYE");
        assert_eq!(rl_check(&[], "BYE"), 1);
        assert_eq!(rl_check(&[], "OPTIONS"), -1, "pipe all holds 2");
        assert_eq!(rl_check(&[Arg::Str("inv".into())], "OPTIONS"), -1);
        assert_eq!(rl_check(&[Arg::Str("nope".into())], "OPTIONS"), -2, "no such pipe");
        assert!((reg.get("rl_check").unwrap().fixup)(&[Arg::Int(1), Arg::Int(2)]).is_err());
    }

    #[test]
    fn rl_check_without_a_matching_queue_is_not_limited() {
        let rl = Arc::new(RateLimit::default());
        rl.set_param("pipe", &Arg::Str("p:TAILDROP:0".into())).unwrap();
        rl.set_param("queue", &Arg::Str("p:INVITE".into())).unwrap();
        let mut reg = Registry::default();
        reg.load(rl).unwrap();
        assert_eq!(call(&reg, "rl_check", &[], &request("MESSAGE")).0, 1);
        assert_eq!(call(&reg, "rl_check", &[], &request("INVITE")).0, -1);
        let reply = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nCSeq: 1 INVITE\r\n\r\n";
        assert_eq!(call(&reg, "rl_check", &[], reply).0, -1, "replies have no method queue");
    }

    #[test]
    fn pl_check_creates_pipes_on_demand() {
        let mut reg = Registry::default();
        reg.load(Arc::new(PipeLimit::default())).unwrap();
        let req = request("INVITE");
        let check = |args: &[Arg]| call(&reg, "pl_check", args, &req).0;
        assert_eq!(check(&[Arg::Str("p".into())]), -2, "no such pipe yet");
        let create = [Arg::Str("p".into()), Arg::Str("TAILDROP".into()), Arg::Str("2".into())];
        assert_eq!(check(&create), 1);
        assert_eq!(check(&[Arg::Str("p".into())]), 1);
        assert_eq!(check(&create), -1, "an existing pipe keeps its limit");
        let bad = [Arg::Str("q".into()), Arg::Str("LIFO".into()), Arg::Str("2".into())];
        assert!((reg.get("pl_check").unwrap().fixup)(&bad).is_err());
    }

    #[test]
    fn pl_drop_replies_with_retry_after() {
        let pl = Arc::new(PipeLimit::default());
        pl.set_param("reply_code", &Arg::Int(429)).unwrap();
        pl.set_param("reply_reason", &Arg::Str("Too Many".into())).unwrap();
        assert!(pl.set_param("reply_code", &Arg::Int(99)).is_err());
        assert!(pl.set_param("reply_code", &Arg::Int(700)).is_err());
        let mut reg = Registry::default();
        reg.load(pl).unwrap();
        let req = request("INVITE");
        let retry = |sent: &[String]| sent[0].lines().find_map(|l| l.strip_prefix("Retry-After: ")).map(|v| v.parse::<i64>().unwrap());
        let (r, sent) = call(&reg, "pl_drop", &[], &req);
        assert_eq!(r, 1);
        assert!(sent[0].starts_with("SIP/2.0 429 Too Many\r\n"), "{}", sent[0]);
        assert_eq!(retry(&sent), None);
        let (_, sent) = call(&reg, "pl_drop", &[Arg::Int(7)], &req);
        assert_eq!(retry(&sent), Some(7));
        for _ in 0..50 {
            let (_, sent) = call(&reg, "pl_drop", &[Arg::Int(0), Arg::Int(3), Arg::Int(5)], &req);
            assert!((3..=5).contains(&retry(&sent).unwrap()));
        }
        let (_, sent) = call(&reg, "pl_drop", &[Arg::Int(0), Arg::Int(4), Arg::Int(4)], &req);
        assert_eq!(retry(&sent), Some(4));
        let (_, sent) = call(&reg, "pl_drop", &[Arg::Int(0), Arg::Int(5), Arg::Int(3)], &req);
        assert_eq!(retry(&sent), None, "an empty range: no Retry-After");
        assert!((reg.get("pl_drop").unwrap().fixup)(&[Arg::Int(1), Arg::Int(2)]).is_err());
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::testutil::{Sent, TextDb, call, call_from, request, rpc};
    use sip_core::{Dest, Proto};

    fn s(v: &str) -> Arg {
        Arg::Str(v.into())
    }

    fn pike(density: i64) -> (Arc<Pike>, Registry) {
        let pk = Arc::new(Pike::default());
        pk.set_param("sampling_time_unit", &Arg::Int(1 << 28)).unwrap();
        pk.set_param("reqs_density_per_unit", &Arg::Int(density)).unwrap();
        let mut reg = Registry::default();
        reg.load(pk.clone()).unwrap();
        (pk, reg)
    }

    #[test]
    fn pike_params() {
        let pk = Pike::default();
        pk.set_param("pike_log_level", &Arg::Int(-1)).unwrap();
        pk.set_param("remove_latency", &Arg::Int(30)).unwrap();
        assert_eq!(pk.remove_latency.load(Ordering::Relaxed), 30);
        assert!(pk.set_param("sampling_time_unit", &s("x")).is_err(), "not a number");
    }

    #[test]
    fn pike_check_ip_counts_the_given_address() {
        let (_, reg) = pike(1);
        let req = request("OPTIONS");
        let check = |ip: &str| call(&reg, "pike_check_ip", &[s(ip)], &req).0;
        assert_eq!(check("192.0.2.1"), 1);
        assert_eq!(check(" 192.0.2.1 "), -1, "second hit over a density of 1; trimmed");
        assert_eq!(check("2001:db8::1"), 1);
        assert_eq!(check("not-an-ip"), -1);
        assert_eq!(check(""), -1);
        assert!((reg.get("pike_check_ip").unwrap().fixup)(&[]).is_err());
    }

    #[test]
    fn pike_top_lists_blocked_or_all() {
        let (_, reg) = pike(1);
        let req = request("OPTIONS");
        for ip in ["192.0.2.1", "192.0.2.1", "192.0.2.2"] {
            call(&reg, "pike_check_ip", &[s(ip)], &req);
        }
        assert_eq!(rpc(&reg, "pike.top", json!([])), Ok(json!([{"ip": "192.0.2.1", "blocked": true, "hits": 2, "prev": 0}])));
        assert_eq!(rpc(&reg, "pike.top", json!(["HOT"])).unwrap().as_array().unwrap().len(), 1);
        let mut all: Vec<String> =
            rpc(&reg, "pike.top", json!(["all"])).unwrap().as_array().unwrap().iter().map(|e| e["ip"].as_str().unwrap().to_string()).collect();
        all.sort();
        assert_eq!(all, ["192.0.2.1", "192.0.2.2"]);
    }

    /// An event route that records `$si` (the context's source address).
    #[derive(Default)]
    struct Blocked(Mutex<Vec<std::net::SocketAddr>>);
    impl sip_core::RouteRunner for Blocked {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            lock(&self.0).push(ctx.src.addr);
            true
        }
    }

    #[test]
    fn pike_check_req_raises_pike_blocked_once_with_the_source() {
        let (pk, reg) = pike(1);
        let rec = Arc::new(Blocked::default());
        reg.hub.set_names(sip_core::RouteNames { event: vec!["pike:blocked".into()], ..Default::default() });
        reg.hub.set_runner(rec.clone());
        let src = Dest::new(Proto::Udp, "192.0.2.9:5070".parse().unwrap());
        let req = request("INVITE");
        let check = || call_from(&reg, "pike_check_req", &[], &req, Some(src)).0;
        assert_eq!(check(), 1);
        assert_eq!(check(), -1);
        assert!(lock(&rec.0).is_empty(), "no network yet (before spawn): no event");
        let net: Arc<dyn Outbound> = Arc::new(Sent::default());
        assert!(pk.net.set(net).is_ok());
        pk.ips.remove(&src.addr.ip());
        assert_eq!(check(), 1);
        assert_eq!(check(), -1);
        assert_eq!(check(), -1);
        assert_eq!(*lock(&rec.0), [src.addr], "once, when the address starts flooding");
    }

    #[test]
    fn ratelimit_ignored_and_unknown_params() {
        let rl = RateLimit::default();
        for name in ["reply_code", "reply_reason", "hash_size", "load_source", "limit_hash_size"] {
            assert!(rl.set_param(name, &Arg::Int(1)).is_ok(), "{name}");
        }
        assert!(rl.set_param("nope", &Arg::Int(1)).is_err());
    }

    #[test]
    fn pipelimit_ignored_and_unknown_params() {
        let pl = PipeLimit::default();
        for name in ["hash_size", "load_source", "clean_unused", "plp_pipeid_column", "plp_limit_column", "plp_algorithm_column"] {
            assert!(pl.set_param(name, &Arg::Int(1)).is_ok(), "{name}");
        }
        assert!(pl.set_param("nope", &Arg::Int(1)).is_err());
        assert!(pl.set_param("reply_code", &s("x")).is_err());
    }

    const PIPES: &str = "pipeid(string) algorithm(string) plimit(int)\n";

    #[test]
    fn pipelimit_loads_and_reloads_pipes_from_the_database() {
        let db = TextDb::new(&[("mypipes", &format!("{PIPES}a:TAILDROP:1\nb:red:5\n"))]);
        let pl = Arc::new(PipeLimit::default());
        pl.set_param("db_url", &s(&db.url())).unwrap();
        pl.set_param("table_name", &s("mypipes")).unwrap();
        let mut reg = Registry::default();
        reg.load(pl.clone()).unwrap();
        let req = request("INVITE");
        let check = |p: &str| call(&reg, "pl_check", &[s(p)], &req).0;
        assert_eq!((check("a"), check("a")), (1, -1));
        let b = read(&pl.pipes)["b"].clone();
        assert_eq!((*lock(&b.alg), b.limit.load(Ordering::Relaxed)), (Alg::Red, 5));

        db.write("mypipes", &format!("{PIPES}a:NETWORK:3\nc:FEEDBACK:2\n"));
        assert_eq!(rpc(&reg, "pl.reload", json!([])), Ok(json!(2)));
        let a = read(&pl.pipes)["a"].clone();
        assert_eq!(
            (*lock(&a.alg), a.limit.load(Ordering::Relaxed), a.counter.load(Ordering::Relaxed)),
            (Alg::Network, 3, 2),
            "updated in place: counters kept"
        );
        assert!(read(&pl.pipes).contains_key("b"), "a pipe gone from the table stays");
        assert_eq!(check("a"), 1);
        assert_eq!(check("c"), 1);

        db.write("mypipes", &format!("{PIPES}a:LIFO:3\n"));
        assert!(rpc(&reg, "pl.reload", json!([])).unwrap_err().contains("LIFO"));
        assert!((reg.get("pl_check").unwrap().fixup)(&[s("a"), s("RED")]).is_err(), "two arguments");
    }

    #[test]
    fn pipelimit_without_its_table_fails_to_load() {
        let db = TextDb::new(&[]);
        let pl = Arc::new(PipeLimit::default());
        pl.set_param("db_url", &s(&db.url())).unwrap();
        assert!(Registry::default().load(pl).is_err());
    }
}
