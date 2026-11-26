//! Asynchronous processing (Kamailio `async`, `http_async_client`): a
//! request is suspended in tm (`Tm::suspend`), the slow part runs on a
//! worker pool or a timer, and the script continues afterwards on the same
//! transaction (`Tm::resume`) — the SIP workers never block.
//!
//! * `async` — `async_route(route, s)`, `async_ms_route(route, ms)`,
//!   `async_sleep(s)`, `async_ms_sleep(ms)` (continue with the next action
//!   of the same block, like Kamailio), `async_task_route(route)` (run the
//!   route on a pool thread now). Parameter `workers` (default 1).
//! * `http_async_client` — `http_async_query(url, route)` with the request
//!   built in `$http_req(...)`; the route sees `$http_ok`, `$http_err`,
//!   `$http_rs`, `$http_rr`, `$http_rb`, `$http_bs`, `$http_hdr(name)`,
//!   `$http_time`. Parameters `workers`, `connection_timeout` (ms).
//! * `http_client` — blocking `http_client_query`, `http_connect`.
//! * `jansson` / `json` — JSON in the script.
//! * `jsonrpcs` — `jsonrpc_exec()` and a FIFO transport.

#[cfg(feature = "http")]
mod http;
mod json;
mod rpcs;

use mod_txn::Tm;
use sip_core::module::{Arg, RC_ERR};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Continuation, Ctx, Module};
use std::collections::BinaryHeap;
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["async", "http_async_client", "http_client", "jansson", "json", "jsonrpcs"];

/// An `async_sleep`-style delay in milliseconds: `d` units of `scale` ms.
/// Negative is no delay; a huge one saturates instead of wrapping into a
/// short (or, in debug builds, panicking) one.
fn delay_ms(d: i64, scale: u64) -> u64 {
    u64::try_from(d).unwrap_or(0).saturating_mul(scale)
}

/// Exactly `N` arguments, as an array to destructure.
fn fixed_args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "async" => Arc::new(Async::default()),
        #[cfg(feature = "http")]
        "http_async_client" => Arc::new(http::HttpAsync::default()),
        #[cfg(feature = "http")]
        "http_client" => Arc::new(http::HttpClient::default()),
        "jansson" => Arc::new(json::Jansson::named("jansson")),
        "json" => Arc::new(json::Jansson::named("json")),
        "jsonrpcs" => Arc::new(rpcs::JsonRpcs::default()),
        _ => return None,
    })
}

type Job = Box<dyn FnOnce() + Send>;

/// A fixed pool of threads fed through a channel.
pub struct Pool {
    tx: Mutex<Sender<Job>>,
}

impl Pool {
    /// Starts `n` (at least one) worker threads; fails if any can't be started.
    pub fn new(name: &str, n: usize) -> Result<Arc<Self>, String> {
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..n.max(1) {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || {
                    loop {
                        let job = lock(&rx).recv();
                        match job {
                            Ok(j) => {
                                if sip_core::panic::catch(j).is_err() {
                                    sip_core::elog!("async: panic in a job");
                                }
                            }
                            Err(_) => return,
                        }
                    }
                })
                .map_err(|e| format!("cannot start thread {name}-{i}: {e}"))?;
        }
        Ok(Arc::new(Self { tx: Mutex::new(tx) }))
    }

    pub fn exec(&self, j: impl FnOnce() + Send + 'static) -> bool {
        lock(&self.tx).send(Box::new(j)).is_ok()
    }
}

struct Timed(Instant, u64, Job);

impl PartialEq for Timed {
    fn eq(&self, o: &Self) -> bool {
        (self.0, self.1) == (o.0, o.1)
    }
}
impl Eq for Timed {}
impl PartialOrd for Timed {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Timed {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        // Min-heap on (deadline, sequence).
        (o.0, o.1).cmp(&(self.0, self.1))
    }
}

/// One thread with a deadline heap; due jobs go to the pool.
pub struct Timer {
    q: Mutex<(BinaryHeap<Timed>, u64)>,
    cv: Condvar,
}

impl Timer {
    /// Starts the timer thread.
    pub fn new(pool: Arc<Pool>) -> Result<Arc<Self>, String> {
        let t = Arc::new(Self { q: Mutex::new((BinaryHeap::new(), 0)), cv: Condvar::new() });
        let me = t.clone();
        std::thread::Builder::new()
            .name("async-timer".into())
            .spawn(move || {
                let mut g = lock(&me.q);
                loop {
                    let now = Instant::now();
                    while g.0.peek().is_some_and(|t| t.0 <= now) {
                        if let Some(Timed(_, _, job)) = g.0.pop() {
                            pool.exec(job);
                        }
                    }
                    g = match g.0.peek().map(|t| t.0.saturating_duration_since(now)) {
                        Some(d) => me.cv.wait_timeout(g, d).unwrap_or_else(|e| e.into_inner()).0,
                        None => me.cv.wait(g).unwrap_or_else(|e| e.into_inner()),
                    };
                }
            })
            .map_err(|e| format!("cannot start thread async-timer: {e}"))?;
        Ok(t)
    }

    pub fn after(&self, d: Duration, j: impl FnOnce() + Send + 'static) {
        let mut g = lock(&self.q);
        // Only orders equal deadlines: wrapping is harmless.
        g.1 = g.1.wrapping_add(1);
        let seq = g.1;
        g.0.push(Timed(deadline(Instant::now(), d), seq, Box::new(j)));
        self.cv.notify_one();
    }
}

/// The longest a timer waits (ten years): longer script delays are clamped
/// to it, so the deadline always fits in an `Instant`.
const MAX_DELAY: Duration = Duration::from_secs(315_360_000);

/// When a timer started at `now` with delay `d` fires.
fn deadline(now: Instant, d: Duration) -> Instant {
    now.checked_add(d.min(MAX_DELAY)).unwrap_or(now)
}

/// Continue a suspended transaction with `cont`, after `prepare`.
pub(crate) fn resume_with(tm: &Tm, id: &mod_txn::TxnId, cont: &Continuation, prepare: impl FnOnce(&mut Ctx<'_, '_>)) -> bool {
    tm.resume(id, |r, c| {
        prepare(c);
        r.resume(cont, c);
    })
}

/// The value in `cell`, built by `init` on first use. A failed build is
/// logged and retried on the next call.
pub(crate) fn lazy<T>(cell: &OnceLock<T>, init: impl FnOnce() -> Result<T, String>) -> Option<&T> {
    if let Some(v) = cell.get() {
        return Some(v);
    }
    match init() {
        // A racing caller may have won; its value is kept and ours dropped.
        Ok(v) => Some(cell.get_or_init(|| v)),
        Err(e) => {
            sip_core::elog!("async: {e}");
            None
        }
    }
}

/// Index of `route[name]`, resolved once the script is compiled.
pub(crate) fn route_idx(reg_hub: &sip_core::RouteHub, name: &str) -> Option<usize> {
    reg_hub.runner()?.route_index(name)
}

#[derive(Default)]
pub struct Async {
    workers: std::sync::atomic::AtomicUsize,
    pool: OnceLock<Arc<Pool>>,
    timer: OnceLock<Arc<Timer>>,
}

impl Async {
    /// The worker pool, started on first use; `None` (logged) if its
    /// threads can't be started — the caller fails the job.
    fn pool(&self) -> Option<&Arc<Pool>> {
        lazy(&self.pool, || Pool::new("async", self.workers.load(std::sync::atomic::Ordering::Relaxed).max(1)))
    }

    /// The timer thread (and the pool it feeds), started on first use.
    fn timer(&self) -> Option<&Arc<Timer>> {
        let pool = self.pool()?.clone();
        lazy(&self.timer, || Timer::new(pool))
    }
}

impl Module for Async {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("workers", Ty::Int { min: 1, max: 256 }, "1", "Threads that run async tasks")])
    }

    fn name(&self) -> &'static str {
        "async"
    }

    fn set_param(&self, name: &str, v: &sip_core::Arg) -> Result<(), String> {
        match name {
            "workers" => self.workers.store(usize::try_from(v.int()?.clamp(1, 256)).unwrap_or(1), std::sync::atomic::Ordering::Relaxed),
            "ms_timer" => {}
            _ => return Err(format!("async: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::schema::Unit;
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, hidden, sig};
        const SLEEP: &[Param] = &[arg("duration", Duration(Unit::Ms))];
        Some(vec![
            sig("async_ms_sleep", "sleep", SLEEP, Ret::Void, "Pause this request (the transaction waits, the worker doesn't), then go on")
                .allowed(ctx::REQUEST),
            hidden("async_sleep", "use async.sleep(duration), which takes any duration (2s, 500ms)"),
            hidden("async_route", "takes a route to resume in; .fsr uses await (coming)"),
            hidden("async_ms_route", "takes a route to resume in; .fsr uses await (coming)"),
            hidden("async_task_route", "takes a route to resume in; .fsr uses await (coming)"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut sip_core::Registry) -> Result<(), String> {
        use sip_core::Arg;
        use sip_core::module::DynInt;
        let tm = reg.api::<Tm>().ok_or("async needs tm (load it first)")?;
        let hub = reg.hub.clone();
        // async_route / async_ms_route(route, delay)
        for (name, ms) in [("async_route", 1000u64), ("async_ms_route", 1)] {
            let (me, tm, hub) = (self.clone(), tm.clone(), hub.clone());
            reg.export(
                "async",
                name,
                |a: &[Arg]| {
                    let [route, delay] = fixed_args(a)?;
                    Ok((route.str()?.to_string(), delay.dyn_int()?))
                },
                move |ctx: &mut Ctx, (route, d): &(String, DynInt)| {
                    let Some(idx) = route_idx(&hub, route) else { return -1 };
                    let Some(timer) = me.timer() else { return RC_ERR };
                    let d = delay_ms(d.eval(ctx).unwrap_or(0), ms);
                    let id = match tm.suspend_for(ctx, d) {
                        Ok(id) => id,
                        Err(rc) => return rc,
                    };
                    let tm = tm.clone();
                    timer.after(Duration::from_millis(d), move || {
                        resume_with(&tm, &id, &Continuation::route(idx), |_| {});
                    });
                    0
                },
            );
        }
        // async_sleep / async_ms_sleep(delay): continue after the call.
        for (name, ms) in [("async_sleep", 1000u64), ("async_ms_sleep", 1)] {
            let (me, tm) = (self.clone(), tm.clone());
            reg.export(
                "async",
                name,
                |a: &[Arg]| {
                    let [delay] = fixed_args(a)?;
                    delay.dyn_int()
                },
                move |ctx: &mut Ctx, d: &DynInt| {
                    let Some(timer) = me.timer().cloned() else { return RC_ERR };
                    let d = delay_ms(d.eval(ctx).unwrap_or(0), ms);
                    let id = match tm.suspend_for(ctx, d) {
                        Ok(id) => id,
                        Err(rc) => return rc,
                    };
                    let tm = tm.clone();
                    ctx.ext.push(Box::new(sip_core::AsyncPending(Box::new(move |cont| {
                        timer.after(Duration::from_millis(d), move || {
                            resume_with(&tm, &id, &cont, |_| {});
                        });
                    }))));
                    0
                },
            );
        }
        // async_task_route(route): run it on a pool thread now.
        let (me, tm2) = (self.clone(), tm.clone());
        reg.export(
            "async",
            "async_task_route",
            |a: &[Arg]| {
                let [route] = fixed_args(a)?;
                Ok(route.str()?.to_string())
            },
            move |ctx: &mut Ctx, route: &String| {
                let Some(idx) = route_idx(&hub, route) else { return -1 };
                let Some(pool) = me.pool() else { return RC_ERR };
                let id = match tm2.suspend(ctx) {
                    Ok(id) => id,
                    Err(rc) => return rc,
                };
                let tm = tm2.clone();
                pool.exec(move || {
                    resume_with(&tm, &id, &Continuation::route(idx), |_| {});
                });
                0
            },
        );
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn sip_core::Outbound>) -> Result<(), String> {
        // Started now so a thread limit shows at startup, not on first use.
        self.timer().map(|_| ()).ok_or_else(|| "cannot start the async worker/timer threads".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_DELAY, deadline, delay_ms};
    use std::time::{Duration, Instant};

    #[test]
    fn delays_saturate() {
        assert_eq!(delay_ms(3, 1000), 3000);
        assert_eq!(delay_ms(-5, 1000), 0);
        assert_eq!(delay_ms(i64::MAX, 1000), u64::MAX);
        assert_eq!(delay_ms(i64::MAX, 1), 9_223_372_036_854_775_807);
    }

    #[test]
    fn huge_delays_are_clamped() {
        // async_sleep(9223372036854775807): u64::MAX ms can't be added to an Instant.
        let now = Instant::now();
        assert_eq!(deadline(now, Duration::from_millis(delay_ms(i64::MAX, 1000))), now + MAX_DELAY);
        assert_eq!(deadline(now, Duration::from_millis(1500)), now + Duration::from_millis(1500));
    }
}

#[cfg(test)]
mod timer_tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn delay_ms_scales_and_clamps() {
        let cases: &[(i64, u64, u64)] = &[
            (0, 1000, 0),
            (1, 1000, 1000),
            (250, 1, 250),
            (-1, 1000, 0),
            (i64::MIN, 1, 0),
            (i64::MAX, 1, i64::MAX as u64),
            (i64::MAX, 3, u64::MAX),
            (18_446_744_073_709_551, 1000, 18_446_744_073_709_551_000),
            (18_446_744_073_709_552, 1000, u64::MAX),
        ];
        for &(d, scale, want) in cases {
            assert_eq!(delay_ms(d, scale), want, "{d} x {scale}");
        }
    }

    #[test]
    fn deadline_is_clamped_to_ten_years() {
        let now = Instant::now();
        assert_eq!(deadline(now, Duration::ZERO), now);
        assert_eq!(deadline(now, MAX_DELAY), now + MAX_DELAY);
        assert_eq!(deadline(now, MAX_DELAY + Duration::from_secs(1)), now + MAX_DELAY);
        assert_eq!(deadline(now, Duration::MAX), now + MAX_DELAY);
    }

    fn timed(at: Instant, seq: u64) -> Timed {
        Timed(at, seq, Box::new(|| {}))
    }

    #[test]
    fn timer_heap_pops_earliest_deadline_then_lowest_sequence() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut heap = BinaryHeap::new();
        for (d, seq) in [(30, 1), (10, 2), (20, 3), (10, 4), (0, 9), (10, 0)] {
            heap.push(timed(t0 + ms(d), seq));
        }
        let order: Vec<(u128, u64)> = std::iter::from_fn(|| heap.pop()).map(|t| (t.0.duration_since(t0).as_millis(), t.1)).collect();
        assert_eq!(order, [(0, 9), (10, 0), (10, 2), (10, 4), (20, 3), (30, 1)]);
        assert!(timed(t0, 1) == timed(t0, 1));
        assert!(timed(t0, 1) > timed(t0, 2), "greater = sooner (max-heap of a min order)");
    }

    #[test]
    fn timer_runs_due_jobs_in_order_and_not_late_ones_first() {
        let pool = Pool::new("t-test", 1).unwrap();
        let timer = Timer::new(pool).unwrap();
        let (tx, rx) = mpsc::channel();
        let later = tx.clone();
        timer.after(Duration::from_secs(3600), move || later.send(0).unwrap());
        for i in 1..=5 {
            let tx = tx.clone();
            timer.after(Duration::ZERO, move || tx.send(i).unwrap());
        }
        let got: Vec<i32> = (0..5).map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap()).collect();
        assert_eq!(got, [1, 2, 3, 4, 5], "same deadline: submission order; the far job does not block them");
    }

    #[test]
    fn pool_runs_jobs_and_survives_a_panicking_one() {
        let pool = Pool::new("p-test", 1).unwrap();
        let (tx, rx) = mpsc::channel();
        assert!(pool.exec(|| panic!("job panics")));
        assert!(pool.exec(move || tx.send(7).unwrap()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), 7);
    }

    #[test]
    fn lazy_retries_after_a_failed_init() {
        let cell = OnceLock::new();
        assert_eq!(lazy(&cell, || Err::<u8, _>("no".into())), None);
        assert_eq!(lazy(&cell, || Ok(1)), Some(&1));
        assert_eq!(lazy(&cell, || Ok(2)), Some(&1), "built once");
    }

    #[test]
    fn async_params() {
        let a = Async::default();
        for (v, want) in [(0, 1), (5, 5), (1000, 256), (-3, 1)] {
            a.set_param("workers", &Arg::Int(v)).unwrap();
            assert_eq!(a.workers.load(std::sync::atomic::Ordering::Relaxed), want, "{v}");
        }
        assert!(a.set_param("nope", &Arg::Int(1)).is_err());
        let names: Vec<&str> = NAMES.iter().copied().filter(|n| module(n).is_some()).collect();
        assert_eq!(names, NAMES, "every name has a module");
        for n in NAMES {
            assert_eq!(module(n).unwrap().name(), *n);
        }
    }
}
