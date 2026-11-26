//! `cnxcc` — credit control per customer, enforced on the calls the
//! `dialog` module tracks (call `dlg_manage()` first):
//! * `cnxcc_set_max_credit(customer, max_credit, connect_cost,
//!   cost_per_second, initial_pulse, final_pulse)` — money: the customer's
//!   running calls together may not cost more than `max_credit`;
//! * `cnxcc_set_max_time(customer, max_seconds)` — total talk time;
//! * `cnxcc_set_max_channels(customer, max)` — concurrent calls (-1 when
//!   the limit is reached).
//!
//! When the credit runs out every call of the customer is ended (BYE to
//! both sides). `cnxcc_get_channel_count(customer, $var)`,
//! `cnxcc_terminate_all(customer)`. RPC `cnxcc.active_clients`,
//! `cnxcc.check_client <customer>`, `cnxcc.kill_call <callid>`.

use crate::pv_arg;
use mod_dialog::{Dialog, DlgChange};
use sip_core::module::{DynStr, rc};
use sip_core::pv::{PvRef, Val};
use sip_core::schema::ParamSpec;
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Outbound, Registry};
use sip_parser::{HdrFlags, HdrKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
enum Limit {
    Money { max: f64, connect: f64, per_sec: f64, initial: u64, fin: u64 },
    Time { max: u64 },
    Channels { max: usize },
}

#[derive(Clone, Debug)]
struct Call {
    callid: String,
    /// When the call was answered.
    started: Option<Instant>,
}

#[derive(Clone, Debug)]
struct Client {
    limit: Limit,
    calls: Vec<Call>,
    /// Consumed by calls that already ended.
    spent: f64,
}

/// Whole seconds from a script number: `as` drops the fraction,
/// saturates, and maps negatives and NaN to 0.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "float to int `as` saturates and maps NaN to 0: the clamp wanted")]
fn whole_secs(x: f64) -> u64 {
    x as u64
}

impl Client {
    /// Billed cost of a call of `secs` seconds (pulses).
    fn cost(&self, secs: u64) -> f64 {
        match self.limit {
            Limit::Money { connect, per_sec, initial, fin, .. } => {
                let billed = if secs <= initial || fin == 0 {
                    initial.max(secs)
                } else {
                    initial.saturating_add(secs.saturating_sub(initial).div_ceil(fin).saturating_mul(fin))
                };
                connect + billed as f64 * per_sec
            }
            Limit::Time { .. } => secs as f64,
            Limit::Channels { .. } => 0.0,
        }
    }

    fn consumed(&self) -> f64 {
        self.spent + self.calls.iter().filter_map(|c| c.started).map(|s| self.cost(s.elapsed().as_secs())).sum::<f64>()
    }

    fn exhausted(&self) -> bool {
        match self.limit {
            Limit::Money { max, .. } => self.consumed() >= max,
            Limit::Time { max } => self.consumed() >= max as f64,
            Limit::Channels { .. } => false,
        }
    }
}

#[derive(Default)]
pub struct Cnxcc {
    clients: Mutex<HashMap<String, Client>>,
    dlg: OnceLock<Arc<Dialog>>,
}

fn callid(ctx: &mut Ctx<'_, '_>) -> Option<String> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    ctx.msg.get(HdrKind::CallId).map(|h| String::from_utf8_lossy(h.body).into_owned())
}

impl Cnxcc {
    fn add(&self, ctx: &mut Ctx<'_, '_>, customer: String, limit: Limit) -> i32 {
        let Some(cid) = callid(ctx) else { return -1 };
        let mut cl = lock(&self.clients);
        let c = cl.entry(customer).or_insert_with(|| Client { limit: limit.clone(), calls: vec![], spent: 0.0 });
        c.limit = limit;
        if let Limit::Channels { max } = c.limit
            && c.calls.len() >= max
        {
            return -1;
        }
        if c.exhausted() {
            return -1;
        }
        if !c.calls.iter().any(|x| x.callid == cid) {
            c.calls.push(Call { callid: cid, started: None });
        }
        1
    }

    fn on_change(&self, ch: &DlgChange) {
        let mut cl = lock(&self.clients);
        for c in cl.values_mut() {
            let Some(i) = c.calls.iter().position(|x| x.callid == ch.callid) else { continue };
            match ch.state {
                "confirmed" => {
                    if let Some(call) = c.calls.get_mut(i) {
                        call.started = Some(Instant::now());
                    }
                }
                "terminated" => {
                    let call = c.calls.remove(i);
                    if let Some(s) = call.started {
                        c.spent += c.cost(s.elapsed().as_secs());
                    }
                }
                _ => {}
            }
        }
    }

    fn kill(&self, callids: Vec<String>) {
        if let Some(d) = self.dlg.get() {
            for c in callids {
                d.end_by_callid(&c);
            }
        }
    }

    fn tick(&self) {
        let victims: Vec<String> = {
            let cl = lock(&self.clients);
            cl.iter()
                .filter(|(_, c)| c.exhausted() && c.calls.iter().any(|x| x.started.is_some()))
                .flat_map(|(name, c)| {
                    sip_core::log::log(sip_core::log::L_NOTICE, &format!("cnxcc: customer {name} is out of credit, ending its calls"));
                    c.calls.iter().map(|x| x.callid.clone()).collect::<Vec<_>>()
                })
                .collect()
        };
        self.kill(victims);
    }
}

fn nums<const N: usize>(a: &[Arg]) -> Result<[DynStr; N], String> {
    let a: &[Arg; N] = crate::fixed_args(a)?;
    let v: Vec<DynStr> = a.iter().map(Arg::dyn_str).collect::<Result<_, _>>()?;
    v.try_into().map_err(|_| format!("expected {N} argument(s)"))
}

impl Module for Cnxcc {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "cnxcc"
    }

    fn set_param(&self, name: &str, _v: &Arg) -> Result<(), String> {
        match name {
            "redis" | "credit_check_period" | "dlg_flag" => Ok(()),
            _ => Err(format!("cnxcc: unknown parameter {name:?}")),
        }
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::schema::Unit;
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const CREDIT: &[Param] = &[
            arg("customer", Str),
            arg("max_credit", Any).eg("\"10.50\""),
            arg("connect_cost", Any).eg("\"0.10\""),
            arg("cost_per_second", Any).eg("\"0.02\""),
            arg("initial_pulse", Duration(Unit::Sec)),
            arg("final_pulse", Duration(Unit::Sec)),
        ];
        const TIME: &[Param] = &[arg("customer", Str), arg("max_time", Duration(Unit::Sec))];
        const CHANNELS: &[Param] = &[arg("customer", Str), arg("max", Int)];
        const COUNT: &[Param] = &[arg("customer", Str), arg("count", Var)];
        const CUSTOMER: &[Param] = &[arg("customer", Str)];
        Some(vec![
            sig("cnxcc_set_max_credit", "set_max_credit", CREDIT, Ret::Bool, "Bill this call to the customer's credit (money); false when it is used up")
                .allowed(ctx::REQUEST),
            sig("cnxcc_set_max_time", "set_max_time", TIME, Ret::Bool, "Count this call against the customer's total talk time; false when it is used up")
                .allowed(ctx::REQUEST),
            sig(
                "cnxcc_set_max_channels",
                "set_max_channels",
                CHANNELS,
                Ret::Bool,
                "Count this call against the customer's concurrent calls; false at the limit",
            )
            .allowed(ctx::REQUEST),
            sig("cnxcc_get_channel_count", "get_channel_count", COUNT, Ret::Bool, "The customer's current number of calls, into `count`").allowed(ctx::ANY),
            sig("cnxcc_terminate_all", "terminate_all", CUSTOMER, Ret::Void, "End every call of the customer").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let dlg = reg.api::<Dialog>().ok_or("cnxcc needs dialog loaded first")?;
        let me = self.clone();
        dlg.on_state(Arc::new(move |c| me.on_change(c)));
        let _ = self.dlg.set(dlg);
        let m = "cnxcc";
        let me = self.clone();
        reg.export(
            m,
            "cnxcc_set_max_credit",
            |a: &[Arg]| nums(a),
            move |ctx: &mut Ctx, [customer, max, connect, per_sec, initial, fin]: &[DynStr; 6]| {
                let customer = customer.eval(ctx).into_owned();
                let mut num = |x: &DynStr| x.eval(ctx).trim().parse::<f64>().unwrap_or(0.0);
                let limit =
                    Limit::Money { max: num(max), connect: num(connect), per_sec: num(per_sec), initial: whole_secs(num(initial)), fin: whole_secs(num(fin)) };
                me.add(ctx, customer, limit)
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "cnxcc_set_max_time",
            |a: &[Arg]| nums(a),
            move |ctx: &mut Ctx, [customer, max]: &[DynStr; 2]| {
                let (c, t) = (customer.eval(ctx).into_owned(), max.eval(ctx).trim().parse::<u64>().unwrap_or(0));
                me.add(ctx, c, Limit::Time { max: t })
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "cnxcc_set_max_channels",
            |a: &[Arg]| nums(a),
            move |ctx: &mut Ctx, [customer, max]: &[DynStr; 2]| {
                let (c, n) = (customer.eval(ctx).into_owned(), max.eval(ctx).trim().parse::<usize>().unwrap_or(0));
                me.add(ctx, c, Limit::Channels { max: n })
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "cnxcc_get_channel_count",
            |a: &[Arg]| -> Result<(DynStr, PvRef), String> {
                let [customer, out] = crate::fixed_args(a)?;
                Ok((customer.dyn_str()?, pv_arg(out)?))
            },
            move |ctx: &mut Ctx, (c, out): &(DynStr, PvRef)| {
                let c = c.eval(ctx).into_owned();
                let n = lock(&me.clients).get(&c).map_or(0, |x| x.calls.len());
                rc(out.set(ctx, Val::Int(i64::try_from(n).unwrap_or(i64::MAX))).is_ok())
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "cnxcc_terminate_all",
            |a: &[Arg]| nums(a),
            move |ctx: &mut Ctx, [customer]: &[DynStr; 1]| {
                let c = customer.eval(ctx).into_owned();
                let ids = lock(&me.clients).get(&c).map(|x| x.calls.iter().map(|y| y.callid.clone()).collect()).unwrap_or_default();
                me.kill(ids);
                1
            },
        );
        let me = self.clone();
        reg.rpc.add("cnxcc.active_clients", "Customers with calls", move |_| {
            let cl = lock(&me.clients);
            Ok(json!(cl.iter().filter(|(_, c)| !c.calls.is_empty()).map(|(n, c)| json!({"client_id": n, "calls": c.calls.len()})).collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("cnxcc.check_client", "cnxcc.check_client <customer>", move |p| {
            let n = sip_core::rpc::str_param(p, 0)?;
            let cl = lock(&me.clients);
            let c = cl.get(&n).ok_or("no such client")?;
            let (kind, max) = match c.limit {
                Limit::Money { max, .. } => ("money", max),
                Limit::Time { max } => ("time", max as f64),
                Limit::Channels { max } => ("channels", max as f64),
            };
            Ok(json!({"client_id": n, "type": kind, "max": max, "consumed": c.consumed(), "calls": c.calls.iter().map(|x| json!({"call_id": x.callid, "answered": x.started.is_some()})).collect::<Vec<_>>()}))
        });
        let me = self.clone();
        reg.rpc.add("cnxcc.kill_call", "cnxcc.kill_call <callid>", move |p| {
            let c = sip_core::rpc::str_param(p, 0)?;
            me.kill(vec![c]);
            Ok(json!(0))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("cnxcc-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(500));
                    self.tick();
                }
            })
            .map_err(|e| format!("cannot start the cnxcc timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulses() {
        let c = Client { limit: Limit::Money { max: 10.0, connect: 1.0, per_sec: 0.5, initial: 30, fin: 6 }, calls: vec![], spent: 0.0 };
        assert_eq!(c.cost(0), 1.0 + 15.0, "initial pulse is always billed");
        assert_eq!(c.cost(31), 1.0 + 36.0 * 0.5, "next pulse rounds up");
        let t = Client { limit: Limit::Time { max: 5 }, calls: vec![], spent: 5.0 };
        assert!(t.exhausted());
    }
}

#[cfg(test)]
mod billing_tests {
    use super::*;
    use sip_core::{Dest, Lumps, Proto};

    fn money(max: f64, connect: f64, per_sec: f64, initial: u64, fin: u64) -> Client {
        Client { limit: Limit::Money { max, connect, per_sec, initial, fin }, calls: vec![], spent: 0.0 }
    }

    #[test]
    fn cost_bills_the_initial_pulse_then_whole_final_pulses() {
        // (initial, final, seconds, billed seconds); connect 1, 0.5 per second.
        let cases: &[(u64, u64, u64, u64)] = &[
            (30, 6, 0, 30),
            (30, 6, 1, 30),
            (30, 6, 30, 30),
            (30, 6, 31, 36),
            (30, 6, 36, 36),
            (30, 6, 37, 42),
            (60, 60, 61, 120),
            (1, 1, 59, 59),
            (0, 1, 0, 0),
            (0, 1, 7, 7),
            (0, 60, 1, 60),
            (0, 60, 60, 60),
            (0, 60, 61, 120),
            (30, 0, 10, 30),
            (30, 0, 45, 45),
        ];
        for &(initial, fin, secs, billed) in cases {
            let c = money(100.0, 1.0, 0.5, initial, fin);
            assert_eq!(c.cost(secs), 1.0 + billed as f64 * 0.5, "initial {initial}, final {fin}, {secs} s");
        }
    }

    #[test]
    fn cost_saturates_instead_of_overflowing() {
        let c = money(1.0, 0.0, 1.0, u64::MAX - 1, 7);
        assert_eq!(c.cost(u64::MAX), u64::MAX as f64);
        let c = money(1.0, 0.0, 1.0, 0, 7);
        assert!(c.cost(u64::MAX).is_finite());
    }

    #[test]
    fn time_and_channel_limits_cost_seconds_and_nothing() {
        let t = Client { limit: Limit::Time { max: 60 }, calls: vec![], spent: 0.0 };
        assert_eq!(t.cost(42), 42.0);
        let ch = Client { limit: Limit::Channels { max: 1 }, calls: vec![], spent: 1e9 };
        assert_eq!(ch.cost(42), 0.0);
        assert!(!ch.exhausted(), "a channel limit never runs out of credit");
    }

    #[test]
    fn exhausted_at_exactly_the_maximum() {
        let mut t = Client { limit: Limit::Time { max: 5 }, calls: vec![], spent: 4.0 };
        assert!(!t.exhausted());
        t.spent = 5.0;
        assert!(t.exhausted());
        // An answered call bills its connect cost and initial pulse at once.
        let mut m = money(16.0, 1.0, 0.5, 30, 6);
        m.calls.push(Call { callid: "a".into(), started: None });
        assert!(!m.exhausted(), "unanswered calls cost nothing");
        m.calls[0].started = Some(Instant::now());
        assert_eq!(m.consumed(), 16.0);
        assert!(m.exhausted());
        m.limit = Limit::Money { max: 16.5, connect: 1.0, per_sec: 0.5, initial: 30, fin: 6 };
        assert!(!m.exhausted());
    }

    #[test]
    fn whole_secs_truncates_and_clamps() {
        let cases = [(0.0, 0), (1.9, 1), (59.999, 59), (-1.0, 0), (f64::NAN, 0), (f64::INFINITY, u64::MAX), (1e30, u64::MAX)];
        for (x, want) in cases {
            assert_eq!(whole_secs(x), want, "{x}");
        }
    }

    fn change(state: &'static str, callid: &str) -> DlgChange {
        DlgChange {
            state,
            callid: callid.into(),
            from_uri: String::new(),
            to_uri: String::new(),
            from_tag: String::new(),
            to_tag: String::new(),
            req_uri: String::new(),
            flags: 0,
        }
    }

    #[test]
    fn dialog_changes_start_and_settle_calls() {
        let cc = Cnxcc::default();
        let mut c = money(100.0, 1.0, 0.5, 30, 6);
        c.calls = vec![Call { callid: "c1".into(), started: None }, Call { callid: "c2".into(), started: None }];
        lock(&cc.clients).insert("cust".into(), c);
        let snapshot = |cc: &Cnxcc| {
            let cl = lock(&cc.clients);
            let c = &cl["cust"];
            (c.calls.iter().map(|x| (x.callid.clone(), x.started.is_some())).collect::<Vec<_>>(), c.spent)
        };
        cc.on_change(&change("early", "c1"));
        cc.on_change(&change("confirmed", "other"));
        assert_eq!(snapshot(&cc), (vec![("c1".into(), false), ("c2".into(), false)], 0.0));
        cc.on_change(&change("confirmed", "c1"));
        assert_eq!(snapshot(&cc), (vec![("c1".into(), true), ("c2".into(), false)], 0.0));
        cc.on_change(&change("terminated", "c2"));
        assert_eq!(snapshot(&cc), (vec![("c1".into(), true)], 0.0), "an unanswered call costs nothing");
        cc.on_change(&change("terminated", "c1"));
        assert_eq!(snapshot(&cc), (vec![], 16.0), "connect cost + initial pulse");
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

    /// `Cnxcc::add` for a request with this Call-ID.
    fn add(cc: &Cnxcc, callid: &str, customer: &str, limit: Limit) -> i32 {
        let req = format!("INVITE sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nCall-ID: {callid}\r\nCSeq: 1 INVITE\r\n\r\n");
        let arena = bumpalo::Bump::new();
        let mut msg = sip_parser::Msg::parse(req.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, std::net::SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        cc.add(&mut ctx, customer.into(), limit)
    }

    #[test]
    fn max_channels_refuses_the_call_over_the_limit() {
        let cc = Cnxcc::default();
        let two = || Limit::Channels { max: 2 };
        assert_eq!(add(&cc, "c1", "cust", two()), 1);
        assert_eq!(add(&cc, "c2", "cust", two()), 1);
        assert_eq!(add(&cc, "c3", "cust", two()), -1);
        assert_eq!(add(&cc, "c3", "other", two()), 1, "limits are per customer");
        assert_eq!(lock(&cc.clients)["cust"].calls.len(), 2);
        assert_eq!(add(&cc, "c4", "none", Limit::Channels { max: 0 }), -1);
    }

    #[test]
    fn a_repeated_call_id_is_counted_once() {
        let cc = Cnxcc::default();
        let lim = || Limit::Channels { max: 5 };
        assert_eq!(add(&cc, "c1", "cust", lim()), 1);
        assert_eq!(add(&cc, "c1", "cust", lim()), 1);
        assert_eq!(lock(&cc.clients)["cust"].calls.len(), 1);
    }

    #[test]
    fn credit_already_used_up_refuses_new_calls() {
        let cc = Cnxcc::default();
        assert_eq!(add(&cc, "c1", "cust", Limit::Time { max: 0 }), -1, "no time at all");
        assert_eq!(add(&cc, "c1", "rich", Limit::Time { max: 60 }), 1);
        lock(&cc.clients).get_mut("rich").unwrap().spent = 60.0;
        assert_eq!(add(&cc, "c2", "rich", Limit::Time { max: 60 }), -1);
        assert_eq!(add(&cc, "c2", "rich", Limit::Time { max: 61 }), 1, "the latest limit applies");
    }
}

#[cfg(test)]
mod script_tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, pv, registry, rpc, with_ctx};
    use sip_core::serde_json::json;

    /// A registry with a (bare) dialog API and cnxcc.
    fn cnxcc() -> Registry {
        let mut reg = registry(vec![]);
        reg.provide(Arc::new(Dialog::default()));
        reg.load(Arc::new(Cnxcc::default())).unwrap();
        reg
    }

    fn with_call<R>(callid: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        with_ctx(&invite("").replace("cid-1", callid), &FakeNet(None), f)
    }

    #[test]
    fn cnxcc_needs_the_dialog_module() {
        let err = Arc::new(Cnxcc::default()).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("dialog"), "{err}");
    }

    #[test]
    fn cnxcc_parameters() {
        let c = Cnxcc::default();
        for ok in ["redis", "credit_check_period", "dlg_flag"] {
            assert!(c.set_param(ok, &Arg::Int(1)).is_ok(), "{ok}");
        }
        assert!(c.set_param("nope", &Arg::Int(1)).is_err());
    }

    #[test]
    fn script_functions_register_calls_per_limit() {
        let reg = cnxcc();
        assert_eq!(with_call("m1", |ctx| call(&reg, ctx, "cnxcc_set_max_credit", &["cm", "10.5", "0.1", "0.02", "30", "6"])).unwrap(), 1);
        assert_eq!(with_call("m2", |ctx| call(&reg, ctx, "cnxcc_set_max_credit", &["broke", "0", "x", "", "-5", "nan"])).unwrap(), -1, "no credit");
        assert_eq!(with_call("t1", |ctx| call(&reg, ctx, "cnxcc_set_max_time", &["ct", " 60 "])).unwrap(), 1);
        assert_eq!(with_call("t2", |ctx| call(&reg, ctx, "cnxcc_set_max_time", &["ct0", "soon"])).unwrap(), -1, "unparsable: no time");
        assert_eq!(with_call("c1", |ctx| call(&reg, ctx, "cnxcc_set_max_channels", &["cc", "1"])).unwrap(), 1);
        assert_eq!(with_call("c2", |ctx| call(&reg, ctx, "cnxcc_set_max_channels", &["cc", "1"])).unwrap(), -1);
        with_call("x", |ctx| {
            assert_eq!(call(&reg, ctx, "cnxcc_get_channel_count", &["cc", "$var(n)"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$var(n)"), Val::Int(1));
            assert_eq!(call(&reg, ctx, "cnxcc_get_channel_count", &["unknown", "$var(n)"]).unwrap(), 1);
            assert_eq!(pv(&reg, ctx, "$var(n)"), Val::Int(0));
            assert_eq!(call(&reg, ctx, "cnxcc_terminate_all", &["cc"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "cnxcc_terminate_all", &["unknown"]).unwrap(), 1);
        });
        assert!(fixup(&reg, "cnxcc_get_channel_count", &[Arg::Str("c".into()), Arg::Str("n".into())]).is_err(), "not a variable");
        assert!(fixup(&reg, "cnxcc_set_max_time", &[Arg::Str("c".into())]).is_err());
    }

    #[test]
    fn rpcs_report_clients_and_kill_calls() {
        let reg = cnxcc();
        with_call("m1", |ctx| call(&reg, ctx, "cnxcc_set_max_credit", &["cm", "10.5", "0.1", "0.02", "30", "6"])).unwrap();
        with_call("t1", |ctx| call(&reg, ctx, "cnxcc_set_max_time", &["ct", "60"])).unwrap();
        with_call("c1", |ctx| call(&reg, ctx, "cnxcc_set_max_channels", &["cc", "3"])).unwrap();
        with_call("c2", |ctx| call(&reg, ctx, "cnxcc_set_max_channels", &["cc", "3"])).unwrap();
        let mut active = rpc(&reg, "cnxcc.active_clients", json!([])).unwrap().as_array().unwrap().clone();
        active.sort_by_key(|v| v["client_id"].as_str().unwrap_or("").to_string());
        assert_eq!(active, [json!({"client_id": "cc", "calls": 2}), json!({"client_id": "cm", "calls": 1}), json!({"client_id": "ct", "calls": 1})]);
        let cases = [("cm", "money", 10.5), ("ct", "time", 60.0), ("cc", "channels", 3.0)];
        for (client, kind, max) in cases {
            let r = rpc(&reg, "cnxcc.check_client", json!([client])).unwrap();
            assert_eq!((r["type"].as_str(), r["max"].as_f64(), r["consumed"].as_f64()), (Some(kind), Some(max), Some(0.0)), "{client}");
        }
        let r = rpc(&reg, "cnxcc.check_client", json!(["cc"])).unwrap();
        assert_eq!(r["calls"], json!([{"call_id": "c1", "answered": false}, {"call_id": "c2", "answered": false}]));
        assert_eq!(rpc(&reg, "cnxcc.check_client", json!(["nobody"])).err().as_deref(), Some("no such client"));
        assert!(rpc(&reg, "cnxcc.check_client", json!([])).is_err());
        assert_eq!(rpc(&reg, "cnxcc.kill_call", json!(["c1"])).unwrap(), json!(0), "no such dialog: nothing to end");
        assert!(rpc(&reg, "cnxcc.kill_call", json!([])).is_err());
    }
}
