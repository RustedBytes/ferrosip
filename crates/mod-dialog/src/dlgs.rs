//! `dlgs`: lightweight dialog statistics (Kamailio `dlgs`). Unlike
//! `dialog`, it doesn't follow routing or send anything: it tracks calls by
//! Call-ID from `dlgs_init()` through their replies and in-dialog requests,
//! for counting and listing.
//!
//! - `dlgs_init(src, dst, data)`: start tracking the INVITE being handled.
//! - INVITE replies (observed automatically): 1xx (not 100) → progress,
//!   2xx → answered, 487 → canceled, other ≥300 → not answered.
//! - `dlgs_update()` on in-dialog requests: ACK → confirmed, BYE →
//!   terminated, CANCEL → canceled.
//! - `dlgs_count(field, op, value)`: field `src`/`dst`/`data`/`any`, op
//!   `eq`/`ne`/`re`/`sw`/`fm` (prefix); `dlgs_tags_add(tag)`,
//!   `dlgs_tags_rm(tag)`, `dlgs_tags_count(tag)`.
//! - Records expire `init_lifetime` (s) after creation while unanswered,
//!   `active_lifetime` while answered/confirmed, `finish_lifetime` after
//!   ending.
//! - RPC: `dlgs.stats`, `dlgs.list`, `dlgs.get <call-id>`.

use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::{Value, json};
use sip_core::{Arg, Ctx, Module, Outbound, Registry, ShardedMap, want_args};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Init,
    Progress,
    Answered,
    Confirmed,
    Terminated,
    NotAnswered,
    Canceled,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Init => "init",
            State::Progress => "progress",
            State::Answered => "answered",
            State::Confirmed => "confirmed",
            State::Terminated => "terminated",
            State::NotAnswered => "notanswered",
            State::Canceled => "canceled",
        }
    }
    fn ended(self) -> bool {
        matches!(self, State::Terminated | State::NotAnswered | State::Canceled)
    }
    fn active(self) -> bool {
        matches!(self, State::Answered | State::Confirmed)
    }
}

#[derive(Clone)]
struct Item {
    src: String,
    dst: String,
    data: String,
    state: State,
    tags: Vec<String>,
    /// Last state change (lifetimes count from here).
    since: Instant,
    started_unix: u64,
}

pub struct Dlgs {
    items: ShardedMap<Box<str>, Item>,
    timer_interval: AtomicU64,
    init_lifetime: AtomicU64,
    active_lifetime: AtomicU64,
    finish_lifetime: AtomicU64,
}

impl Default for Dlgs {
    fn default() -> Self {
        Self {
            items: ShardedMap::new(64),
            timer_interval: AtomicU64::new(30),
            init_lifetime: AtomicU64::new(180),
            active_lifetime: AtomicU64::new(7200),
            finish_lifetime: AtomicU64::new(10),
        }
    }
}

fn call_id(ctx: &mut Ctx<'_, '_>) -> Option<Box<str>> {
    ctx.msg.parse_headers(HdrFlags::CALLID).ok()?;
    let b = ctx.msg.get(HdrKind::CallId)?.body;
    std::str::from_utf8(b).ok().map(|s| s.trim().into())
}

/// The CSeq method of a reply.
fn cseq_method(ctx: &mut Ctx<'_, '_>) -> Option<Method> {
    ctx.msg.parse_headers(HdrFlags::CSEQ).ok()?;
    Some(Method::from_cseq(ctx.msg.get(HdrKind::CSeq)?.body))
}

fn matches(op: &str, v: &str, want: &str) -> bool {
    match op {
        "eq" => v == want,
        "ne" => v != want,
        "sw" | "fm" => v.starts_with(want),
        "re" => regex::Regex::new(want).is_ok_and(|r| r.is_match(v)),
        _ => false,
    }
}

impl Dlgs {
    fn set_state(&self, cid: &str, to: State) {
        self.items.with(cid, |it| {
            // Only forward: a late provisional must not reopen an answered call.
            let rank = |s: State| match s {
                State::Init => 0,
                State::Progress => 1,
                State::Answered => 2,
                State::Confirmed => 3,
                _ => 4,
            };
            if !it.state.ended() && rank(to) >= rank(it.state) && it.state != to {
                it.state = to;
                it.since = Instant::now();
            }
        });
    }

    fn expire(&self) {
        let (init, active, fin) = (
            Duration::from_secs(self.init_lifetime.load(Ordering::Relaxed)),
            Duration::from_secs(self.active_lifetime.load(Ordering::Relaxed)),
            Duration::from_secs(self.finish_lifetime.load(Ordering::Relaxed)),
        );
        self.items.retain(|_, it| {
            let age = it.since.elapsed();
            age < if it.state.ended() {
                fin
            } else if it.state.active() {
                active
            } else {
                init
            }
        });
    }

    fn json(cid: &str, it: &Item) -> Value {
        json!({"callid": cid, "src": it.src, "dst": it.dst, "data": it.data, "state": it.state.name(),
               "tags": it.tags, "start": it.started_unix})
    }
}

impl Module for Dlgs {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("timer_interval", Ty::Duration(Unit::Sec), "30s", "How often expired records are removed"),
            p("init_lifetime", Ty::Duration(Unit::Sec), "3m", "Lifetime of a record not yet answered"),
            p("active_lifetime", Ty::Duration(Unit::Sec), "2h", "Lifetime of an answered or confirmed record"),
            p("finish_lifetime", Ty::Duration(Unit::Sec), "10s", "How long an ended record is kept"),
        ])
    }

    fn name(&self) -> &'static str {
        "dlgs"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = || -> Result<u64, String> { u64::try_from(v.int()?).map_err(|_| format!("dlgs: {name} must be >= 0")) };
        match name {
            "timer_interval" => self.timer_interval.store(n()?.max(1), Ordering::Relaxed),
            "init_lifetime" => self.init_lifetime.store(n()?, Ordering::Relaxed),
            "active_lifetime" => self.active_lifetime.store(n()?, Ordering::Relaxed),
            "finish_lifetime" => self.finish_lifetime.store(n()?, Ordering::Relaxed),
            "hash_size" => {}
            _ => return Err(format!("dlgs: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn observes(&self) -> bool {
        true
    }

    /// INVITE replies move the tracked call along.
    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        if self.items.is_empty() || cseq_method(ctx) != Some(Method::Invite) {
            return;
        }
        let Some(code) = ctx.msg.status() else { return };
        let Some(cid) = call_id(ctx) else { return };
        let to = match code {
            101..=199 => State::Progress,
            200..=299 => State::Answered,
            487 => State::Canceled,
            300.. => State::NotAnswered,
            _ => return,
        };
        self.set_state(&cid, to);
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, sig};
        const INIT: &[Param] = &[arg("src", Str), arg("dst", Str), arg("data", Str)];
        const COUNT: &[Param] = &[arg("field", Enum(&["src", "dst", "data", "any"])), arg("op", Enum(&["eq", "ne", "sw", "re"])), arg("value", Str)];
        const TAG: &[Param] = &[arg("tag", Str)];
        Some(vec![
            sig("dlgs_init", "track", INIT, Ret::Bool, "Start tracking this INVITE's call, with source, destination and data").allowed(ctx::REQUEST),
            sig("dlgs_update", "update", &[], Ret::Bool, "Move the tracked call along on ACK, BYE or CANCEL").allowed(ctx::REQUEST),
            sig("dlgs_count", "count", COUNT, Ret::Bool, "Number of active calls whose field matches value by op (false: none)").allowed(ctx::ANY),
            sig("dlgs_tags_add", "add_tag", TAG, Ret::Bool, "Tag this message's tracked call"),
            sig("dlgs_tags_rm", "remove_tag", TAG, Ret::Bool, "Remove a tag from this message's tracked call"),
            sig("dlgs_tags_count", "count_tagged", TAG, Ret::Bool, "Number of active calls with this tag (false: none)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let me = self.clone();
        reg.export(
            "dlgs",
            "dlgs_init",
            |a: &[Arg]| {
                let [x, y, z] = crate::args(a)?;
                Ok((x.dyn_str()?, y.dyn_str()?, z.dyn_str()?))
            },
            move |ctx: &mut Ctx, (s, d, x): &(DynStr, DynStr, DynStr)| {
                if ctx.msg.method() != Some(Method::Invite) {
                    return -1;
                }
                let Some(cid) = call_id(ctx) else { return -1 };
                let started_unix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
                let item = Item {
                    src: s.eval(ctx).into_owned(),
                    dst: d.eval(ctx).into_owned(),
                    data: x.eval(ctx).into_owned(),
                    state: State::Init,
                    tags: Vec::new(),
                    since: Instant::now(),
                    started_unix,
                };
                // A retransmitted or re-sent INVITE keeps the existing record.
                me.items.insert_if_absent(cid, item);
                1
            },
        );
        let me = self.clone();
        reg.export(
            "dlgs",
            "dlgs_update",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let Some(cid) = call_id(ctx) else { return -1 };
                let to = match ctx.msg.method() {
                    Some(Method::Ack) => State::Confirmed,
                    Some(Method::Bye) => State::Terminated,
                    Some(Method::Cancel) => State::Canceled,
                    _ => return 1,
                };
                me.set_state(&cid, to);
                1
            },
        );
        let me = self.clone();
        reg.export(
            "dlgs",
            "dlgs_count",
            |a: &[Arg]| {
                let [x, y, z] = crate::args(a)?;
                Ok((x.dyn_str()?, y.dyn_str()?, z.dyn_str()?))
            },
            move |ctx: &mut Ctx, (f, o, v): &(DynStr, DynStr, DynStr)| {
                let (f, o, v) = (f.eval(ctx).into_owned(), o.eval(ctx).into_owned(), v.eval(ctx).into_owned());
                let mut n = 0i32;
                me.items.for_each_mut(|_, it| {
                    let hit = match f.as_str() {
                        "src" => matches(&o, &it.src, &v),
                        "dst" => matches(&o, &it.dst, &v),
                        "data" => matches(&o, &it.data, &v),
                        "any" => [&it.src, &it.dst, &it.data].iter().any(|x| matches(&o, x, &v)),
                        _ => false,
                    };
                    n = n.saturating_add(i32::from(hit && !it.state.ended()));
                });
                // Like Kamailio: the count, or -1 for none (so `if` works).
                if n > 0 { n } else { -1 }
            },
        );
        let tag_fix = |a: &[Arg]| {
            let [tag] = crate::args(a)?;
            tag.dyn_str()
        };
        let me = self.clone();
        reg.export("dlgs", "dlgs_tags_add", tag_fix, move |ctx: &mut Ctx, t: &DynStr| {
            let t = t.eval(ctx).into_owned();
            let Some(cid) = call_id(ctx) else { return -1 };
            if me.items.with(&*cid, |it| it.tags.push(t)).is_some() { 1 } else { -1 }
        });
        let me = self.clone();
        reg.export("dlgs", "dlgs_tags_rm", tag_fix, move |ctx: &mut Ctx, t: &DynStr| {
            let t = t.eval(ctx).into_owned();
            let Some(cid) = call_id(ctx) else { return -1 };
            if me.items.with(&*cid, |it| it.tags.retain(|x| *x != t)).is_some() { 1 } else { -1 }
        });
        let me = self.clone();
        reg.export("dlgs", "dlgs_tags_count", tag_fix, move |ctx: &mut Ctx, t: &DynStr| {
            let t = t.eval(ctx).into_owned();
            let mut n = 0i32;
            me.items.for_each_mut(|_, it| n = n.saturating_add(i32::from(!it.state.ended() && it.tags.contains(&t))));
            if n > 0 { n } else { -1 }
        });

        let me = self.clone();
        reg.rpc.add("dlgs.stats", "Tracked calls by state", move |_| {
            let mut by: std::collections::BTreeMap<&'static str, u64> = Default::default();
            me.items.for_each_mut(|_, it| {
                let n = by.entry(it.state.name()).or_default();
                *n = n.saturating_add(1);
            });
            let all: u64 = by.values().sum();
            Ok(json!({"all": all, "states": by}))
        });
        let me = self.clone();
        reg.rpc.add("dlgs.list", "Tracked calls", move |_| {
            let mut v = Vec::new();
            me.items.for_each_mut(|k, it| v.push(Dlgs::json(k, it)));
            Ok(Value::Array(v))
        });
        let me = self.clone();
        reg.rpc.add("dlgs.get", "dlgs.get <call-id>", move |p| {
            let cid = sip_core::rpc::str_param(p, 0)?;
            me.items.get_cloned(cid.as_str()).map(|it| Dlgs::json(&cid, &it)).ok_or_else(|| "not found".to_string())
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        static STARTED: OnceLock<()> = OnceLock::new();
        if STARTED.set(()).is_err() {
            return Ok(());
        }
        std::thread::Builder::new()
            .name("dlgs-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(self.timer_interval.load(Ordering::Relaxed)));
                    self.expire();
                }
            })
            .map_err(|e| format!("cannot start the dlgs timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(state: State) -> Item {
        Item { src: "a".into(), dst: "b".into(), data: "x".into(), state, tags: vec![], since: Instant::now(), started_unix: 0 }
    }

    #[test]
    fn states_only_move_forward_and_expire_by_lifetime() {
        let d = Dlgs::default();
        d.items.insert("c1".into(), item(State::Init));
        d.set_state("c1", State::Answered);
        d.set_state("c1", State::Progress); // late 180 after the 200
        assert_eq!(d.items.get_cloned("c1").unwrap().state, State::Answered);
        d.set_state("c1", State::Terminated);
        d.set_state("c1", State::Answered); // nothing reopens an ended call
        assert_eq!(d.items.get_cloned("c1").unwrap().state, State::Terminated);
        d.finish_lifetime.store(0, Ordering::Relaxed);
        d.items.insert("c2".into(), item(State::Confirmed));
        d.expire();
        assert!(d.items.get_cloned("c1").is_none(), "ended + finish_lifetime 0 → gone");
        assert!(d.items.get_cloned("c2").is_some(), "active calls stay for active_lifetime");
    }

    #[test]
    fn match_ops() {
        assert!(matches("eq", "alice", "alice") && !matches("ne", "alice", "alice"));
        assert!(matches("sw", "sip:alice@x", "sip:al") && matches("re", "sip:alice@x", "^sip:a.*@x$"));
        assert!(!matches("zz", "a", "a"));
    }

    use bumpalo::Bump;
    use sip_core::{Dest, Lumps, Proto};
    use sip_parser::Msg;
    use std::net::SocketAddr;

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// Runs `f` on a context for `raw` (`\n` line ends become CRLF).
    fn with_msg<R>(raw: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        let raw = raw.replace('\n', "\r\n");
        let arena = Bump::new();
        let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let src = Dest::new(Proto::Udp, SocketAddr::from(([192, 0, 2, 9], 5060)));
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, src, 0);
        f(&mut ctx)
    }

    /// A request of call `cid` (CSeq method = `method`).
    fn request(method: &str, cid: &str) -> String {
        format!(
            "{method} sip:bob@b.example SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>\nCall-ID: {cid}\nCSeq: 1 {method}\nContent-Length: 0\n\n"
        )
    }

    fn reply(status: &str, cid: &str, method: &str) -> String {
        format!(
            "SIP/2.0 {status}\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>;tag=tt\nCall-ID: {cid}\nCSeq: 1 {method}\nContent-Length: 0\n\n"
        )
    }

    fn registry() -> (Arc<Dlgs>, Registry) {
        let d = Arc::new(Dlgs::default());
        let mut reg = Registry::default();
        reg.load(d.clone()).unwrap();
        (d, reg)
    }

    fn call(reg: &Registry, msg: &str, name: &str, args: &[&str]) -> i32 {
        let args: Vec<Arg> = args.iter().map(|a| Arg::Str((*a).into())).collect();
        let e = reg.get(name).unwrap();
        let fixed = (e.fixup)(&args).unwrap();
        with_msg(msg, |ctx| (e.func)(ctx, &*fixed))
    }

    fn rpc(reg: &Registry, method: &str, params: Value) -> Value {
        reg.rpc.call(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
    }

    fn state_of(d: &Dlgs, cid: &str) -> Option<&'static str> {
        d.items.get_cloned(cid).map(|it| it.state.name())
    }

    #[test]
    fn dlgs_tracks_calls_through_replies_and_in_dialog_requests() {
        let (d, reg) = registry();
        let invite = |cid: &str| call(&reg, &request("INVITE", cid), "dlgs_init", &["alice", "bob", "x"]);
        let observe = |status: &str, cid: &str, method: &str| with_msg(&reply(status, cid, method), |ctx| d.observe_reply(ctx));
        observe("180 Ringing", "c1", "INVITE");
        assert!(d.items.is_empty(), "nothing tracked: replies are ignored");
        assert_eq!(call(&reg, &request("BYE", "c1"), "dlgs_init", &["a", "b", "x"]), -1, "INVITE only");
        assert_eq!(invite("c1"), 1);
        let steps: &[(&str, &str, &str)] = &[
            ("100 Trying", "INVITE", "init"),
            ("180 Ringing", "BYE", "init"),
            ("183 Session Progress", "INVITE", "progress"),
            ("200 OK", "INVITE", "answered"),
            ("180 Ringing", "INVITE", "answered"),
        ];
        for (status, method, want) in steps {
            observe(status, "c1", method);
            assert_eq!(state_of(&d, "c1"), Some(*want), "{status} to {method}");
        }
        for (method, want) in [("INFO", "answered"), ("ACK", "confirmed"), ("BYE", "terminated"), ("ACK", "terminated")] {
            assert_eq!(call(&reg, &request(method, "c1"), "dlgs_update", &[]), 1);
            assert_eq!(state_of(&d, "c1"), Some(want), "{method}");
        }
        assert_eq!(invite("c1"), 1);
        assert_eq!(state_of(&d, "c1"), Some("terminated"), "a re-sent INVITE keeps the record");
        for (cid, status, want) in [("c2", "487 Request Terminated", "canceled"), ("c3", "486 Busy Here", "notanswered"), ("c4", "302 Moved", "notanswered")] {
            invite(cid);
            observe(status, cid, "INVITE");
            assert_eq!(state_of(&d, cid), Some(want), "{status}");
        }
        invite("c5");
        call(&reg, &request("CANCEL", "c5"), "dlgs_update", &[]);
        assert_eq!(state_of(&d, "c5"), Some("canceled"));
        let stats = rpc(&reg, "dlgs.stats", json!([]))["result"].clone();
        assert_eq!(stats, json!({"all": 5, "states": {"canceled": 2, "notanswered": 2, "terminated": 1}}));
        assert_eq!(rpc(&reg, "dlgs.list", json!([]))["result"].as_array().unwrap().len(), 5);
        let one = rpc(&reg, "dlgs.get", json!(["c3"]))["result"].clone();
        assert_eq!(
            (one["callid"].as_str(), one["src"].as_str(), one["dst"].as_str(), one["data"].as_str()),
            (Some("c3"), Some("alice"), Some("bob"), Some("x"))
        );
        assert_eq!(one["state"], "notanswered");
        assert_eq!(rpc(&reg, "dlgs.get", json!(["c9"]))["error"]["message"], "not found");
        assert_eq!(rpc(&reg, "dlgs.get", json!([]))["error"]["message"], "missing parameter 1");
    }

    #[test]
    fn dlgs_counts_active_calls_by_field_and_by_tag() {
        let (d, reg) = registry();
        let count = |args: &[&str]| call(&reg, &request("OPTIONS", "x"), "dlgs_count", args);
        assert_eq!(count(&["any", "eq", "alice"]), -1, "none: -1");
        call(&reg, &request("INVITE", "c1"), "dlgs_init", &["sip:alice@a", "sip:bob@b", "gold"]);
        call(&reg, &request("INVITE", "c2"), "dlgs_init", &["sip:alice@a", "sip:carol@c", "silver"]);
        call(&reg, &request("INVITE", "c3"), "dlgs_init", &["sip:dave@d", "sip:bob@b", "gold"]);
        let cases: &[(&[&str], i32)] = &[
            (&["src", "eq", "sip:alice@a"], 2),
            (&["src", "ne", "sip:alice@a"], 1),
            (&["dst", "sw", "sip:bob"], 2),
            (&["dst", "fm", "sip:carol"], 1),
            (&["data", "re", "^(gold|silver)$"], 3),
            (&["data", "re", "("], -1),
            (&["any", "eq", "gold"], 2),
            (&["any", "sw", "sip:"], 3),
            (&["callid", "eq", "c1"], -1),
            (&["src", "like", "sip:alice@a"], -1),
        ];
        for (args, want) in cases {
            assert_eq!(count(args), *want, "{args:?}");
        }
        call(&reg, &request("BYE", "c1"), "dlgs_update", &[]);
        assert_eq!(count(&["src", "eq", "sip:alice@a"]), 1, "ended calls don't count");
        // Tags.
        let tag = |name: &str, cid: &str, t: &str| call(&reg, &request("INFO", cid), name, &[t]);
        assert_eq!(tag("dlgs_tags_count", "c1", "vip"), -1);
        assert_eq!(tag("dlgs_tags_add", "c9", "vip"), -1, "not tracked");
        assert_eq!(tag("dlgs_tags_rm", "c9", "vip"), -1, "not tracked");
        for cid in ["c1", "c2", "c3"] {
            assert_eq!(tag("dlgs_tags_add", cid, "vip"), 1);
        }
        assert_eq!(tag("dlgs_tags_count", "x", "vip"), 2, "c1 ended");
        assert_eq!(tag("dlgs_tags_rm", "c2", "vip"), 1);
        assert_eq!(tag("dlgs_tags_rm", "c2", "vip"), 1, "a tracked call, even without the tag");
        assert_eq!(tag("dlgs_tags_count", "x", "vip"), 1);
        assert_eq!(d.items.get_cloned("c3").unwrap().tags, ["vip"]);
        assert_eq!(rpc(&reg, "dlgs.get", json!(["c3"]))["result"]["tags"], json!(["vip"]));
    }

    #[test]
    fn dlgs_state_names_parameters_and_lifetimes() {
        let names: Vec<&str> =
            [State::Init, State::Progress, State::Answered, State::Confirmed, State::Terminated, State::NotAnswered, State::Canceled].map(State::name).to_vec();
        assert_eq!(names, ["init", "progress", "answered", "confirmed", "terminated", "notanswered", "canceled"]);
        let d = Dlgs::default();
        for (name, v) in [("timer_interval", 0), ("init_lifetime", 5), ("active_lifetime", 6), ("finish_lifetime", 7), ("hash_size", 9)] {
            d.set_param(name, &Arg::Int(v)).unwrap();
        }
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        assert_eq!((load(&d.timer_interval), load(&d.init_lifetime), load(&d.active_lifetime), load(&d.finish_lifetime)), (1, 5, 6, 7), "interval at least 1s");
        assert!(d.set_param("init_lifetime", &Arg::Int(-1)).unwrap_err().contains("must be >= 0"));
        assert!(d.set_param("init_lifetime", &Arg::Str("x".into())).is_err());
        assert!(d.set_param("bogus", &Arg::Int(1)).unwrap_err().contains("unknown parameter"));
        // Each state ages by its own lifetime.
        let d = Dlgs::default();
        for (cid, st) in [("i", State::Init), ("p", State::Progress), ("a", State::Answered), ("t", State::Terminated)] {
            d.items.insert(cid.into(), item(st));
        }
        d.init_lifetime.store(0, Ordering::Relaxed);
        d.expire();
        let left = |d: &Dlgs| ["i", "p", "a", "t"].into_iter().filter(|c| d.items.get_cloned(*c).is_some()).collect::<Vec<_>>();
        assert_eq!(left(&d), ["a", "t"], "unanswered: init_lifetime");
        d.active_lifetime.store(0, Ordering::Relaxed);
        d.expire();
        assert_eq!(left(&d), ["t"], "answered: active_lifetime");
    }
}
