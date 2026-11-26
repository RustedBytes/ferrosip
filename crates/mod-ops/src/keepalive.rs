//! `keepalive`: probe destinations with OPTIONS every `ping_interval`
//! seconds. A 2xx marks a destination up; anything else (including our own
//! timeout) marks it down. `is_alive(uri)` returns 1 (up), -1 (down) or -2
//! (not probed yet / unknown); state changes run
//! `event_route[keepalive:dst-up]` / `[keepalive:dst-down]` with the
//! destination as `$ru`. Parameters: `destination` (repeatable),
//! `ping_interval`, `ping_from`, `delete_counter` (remove a destination
//! after that many failed probes; 0 = never). RPC: `keepalive.list`,
//! `keepalive.add <uri> [owner]`, `keepalive.del <uri> [owner]`,
//! `keepalive.get <uri>`, `keepalive.flush`.

use mod_txn::{Tm, UacRequest};
use serde_json::{Value, json};
use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Unknown,
    Up,
    Down,
}

#[derive(Clone, Debug)]
struct Dst {
    owner: String,
    state: State,
    failures: u64,
    /// Unix seconds.
    last_up: u64,
    last_down: u64,
}

pub struct Keepalive {
    dsts: Mutex<BTreeMap<String, Dst>>,
    interval: AtomicU64,
    delete_after: AtomicU64,
    from: Mutex<String>,
    tm: OnceLock<Arc<Tm>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self {
            dsts: Mutex::default(),
            interval: AtomicU64::new(30),
            delete_after: AtomicU64::new(0),
            from: Mutex::new("sip:keepalive@ferrosip".into()),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
            net: OnceLock::new(),
        }
    }
}

fn norm(uri: &str) -> String {
    let u = uri.trim();
    if u.starts_with("sip:") || u.starts_with("sips:") { u.to_string() } else { format!("sip:{u}") }
}

impl Keepalive {
    fn add(&self, uri: &str, owner: &str) {
        lock(&self.dsts).entry(norm(uri)).or_insert(Dst { owner: owner.into(), state: State::Unknown, failures: 0, last_up: 0, last_down: 0 });
    }

    fn probe_all(self: &Arc<Self>) {
        let uris: Vec<String> = lock(&self.dsts).keys().cloned().collect();
        for u in uris {
            self.probe(&u);
        }
    }

    fn probe(self: &Arc<Self>, uri: &str) {
        let Some(tm) = self.tm.get() else { return };
        let me = self.clone();
        let u = uri.to_string();
        let req = UacRequest { method: "OPTIONS".into(), ruri: uri.into(), from: Some(lock(&self.from).clone()), cseq: 1, ..Default::default() };
        let res = tm.t_uac(req, Some(Box::new(move |code, _| me.result(&u, (200..300).contains(&code)))));
        if res.is_err() {
            self.result(uri, false);
        }
    }

    fn result(&self, uri: &str, up: bool) {
        let changed = {
            let mut g = lock(&self.dsts);
            let Some(d) = g.get_mut(uri) else { return };
            let old = d.state;
            if up {
                d.state = State::Up;
                d.failures = 0;
                d.last_up = unix_secs();
            } else {
                d.state = State::Down;
                d.failures = d.failures.saturating_add(1);
                d.last_down = unix_secs();
            }
            let n = self.delete_after.load(Ordering::Relaxed);
            if !up && n > 0 && d.failures >= n {
                g.remove(uri);
            }
            (old != if up { State::Up } else { State::Down }).then_some(up)
        };
        if let (Some(up), Some(hub), Some(net)) = (changed, self.hub.get(), self.net.get()) {
            let u = uri.to_string();
            hub.run_event_with(if up { "keepalive:dst-up" } else { "keepalive:dst-down" }, &**net, None, move |ctx| {
                ctx.new_ruri = Some(u.into_bytes());
            });
        }
    }

    fn json(uri: &str, d: &Dst) -> Value {
        json!({"uri": uri, "owner": d.owner, "state": match d.state { State::Up => "up", State::Down => "down", State::Unknown => "unknown" },
               "failures": d.failures, "last_up": d.last_up, "last_down": d.last_down})
    }
}

impl Module for Keepalive {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("destination", Ty::List(&Ty::Str), "", "SIP URIs to probe with OPTIONS"),
            p("ping_interval", Ty::Duration(Unit::Sec), "30s", "Probe each destination this often"),
            p("delete_counter", UINT, "0", "Remove a destination after this many failed probes (0: never)"),
            p("ping_from", Ty::Str, "sip:keepalive@ferrosip", "From URI of the probes"),
        ])
    }

    fn name(&self) -> &'static str {
        "keepalive"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "destination" => self.add(v.str()?, "config"),
            "ping_interval" => self.interval.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "delete_counter" => self.delete_after.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "ping_from" => *lock(&self.from) = v.str()?.into(),
            _ => return Err(format!("keepalive: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const URI: &[Param] = &[arg("uri", Uri)];
        Some(vec![
            sig("is_alive", "is_alive", URI, Ret::Bool, "The destination answered its last OPTIONS probe (false: down, or not probed yet)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.tm.set(reg.api::<Tm>().ok_or("keepalive needs tm (load it first)")?);
        let _ = self.hub.set(reg.hub.clone());
        let me = self.clone();
        reg.export(
            "keepalive",
            "is_alive",
            |a: &[Arg]| {
                let [dst] = crate::fixed_args(a)?;
                dst.dyn_str()
            },
            move |ctx: &mut Ctx, d: &DynStr| {
                let u = norm(&d.eval(ctx));
                match lock(&me.dsts).get(&u).map(|d| d.state) {
                    Some(State::Up) => 1,
                    Some(State::Down) => -1,
                    _ => -2,
                }
            },
        );
        let me = self.clone();
        reg.rpc.add("keepalive.list", "Monitored destinations", move |_| Ok(lock(&me.dsts).iter().map(|(u, d)| Self::json(u, d)).collect()));
        let me = self.clone();
        reg.rpc.add("keepalive.get", "One destination", move |p| {
            let u = norm(&sip_core::rpc::str_param(p, 0)?);
            lock(&me.dsts).get(&u).map(|d| Self::json(&u, d)).ok_or_else(|| "not found".to_string())
        });
        let me = self.clone();
        reg.rpc.add("keepalive.add", "Add a destination (uri [owner])", move |p| {
            let u = sip_core::rpc::str_param(p, 0)?;
            me.add(&u, &sip_core::rpc::str_param(p, 1).unwrap_or_else(|_| "rpc".into()));
            me.probe(&norm(&u));
            Ok(json!("ok"))
        });
        let me = self.clone();
        reg.rpc.add("keepalive.del", "Remove a destination (uri)", move |p| {
            let u = norm(&sip_core::rpc::str_param(p, 0)?);
            lock(&me.dsts).remove(&u).map(|_| json!("ok")).ok_or_else(|| "not found".to_string())
        });
        let me = self.clone();
        reg.rpc.add("keepalive.flush", "Remove all destinations", move |_| {
            lock(&me.dsts).clear();
            Ok(json!("ok"))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        std::thread::Builder::new()
            .name("keepalive".into())
            .spawn(move || {
                loop {
                    self.probe_all();
                    std::thread::sleep(Duration::from_secs(self.interval.load(Ordering::Relaxed)));
                }
            })
            .map_err(|e| format!("cannot start the keepalive thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(k: &Keepalive, uri: &str) -> Option<(State, u64)> {
        lock(&k.dsts).get(uri).map(|d| (d.state, d.failures))
    }

    #[test]
    fn norm_adds_a_sip_scheme() {
        let cases = [
            ("10.0.0.1", "sip:10.0.0.1"),
            (" gw.example:5060 ", "sip:gw.example:5060"),
            ("sip:a@b", "sip:a@b"),
            ("sips:b", "sips:b"),
            ("tel:+1", "sip:tel:+1"),
        ];
        for (input, want) in cases {
            assert_eq!(norm(input), want, "{input:?}");
        }
    }

    #[test]
    fn add_is_idempotent_and_keeps_the_first_owner() {
        let k = Keepalive::default();
        k.add("10.0.0.1", "config");
        k.add("sip:10.0.0.1", "rpc");
        let g = lock(&k.dsts);
        assert_eq!(g.len(), 1);
        assert_eq!(g["sip:10.0.0.1"].owner, "config");
        assert_eq!(g["sip:10.0.0.1"].state, State::Unknown);
    }

    #[test]
    fn probe_results_drive_the_state() {
        let k = Keepalive::default();
        let u = "sip:gw";
        k.add(u, "t");
        let before = unix_secs();
        let steps: &[(bool, State, u64)] =
            &[(false, State::Down, 1), (false, State::Down, 2), (true, State::Up, 0), (true, State::Up, 0), (false, State::Down, 1)];
        for &(up, st, fails) in steps {
            k.result(u, up);
            assert_eq!(state(&k, u), Some((st, fails)), "after {up}");
        }
        let d = lock(&k.dsts)[u].clone();
        assert!(d.last_up >= before && d.last_down >= d.last_up);
        k.result("sip:unknown", true);
        assert_eq!(state(&k, "sip:unknown"), None, "results for unknown destinations are ignored");
    }

    #[test]
    fn delete_counter_removes_after_that_many_failures() {
        let k = Keepalive::default();
        k.set_param("delete_counter", &Arg::Int(3)).unwrap();
        k.add("sip:gw", "t");
        k.result("sip:gw", false);
        k.result("sip:gw", false);
        k.result("sip:gw", true);
        k.result("sip:gw", false);
        k.result("sip:gw", false);
        assert_eq!(state(&k, "sip:gw"), Some((State::Down, 2)), "a success resets the count");
        k.result("sip:gw", false);
        assert_eq!(state(&k, "sip:gw"), None);
    }

    #[test]
    fn json_shape() {
        let d = Dst { owner: "o".into(), state: State::Down, failures: 2, last_up: 5, last_down: 9 };
        assert_eq!(Keepalive::json("sip:x", &d), json!({"uri": "sip:x", "owner": "o", "state": "down", "failures": 2, "last_up": 5, "last_down": 9}));
        let d = Dst { state: State::Unknown, ..d };
        assert_eq!(Keepalive::json("sip:x", &d)["state"], "unknown");
    }

    #[test]
    fn params() {
        let k = Keepalive::default();
        k.set_param("destination", &Arg::Str("10.0.0.9".into())).unwrap();
        assert!(lock(&k.dsts).contains_key("sip:10.0.0.9"));
        k.set_param("ping_interval", &Arg::Int(0)).unwrap();
        assert_eq!(k.interval.load(Ordering::Relaxed), 1);
        k.set_param("delete_counter", &Arg::Int(-1)).unwrap();
        assert_eq!(k.delete_after.load(Ordering::Relaxed), 0);
        assert!(k.set_param("nope", &Arg::Int(1)).is_err());
    }
}
