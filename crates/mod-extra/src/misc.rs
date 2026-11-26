//! * `outbound` — RFC 5626 for edge proxies: turns on flow tokens in
//!   Path / Record-Route (`sip_core::flow`, used by `path` and `rr`) and
//!   routes requests carrying them back over the client's connection.
//!   Parameters: `flow_token_secret` (random), `force_outbound_flag`.
//! * `tsilo` — transaction storage: `ts_store([uri])` after `t_relay()`
//!   keeps an INVITE's transaction under the callee's AoR;
//!   `ts_append(table, uri)` after `save()` adds a branch to the client
//!   that just registered (its new contacts) while the call still rings.
//! * `rtimer` — `modparam("rtimer", "timer", "name=t1;interval=10")` +
//!   `modparam("rtimer", "exec", "timer=t1;route=MYROUTE")`: run
//!   `route[MYROUTE]` periodically (`interval` in seconds, `100ms` …).

use crate::kv_list;
use mod_location::store::Usrloc;
use mod_txn::{Tm, TxnId};
use sip_core::module::{DynStr, rc};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound as Net, Registry, RouteHub, ShardedMap};
use sip_parser::uri::{name_addr, split_list};
use sip_parser::{HdrFlags, HdrKind};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

// ---------------------------------------------------------------- outbound --

#[derive(Default)]
pub struct Outbound {
    secret: Mutex<Option<String>>,
    force_flag: std::sync::atomic::AtomicI64,
}

impl Module for Outbound {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("flow_token_secret", Ty::Str, "", "Secret that signs flow tokens (default: random)"),
            p("force_outbound_flag", Ty::Int { min: -1, max: 63 }, "0", "Request flag that forces a flow token (0 or -1: none)"),
        ])
    }

    fn name(&self) -> &'static str {
        "outbound"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "flow_token_secret" => *lock(&self.secret) = Some(v.str()?.into()),
            "force_outbound_flag" => self.force_flag.store(v.int()?, std::sync::atomic::Ordering::Relaxed),
            "force_no_outbound_flag" => {}
            _ => return Err(format!("outbound: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, _reg: &mut Registry) -> Result<(), String> {
        let secret = lock(&self.secret).clone().map(String::into_bytes).unwrap_or_else(|| {
            let mut s = vec![0u8; 32];
            let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut s);
            s
        });
        sip_core::flow::enable(&secret);
        let f = self.force_flag.load(std::sync::atomic::Ordering::Relaxed);
        sip_core::flow::set_force_flag(if f == 0 { -1 } else { f });
        Ok(())
    }
}

// ------------------------------------------------------------------- tsilo --

pub struct Tsilo {
    /// AoR → stored INVITE transactions.
    store: ShardedMap<String, Vec<(TxnId, u64)>>,
    tm: OnceLock<Arc<Tm>>,
    ul: OnceLock<Arc<Usrloc>>,
}

fn aor_of(uri: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let u = sip_parser::parse_uri(uri)?;
    Some((u.user?.to_vec(), u.host.to_ascii_lowercase()))
}

impl Default for Tsilo {
    fn default() -> Self {
        Self { store: ShardedMap::new(16), tm: OnceLock::new(), ul: OnceLock::new() }
    }
}

impl Tsilo {
    fn key(&self, uri: &[u8]) -> Option<String> {
        let (u, h) = aor_of(uri)?;
        Some(String::from_utf8_lossy(&self.ul.get()?.aor(&u, &h)).into_owned())
    }

    fn ts_store(&self, ctx: &mut Ctx<'_, '_>, uri: Option<String>) -> i32 {
        let Some(tm) = self.tm.get() else { return -1 };
        let Some(id) = tm.txn_of(ctx) else { return -1 };
        let uri = uri.map(String::into_bytes).unwrap_or_else(|| ctx.msg.ruri().unwrap_or_default().to_vec());
        let Some(k) = self.key(&uri) else { return -1 };
        let exp = unix_secs().saturating_add(180);
        self.store.alter(k, |cur| {
            let mut v = cur.unwrap_or_default();
            if !v.iter().any(|(x, _)| *x == id) {
                v.push((id, exp));
            }
            (Some(v), ())
        });
        1
    }

    /// Add the contacts this REGISTER just saved to the stored INVITEs.
    fn ts_append(&self, ctx: &mut Ctx<'_, '_>, uri: Option<String>) -> i32 {
        let (Some(tm), Some(ul)) = (self.tm.get(), self.ul.get()) else { return -1 };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| b.to_vec();
        let to = ctx.msg.get(HdrKind::To).map(|h| s(name_addr(h.body).0)).unwrap_or_default();
        let uri = uri.map(String::into_bytes).unwrap_or(to);
        let Some(k) = self.key(&uri) else { return -1 };
        let Some(txns) = self.store.get_cloned(&k) else { return -1 };
        let callid = ctx.msg.get(HdrKind::CallId).map(|h| s(h.body)).unwrap_or_default();
        let uris: Vec<Vec<u8>> =
            ctx.msg.headers.iter().filter(|h| h.kind == HdrKind::Contact).flat_map(|h| split_list(h.body)).map(|c| s(name_addr(c).0)).collect();
        let contacts: Vec<_> = ul.lookup(k.as_bytes()).into_iter().filter(|c| c.callid == callid && uris.contains(&c.uri)).collect();
        let mut added: i32 = 0;
        for (id, _) in &txns {
            if !tm.txn_pending(id) {
                continue;
            }
            for c in &contacts {
                let dst =
                    c.path.as_deref().and_then(|p| split_list(p).first().and_then(|f| sip_core::pvcore::dest_from_uri(name_addr(f).0))).unwrap_or(c.received);
                added = added.saturating_add(i32::from(tm.append_branch(id, c.uri.clone(), Some(dst), c.path.clone())));
            }
        }
        if added > 0 { added } else { -1 }
    }
}

impl Module for Tsilo {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "tsilo"
    }

    fn set_param(&self, name: &str, _v: &Arg) -> Result<(), String> {
        match name {
            "hash_size" | "use_dialog" => Ok(()),
            _ => Err(format!("tsilo: unknown parameter {name:?}")),
        }
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, ctx, opt, opt_or, sig};
        const STORE: &[Param] = &[opt("uri", Uri)];
        const APPEND: &[Param] = &[opt_or("table", Str, "location").lit(), opt("uri", Uri)];
        Some(vec![
            sig("ts_store", "store", STORE, Ret::Bool, "Keep this INVITE's transaction under the callee's AoR (`uri`, default the R-URI), after relaying")
                .allowed(ctx::REQUEST),
            sig("ts_append", "append", APPEND, Ret::Bool, "After saving a REGISTER: add its new contacts as branches to the stored INVITEs of the AoR")
                .allowed(ctx::REQUEST),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.tm.set(reg.api::<Tm>().ok_or("tsilo needs tm loaded first")?);
        let _ = self.ul.set(reg.api::<Usrloc>().ok_or("tsilo needs usrloc loaded first")?);
        let opt = |a: &[Arg]| -> Result<Option<DynStr>, String> {
            match a {
                [] => Ok(None),
                [uri] => Ok(Some(uri.dyn_str()?)),
                _ => Err("expected [uri]".into()),
            }
        };
        let me = self.clone();
        reg.export("tsilo", "ts_store", opt, move |ctx: &mut Ctx, u: &Option<DynStr>| {
            let u = u.as_ref().map(|u| u.eval(ctx).into_owned());
            me.ts_store(ctx, u)
        });
        let me = self.clone();
        reg.export(
            "tsilo",
            "ts_append",
            |a: &[Arg]| -> Result<Option<DynStr>, String> {
                match a {
                    [_] => Ok(None),
                    [_, uri] => Ok(Some(uri.dyn_str()?)),
                    _ => Err("expected table[, uri]".into()),
                }
            },
            move |ctx: &mut Ctx, u: &Option<DynStr>| {
                let u = u.as_ref().map(|u| u.eval(ctx).into_owned());
                me.ts_append(ctx, u)
            },
        );
        let me = self.clone();
        reg.rpc.add("ts.dump", "Stored transactions by AoR", move |_| {
            let mut v = Vec::new();
            me.store.for_each_mut(|k, l| v.push(json!({"aor": k, "transactions": l.len()})));
            Ok(json!(v))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Net>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("tsilo-gc".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let t = unix_secs();
                    let tm = self.tm.get().cloned();
                    self.store.retain(|_, v| {
                        v.retain(|(id, exp)| *exp > t && tm.as_ref().is_some_and(|tm| tm.txn_pending(id)));
                        !v.is_empty()
                    });
                }
            })
            .map_err(|e| format!("cannot start the tsilo gc thread: {e}"))?;
        Ok(())
    }
}

// ------------------------------------------------------------------ rtimer --

#[derive(Default)]
pub struct Rtimer {
    timers: Mutex<Vec<(String, Duration)>>,
    execs: Mutex<Vec<(String, String)>>,
    hub: OnceLock<Arc<RouteHub>>,
}

fn interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().map_err(|_| format!("rtimer: bad interval {s:?}"))?;
    Ok(match unit {
        "" | "s" => Duration::from_secs(n),
        "ms" => Duration::from_millis(n),
        "u" | "us" => Duration::from_micros(n),
        _ => return Err(format!("rtimer: bad interval unit in {s:?}")),
    })
}

impl Module for Rtimer {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("timer", Ty::List(&Ty::Str), "", "Timers, each \"name=t1;interval=10\" (interval in s, or with ms/us)"),
            p("exec", Ty::List(&Ty::Str), "", "Routes to run, each \"timer=t1;route=MYROUTE\""),
        ])
    }

    fn name(&self) -> &'static str {
        "rtimer"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let kv = kv_list(v.str()?);
        let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
        match name {
            "timer" => {
                let n = get("name").ok_or("rtimer timer: name= is required")?;
                lock(&self.timers).push((n, interval(&get("interval").unwrap_or_else(|| "60".into()))?));
            }
            "exec" => {
                let t = get("timer").ok_or("rtimer exec: timer= is required")?;
                let r = get("route").ok_or("rtimer exec: route= is required")?;
                lock(&self.execs).push((t, r));
            }
            "default_interval" => {}
            _ => return Err(format!("rtimer: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let timers = lock(&self.timers).clone();
        for (t, _) in lock(&self.execs).iter() {
            if !timers.iter().any(|(n, _)| n == t) {
                return Err(format!("rtimer: exec refers to unknown timer {t:?}"));
            }
        }
        let _ = self.hub.set(reg.hub.clone());
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Net>) -> Result<(), String> {
        for (name, every) in lock(&self.timers).clone() {
            let routes: Vec<String> = lock(&self.execs).iter().filter(|(t, _)| *t == name).map(|(_, r)| r.clone()).collect();
            let (hub, net) = (self.hub.get().cloned(), net.clone());
            std::thread::Builder::new()
                .name(format!("rtimer-{name}"))
                .spawn(move || {
                    loop {
                        std::thread::sleep(every);
                        if let Some(h) = &hub {
                            for r in &routes {
                                if h.run_route_with(r, &*net, None, |_| {}).is_none() {
                                    sip_core::log::log(sip_core::log::L_ERR, &format!("rtimer: no route[{r}] in the script"));
                                }
                            }
                        }
                    }
                })
                .map_err(|e| format!("cannot start the rtimer thread: {e}"))?;
        }
        let _ = rc(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{Dest, Lumps, Proto};

    #[test]
    fn aor_of_takes_user_and_lowercased_host() {
        type Case<'a> = (&'a [u8], Option<(&'a [u8], &'a [u8])>);
        let cases: &[Case] = &[
            (b"sip:alice@Example.COM", Some((b"alice", b"example.com"))),
            (b"sip:Alice@example.com:5070;transport=tcp", Some((b"Alice", b"example.com"))),
            (b"sips:bob:pw@[2001:DB8::1]", Some((b"bob", b"[2001:db8::1]"))),
            (b"sip:example.com", None),
            (b"sip:@example.com", None),
            (b"garbage", None),
        ];
        for &(uri, want) in cases {
            let got = aor_of(uri);
            assert_eq!(got.as_ref().map(|(u, h)| (&u[..], &h[..])), want, "{:?}", String::from_utf8_lossy(uri));
        }
    }

    #[test]
    fn key_follows_usrloc_use_domain() {
        let t = Tsilo::default();
        assert_eq!(t.key(b"sip:alice@example.com"), None, "no usrloc yet");
        let ul = Arc::new(Usrloc::default());
        let _ = t.ul.set(ul.clone());
        assert_eq!(t.key(b"sip:alice@Example.com").as_deref(), Some("alice"));
        assert_eq!(t.key(b"sip:example.com"), None);
        ul.set_param("use_domain", &Arg::Int(1)).unwrap();
        assert_eq!(t.key(b"sip:alice@Example.com:5060").as_deref(), Some("alice@example.com"));
    }

    struct NoNet;
    impl Net for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    #[test]
    fn store_and_append_fail_without_tm_and_usrloc() {
        let t = Tsilo::default();
        let req = b"REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nTo: <sip:alice@example.com>\r\nCall-ID: r1\r\n\r\n";
        let arena = bumpalo::Bump::new();
        let mut msg = sip_parser::Msg::parse(req, &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, std::net::SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        assert_eq!(t.ts_store(&mut ctx, None), -1);
        assert_eq!(t.ts_append(&mut ctx, Some("sip:alice@example.com".into())), -1);
        assert!(t.store.is_empty());
    }

    #[test]
    fn rtimer_interval_units() {
        let cases: &[(&str, Option<Duration>)] = &[
            ("10", Some(Duration::from_secs(10))),
            (" 10s ", Some(Duration::from_secs(10))),
            ("0", Some(Duration::ZERO)),
            ("100ms", Some(Duration::from_millis(100))),
            ("250u", Some(Duration::from_micros(250))),
            ("250us", Some(Duration::from_micros(250))),
            ("", None),
            ("ms", None),
            ("10m", None),
            ("1.5", None),
            ("-1", None),
            ("10 ms", None),
            ("99999999999999999999", None),
        ];
        for &(s, want) in cases {
            assert_eq!(interval(s).ok(), want, "{s:?}");
        }
    }

    #[test]
    fn rtimer_params_need_names_and_known_timers() {
        let r = Rtimer::default();
        assert!(r.set_param("timer", &Arg::Str("interval=5".into())).is_err(), "name= is required");
        r.set_param("timer", &Arg::Str("name=t1;interval=100ms".into())).unwrap();
        r.set_param("timer", &Arg::Str("name=t2".into())).unwrap();
        assert!(r.set_param("exec", &Arg::Str("timer=t1".into())).is_err(), "route= is required");
        r.set_param("exec", &Arg::Str("timer=t1;route=R".into())).unwrap();
        assert_eq!(*lock(&r.timers), [("t1".to_string(), Duration::from_millis(100)), ("t2".to_string(), Duration::from_secs(60))]);
        assert!(Arc::new(Rtimer::default()).register(&mut Registry::default()).is_ok());
        r.set_param("exec", &Arg::Str("timer=nope;route=R".into())).unwrap();
        let err = Arc::new(r).register(&mut Registry::default()).err().unwrap();
        assert!(err.contains("nope"), "{err}");
    }
}

#[cfg(test)]
mod script_tests {
    use super::*;
    use crate::testutil::{FakeNet, call, fixup, invite, registry, rpc, with_ctx};

    #[test]
    fn outbound_parameters() {
        let o = Outbound::default();
        assert!(o.set_param("flow_token_secret", &Arg::Str("s".into())).is_ok());
        assert!(o.set_param("force_outbound_flag", &Arg::Int(3)).is_ok());
        assert!(o.set_param("force_no_outbound_flag", &Arg::Int(4)).is_ok());
        assert!(o.set_param("nope", &Arg::Int(1)).is_err());
    }

    #[test]
    fn tsilo_and_rtimer_parameters() {
        let t = Tsilo::default();
        assert!(t.set_param("hash_size", &Arg::Int(10)).is_ok());
        assert!(t.set_param("use_dialog", &Arg::Int(1)).is_ok());
        assert!(t.set_param("nope", &Arg::Int(1)).is_err());
        let r = Rtimer::default();
        assert!(r.set_param("default_interval", &Arg::Str("10".into())).is_ok());
        assert!(r.set_param("nope", &Arg::Str("x".into())).is_err());
        assert!(r.set_param("timer", &Arg::Str("name=t;interval=5x".into())).is_err(), "bad interval");
    }

    #[test]
    fn tsilo_needs_tm_and_usrloc() {
        let mut reg = Registry::default();
        assert!(Arc::new(Tsilo::default()).register(&mut reg).err().unwrap().contains("tm"));
        reg.provide(Arc::new(Tm::default()));
        assert!(Arc::new(Tsilo::default()).register(&mut reg).err().unwrap().contains("usrloc"));
    }

    /// tsilo on a bare tm and usrloc (nothing registered, nothing sent).
    fn tsilo() -> (Arc<Tm>, Registry) {
        let tm = Arc::new(Tm::default());
        let mut reg = registry(vec![]);
        reg.provide(tm.clone());
        reg.provide(Arc::new(Usrloc::default()));
        reg.load(Arc::new(Tsilo::default())).unwrap();
        (tm, reg)
    }

    #[test]
    fn ts_store_keeps_a_transaction_once_per_aor() {
        let (tm, reg) = tsilo();
        let net = FakeNet(None);
        with_ctx(&invite(""), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "ts_store", &[]).unwrap(), -1, "no transaction yet");
            assert!(tm.suspend(ctx).is_ok());
            assert_eq!(call(&reg, ctx, "ts_store", &[]).unwrap(), 1, "the R-URI's AoR");
            assert_eq!(call(&reg, ctx, "ts_store", &["sip:bob@example.com"]).unwrap(), 1, "the same transaction again");
            assert_eq!(call(&reg, ctx, "ts_store", &["sip:carol@example.com"]).unwrap(), 1);
            assert_eq!(call(&reg, ctx, "ts_store", &["no uri"]).unwrap(), -1);
        });
        let mut dump = rpc(&reg, "ts.dump", sip_core::serde_json::json!([])).unwrap().as_array().unwrap().clone();
        dump.sort_by_key(|v| v["aor"].as_str().unwrap_or("").to_string());
        assert_eq!(dump, [sip_core::serde_json::json!({"aor": "bob", "transactions": 1}), sip_core::serde_json::json!({"aor": "carol", "transactions": 1})]);
    }

    #[test]
    fn ts_append_needs_a_stored_aor_and_new_contacts() {
        let (tm, reg) = tsilo();
        let net = FakeNet(None);
        with_ctx(&invite(""), &net, |ctx| {
            assert!(tm.suspend(ctx).is_ok());
            assert_eq!(call(&reg, ctx, "ts_store", &[]).unwrap(), 1);
        });
        let register = "REGISTER sip:example.com SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.5;branch=z9hG4bKr\nFrom: <sip:bob@example.com>;tag=r\n\
To: <sip:bob@example.com>\nCall-ID: reg-1\nCSeq: 1 REGISTER\nContact: <sip:bob@192.0.2.5:5070>\nContent-Length: 0\n\n";
        with_ctx(register, &net, |ctx| {
            assert_eq!(call(&reg, ctx, "ts_append", &["location", "sip:carol@example.com"]).unwrap(), -1, "nothing stored for carol");
            assert_eq!(call(&reg, ctx, "ts_append", &["location"]).unwrap(), -1, "bob has no saved contact from this REGISTER");
            assert_eq!(call(&reg, ctx, "ts_append", &["location", "garbage"]).unwrap(), -1);
        });
        let broken = "REGISTER sip:example.com SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.5;branch=z9hG4bKr\nTo <no colon\n\n";
        with_ctx(broken, &net, |ctx| {
            assert!(ctx.msg.parse_headers(HdrFlags::EOH).is_err());
            assert_eq!(call(&reg, ctx, "ts_append", &["location"]).unwrap(), -1, "unparsable headers");
        });
        assert!(fixup(&reg, "ts_append", &[]).is_err());
        assert!(fixup(&reg, "ts_append", &[Arg::Str("a".into()), Arg::Str("b".into()), Arg::Str("c".into())]).is_err());
        assert!(fixup(&reg, "ts_store", &[Arg::Str("a".into()), Arg::Str("b".into())]).is_err());
    }
}
