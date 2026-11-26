//! `evapi`: an event API for external applications over TCP
//! (`bind_addr`, netstring framing `len:data,` unless `netstring_format`
//! is 0, then one message per line).
//!
//! * `evapi_relay(data)` sends to every client; `evapi_unicast(data, tag)`
//!   / `evapi_multicast(data, tag)` to the client(s) tagged with
//!   `evapi_set_tag(tag)` (call it in `event_route[evapi:connection-new]`).
//! * `evapi_async_relay(data)` suspends the transaction first (tm), so
//!   `$T(id_index)` / `$T(id_label)` can go in `data`; the application
//!   answers and `event_route[evapi:message-received]` resumes it with
//!   `t_continue()`.
//! * Event routes `evapi:connection-new`, `evapi:connection-closed`,
//!   `evapi:message-received` see `$evapi(msg)`, `$evapi(srcaddr)`,
//!   `$evapi(srcport)`, `$evapi(conidx)`; `evapi_close()` drops the client.
//!   RPC `evapi.clients`.

use mod_txn::Tm;
use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, RouteHub};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

struct Client {
    id: u64,
    addr: SocketAddr,
    tag: String,
    out: TcpStream,
}

/// What the evapi event routes see.
#[derive(Clone, Default)]
struct EvCtx {
    id: u64,
    addr: Option<SocketAddr>,
    msg: String,
    close: bool,
}

pub struct Evapi {
    bind: Mutex<String>,
    netstring: AtomicBool,
    clients: Mutex<Vec<Client>>,
    next: AtomicU64,
    tm: OnceLock<Arc<Tm>>,
    hub: OnceLock<Arc<RouteHub>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for Evapi {
    fn default() -> Self {
        Self {
            bind: Mutex::new("127.0.0.1:8448".into()),
            netstring: AtomicBool::new(true),
            clients: Mutex::default(),
            next: AtomicU64::new(1),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
            net: OnceLock::new(),
        }
    }
}

/// Netstrings from a reader: `len:data,`.
fn read_netstring(r: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut len = Vec::new();
    if r.read_until(b':', &mut len)? == 0 {
        return Ok(None);
    }
    // At EOF the length comes without its ':'.
    let n: usize = len
        .strip_suffix(b":")
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| std::io::Error::other("bad netstring length"))?;
    if n > 1 << 20 {
        return Err(std::io::Error::other("netstring too long"));
    }
    let mut buf = vec![0; n];
    r.read_exact(&mut buf)?;
    let mut comma = [0];
    r.read_exact(&mut comma)?;
    if comma != *b"," {
        return Err(std::io::Error::other("netstring without ','"));
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

impl Evapi {
    fn frame(&self, data: &str) -> Vec<u8> {
        if self.netstring.load(Ordering::Relaxed) { format!("{}:{data},", data.len()).into_bytes() } else { format!("{data}\n").into_bytes() }
    }

    /// Send to clients matching `pick`; at most one if `first`. Returns how many got it.
    fn send(&self, data: &str, pick: impl Fn(&Client) -> bool, first: bool) -> usize {
        let f = self.frame(data);
        let mut n: usize = 0;
        let mut g = lock(&self.clients);
        g.retain_mut(|c| {
            if (first && n > 0) || !pick(c) {
                return true;
            }
            match c.out.write_all(&f) {
                Ok(()) => {
                    n = n.saturating_add(1);
                    true
                }
                Err(_) => false,
            }
        });
        n
    }

    fn event(&self, name: &str, ev: EvCtx) -> EvCtx {
        let (Some(hub), Some(net)) = (self.hub.get(), self.net.get()) else { return ev };
        let mut out = ev.clone();
        let slot = Arc::new(Mutex::new(None::<EvCtx>));
        let s2 = slot.clone();
        hub.run_event_with(name, &**net, None, move |ctx| ctx.ext.push(Box::new(EvSlot(s2, ev))));
        if let Some(e) = lock(&slot).take() {
            out = e;
        }
        out
    }

    fn serve(self: Arc<Self>, s: TcpStream, addr: SocketAddr) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let Ok(out) = s.try_clone() else { return };
        lock(&self.clients).push(Client { id, addr, tag: String::new(), out });
        let ev = self.event("evapi:connection-new", EvCtx { id, addr: Some(addr), ..Default::default() });
        let mut r = BufReader::new(s);
        let mut alive = !ev.close;
        while alive {
            let msg = if self.netstring.load(Ordering::Relaxed) {
                read_netstring(&mut r)
            } else {
                let mut l = String::new();
                r.read_line(&mut l).map(|n| (n > 0).then(|| l.trim_end_matches(['\r', '\n']).to_string()))
            };
            match msg {
                Ok(Some(m)) => {
                    let ev = self.event("evapi:message-received", EvCtx { id, addr: Some(addr), msg: m, close: false });
                    alive = !ev.close;
                }
                _ => alive = false,
            }
        }
        lock(&self.clients).retain(|c| c.id != id);
        let _ = r.get_ref().shutdown(std::net::Shutdown::Both);
        self.event("evapi:connection-closed", EvCtx { id, addr: Some(addr), ..Default::default() });
    }
}

/// The event's data, shared back so `evapi_set_tag` / `evapi_close` act.
struct EvSlot(Arc<Mutex<Option<EvCtx>>>, EvCtx);

impl Module for Evapi {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("bind_addr", Ty::Str, "127.0.0.1:8448", "TCP address to accept clients on"),
            p("netstring_format", Ty::Bool, "true", "Netstring framing (false: one message per line)"),
        ])
    }

    fn name(&self) -> &'static str {
        "evapi"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "bind_addr" => *lock(&self.bind) = v.str()?.into(),
            "netstring_format" => self.netstring.store(v.int()? != 0, Ordering::Relaxed),
            "workers" | "max_clients" | "wait_idle" | "wait_increase" => {}
            _ => return Err(format!("evapi: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, hidden, sig};
        const DATA: &[Param] = &[arg("data", Str)];
        const TAGGED: &[Param] = &[arg("data", Str), arg("tag", Str)];
        const TAG: &[Param] = &[arg("tag", Str)];
        Some(vec![
            sig("evapi_relay", "relay", DATA, Ret::Bool, "Send `data` to every connected client; false when none got it").allowed(ctx::ANY),
            sig("evapi_unicast", "unicast", TAGGED, Ret::Bool, "Send `data` to the first client tagged `tag`").allowed(ctx::ANY),
            sig("evapi_multicast", "multicast", TAGGED, Ret::Bool, "Send `data` to every client tagged `tag`").allowed(ctx::ANY),
            sig("evapi_set_tag", "set_tag", TAG, Ret::Bool, "Tag the client of this event (on a new connection)").allowed(ctx::EVENT),
            sig("evapi_close", "close", &[], Ret::Void, "Disconnect the client of this event").allowed(ctx::EVENT),
            hidden("evapi_async_relay", "suspends the transaction for t_continue() in an event route; .fsr uses await (coming)"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.hub.set(reg.hub.clone());
        if let Some(tm) = reg.api::<Tm>() {
            let _ = self.tm.set(tm);
        }
        reg.pv(
            "evapi",
            PvSpec::ro(|c, p| {
                let Some(EvSlot(_, e)) = c.ext::<EvSlot>() else { return Val::Null };
                match p.name.as_str() {
                    "msg" => Val::Str(e.msg.clone()),
                    "srcaddr" => e.addr.map_or(Val::Null, |a| Val::Str(a.ip().to_string())),
                    "srcport" => e.addr.map_or(Val::Null, |a| Val::Int(i64::from(a.port()))),
                    "conidx" => Val::Int(i64::try_from(e.id).unwrap_or(i64::MAX)),
                    _ => Val::Null,
                }
            })
            .with_param(),
        );
        let one = |a: &[Arg]| {
            let [data] = crate::fixed_args(a)?;
            data.dyn_str()
        };
        let two = |a: &[Arg]| {
            let [x, y] = crate::fixed_args(a)?;
            Ok((x.dyn_str()?, y.dyn_str()?))
        };
        let me = self.clone();
        reg.export("evapi", "evapi_relay", one, move |ctx: &mut Ctx, d: &DynStr| {
            let d = d.eval(ctx).into_owned();
            if me.send(&d, |_| true, false) > 0 { 1 } else { -1 }
        });
        for (name, first) in [("evapi_unicast", true), ("evapi_multicast", false)] {
            let me = self.clone();
            reg.export("evapi", name, two, move |ctx: &mut Ctx, (d, t): &(DynStr, DynStr)| {
                let (d, t) = (d.eval(ctx).into_owned(), t.eval(ctx).into_owned());
                if me.send(&d, |c| c.tag == t, first) > 0 { 1 } else { -1 }
            });
        }
        let me = self.clone();
        reg.export("evapi", "evapi_async_relay", one, move |ctx: &mut Ctx, d: &DynStr| {
            let Some(tm) = me.tm.get() else { return -1 };
            if let Err(rc) = tm.suspend(ctx) {
                return rc;
            }
            // Evaluated after suspending, so $T(id_index)/$T(id_label) are set.
            let d = d.eval(ctx).into_owned();
            me.send(&d, |_| true, false);
            0
        });
        let me = self.clone();
        reg.export("evapi", "evapi_set_tag", one, move |ctx: &mut Ctx, t: &DynStr| {
            let t = t.eval(ctx).into_owned();
            let Some(EvSlot(_, e)) = ctx.ext::<EvSlot>() else { return -1 };
            let id = e.id;
            match lock(&me.clients).iter_mut().find(|c| c.id == id) {
                Some(c) => {
                    c.tag = t;
                    1
                }
                None => -1,
            }
        });
        reg.export(
            "evapi",
            "evapi_close",
            |a: &[Arg]| sip_core::want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                let Some(EvSlot(slot, e)) = ctx.ext::<EvSlot>() else { return -1 };
                *lock(slot) = Some(EvCtx { close: true, ..e.clone() });
                1
            },
        );
        let me = self.clone();
        reg.rpc.add("evapi.clients", "Connected evapi clients", move |_| {
            Ok(lock(&me.clients).iter().map(|c| serde_json::json!({"conidx": c.id, "addr": c.addr.to_string(), "tag": c.tag})).collect())
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        let bind = lock(&self.bind).clone();
        let l = match TcpListener::bind(&bind) {
            Ok(l) => l,
            Err(e) => {
                sip_core::elog!("evapi: bind {bind}: {e}");
                return Ok(());
            }
        };
        std::thread::Builder::new()
            .name("evapi".into())
            .spawn(move || {
                for s in l.incoming().flatten() {
                    let Ok(addr) = s.peer_addr() else { continue };
                    let me = self.clone();
                    let spawned = std::thread::Builder::new().name("evapi-client".into()).spawn(move || {
                        sip_core::panic::expendable();
                        me.serve(s, addr)
                    });
                    // The connection is dropped (closed).
                    if let Err(e) = spawned {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("evapi: no thread for client {addr}: {e}"));
                    }
                }
            })
            .map_err(|e| format!("cannot start the evapi thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn netstrings() {
        let mut r = std::io::BufReader::new(&b"5:hello,3:abc,"[..]);
        assert_eq!(super::read_netstring(&mut r).unwrap().as_deref(), Some("hello"));
        assert_eq!(super::read_netstring(&mut r).unwrap().as_deref(), Some("abc"));
        assert_eq!(super::read_netstring(&mut r).unwrap(), None);
        assert!(super::read_netstring(&mut std::io::BufReader::new(&b"3:abcd"[..])).is_err());
        assert!(super::read_netstring(&mut std::io::BufReader::new(&b"12"[..])).is_err(), "length cut off by EOF");
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;
    use std::io::{BufReader, Read};

    /// One read: a netstring, the end of input, or the error text.
    type Outcome = Result<Option<String>, String>;

    fn read_all(bytes: &[u8]) -> Vec<Outcome> {
        let mut r = BufReader::new(bytes);
        let mut out = Vec::new();
        loop {
            let x = read_netstring(&mut r).map_err(|e| e.to_string());
            let end = !matches!(x, Ok(Some(_)));
            out.push(x);
            if end {
                return out;
            }
        }
    }

    #[test]
    fn netstring_reader_cases() {
        let ok = |s: &str| Ok(Some(s.to_string()));
        let err = |s: &str| Err(s.to_string());
        let cases: &[(&[u8], Vec<Outcome>)] = &[
            (b"", vec![Ok(None)]),
            (b"0:,", vec![ok(""), Ok(None)]),
            (b"3:a,b,1:,,", vec![ok("a,b"), ok(","), Ok(None)]),
            (b" 2 :hi,", vec![ok("hi"), Ok(None)]),
            (b"4:\xc3\xa9\r\n,", vec![ok("\u{e9}\r\n"), Ok(None)]),
            (b"2:\xff\xfe,", vec![ok("\u{fffd}\u{fffd}"), Ok(None)]),
            (b"x:abc,", vec![err("bad netstring length")]),
            (b"-1:,", vec![err("bad netstring length")]),
            (b"3:abc;", vec![err("netstring without ','")]),
            (b"5:abc", vec![err("failed to fill whole buffer")]),
            (b"1048577:", vec![err("netstring too long")]),
        ];
        for (bytes, want) in cases {
            assert_eq!(&read_all(bytes), want, "{:?}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn the_largest_netstring_is_read() {
        let data = "x".repeat(1 << 20);
        let framed = format!("{}:{data},", data.len());
        assert_eq!(read_netstring(&mut BufReader::new(framed.as_bytes())).unwrap().map(|s| s.len()), Some(1 << 20));
    }

    #[test]
    fn frame_and_read_round_trip() {
        let e = Evapi::default();
        for s in ["", "hello", "a,b:c", "{\"json\": [1, 2]}", "héllo wörld", "line\nbreak"] {
            let f = e.frame(s);
            assert_eq!(read_netstring(&mut BufReader::new(&f[..])).unwrap().as_deref(), Some(s));
        }
        assert_eq!(e.frame("é"), b"2:\xc3\xa9,", "the length counts bytes");
        e.set_param("netstring_format", &Arg::Int(0)).unwrap();
        assert_eq!(e.frame("msg"), b"msg\n");
    }

    /// A connected pair: the server side as an evapi client, and the peer.
    fn client(e: &Evapi, tag: &str) -> TcpStream {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (out, addr) = l.accept().unwrap();
        let id = e.next.fetch_add(1, Ordering::Relaxed);
        lock(&e.clients).push(Client { id, addr, tag: tag.into(), out });
        peer
    }

    fn recv(peer: &mut TcpStream, n: usize) -> String {
        let mut b = vec![0; n];
        peer.read_exact(&mut b).unwrap();
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn send_picks_clients_by_tag() {
        let e = Evapi::default();
        let mut a1 = client(&e, "a");
        let mut b = client(&e, "b");
        let mut a2 = client(&e, "a");
        assert_eq!(e.send("all", |_| true, false), 3);
        for p in [&mut a1, &mut b, &mut a2] {
            assert_eq!(recv(p, 6), "3:all,");
        }
        assert_eq!(e.send("uni", |c| c.tag == "a", true), 1, "unicast: the first tagged client");
        assert_eq!(recv(&mut a1, 6), "3:uni,");
        assert_eq!(e.send("multi", |c| c.tag == "a", false), 2);
        assert_eq!(recv(&mut a1, 8), "5:multi,");
        assert_eq!(recv(&mut a2, 8), "5:multi,");
        assert_eq!(e.send("none", |c| c.tag == "zzz", false), 0);
        assert_eq!(lock(&e.clients).len(), 3);
    }
}
