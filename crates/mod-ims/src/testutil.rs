//! Helpers for the unit tests: a parsed message in a `Ctx`, the reply the
//! code under test sent, a peer manager that is never started, a network
//! that is "us", an in-memory database, a test script and a registry to
//! call the exported functions through.

use sip_core::{Ctx, Dest, Lumps, Outbound, Proto};
use sip_diameter::{Config, Peers};
use std::net::SocketAddr;
use std::sync::Arc;

/// Sends nothing, advertises nothing.
pub struct NoNet;

impl Outbound for NoNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        None
    }
}

/// Runs `f` on a context for `raw` (`\n` line ends of the header section
/// become CRLF; the body after the blank line is kept as is), received
/// over UDP from 192.0.2.9:5060.
pub fn with_msg<R>(raw: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    with_msg_on(raw, &NoNet, f)
}

/// A request from sip:alice@ims.test to `ruri` with `extra` header lines
/// (each ending in `\n`) and `body`; To is `to`.
pub fn request(method: &str, ruri: &str, to: &str, extra: &str, body: &str) -> String {
    format!(
        "{method} {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:alice@ims.test>;tag=ft\nTo: <{to}>\n\
         Call-ID: cid-1\nCSeq: 7 {method}\nContact: <sip:alice@192.0.2.9:5060>\n{extra}Content-Length: {}\n\n{body}",
        body.len()
    )
}

/// The status code and text of the reply in `ctx.out` (0 when none).
pub fn reply(ctx: &Ctx<'_, '_>) -> (u16, String) {
    let s = String::from_utf8_lossy(ctx.out).into_owned();
    let code = s.get(8..11).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, s)
}

/// The value of the first header `name` in `msg` (a message as text).
pub fn hdr(msg: &str, name: &str) -> Option<String> {
    msg.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// A peer manager (identity scscf.ims.test, realm ims.test) with no peers,
/// never started: it builds messages, and every request fails at once.
pub fn peers() -> Arc<Peers> {
    Peers::try_new(Config { identity: "scscf.ims.test".into(), realm: "ims.test".into(), ..Default::default() }).unwrap()
}

/// Advertises 127.0.0.1:5060 (so Routes to it are ours) and records
/// what is sent.
#[derive(Default)]
pub struct Here(pub std::sync::Mutex<Vec<(Dest, Vec<u8>)>>);

impl Here {
    /// The messages sent so far (as text), oldest first.
    pub fn sent(&self) -> Vec<String> {
        sip_core::sync::lock(&self.0).iter().map(|(_, m)| String::from_utf8_lossy(m).into_owned()).collect()
    }
}

impl Outbound for Here {
    fn send(&self, d: &Dest, m: &[u8]) -> std::io::Result<()> {
        sip_core::sync::lock(&self.0).push((*d, m.to_vec()));
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], 5060)))
    }
}

/// [`with_msg`] with `net` as the context's network.
pub fn with_msg_on<R>(raw: &str, net: &dyn Outbound, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    with_msg_at(raw, net, "192.0.2.9:5060", f)
}

/// [`with_msg_on`], received over UDP from `src`.
pub fn with_msg_at<R>(raw: &str, net: &dyn Outbound, src: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let raw = format!("{}\r\n\r\n{body}", head.replace('\n', "\r\n"));
    let arena = bumpalo::Bump::new();
    let mut m = sip_parser::Msg::parse(raw.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let src = Dest::new(Proto::Udp, src.parse().unwrap());
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, src, 0);
    f(&mut ctx)
}

/// A reply `code` to a REGISTER from sip:alice@ims.test (To-tag added),
/// with `extra` header lines and `body`.
pub fn reply_msg(code: u16, extra: &str, body: &str) -> String {
    format!(
        "SIP/2.0 {code} R\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:alice@ims.test>;tag=ft\nTo: <sip:alice@ims.test>;tag=tt\n\
         Call-ID: cid-1\nCSeq: 7 REGISTER\n{extra}Content-Length: {}\n\n{body}",
        body.len()
    )
}

/// The message with the context's edits applied.
pub fn rendered(ctx: &mut Ctx<'_, '_>) -> String {
    let mut out = Vec::new();
    ctx.lumps.apply(ctx.msg.buf, &mut out);
    String::from_utf8(out).unwrap()
}

/// One row: (column, value) pairs.
pub type Row = Vec<(String, sip_db::DbVal)>;

/// An in-memory database: rows as (column, value) lists; every call fails
/// while `fail` is set.
#[derive(Default)]
pub struct MemDb {
    pub tables: std::sync::Mutex<std::collections::HashMap<String, Vec<Row>>>,
    pub fail: std::sync::atomic::AtomicBool,
}

impl MemDb {
    fn check(&self) -> Result<(), sip_db::DbError> {
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) { Err(sip_db::DbError::Conn("down".into())) } else { Ok(()) }
    }

    /// Adds a row to `table`.
    pub fn put(&self, table: &str, row: &[(&str, sip_db::DbVal)]) {
        sip_core::sync::lock(&self.tables).entry(table.into()).or_default().push(row.iter().map(|(c, v)| (c.to_string(), v.clone())).collect());
    }

    /// The rows of `table`, each as column → value.
    pub fn rows(&self, table: &str) -> Vec<std::collections::HashMap<String, sip_db::DbVal>> {
        sip_core::sync::lock(&self.tables).get(table).map(|t| t.iter().map(|r| r.iter().cloned().collect()).collect()).unwrap_or_default()
    }
}

fn matches(row: &[(String, sip_db::DbVal)], filter: sip_db::Filter<'_>) -> bool {
    filter.iter().all(|(c, v)| row.iter().any(|(rc, rv)| rc == c && rv == v))
}

impl sip_db::DbConn for MemDb {
    fn query(&self, table: &str, cols: &[&str], filter: sip_db::Filter<'_>) -> Result<sip_db::Rows, sip_db::DbError> {
        self.check()?;
        let t = sip_core::sync::lock(&self.tables);
        let rows = t
            .get(table)
            .map(|rows| {
                rows.iter()
                    .filter(|r| matches(r, filter))
                    .map(|r| cols.iter().map(|c| r.iter().find(|(rc, _)| rc == c).map_or(sip_db::DbVal::Null, |(_, v)| v.clone())).collect())
                    .collect()
            })
            .unwrap_or_default();
        Ok(sip_db::Rows { cols: cols.iter().map(|c| c.to_string()).collect(), rows })
    }
    fn insert(&self, table: &str, cols: &[&str], vals: &[sip_db::DbVal]) -> Result<(), sip_db::DbError> {
        self.check()?;
        let row: Vec<(&str, sip_db::DbVal)> = cols.iter().copied().zip(vals.iter().cloned()).collect();
        self.put(table, &row);
        Ok(())
    }
    fn update(&self, _: &str, _: sip_db::Filter<'_>, _: &[(&str, sip_db::DbVal)]) -> Result<usize, sip_db::DbError> {
        self.check()?;
        Ok(0)
    }
    fn delete(&self, table: &str, filter: sip_db::Filter<'_>) -> Result<usize, sip_db::DbError> {
        self.check()?;
        let mut t = sip_core::sync::lock(&self.tables);
        let rows = t.entry(table.into()).or_default();
        let before = rows.len();
        rows.retain(|r| !matches(r, filter));
        Ok(before.saturating_sub(rows.len()))
    }
}

/// The handler of a test script's event routes: (event name, context) →
/// false to drop.
pub type EventFn = Box<dyn Fn(&str, &mut Ctx<'_, '_>) -> bool + Send + Sync>;

/// A script with the named event routes (run by `on_event`) and the named
/// plain routes (that do nothing).
pub struct Script {
    pub events: Vec<String>,
    pub routes: Vec<String>,
    pub on_event: EventFn,
}

impl sip_core::RouteRunner for Script {
    fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
    fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
        true
    }
    fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
        true
    }
    fn run_event(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        self.events.get(idx).is_none_or(|e| (self.on_event)(e, ctx))
    }
    fn route_index(&self, name: &str) -> Option<usize> {
        self.routes.iter().position(|r| r == name)
    }
}

/// Gives `hub` a script with these event routes and plain routes.
pub fn script(hub: &sip_core::RouteHub, events: &[&str], routes: &[&str], on_event: EventFn) {
    let events: Vec<String> = events.iter().map(|e| e.to_string()).collect();
    hub.set_names(sip_core::RouteNames { event: events.clone(), ..Default::default() });
    hub.set_runner(Arc::new(Script { events, routes: routes.iter().map(|r| r.to_string()).collect(), on_event }));
}

/// A registry with the core functions and `cdp` (identity scscf.ims.test,
/// realm ims.test, no peers, never started) loaded; with tm before it when
/// `tm` is set.
pub fn registry(tm: bool) -> sip_core::Registry {
    use sip_core::Module;
    let mut reg = sip_core::Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
    if tm {
        reg.load(Arc::new(mod_txn::Tm::default())).unwrap();
    }
    let cdp = crate::Cdp::default();
    cdp.set_param("identity", &sip_core::Arg::Str("scscf.ims.test".into())).unwrap();
    cdp.set_param("realm", &sip_core::Arg::Str("ims.test".into())).unwrap();
    reg.load(Arc::new(cdp)).unwrap();
    reg
}

/// Calls exported function `name` with `args` (which must pass its fixup).
pub fn call(reg: &sip_core::Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[sip_core::Arg]) -> i32 {
    let e = reg.get(name).unwrap_or_else(|| panic!("no function {name}"));
    let fixed = (e.fixup)(args).unwrap_or_else(|err| panic!("{name}: {err}"));
    (e.func)(ctx, &*fixed)
}

/// The fixup error of `name` with `args`, if any.
pub fn fixup_err(reg: &sip_core::Registry, name: &str, args: &[sip_core::Arg]) -> Option<String> {
    (reg.get(name).unwrap().fixup)(args).err()
}

/// Calls RPC `method`: its result, or its error message.
pub fn rpc(reg: &sip_core::Registry, method: &str, params: sip_core::serde_json::Value) -> Result<sip_core::serde_json::Value, String> {
    let r = reg.rpc.call(&sip_core::serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
    match r.get("error") {
        Some(e) => Err(e["message"].as_str().unwrap_or_default().to_string()),
        None => Ok(r["result"].clone()),
    }
}

/// `"location"` and friends as script arguments.
pub fn s(v: &str) -> sip_core::Arg {
    sip_core::Arg::Str(v.into())
}

/// The `$avp(name)` integer the code under test set, if any.
pub fn avp_int(ctx: &Ctx<'_, '_>, name: &str) -> Option<i64> {
    match ctx.ext::<sip_core::TxnVars>()?.avps.get(name)?.first()? {
        sip_core::pv::Val::Int(n) => Some(*n),
        _ => None,
    }
}
