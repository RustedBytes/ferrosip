//! Helpers for the unit tests: a parsed message in a `Ctx`, a network that
//! only advertises an address, a network that records what is sent, a
//! database that records inserts, a db_text directory, and a registry to
//! call the exported functions through.

use bumpalo::Bump;
use mod_txn::Tm;
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Dest, Lumps, Module, Outbound, Proto, Registry};
use sip_db::{DbConn, DbError, DbVal, Filter, Rows};
use sip_parser::Msg;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Advertises `addr` (if any) for every protocol; sends nothing.
pub struct FakeNet(pub Option<SocketAddr>);

impl Outbound for FakeNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        self.0
    }
}

pub fn udp(addr: &str) -> Dest {
    Dest::new(Proto::Udp, addr.parse().unwrap())
}

/// `\n` line ends → CRLF.
pub fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// Runs `f` on a context for `raw` (CRLF line ends added), received from `src`.
pub fn with_ctx<R>(raw: &str, src: Dest, net: &dyn Outbound, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let raw = crlf(raw);
    let arena = Bump::new();
    let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, src, 0);
    f(&mut ctx)
}

/// The message with the context's edits applied.
pub fn rendered(ctx: &mut Ctx<'_, '_>) -> String {
    let mut out = Vec::new();
    ctx.lumps.apply(ctx.msg.buf, &mut out);
    String::from_utf8(out).unwrap()
}

/// A request with the given R-URI and extra header lines.
pub fn request(method: &str, ruri: &str, extra: &str) -> String {
    format!(
        "{method} {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKt\nFrom: \"Alice\" <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>\nCall-ID: cid-1\nCSeq: 1 {method}\nMax-Forwards: 70\n{extra}Content-Length: 0\n\n"
    )
}

/// One insert: (table, columns, values).
pub type Insert = (String, Vec<String>, Vec<DbVal>);

/// Records inserts.
#[derive(Default)]
pub struct Inserts(pub Mutex<Vec<Insert>>);

impl Inserts {
    pub fn take(&self) -> Vec<Insert> {
        std::mem::take(&mut *lock(&self.0))
    }
}

impl DbConn for Inserts {
    fn query(&self, _: &str, _: &[&str], _: Filter<'_>) -> Result<Rows, DbError> {
        Ok(Rows::default())
    }
    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
        lock(&self.0).push((table.into(), cols.iter().map(|c| c.to_string()).collect(), vals.to_vec()));
        Ok(())
    }
    fn update(&self, _: &str, _: Filter<'_>, _: &[(&str, DbVal)]) -> Result<usize, DbError> {
        Ok(0)
    }
    fn delete(&self, _: &str, _: Filter<'_>) -> Result<usize, DbError> {
        Ok(0)
    }
}

/// Records every message sent; advertises 127.0.0.1:5060.
#[derive(Default)]
pub struct RecNet(pub Mutex<Vec<(Dest, Vec<u8>)>>);

impl RecNet {
    /// The messages sent so far (as text), oldest first.
    pub fn sent(&self) -> Vec<(Dest, String)> {
        lock(&self.0).iter().map(|(d, m)| (*d, String::from_utf8_lossy(m).into_owned())).collect()
    }
}

impl Outbound for RecNet {
    fn send(&self, d: &Dest, m: &[u8]) -> std::io::Result<()> {
        lock(&self.0).push((*d, m.to_vec()));
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], 5060)))
    }
}

/// The reply `code` to a request `req` that tm sent (its first Via, so tm
/// finds the transaction), with `extra` header lines.
pub fn reply_to(req: &str, code: u16, extra: &str) -> String {
    let hdr = |name: &str| req.split("\r\n").find(|l| l.starts_with(name)).unwrap_or_default().to_string();
    let to = hdr("To:");
    let to = if to.contains(";tag=") { to } else { format!("{to};tag=rt") };
    format!("SIP/2.0 {code} R\n{}\n{}\n{to}\n{}\n{}\n{extra}Content-Length: 0\n\n", hdr("Via:"), hdr("From:"), hdr("Call-ID:"), hdr("CSeq:"))
}

/// A fresh db_text directory holding `tables` (name, file contents);
/// removed on drop.
pub struct TextDir(pub PathBuf);

impl TextDir {
    pub fn new(tables: &[(&str, &str)]) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("mod-carrier-dbtext-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        let me = Self(dir);
        for (t, text) in tables {
            me.write(t, text);
        }
        me
    }
    pub fn url(&self) -> String {
        format!("text://{}", self.0.display())
    }
    /// Replaces a table file (with a new mtime, so it is read again).
    pub fn write(&self, table: &str, text: &str) {
        static T: AtomicUsize = AtomicUsize::new(1_000_000);
        let path = self.0.join(table);
        std::fs::write(&path, text).unwrap();
        let at = u64::try_from(T.fetch_add(1, Ordering::Relaxed)).unwrap();
        let f = std::fs::File::options().write(true).open(&path).unwrap();
        f.set_modified(std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(at)).unwrap()).unwrap();
    }
}

impl Drop for TextDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// A registry with the core variables and tm loaded.
pub fn registry() -> (Registry, Arc<Tm>) {
    let mut reg = Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
    let tm = Arc::new(Tm::default());
    reg.load(tm.clone()).unwrap();
    (reg, tm)
}

/// A script argument with variables (`"$avp(x)"`).
pub fn fmt(reg: &Registry, s: &str) -> Arg {
    Arg::Fmt(Arc::new(sip_core::pv::parse_fmt(s, reg.pvs()).unwrap()))
}

/// Calls exported function `name` with `args` (which must pass its fixup).
pub fn call(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[Arg]) -> i32 {
    let e = reg.get(name).unwrap_or_else(|| panic!("no function {name}"));
    let fixed = (e.fixup)(args).unwrap_or_else(|err| panic!("{name}: {err}"));
    (e.func)(ctx, &*fixed)
}

/// The fixup error of `name` with `args`, if any.
pub fn fixup_err(reg: &Registry, name: &str, args: &[Arg]) -> Option<String> {
    (reg.get(name).unwrap().fixup)(args).err()
}

/// Calls RPC `method`; its result, or its error message.
pub fn rpc(reg: &Registry, method: &str, params: sip_core::serde_json::Value) -> Result<sip_core::serde_json::Value, String> {
    let r = reg.rpc.call(&sip_core::serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
    match r.get("error") {
        Some(e) => Err(e["message"].as_str().unwrap_or_default().to_string()),
        None => Ok(r["result"].clone()),
    }
}

/// Starts `tm` on `net` (its timer thread runs until the test process ends).
pub fn start_tm(tm: &Arc<Tm>, net: &Arc<RecNet>) {
    tm.clone().spawn(net.clone()).unwrap();
}
