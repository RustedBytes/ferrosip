//! Helpers for the unit tests: a parsed request in a `Ctx`, a network that
//! only advertises an address, script arguments as the compiler builds
//! them, and calls of exported functions, variables and RPCs.

use bumpalo::Bump;
use sip_core::pv::{Val, parse_fmt, parse_pv};
use sip_core::serde_json::{Value, json};
use sip_core::{Arg, Ctx, Dest, Lumps, Module, Outbound, Proto, Registry};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Advertises `0` (if any) for every protocol; sends nothing.
pub struct FakeNet(pub Option<SocketAddr>);

impl Outbound for FakeNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        self.0
    }
}

/// Where test messages come from.
pub fn src() -> Dest {
    Dest::new(Proto::Udp, SocketAddr::from(([192, 0, 2, 1], 5060)))
}

/// An INVITE to `sip:bob@example.com` with `extra` header lines (`\n` ends).
pub fn invite(extra: &str) -> String {
    format!(
        "INVITE sip:bob@example.com SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKtest1\nFrom: <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@example.com>\nCall-ID: cid-1\nCSeq: 1 INVITE\n{extra}Content-Length: 0\n\n"
    )
}

/// Runs `f` on a context for `raw` (CRLF line ends added).
pub fn with_ctx<R>(raw: &str, net: &dyn Outbound, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
    let raw = raw.replace("\r\n", "\n").replace('\n', "\r\n");
    let arena = Bump::new();
    let mut m = sip_parser::Msg::parse(raw.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, src(), 0);
    f(&mut ctx)
}

/// A registry with the core variables (`$var`, `$avp`, …) and `modules`.
pub fn registry(modules: Vec<Arc<dyn Module>>) -> Registry {
    let mut reg = Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
    for m in modules {
        reg.load(m).unwrap();
    }
    reg
}

/// A script argument as the script compiler builds it.
pub fn arg(reg: &Registry, s: &str) -> Arg {
    let f = parse_fmt(s, reg.pvs()).unwrap();
    if f.has_pv() { Arg::Fmt(Arc::new(f)) } else { Arg::Str(f.literal()) }
}

/// Runs the fixup of `name` on `args` and, if it accepts them, the function.
pub fn call_args(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[Arg]) -> Result<i32, String> {
    let e = reg.get(name).ok_or_else(|| format!("no function {name}"))?;
    let fixed = (e.fixup)(args)?;
    Ok((e.func)(ctx, &*fixed))
}

/// [`call_args`] with arguments written as in a script.
pub fn call(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, args: &[&str]) -> Result<i32, String> {
    let args: Vec<Arg> = args.iter().map(|a| arg(reg, a)).collect();
    call_args(reg, ctx, name, &args)
}

/// Only the fixup of `name`: Err with its message when it refuses `args`.
pub fn fixup(reg: &Registry, name: &str, args: &[Arg]) -> Result<(), String> {
    let e = reg.get(name).ok_or_else(|| format!("no function {name}"))?;
    (e.fixup)(args).map(|_| ())
}

/// The value of the variable `spec` (`$dbr(r=>rows)`).
pub fn pv(reg: &Registry, ctx: &mut Ctx<'_, '_>, spec: &str) -> Val {
    parse_pv(spec, reg.pvs()).unwrap().get(ctx)
}

/// Calls RPC `method`: its result, or its error message.
pub fn rpc(reg: &Registry, method: &str, params: Value) -> Result<Value, String> {
    let r = reg.rpc.call(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
    match r.get("result") {
        Some(v) => Ok(v.clone()),
        None => Err(r["error"]["message"].as_str().unwrap_or("").to_string()),
    }
}

/// A fresh file path in the temp directory (removed when dropped).
pub struct TempFile(pub std::path::PathBuf);

impl TempFile {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("mod-extra-{tag}-{}-{n}.db", std::process::id())))
    }

    /// `sqlite://` URL of the file.
    pub fn url(&self) -> String {
        format!("sqlite://{}", self.0.display())
    }

    /// Runs SQL on the file.
    pub fn sql(&self, sql: &str) -> sip_db::Rows {
        sip_db::connect(&self.url()).unwrap().raw(sql).unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
