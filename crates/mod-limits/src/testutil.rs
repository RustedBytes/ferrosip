//! Helpers for the unit tests: run code or an exported function on a
//! context built from a request, and `db_text` tables in a scratch directory.

use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Dest, Outbound, Proto, Registry, RouteHub, RouteNames, RouteRunner};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Records what is sent.
#[derive(Default)]
pub struct Sent(pub Mutex<Vec<Vec<u8>>>);

impl Outbound for Sent {
    fn send(&self, _: &Dest, data: &[u8]) -> std::io::Result<()> {
        lock(&self.0).push(data.to_vec());
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<std::net::SocketAddr> {
        None
    }
}

/// A runner whose event routes do nothing (the work happens in `prepare`).
struct Noop;

impl RouteRunner for Noop {
    fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
    fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
        true
    }
    fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
        true
    }
    fn run_event(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
        true
    }
}

/// Runs `f` on a context for `msg` (received from 127.0.0.1); returns its
/// result and the messages sent meanwhile.
pub fn with_ctx<R>(msg: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> (R, Vec<String>) {
    with_ctx_from(msg, None, f)
}

/// Like [`with_ctx`], with the source address set to `src`.
pub fn with_ctx_from<R>(msg: &str, src: Option<Dest>, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> (R, Vec<String>) {
    let hub = RouteHub::default();
    hub.set_names(RouteNames { event: vec!["t".into()], ..Default::default() });
    hub.set_runner(Arc::new(Noop));
    let net = Sent::default();
    let mut out = None;
    hub.run_event_with("t", &net, Some(msg.as_bytes()), |ctx| {
        if let Some(s) = src {
            ctx.src = s;
        }
        out = Some(f(ctx));
    });
    let sent = lock(&net.0).iter().map(|m| String::from_utf8_lossy(m).into_owned()).collect();
    (out.expect("the message did not parse"), sent)
}

/// Calls the exported `name` with `args` for `msg`; its result and what was sent.
pub fn call(reg: &Registry, name: &str, args: &[Arg], msg: &str) -> (i32, Vec<String>) {
    call_from(reg, name, args, msg, None)
}

/// Like [`call`], for a message received from `src`.
pub fn call_from(reg: &Registry, name: &str, args: &[Arg], msg: &str, src: Option<Dest>) -> (i32, Vec<String>) {
    let e = reg.get(name).unwrap_or_else(|| panic!("no function {name}"));
    let fixed = (e.fixup)(args).unwrap_or_else(|err| panic!("{name}{args:?}: {err}"));
    with_ctx_from(msg, src, |ctx| (e.func)(ctx, &*fixed))
}

/// The JSON-RPC result of `method(params)`, or its error message.
pub fn rpc(reg: &Registry, method: &str, params: sip_core::serde_json::Value) -> Result<sip_core::serde_json::Value, String> {
    let r = reg.rpc.call(&sip_core::serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
    match r.get("result") {
        Some(v) => Ok(v.clone()),
        None => Err(r["error"]["message"].as_str().unwrap_or_default().to_string()),
    }
}

/// A request with these extra header lines (each ending in `\r\n`).
pub fn request_with(method: &str, ruri: &str, extra: &str) -> String {
    format!(
        "{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKa\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 {method}\r\n{extra}Content-Length: 0\r\n\r\n"
    )
}

/// A plain request.
pub fn request(method: &str) -> String {
    request_with(method, "sip:b@x", "")
}

/// A `db_text` directory, removed on drop.
pub struct TextDb(pub PathBuf);

impl TextDb {
    /// A fresh directory with these (table, file contents) files.
    pub fn new(tables: &[(&str, &str)]) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("ferrosip-limits-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Self(dir);
        for (t, text) in tables {
            db.write(t, text);
        }
        db
    }

    pub fn write(&self, table: &str, text: &str) {
        std::fs::write(self.0.join(table), text).unwrap();
    }

    pub fn read(&self, table: &str) -> String {
        std::fs::read_to_string(self.0.join(table)).unwrap()
    }

    pub fn url(&self) -> String {
        format!("text://{}", self.0.display())
    }
}

impl Drop for TextDb {
    fn drop(&mut self) {
        #[allow(clippy::let_underscore_must_use, reason = "best effort cleanup of a scratch directory")]
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
