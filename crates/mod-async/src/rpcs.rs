//! `jsonrpcs`: run management commands from the script
//! (`jsonrpc_exec(json)` → `$jsonrpl(code)`, `$jsonrpl(text)`,
//! `$jsonrpl(body)`) and serve them on a FIFO like Kamailio's `kamctl`:
//! write a JSON-RPC request with `"reply_name": "<fifo>"` into `fifo_name`;
//! the response is written to that FIFO in `fifo_reply_dir`. (The UNIX
//! socket of `--rpc-socket` / `ferroctl` is the core's.)

use sip_core::module::DynStr;
use sip_core::pv::{PvSpec, Val};
use sip_core::rpc::RpcTable;
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Registry};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Default)]
struct JsonRpl {
    code: i64,
    text: String,
    body: String,
}

pub struct JsonRpcs {
    fifo: Mutex<Option<String>>,
    reply_dir: Mutex<String>,
    rpc: OnceLock<Arc<RpcTable>>,
}

impl Default for JsonRpcs {
    fn default() -> Self {
        Self { fifo: Mutex::new(None), reply_dir: Mutex::new("/tmp/".into()), rpc: OnceLock::new() }
    }
}

fn mkfifo(path: &str) -> std::io::Result<()> {
    use rustix::fs::{CWD, Mode, mkfifoat};
    let _ = std::fs::remove_file(path);
    mkfifoat(CWD, path, Mode::from_raw_mode(0o660)).map_err(std::io::Error::from)
}

/// Requests in a chunk of FIFO input: one or more JSON values.
fn requests(buf: &str) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_str(buf).into_iter::<serde_json::Value>().filter_map(Result::ok).collect()
}

impl Module for JsonRpcs {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("fifo_name", Ty::Str, "", "FIFO to read JSON-RPC requests from (none: no FIFO)"),
            p("fifo_reply_dir", Ty::Str, "/tmp/", "Directory of the reply FIFOs"),
        ])
    }

    fn name(&self) -> &'static str {
        "jsonrpcs"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "fifo_name" => *lock(&self.fifo) = Some(v.str()?.into()),
            "fifo_reply_dir" => *lock(&self.reply_dir) = v.str()?.into(),
            "transport" | "fifo_mode" | "fifo_group" | "fifo_user" | "dgram_socket" | "dgram_mode" | "pretty_format" | "tcp_socket" => {}
            _ => return Err(format!("jsonrpcs: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const EXEC: &[Param] = &[arg("request", Str)];
        Some(vec![
            sig("jsonrpc_exec", "exec", EXEC, Ret::Void, "Run a JSON-RPC management command; the answer is in $jsonrpl(code|text|body)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let rpc = reg.rpc.clone();
        let _ = self.rpc.set(rpc.clone());
        reg.pv(
            "jsonrpl",
            PvSpec::ro(|c, p| {
                let Some(r) = c.ext::<JsonRpl>() else { return Val::Null };
                match p.name.as_str() {
                    "code" => Val::Int(r.code),
                    "text" => Val::Str(r.text.clone()),
                    "body" => Val::Str(r.body.clone()),
                    _ => Val::Null,
                }
            })
            .with_param(),
        );
        reg.export(
            "jsonrpcs",
            "jsonrpc_exec",
            |a: &[Arg]| {
                let [cmd] = crate::fixed_args(a)?;
                cmd.dyn_str()
            },
            move |ctx: &mut Ctx, cmd: &DynStr| {
                let cmd = cmd.eval(ctx).into_owned();
                let resp = rpc.handle_line(&cmd);
                let (code, text) = match resp.get("error") {
                    Some(e) => {
                        (e.get("code").and_then(|c| c.as_i64()).unwrap_or(500), e.get("message").and_then(|m| m.as_str()).unwrap_or("error").to_string())
                    }
                    None => (200, "OK".into()),
                };
                *ctx.ext_mut::<JsonRpl>() = JsonRpl { code, text, body: resp.to_string() };
                1
            },
        );
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn sip_core::Outbound>) -> Result<(), String> {
        let Some(path) = lock(&self.fifo).clone() else { return Ok(()) };
        if let Err(e) = mkfifo(&path) {
            sip_core::elog!("jsonrpcs: fifo {path}: {e}");
            return Ok(());
        }
        let me = self.clone();
        std::thread::Builder::new()
            .name("jsonrpcs-fifo".into())
            .spawn(move || {
                loop {
                    // Opening blocks until a writer comes; read until it closes.
                    let Ok(mut f) = std::fs::File::open(&path) else { return };
                    let mut buf = String::new();
                    if f.read_to_string(&mut buf).is_err() {
                        continue;
                    }
                    let Some(rpc) = me.rpc.get() else { continue };
                    for req in requests(&buf) {
                        let resp = rpc.call(&req);
                        let Some(name) = req.get("reply_name").and_then(|n| n.as_str()) else { continue };
                        if name.contains('/') && !name.starts_with('/') || name.contains("..") {
                            continue;
                        }
                        let target = if name.starts_with('/') { name.to_string() } else { format!("{}{name}", lock(&me.reply_dir)) };
                        if let Ok(mut out) = std::fs::OpenOptions::new().write(true).open(&target) {
                            let _ = writeln!(out, "{resp}");
                        }
                    }
                }
            })
            .map_err(|e| format!("cannot start the jsonrpcs fifo thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn several_requests() {
        let r = super::requests("{\"method\":\"a\"}\n{\"method\":\"b\",\"id\":2}");
        assert_eq!(r.len(), 2);
        assert_eq!(r[1]["id"], 2);
    }
}
