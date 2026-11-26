//! Management RPC (Kamailio `ctl` / `jsonrpcs`): JSON-RPC 2.0 commands that
//! modules register (`ul.dump`, `dispatcher.reload`, `stats.get_statistics`,
//! …), served on a UNIX stream socket, one JSON request per line.
//! `tools/ferroctl` is the command-line client (like `kamcmd`).

use crate::sync::{read, write};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, RwLock};
use std::thread;

pub type RpcFn = Arc<dyn Fn(&[Value]) -> Result<Value, String> + Send + Sync>;

#[derive(Default)]
pub struct RpcTable {
    cmds: RwLock<BTreeMap<String, (String, RpcFn)>>,
}

impl RpcTable {
    pub fn add(&self, name: &str, help: &str, f: impl Fn(&[Value]) -> Result<Value, String> + Send + Sync + 'static) {
        write(&self.cmds).insert(name.to_string(), (help.to_string(), Arc::new(f)));
    }

    pub fn names(&self) -> Vec<(String, String)> {
        read(&self.cmds).iter().map(|(k, (h, _))| (k.clone(), h.clone())).collect()
    }

    /// Execute one JSON-RPC request (object) and build the response.
    pub fn call(&self, req: &Value) -> Value {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let Some(method) = req.get("method").and_then(Value::as_str) else {
            return json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "Invalid Request"}});
        };
        let params: Vec<Value> = match req.get("params") {
            Some(Value::Array(a)) => a.clone(),
            Some(Value::Null) | None => vec![],
            Some(v) => vec![v.clone()],
        };
        if method == "system.listMethods" {
            return json!({"jsonrpc": "2.0", "id": id, "result": self.names().into_iter().map(|(n, _)| n).collect::<Vec<_>>()});
        }
        if method == "system.methodHelp" {
            let name = params.first().and_then(Value::as_str).unwrap_or("");
            let help = read(&self.cmds).get(name).map(|(h, _)| h.clone());
            return match help {
                Some(h) => json!({"jsonrpc": "2.0", "id": id, "result": h}),
                None => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}}),
            };
        }
        let f = read(&self.cmds).get(method).map(|(_, f)| f.clone());
        match f {
            None => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Method not found"}}),
            Some(f) => match crate::panic::catch(|| f(&params)) {
                Ok(Ok(v)) => json!({"jsonrpc": "2.0", "id": id, "result": v}),
                Ok(Err(e)) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": 500, "message": e}}),
                Err(_) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": 500, "message": "internal error"}}),
            },
        }
    }

    /// Handle one line of input (a request or a batch).
    pub fn handle_line(&self, line: &str) -> Value {
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Array(batch)) => Value::Array(batch.iter().map(|r| self.call(r)).collect()),
            Ok(req) => self.call(&req),
            Err(e) => json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("Parse error: {e}")}}),
        }
    }

    /// Serve on a UNIX socket (removed and re-created at startup).
    pub fn serve_unix(self: &Arc<Self>, path: &str) -> std::io::Result<()> {
        #[allow(clippy::let_underscore_must_use, reason = "a stale socket file may not exist")]
        let _ = std::fs::remove_file(path);
        let l = UnixListener::bind(path)?;
        let me = self.clone();
        thread::Builder::new().name("rpc".into()).spawn(move || {
            for conn in l.incoming().flatten() {
                let me = me.clone();
                let spawned = thread::Builder::new().name("rpc-conn".into()).spawn(move || {
                    crate::panic::expendable();
                    let mut w = match conn.try_clone() {
                        Ok(w) => w,
                        Err(_) => return,
                    };
                    for line in BufReader::new(conn).lines() {
                        let Ok(line) = line else { return };
                        if line.trim().is_empty() {
                            continue;
                        }
                        let resp = me.handle_line(&line);
                        if writeln!(w, "{resp}").is_err() {
                            return;
                        }
                    }
                });
                // The connection is dropped (closed).
                if let Err(e) = spawned {
                    crate::log::log(crate::log::L_ERR, &format!("rpc: no thread for a connection: {e}"));
                }
            }
        })?;
        Ok(())
    }
}

/// Helpers for handlers.
pub fn str_param(p: &[Value], i: usize) -> Result<String, String> {
    match p.get(i) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(v) => Ok(v.to_string()),
        None => Err(format!("missing parameter {}", i.saturating_add(1))),
    }
}

pub fn int_param(p: &[Value], i: usize) -> Result<i64, String> {
    match p.get(i) {
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| "expected an integer".into()),
        Some(Value::String(s)) => s.parse().map_err(|_| format!("expected an integer, got {s:?}")),
        _ => Err(format!("missing parameter {}", i.saturating_add(1))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch() {
        let t = RpcTable::default();
        t.add("echo", "returns its params", |p| Ok(Value::Array(p.to_vec())));
        t.add("fail", "", |_| Err("nope".into()));
        let r = t.handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"echo","params":[1,"a"]}"#);
        assert_eq!(r["result"], json!([1, "a"]));
        assert_eq!(t.handle_line(r#"{"id":2,"method":"fail"}"#)["error"]["message"], "nope");
        assert_eq!(t.handle_line(r#"{"id":3,"method":"x"}"#)["error"]["code"], -32601);
        assert_eq!(t.handle_line("garbage")["error"]["code"], -32700);
        assert_eq!(t.handle_line(r#"{"id":4,"method":"system.listMethods"}"#)["result"], json!(["echo", "fail"]));
        assert_eq!(t.handle_line(r#"[{"id":5,"method":"echo"},{"id":6,"method":"echo"}]"#).as_array().unwrap().len(), 2);
    }
}
