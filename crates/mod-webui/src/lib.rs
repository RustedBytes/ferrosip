//! `webui` — a read-only administrator web UI: a Preact + TypeScript
//! single-page app (sources in `ui/`, built bundle embedded) over a small
//! JSON API that only calls read-only RPCs.
//!
//! ```text
//! loadmodule "webui"
//! modparam("webui", "listen", "127.0.0.1:8090")
//! modparam("webui", "user", "admin")
//! modparam("webui", "password_hash", "sha256:<salt>:<hex>")   # ferroctl webui-hash <password>
//! ```
//!
//! Parameters: `listen` (required), `user` and `password_hash` (required:
//! HTTP Basic auth on every request), `realm` ("ferrosip"),
//! `max_connections` (64), `refresh_ms` (2000, the UI's polling interval),
//! `log_buffer` (2000 lines kept for the log view; 0 turns it off).
//! Basic auth sends the password with each request: listen on 127.0.0.1
//! or put a TLS reverse proxy in front.

pub mod api;
mod assets;
pub mod auth;
mod http;

use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p};
use sip_core::sync::lock;
use sip_core::{Arg, Module, Outbound, Registry};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Default)]
struct Params {
    listen: Option<String>,
    user: Option<String>,
    password_hash: Option<String>,
    realm: Option<String>,
    max_connections: Option<usize>,
    refresh_ms: Option<u64>,
    log_buffer: Option<usize>,
}

#[derive(Default)]
pub struct WebUi {
    params: Mutex<Params>,
    server: OnceLock<(Arc<http::Server>, String)>,
}

impl Module for WebUi {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("listen", Ty::Str, "", "ip:port of the web UI (required)"),
            p("user", Ty::Str, "", "Login name (required)"),
            p("password_hash", Ty::Str, "", "sha256:<salt>:<hex> from ferroctl webui-hash (required)"),
            p("realm", Ty::Str, "ferrosip", "Basic-auth realm"),
            p("max_connections", Ty::Int { min: 1, max: 4096 }, "64", "Concurrent HTTP connections"),
            p("refresh_ms", Ty::Duration(Unit::Ms), "2s", "How often the UI polls"),
            p("log_buffer", UINT, "2000", "Log lines kept for the Logs page (0: off)"),
        ])
    }

    fn name(&self) -> &'static str {
        "webui"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut p = lock(&self.params);
        let n = |v: &Arg| usize::try_from(v.int()?).map_err(|_| format!("webui: {name} must be >= 0"));
        match name {
            "listen" => p.listen = Some(v.str()?.to_string()),
            "user" => p.user = Some(v.str()?.to_string()),
            "password_hash" => p.password_hash = Some(v.str()?.to_string()),
            "realm" => p.realm = Some(v.str()?.replace('"', "")),
            "max_connections" => p.max_connections = Some(n(v)?.max(1)),
            "refresh_ms" => p.refresh_ms = Some(n(v)?.max(500) as u64),
            "log_buffer" => p.log_buffer = Some(n(v)?),
            _ => return Err(format!("webui: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let p = lock(&self.params);
        let listen = p.listen.clone().ok_or("webui: modparam(\"webui\", \"listen\", \"ip:port\") is required")?;
        let (Some(user), Some(hash)) = (&p.user, &p.password_hash) else {
            return Err("webui: user and password_hash are required (ferroctl webui-hash <password> makes the hash)".into());
        };
        let creds = auth::Credentials::new(user, hash)?;
        let log_lines = p.log_buffer.unwrap_or(2000);
        if log_lines > 0 {
            sip_core::log::enable_ring(log_lines);
        }
        let api = api::Api::new(reg.rpc.clone(), p.refresh_ms.unwrap_or(2000));
        let server = http::Server::new(api, creds, p.realm.clone().unwrap_or_else(|| "ferrosip".into()), p.max_connections.unwrap_or(64));
        let _ = self.server.set((Arc::new(server), listen));
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        let Some((server, listen)) = self.server.get() else { return Ok(()) };
        // Like a SIP listener that can't bind: a startup error.
        let l = TcpListener::bind(listen.as_str()).map_err(|e| format!("cannot listen on {listen}: {e}"))?;
        sip_core::elog!("webui: listening on http://{listen}/");
        let s = server.clone();
        std::thread::Builder::new().name("webui".into()).spawn(move || s.run(l)).map_err(|e| format!("cannot start the webui thread: {e}"))?;
        Ok(())
    }
}
