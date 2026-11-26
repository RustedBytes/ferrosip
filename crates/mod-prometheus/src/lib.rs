//! `prometheus` — a Prometheus exporter with native names, labels and
//! latency histograms, on its own HTTP listener.
//!
//! ```text
//! loadmodule "prometheus"
//! modparam("prometheus", "listen", "127.0.0.1:9095")
//! modparam("prometheus", "bearer_token_file", "/run/secrets/metrics")   # optional
//! ```
//!
//! `GET /metrics` serves:
//! - every statistic: labelled families for the known ones
//!   (`ferrosip_tm_replies_total{class="2xx"}`), `ferrosip_<group>_<name>`
//!   for the rest;
//! - per-method request counters and the latency histograms (routing
//!   time, transaction time, post-dial delay, AI calls);
//! - `process_*` and `ferrosip_build_info`.
//!
//! `xhttp_prom` stays for Kamailio-compatible names. See README.md.

mod expose;
mod http;
mod process;

use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sync::lock;
use sip_core::{Arg, Module, Outbound, Registry};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Default)]
struct Params {
    listen: Option<String>,
    path: Option<String>,
    prefix: Option<String>,
    max_connections: Option<usize>,
    token: Option<String>,
    token_file: Option<String>,
    groups: Option<String>,
}

#[derive(Default)]
pub struct Prometheus {
    params: Mutex<Params>,
    server: OnceLock<(Arc<http::Server>, String)>,
}

fn page(prefix: &str, groups: &[String]) -> String {
    expose::render(prefix, groups)
}

impl Module for Prometheus {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("listen", Ty::Str, "", "ip:port of the metrics listener (required)"),
            p("path", Ty::Str, "/metrics", "Metrics path"),
            p("prefix", Ty::Str, "ferrosip_", "Metric name prefix (not for process_*)"),
            p("max_connections", Ty::Int { min: 1, max: 4096 }, "16", "Concurrent HTTP connections"),
            p("bearer_token", Ty::Str, "", "Require Authorization: Bearer <token>"),
            p("bearer_token_file", Ty::Str, "", "Read the token from this file"),
            p("groups", Ty::Str, "all", "Statistic groups to include, comma-separated"),
        ])
    }

    fn name(&self) -> &'static str {
        "prometheus"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut p = lock(&self.params);
        match name {
            "listen" => p.listen = Some(v.str()?.to_string()),
            "path" => p.path = Some(v.str()?.to_string()),
            "prefix" => p.prefix = Some(v.str()?.to_string()),
            "max_connections" => p.max_connections = Some(usize::try_from(v.int()?).map_err(|_| "prometheus: max_connections must be >= 1")?.max(1)),
            "bearer_token" => p.token = Some(v.str()?.to_string()),
            "bearer_token_file" => p.token_file = Some(v.str()?.to_string()),
            "groups" => p.groups = Some(v.str()?.to_string()),
            _ => return Err(format!("prometheus: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let p = lock(&self.params);
        let listen = p.listen.clone().ok_or("prometheus: modparam(\"prometheus\", \"listen\", \"ip:port\") is required")?;
        let path = p.path.clone().unwrap_or_else(|| "/metrics".into());
        if !path.starts_with('/') || path == "/" || path == "/-/healthy" {
            return Err(format!("prometheus: path {path:?} must start with / (and not be / or /-/healthy)"));
        }
        let prefix = expose::sanitize(&p.prefix.clone().unwrap_or_else(|| "ferrosip_".into()));
        let token = match &p.token_file {
            Some(f) => Some(std::fs::read_to_string(f).map_err(|e| format!("prometheus: bearer_token_file {f}: {e}"))?.trim().to_string()),
            None => p.token.clone(),
        }
        .filter(|t| !t.is_empty());
        let groups: Vec<String> = p
            .groups
            .as_deref()
            .filter(|g| g.trim() != "all")
            .map(|g| g.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_default();
        // Counters that only appear when something goes wrong: create them
        // now (at 0) so they are exported from the first scrape.
        for (g, n) in
            [("core", "panics"), ("core", "send_errors"), ("udp", "recv_errors"), ("tcp", "accepted"), ("tcp", "rejected"), ("tcp", "rejected_iplimit")]
        {
            sip_core::stats::counter(g, n);
        }
        let (pr, gr) = (prefix.clone(), groups.clone());
        reg.rpc.add("prometheus.metrics", "The Prometheus exposition, as served at the metrics path", move |_| Ok(sip_core::serde_json::json!(page(&pr, &gr))));
        let server = http::Server::new(path, token, p.max_connections.unwrap_or(16), Box::new(move || page(&prefix, &groups)));
        let _ = self.server.set((Arc::new(server), listen));
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        let Some((server, listen)) = self.server.get() else { return Ok(()) };
        // Like a SIP listener that can't bind: a startup error.
        let l = TcpListener::bind(listen.as_str()).map_err(|e| format!("cannot listen on {listen}: {e}"))?;
        sip_core::elog!("prometheus: metrics on http://{listen}{}", server.path);
        let s = server.clone();
        std::thread::Builder::new().name("prometheus".into()).spawn(move || s.run(l)).map_err(|e| format!("cannot start the prometheus thread: {e}"))?;
        Ok(())
    }
}
