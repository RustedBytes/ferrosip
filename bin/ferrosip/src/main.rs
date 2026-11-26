//! ferrosip — main: parse config, load modules, compile routes, start transports.
//! Mirrors Kamailio's main.c startup: cfg parse → mod_init → fixups → fork.

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use sip_core::sync::lock;
mod compat;
mod config;
mod import;
mod lint;
mod testing;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use sip_core::{Module, Outbound, Registry, corefns::CoreModule};
use sip_script::{Engine, Live};
use sip_transport::{Config, Listen, TcpOpts, TlsFiles};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, fs, process};

/// Modules are linked in statically and looked up by name; `loadmodule`
/// selects which ones get initialised. (Kamailio dlopen()s .so files; in Rust
/// static linking is simpler and lets LTO inline module code into the core.)
fn module_by_name(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "tm" => Arc::new(mod_txn::Tm::default()),
        "maxfwd" => Arc::new(mod_maxfwd::MaxFwd::default()),
        "usrloc" => Arc::new(mod_location::store::Usrloc::default()),
        "registrar" => Arc::new(mod_location::Registrar::default()),
        "auth" => Arc::new(mod_auth::Auth::default()),
        "auth_db" => Arc::new(mod_auth::AuthDb::default()),
        "auth_ephemeral" => Arc::new(mod_auth::AuthEphemeral::default()),
        "dialog" => Arc::new(mod_dialog::Dialog::default()),
        "dlgs" => Arc::new(mod_dialog::dlgs::Dlgs::default()),
        other => {
            return mod_sip::module(other)
                .or_else(|| mod_routing::module(other))
                .or_else(|| mod_limits::module(other))
                .or_else(|| mod_media::module(other))
                .or_else(|| mod_carrier::module(other))
                .or_else(|| mod_presence::module(other))
                .or_else(|| mod_extra::module(other))
                .or_else(|| lua_module(other))
                .or_else(|| webui_module(other))
                .or_else(|| ai_module(other))
                .or_else(|| prometheus_module(other))
                .or_else(|| mod_ims::module(other))
                .or_else(|| mod_async::module(other))
                .or_else(|| mod_ops::module(other))
                .or_else(|| compat::builtin_module(other));
        }
    })
}

#[cfg(feature = "webui")]
fn webui_module(name: &str) -> Option<Arc<dyn Module>> {
    (name == "webui").then(|| Arc::new(mod_webui::WebUi::default()) as Arc<dyn Module>)
}

#[cfg(not(feature = "webui"))]
fn webui_module(_name: &str) -> Option<Arc<dyn Module>> {
    None
}

#[cfg(feature = "prometheus")]
fn prometheus_module(name: &str) -> Option<Arc<dyn Module>> {
    (name == "prometheus").then(|| Arc::new(mod_prometheus::Prometheus::default()) as Arc<dyn Module>)
}

#[cfg(not(feature = "prometheus"))]
fn prometheus_module(_name: &str) -> Option<Arc<dyn Module>> {
    None
}

#[cfg(feature = "ai")]
fn ai_module(name: &str) -> Option<Arc<dyn Module>> {
    (name == "ai").then(|| Arc::new(mod_ai::Ai::default()) as Arc<dyn Module>)
}

#[cfg(not(feature = "ai"))]
fn ai_module(_name: &str) -> Option<Arc<dyn Module>> {
    None
}

#[cfg(feature = "lua")]
fn lua_module(name: &str) -> Option<Arc<dyn Module>> {
    mod_lua::module(name)
}

#[cfg(not(feature = "lua"))]
fn lua_module(_name: &str) -> Option<Arc<dyn Module>> {
    None
}

/// For a module that exists but was left out of this build: the cargo
/// feature that brings it back.
fn feature_for(name: &str) -> Option<&'static str> {
    match name {
        "app_lua" if cfg!(not(feature = "lua")) => Some("lua"),
        "webui" if cfg!(not(feature = "webui")) => Some("webui"),
        "ai" if cfg!(not(feature = "ai")) => Some("ai"),
        "prometheus" if cfg!(not(feature = "prometheus")) => Some("prometheus"),
        "http_client" | "http_async_client" if cfg!(not(feature = "http")) => Some("http"),
        _ => None,
    }
}

/// The optional Cargo features this binary was built with (`--version`).
fn features() -> Vec<&'static str> {
    [
        ("db-sqlite", cfg!(feature = "db-sqlite")),
        ("db-mysql", cfg!(feature = "db-mysql")),
        ("db-postgres", cfg!(feature = "db-postgres")),
        ("lua", cfg!(feature = "lua")),
        ("http", cfg!(feature = "http")),
        ("webui", cfg!(feature = "webui")),
        ("ai", cfg!(feature = "ai")),
        ("prometheus", cfg!(feature = "prometheus")),
        ("mimalloc", cfg!(feature = "mimalloc")),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect()
}

const USAGE: &str = "usage: ferrosip [check] [options]
       ferrosip schema [--markdown] [MODULE…]
       ferrosip fmt [--check] FILE.fsr|DIR…
       ferrosip import KAMAILIO.cfg [-o DIR] [--define NAME]…   a .cfg → ferrosip.toml + routes/main.fsr
       ferrosip lint [--config ferrosip.toml] [-f ROUTING] [--fix] [-W|-A|-D LINT]   clippy-style suggestions (lint --help)
       ferrosip test [options] [TEST.fsr…] [--filter NAME]   run the routing's `test` blocks
  --config FILE           ferrosip.toml: listeners, TLS, modules and their parameters; routing in [routing] entry
  --overlay FILE          merged over --config (repeatable; e.g. envs/prod.toml)
  --set PATH=VALUE        one value over both (repeatable; e.g. modules.txn.fr_timer=10s)
  --explain               with check: print the effective configuration and where each value came from
  --lowered               with check: print the .cfg a .fsr routing entry compiles to
  -f FILE                 routing script (default etc/ferrosip.cfg, or [routing] entry)
  -c, check               check the configuration (parse, load modules, parameters, fixups) and exit
  -V, --version           print the version and the optional features this binary was built with
  --define NAME[=VALUE]   preprocessor define, as #!define (repeatable; Kamailio -A)
  -l PROTO:IP:PORT        listen socket, repeatable; PROTO = udp|tcp|tls|ws|wss
                          (default: udp:127.0.0.1:5060 tcp:127.0.0.1:5060)
  -a IP                   IP to advertise in Via (default: bind address)
  -n N                    UDP workers per UDP socket (children)
  --tcp-readers N         TCP/TLS reader threads (tcp_children)
  --tcp-max-conns N       tcp_max_connections (default 4096)
  --tcp-accept-iplimit N  tcp_accept_iplimit: inbound connections per source IP (default 1024, 0 = no limit)
  --tcp-lifetime SECS     tcp_connection_lifetime (default 120)
  --tcp-wq-max BYTES      tcp_conn_wq_max (default 262144)
  --tls-cert PEM          certificate chain for tls:/wss: listeners
  --tls-key PEM           private key for --tls-cert
  --tls-ca PEM            CA bundle to verify servers on outbound TLS (and clients, see below)
  --tls-verify-client     require + verify client certificates on tls:/wss: (mutual TLS)
  --tls-sni NAME=CERT,KEY extra certificate chosen by SNI server name (repeatable)
  --tls-profile FILE      per-listener [server:IP:PORT] / per-peer [client:IP:PORT] TLS settings (Kamailio tls.cfg syntax)
  --tls-session-cache N   TLS server session cache entries (0 = no resumption by session id)
  --tls-tickets           issue stateless TLS session tickets
  --tcp-connect-timeout S tcp_connect_timeout (default 10)
  --tcp-keepalive SECS    enable TCP keep-alive probes after SECS idle
  --tcp-accept-aliases    honour Via ;alias (RFC 5923) connection reuse
  --ws-origin ORIGIN      allowed browser Origin for ws:/wss: (repeatable; default any)
  --ws-deflate            accept permessage-deflate (RFC 7692) on ws:/wss:
  --rpc-socket PATH       JSON-RPC control socket for ferroctl (default /tmp/ferrosip-rpc.sock; \"none\" disables)
  --shutdown-timeout SECS on SIGTERM/SIGINT, wait up to SECS for transactions in flight (default 5)
  -A HOST                 alias: also treat HOST as \"myself\" (repeatable)
  --debug LEVEL           log level: alert|crit|err|warn|notice|info|debug or -5..3 (default info)";

/// `ferrosip test`.
#[derive(Default)]
struct Test {
    /// Running the tests (spawning one child per test).
    parent: bool,
    /// A child: run test N (1-based).
    run: Option<usize>,
    /// Test files besides the routing's own.
    files: Vec<std::path::PathBuf>,
    filter: Option<String>,
}

struct Opts {
    cfg_file: String,
    /// `-f` given (else the file comes from ferrosip.toml's `[routing] entry`).
    cfg_file_set: bool,
    /// `--config ferrosip.toml`, `--overlay`, `--set`.
    toml: Option<std::path::PathBuf>,
    overlays: Vec<std::path::PathBuf>,
    sets: Vec<String>,
    /// `check --explain`: print the effective configuration.
    explain: bool,
    /// `check --lowered`: print the `.cfg` a `.fsr` entry compiles to.
    lowered: bool,
    test: Test,
    cfg: Config,
    rpc_socket: String,
    shutdown_timeout: Duration,
    check: bool,
    /// `--define NAME[=VALUE]` for the preprocessor (Kamailio `-A`).
    defines: Vec<(String, String)>,
    /// Settings given on the command line: config-file core parameters
    /// don't override them.
    set: std::collections::HashSet<&'static str>,
}

fn opts() -> Result<Opts, String> {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    let mut cfg_file = "etc/ferrosip.cfg".to_string();
    let mut rpc_socket = "/tmp/ferrosip-rpc.sock".to_string();
    let mut shutdown_timeout = Duration::from_secs(5);
    let mut check = false;
    let mut defines = Vec::new();
    let mut set = std::collections::HashSet::new();
    let mut c = Config {
        listen: vec![],
        udp_workers: cpus,
        tcp: TcpOpts { readers: cpus.div_ceil(2), ..TcpOpts::default() },
        tls: TlsFiles::default(),
        advertise_ip: None,
    };
    let (mut cfg_file_set, mut toml, mut overlays, mut sets, mut explain, mut lowered) = (false, None, Vec::new(), Vec::new(), false, false);
    let mut a = env::args().skip(1).peekable();
    // `ferrosip check …` = `ferrosip -c …`.
    if a.peek().is_some_and(|x| x == "check") {
        a.next();
        check = true;
    }
    // `ferrosip test [FILE.fsr…] [--filter NAME]`: run the routing's tests.
    let mut test = Test::default();
    if a.peek().is_some_and(|x| x == "test") {
        a.next();
        test.parent = true;
    }
    while let Some(k) = a.next() {
        let mut v = || a.next().ok_or(format!("{k} needs a value"));
        let num = |s: String| s.parse::<usize>().map_err(|e| format!("{k}: {e}"));
        set.insert(match k.as_str() {
            "-l" => "listen",
            "-n" => "children",
            "--tcp-readers" => "tcp_children",
            "--tcp-max-conns" => "tcp_max_connections",
            "--tcp-accept-iplimit" => "tcp_accept_iplimit",
            "--tcp-lifetime" => "tcp_connection_lifetime",
            "--tcp-wq-max" => "tcp_conn_wq_max",
            "--tcp-connect-timeout" => "tcp_connect_timeout",
            "--tcp-accept-aliases" => "tcp_accept_aliases",
            "--debug" => "debug",
            "--rpc-socket" => "rpc_socket",
            "--shutdown-timeout" => "shutdown_timeout",
            "--tcp-keepalive" => "tcp_keepalive",
            "-a" => "advertise",
            "--ws-origin" => "ws_origins",
            "--ws-deflate" => "ws_deflate",
            "--tls-cert" | "--tls-key" | "--tls-ca" | "--tls-verify-client" | "--tls-sni" | "--tls-session-cache" | "--tls-tickets" => "tls",
            _ => "",
        });
        match k.as_str() {
            "-f" => {
                cfg_file = v()?;
                cfg_file_set = true;
            }
            "--config" => toml = Some(v()?.into()),
            "--overlay" => overlays.push(v()?.into()),
            "--set" => sets.push(v()?),
            "--explain" => explain = true,
            "--lowered" => lowered = true,
            "--define" => {
                let d = v()?;
                let (n, val) = d.split_once('=').unwrap_or((&d, ""));
                defines.push((n.to_string(), val.to_string()));
            }
            "-c" => check = true,
            "-l" => c.listen.push(Listen::parse(&v()?)?),
            "-a" => c.advertise_ip = Some(v()?.parse().map_err(|e| format!("-a: {e}"))?),
            "-n" => c.udp_workers = num(v()?)?,
            "--tcp-readers" => c.tcp.readers = num(v()?)?,
            "--tcp-max-conns" => c.tcp.max_connections = num(v()?)?,
            "--tcp-accept-iplimit" => c.tcp.accept_iplimit = num(v()?)?,
            "--tcp-lifetime" => c.tcp.connection_lifetime = Duration::from_secs(num(v()?)? as u64),
            "--tcp-wq-max" => c.tcp.conn_wq_max = num(v()?)?,
            "--tls-cert" => c.tls.cert = Some(v()?.into()),
            "--tls-key" => c.tls.key = Some(v()?.into()),
            "--tls-ca" => c.tls.ca = Some(v()?.into()),
            "--tls-verify-client" => c.tls.verify_client = true,
            "--tls-profile" => c.tls.profile = Some(v()?.into()),
            "--tls-session-cache" => c.tls.session_cache = Some(num(v()?)?),
            "--tls-tickets" => c.tls.tickets = true,
            "--rpc-socket" => rpc_socket = v()?,
            "--shutdown-timeout" => shutdown_timeout = Duration::from_secs(num(v()?)? as u64),
            "--debug" => sip_core::log::set_level(sip_core::log::parse(&v()?).ok_or("--debug: level name or number")?),
            "-A" => sip_core::net::add_alias(&v()?),
            "--tls-sni" => {
                let s = v()?;
                let (name, files) = s.split_once('=').ok_or("--tls-sni expects NAME=CERT,KEY")?;
                let (cert, key) = files.split_once(',').ok_or("--tls-sni expects NAME=CERT,KEY")?;
                c.tls.sni.push((name.to_string(), cert.into(), key.into()));
            }
            "--tcp-connect-timeout" => c.tcp.connect_timeout = Duration::from_secs(num(v()?)? as u64),
            "--tcp-keepalive" => c.tcp.keepalive = Some(Duration::from_secs(num(v()?)? as u64)),
            "--tcp-accept-aliases" => c.tcp.accept_aliases = true,
            "--ws-origin" => c.tcp.ws.allowed_origins.push(v()?),
            "--ws-deflate" => c.tcp.ws.deflate = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            "-V" | "--version" => {
                let f = features();
                println!("ferrosip {} (features: {})", env!("CARGO_PKG_VERSION"), if f.is_empty() { "none".to_string() } else { f.join(" ") });
                process::exit(0);
            }
            "--filter" if test.parent => test.filter = Some(v()?),
            // Internal: a child of `ferrosip test` running one test.
            "--run-test" => test.run = Some(num(v()?)?),
            "--test-file" => test.files.push(v()?.into()),
            f if test.parent && !f.starts_with('-') => test.files.push(f.into()),
            _ => return Err(format!("unknown option {k}\n{USAGE}")),
        }
    }
    if (explain || !overlays.is_empty() || !sets.is_empty()) && toml.is_none() {
        return Err("--explain, --overlay and --set need --config ferrosip.toml".into());
    }
    Ok(Opts { cfg_file, cfg_file_set, toml, overlays, sets, explain, lowered, test, cfg: c, rpc_socket, shutdown_timeout, check, defines, set })
}

/// The modules `module_by_name` resolves itself (before the crates').
const BIN_MODULES: &[&str] = &["tm", "maxfwd", "usrloc", "registrar", "auth", "auth_db", "auth_ephemeral", "dialog", "dlgs"];

/// Every module in this build (`ferrosip schema`, implicit loading, and a
/// test that each one has a schema).
fn all_modules() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = BIN_MODULES.to_vec();
    for names in [
        mod_sip::NAMES,
        mod_routing::NAMES,
        mod_limits::NAMES,
        mod_media::NAMES,
        mod_carrier::NAMES,
        mod_presence::NAMES,
        mod_extra::NAMES,
        mod_ims::NAMES,
        mod_async::NAMES,
        mod_ops::NAMES,
    ] {
        v.extend_from_slice(names);
    }
    #[cfg(feature = "lua")]
    v.extend_from_slice(mod_lua::NAMES);
    #[cfg(feature = "webui")]
    v.push("webui");
    #[cfg(feature = "ai")]
    v.push("ai");
    #[cfg(feature = "prometheus")]
    v.push("prometheus");
    // Names a feature left out of this build don't resolve.
    v.retain(|m| module_by_name(m).is_some());
    v
}

/// For the config loader: unknown module, no schema, or its parameters.
fn schema_of(name: &str) -> Option<Option<Vec<sip_core::schema::ParamSpec>>> {
    module_by_name(name).map(|m| m.params())
}

fn errors(file: &std::path::Path, e: Vec<String>) -> String {
    let n = e.len();
    format!("{}: {n} problem{}:\n  {}", file.display(), if n == 1 { "" } else { "s" }, e.join("\n  "))
}

/// Apply ferrosip.toml to the options (command-line flags win) and return
/// the modules it loads. Kamailio-style core parameters in the `.cfg` then
/// only fill what neither set.
fn apply_toml(o: &mut Opts) -> Result<Option<(config::Layered, Vec<config::ModLoad>)>, String> {
    let Some(file) = o.toml.clone() else { return Ok(None) };
    let l = config::load(&file, &o.overlays, &o.sets)?;
    // Every problem at once: settings and modules.
    let (s, mods) = match (config::settings(&l), config::modules(&l, &schema_of)) {
        (Ok(s), Ok(m)) => (s, m),
        (s, m) => return Err(errors(&file, s.err().unwrap_or_default().into_iter().chain(m.err().unwrap_or_default()).collect())),
    };
    let c = &s.core;
    // `mark` also keeps the `.cfg`'s core parameters from overriding these.
    let mut take = |key: &'static str, cli: &'static str| -> bool {
        if c.0.contains_key(key) && !o.set.contains(cli) {
            o.set.insert(cli);
            true
        } else {
            false
        }
    };
    if take("workers", "children") {
        o.cfg.udp_workers = c.count("workers").unwrap_or(1);
    }
    if take("tcp_readers", "tcp_children") {
        o.cfg.tcp.readers = c.count("tcp_readers").unwrap_or(1);
    }
    if take("log_level", "debug") {
        sip_core::log::set_level(c.int("log_level").and_then(|l| i32::try_from(l).ok()).unwrap_or(2));
    }
    if take("rpc_socket", "rpc_socket") {
        o.rpc_socket = c.str("rpc_socket").unwrap_or_default();
    }
    if take("shutdown_timeout", "shutdown_timeout") {
        o.shutdown_timeout = c.secs("shutdown_timeout").unwrap_or(Duration::from_secs(5));
    }
    if take("advertise", "advertise") {
        let a = c.str("advertise").unwrap_or_default();
        o.cfg.advertise_ip = Some(a.parse().map_err(|_| format!("{}: core.advertise: {a:?} is not an IP address", file.display()))?);
    }
    if take("tcp_max_connections", "tcp_max_connections") {
        o.cfg.tcp.max_connections = c.count("tcp_max_connections").unwrap_or(0);
    }
    if take("tcp_accept_iplimit", "tcp_accept_iplimit") {
        o.cfg.tcp.accept_iplimit = c.count("tcp_accept_iplimit").unwrap_or(0);
    }
    if take("tcp_connection_lifetime", "tcp_connection_lifetime") {
        o.cfg.tcp.connection_lifetime = c.secs("tcp_connection_lifetime").unwrap_or_default();
    }
    if take("tcp_connect_timeout", "tcp_connect_timeout") {
        o.cfg.tcp.connect_timeout = c.secs("tcp_connect_timeout").unwrap_or_default();
    }
    if take("tcp_keepalive", "tcp_keepalive") {
        o.cfg.tcp.keepalive = Some(c.secs("tcp_keepalive").unwrap_or_default());
    }
    if take("tcp_conn_wq_max", "tcp_conn_wq_max") {
        o.cfg.tcp.conn_wq_max = c.count("tcp_conn_wq_max").unwrap_or(0);
    }
    if take("tcp_accept_aliases", "tcp_accept_aliases") {
        o.cfg.tcp.accept_aliases = c.int("tcp_accept_aliases") == Some(1);
    }
    if take("ws_origins", "ws_origins") {
        o.cfg.tcp.ws.allowed_origins = c.strs("ws_origins");
    }
    if take("force_rport", "force_rport") {
        sip_core::module::set_force_rport(c.int("force_rport") != Some(0));
    }
    if take("ws_deflate", "ws_deflate") {
        o.cfg.tcp.ws.deflate = c.int("ws_deflate") == Some(1);
    }
    for a in c.strs("aliases") {
        sip_core::net::add_alias(&a);
    }
    // Listeners and TLS.
    let tls_path = |a: &[sip_core::Arg]| a.first().and_then(|a| a.str().ok()).map(|p| if p.starts_with('/') { p.into() } else { l.dir.join(p) });
    let mut profiles = String::new();
    if !s.listen.is_empty() && !o.set.contains("listen") {
        o.set.insert("listen");
        o.cfg.listen.clear();
        for ls in &s.listen {
            let mut li =
                Listen::parse(&format!("{}:{}", ls.proto, ls.addr)).map_err(|e| format!("{}: listen {}:{}: {e}", file.display(), ls.proto, ls.addr))?;
            if let Some(a) = &ls.advertise {
                li.advertise = Some(a.parse().map_err(|_| format!("{}: listen {}: advertise {a:?} is not ip:port", file.display(), ls.addr))?);
            }
            if let Some(name) = ls.tls.as_deref().filter(|n| *n != "default") {
                let t = s.tls.get(name).ok_or_else(|| format!("{}: listen {}: no [tls.{name}] section", file.display(), ls.addr))?;
                profiles.push_str(&format!("[server:{}]\n", li.addr));
                for (k, line) in [("cert", "certificate"), ("key", "private_key"), ("ca", "ca_list")] {
                    if let Some(p) = t.get(k).and_then(|a| tls_path(a)) {
                        profiles.push_str(&format!("{line} = {}\n", p.display()));
                    }
                }
                if t.get("verify_client").and_then(|a| a.first()).and_then(|a| a.int().ok()) == Some(1) {
                    profiles.push_str("verify_certificate = yes\nrequire_certificate = yes\n");
                }
            }
            o.cfg.listen.push(li);
        }
    }
    if let Some(t) = s.tls.get("default")
        && !o.set.contains("tls")
    {
        let flag = |k: &str| t.get(k).and_then(|a| a.first()).and_then(|a| a.int().ok()) == Some(1);
        o.cfg.tls.cert = t.get("cert").and_then(|a| tls_path(a)).or(o.cfg.tls.cert.take());
        o.cfg.tls.key = t.get("key").and_then(|a| tls_path(a)).or(o.cfg.tls.key.take());
        o.cfg.tls.ca = t.get("ca").and_then(|a| tls_path(a)).or(o.cfg.tls.ca.take());
        o.cfg.tls.verify_client |= flag("verify_client");
        o.cfg.tls.tickets |= flag("tickets");
        // `session_cache` is a UINT (0 or more).
        if let Some(n) = t.get("session_cache").and_then(|a| a.first()).and_then(|a| a.int().ok()).and_then(|n| usize::try_from(n).ok()) {
            o.cfg.tls.session_cache = Some(n);
        }
        for spec in t.get("sni").into_iter().flatten().filter_map(|a| a.str().ok()) {
            let (name, files) = spec.split_once('=').ok_or_else(|| format!("{}: tls.default.sni {spec:?}: expected name=cert,key", file.display()))?;
            let (cert, key) = files.split_once(',').ok_or_else(|| format!("{}: tls.default.sni {spec:?}: expected name=cert,key", file.display()))?;
            o.cfg.tls.sni.push((name.into(), l.dir.join(cert), l.dir.join(key)));
        }
    }
    if let Some(p) = s.tls.get("default").and_then(|t| t.get("profile")).and_then(|a| tls_path(a))
        && o.cfg.tls.profile.is_none()
    {
        o.cfg.tls.profile = Some(p);
    }
    if !profiles.is_empty() {
        o.cfg.tls.profile_text = Some(profiles);
    }
    for (name, val, desc) in &s.cfg_vars {
        sip_core::cfgvars::declare(name, val.clone(), desc.clone());
    }
    if !o.cfg_file_set {
        match &s.entry {
            Some(e) => o.cfg_file = e.display().to_string(),
            None => return Err(format!("{}: [routing] entry = \"routes/main.cfg\" is needed (or -f)", file.display())),
        }
    }
    Ok(Some((l, mods)))
}

/// Which module provides each script function and pseudo-variable
/// (`ferrosip schema --functions`, committed as functions.txt).
static FUNCTIONS: &str = include_str!("functions.txt");

/// The module providing function `name` (`kind` "fn") or variable `$name`
/// ("pv"). When several do (registrar and the IMS registrars both have
/// `save`), the one listed first in `all_modules` wins.
/// Every module providing function / variable `name`, preferred first.
fn providers(kind: &str, name: &str) -> Vec<&'static str> {
    let all = all_modules();
    let mut v: Vec<(usize, &'static str)> = FUNCTIONS
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some(kind) && w.next() == Some(name)).then(|| w.next()).flatten()
        })
        .filter_map(|m| all.iter().enumerate().find(|&(_, x)| *x == m).map(|(i, x)| (i, *x)))
        .collect();
    v.sort();
    v.into_iter().map(|(_, m)| m).collect()
}

/// Every module in dependency order before it (deepest first).
fn dep_chain(m: &str, out: &mut Vec<&'static str>) {
    for d in config::deps(m) {
        if !out.contains(d) {
            dep_chain(d, out);
            out.push(d);
        }
    }
}

/// Placeholder values for modules that refuse to register without them,
/// so their functions can be indexed (never used to run anything).
const INDEX_PARAMS: &[(&str, &[(&str, &str)])] = &[
    ("auth_db", &[("db_url", "text:///nonexistent")]),
    ("auth_ephemeral", &[("secret", "index")]),
    ("dispatcher", &[("list_file", "/dev/null")]),
    ("rtpengine", &[("rtpengine_sock", "udp:127.0.0.1:2223")]),
    ("siptrace", &[("duplicate_uri", "sip:127.0.0.1:9060")]),
    ("xhttp", &[("listen", "127.0.0.1:0")]),
    ("webui", &[("listen", "127.0.0.1:0"), ("user", "index"), ("password_hash", "sha256:x:0000000000000000000000000000000000000000000000000000000000000000")]),
    ("prometheus", &[("listen", "127.0.0.1:0")]),
    ("dialog", &[("profiles_no_value", "calls"), ("profiles_with_value", "caller")]),
];

fn index_module(m: &str) -> Result<Arc<dyn Module>, String> {
    let module = module_by_name(m).ok_or_else(|| format!("unknown module {m}"))?;
    for (n, v) in INDEX_PARAMS.iter().filter(|(x, _)| *x == m).flat_map(|(_, p)| p.iter()) {
        module.set_param(n, &sip_core::Arg::Str(v.to_string()))?;
    }
    Ok(module)
}

/// `ferrosip schema --functions-of M`: what module M adds to a registry
/// (after its dependencies), as index lines. One process per module:
/// registration has process-wide side effects (send filters, hooks).
fn functions_of(m: &str) -> Result<String, String> {
    use std::collections::HashSet;
    sip_db::set_check_only(true);
    let mut reg = Registry::default();
    reg.load(Arc::new(CoreModule))?;
    let mut chain = Vec::new();
    dep_chain(m, &mut chain);
    for d in chain {
        reg.load(index_module(d)?).map_err(|e| format!("needs {d}: {e}"))?;
    }
    let (f0, p0): (HashSet<String>, HashSet<String>) = (reg.exports().map(|(n, _)| n.clone()).collect(), reg.pvs().keys().cloned().collect());
    reg.load(index_module(m)?)?;
    let mut out = String::new();
    for f in reg.exports().map(|(n, _)| n).filter(|n| !f0.contains(*n)) {
        out.push_str(&format!("fn {f} {m}\n"));
    }
    for p in reg.pvs().keys().filter(|n| !p0.contains(*n)) {
        out.push_str(&format!("pv {p} {m}\n"));
    }
    Ok(out)
}

/// `ferrosip schema --functions`: the whole index, one child process per
/// module.
fn function_index() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let mut lines = std::collections::BTreeSet::new();
    let mut skipped = Vec::new();
    for m in all_modules() {
        let out = process::Command::new(&exe).args(["schema", "--functions-of", m]).output().map_err(|e| e.to_string())?;
        if out.status.success() {
            lines.extend(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string));
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            skipped.push(format!("# skipped {m}: {}", err.lines().last().unwrap_or("failed")));
        }
    }
    let mut out = String::from("# Generated by `ferrosip schema --functions`: do not edit.\n# fn <function> <module> / pv <variable> <module>\n");
    for s in skipped.into_iter().chain(lines) {
        out.push_str(&s);
        out.push('\n');
    }
    Ok(out)
}

/// With ferrosip.toml, a module loads when the routing script uses one of
/// its functions or variables (a plain .cfg still needs `loadmodule`, as
/// in Kamailio).
fn implicit_modules(plan: Vec<config::ModLoad>, ast: &sip_script::Ast, fsr: bool) -> Result<Vec<config::ModLoad>, String> {
    let uses = sip_script::uses(ast);
    let mut extra: Vec<(String, String)> = Vec::new();
    // .fsr names its modules (events, tables, namespaced calls): load them
    // like the others, dependencies first. A .cfg's loadmodules are its own.
    if fsr {
        for m in ast.modules.iter().filter(|m| !plan.iter().any(|p| &p.name == *m)) {
            extra.push((m.clone(), "used by the routing".into()));
        }
    }
    let have: Vec<String> = plan.iter().map(|m| m.name.clone()).chain(ast.modules.iter().cloned()).collect();
    let wanted = uses.functions.iter().map(|f| ("fn", f, format!("{f}()"))).chain(uses.pvs.iter().map(|p| ("pv", p, format!("${p}"))));
    for (kind, name, shown) in wanted {
        // A module already loaded that provides it (ims_registrar_scscf's
        // save, not registrar's) is the one used.
        let all = providers(kind, name);
        if all.iter().any(|m| have.iter().any(|h| h == m) || extra.iter().any(|(x, _)| x == m)) {
            continue;
        }
        if let Some(&m) = all.first() {
            extra.push((m.to_string(), format!("loaded for {shown}")));
        }
    }
    if extra.is_empty() { Ok(plan) } else { config::add_modules(plan, &extra, &schema_of) }
}

/// `ferrosip schema --fsr`: every function `.fsr` can call, by namespace
/// (docs/functions-reference.md).
fn fsr_reference() -> String {
    use sip_core::sig::{ArgTy, Ret, ctx};
    let mut by_ns: std::collections::BTreeMap<String, Vec<(&str, sip_core::sig::FnSig)>> = Default::default();
    let mut hidden = Vec::new();
    for m in all_modules() {
        for s in module_by_name(m).and_then(|x| x.functions()).unwrap_or_default() {
            if s.fsr.is_empty() {
                hidden.push((m, s));
            } else {
                by_ns.entry(s.ns.unwrap_or(fsr_namespace(m)).to_string()).or_default().push((m, s));
            }
        }
    }
    let ty = |t: ArgTy| match t {
        ArgTy::Str => "Str".to_string(),
        ArgTy::Int => "Int".into(),
        ArgTy::Bool => "Bool".into(),
        ArgTy::Duration(_) => "Duration".into(),
        ArgTy::Uri => "Uri".into(),
        ArgTy::Flag => "Flag".into(),
        ArgTy::Var => "Var".into(),
        ArgTy::Any => "Str|Int".into(),
        ArgTy::Enum(v) => v.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join("|"),
    };
    let mut out = String::from(
        "# `.fsr` functions\n\nGenerated by `ferrosip schema --fsr`: do not edit. The language: [fsr.md](fsr.md).\n\n\
         Each function is `namespace.name(…)`; the namespace is the module's ferrosip name.\n\
         - `x?` may be left out (`x = v`: `v` when left out), `const` must be written as a constant;\n\
         - **returns** `Bool` (a check), `Action` (answers or relays the request: the route ends) or nothing;\n\
         - **where**: request processing (`route`), `after await`, `on reply`, event routes (`event`).\n",
    );
    for (ns, mut fns) in by_ns {
        fns.sort_by_key(|(_, s)| s.fsr);
        out.push_str(&format!("\n## {ns}\n\n| function | returns | where | calls | |\n|---|---|---|---|---|\n"));
        for (m, s) in fns {
            let params: Vec<String> = s
                .params
                .iter()
                .map(|p| {
                    let mut x = format!("{}{}: {}", p.name, if p.optional && p.default.is_none() { "?" } else { "" }, ty(p.ty));
                    if let Some(d) = p.default {
                        x.push_str(&format!(" = {}", if d.is_empty() { "\"\"" } else { d }));
                    }
                    if p.literal {
                        x.push_str(" const");
                    }
                    x
                })
                .collect();
            let ret = match s.ret {
                Ret::Bool => "Bool".to_string(),
                Ret::Action => "Action".to_string(),
                Ret::Void => String::new(),
                Ret::Await(a) => format!("await → {} ({})", a.name, a.fields.iter().map(|(f, ..)| *f).collect::<Vec<_>>().join(", ")),
            };
            let mut wh = Vec::new();
            // an awaitable call can't follow `await txn.relay`
            let after = if matches!(s.ret, Ret::Await(_)) { 0 } else { ctx::FAILURE };
            for (bit, name) in [(ctx::REQUEST, "route"), (after, "after await"), (ctx::REPLY, "on reply"), (ctx::EVENT, "event")] {
                if s.allowed & bit != 0 {
                    wh.push(name);
                }
            }
            let fixed =
                if s.fixed.is_empty() { String::new() } else { format!("{}, ", s.fixed.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ")) };
            out.push_str(&format!(
                "| `{}({})` | {ret} | {} | `{}({fixed}…)` ({m}) | {} |\n",
                s.fsr,
                params.join(", ").replace('|', "\\|"),
                wh.join(", "),
                s.name,
                config::md_text(s.doc)
            ));
        }
    }
    hidden.sort_by_key(|(m, s)| (*m, s.name));
    out.push_str("\n## Not offered in `.fsr`\n\n| function | module | why |\n|---|---|---|\n");
    for (m, s) in hidden {
        out.push_str(&format!("| `{}` | {m} | {} |\n", s.name, config::md_text(s.doc)));
    }
    out
}

/// `ferrosip schema [--markdown] [module…]`.
fn print_schema(args: &[String]) -> Result<(), String> {
    if let Some(i) = args.iter().position(|a| a == "--functions-of") {
        print!("{}", functions_of(args.get(i.saturating_add(1)).ok_or("--functions-of MODULE")?)?);
        return Ok(());
    }
    if args.iter().any(|a| a == "--functions") {
        print!("{}", function_index()?);
        return Ok(());
    }
    if args.iter().any(|a| a == "--fsr") {
        print!("{}", fsr_reference());
        return Ok(());
    }
    let markdown = args.iter().any(|a| a == "--markdown");
    let wanted: Vec<&str> = args.iter().filter(|a| !a.starts_with("--")).map(String::as_str).collect();
    let mut mods = Vec::new();
    for m in all_modules() {
        let alias = config::ALIASES.iter().find(|a| a.always.contains(&m) || a.optional.contains(&m)).map(|a| a.name);
        if !wanted.is_empty() && !wanted.iter().any(|w| *w == m || Some(*w) == alias) {
            continue;
        }
        let Some(params) = schema_of(m).flatten() else { continue };
        mods.push((m, params));
    }
    if !wanted.is_empty() && mods.is_empty() && !wanted.iter().all(|w| ["core", "listen", "tls"].contains(w)) {
        return Err(format!("no schema for {}", wanted.join(", ")));
    }
    let all = ["core", "listen", "tls"];
    let sections: Vec<&str> = if wanted.is_empty() { all.to_vec() } else { all.iter().filter(|s| wanted.contains(s)).copied().collect() };
    print!("{}", config::reference(&mods, markdown, &sections));
    Ok(())
}

/// Kamailio core parameters from the script (`debug=2`, `listen=…`,
/// `children=8`, …), unless the same setting was given on the command line.
/// Parameters without a ferrosip equivalent are accepted with a notice;
/// unknown ones get a warning (Kamailio would refuse to start).
fn apply_core(core: &[sip_script::preprocess::CoreParam], o: &mut Opts) -> Result<(), String> {
    let mut ignored = Vec::new();
    for p in core {
        let name = p.name.to_ascii_lowercase();
        if o.set.contains(name.as_str()) {
            continue;
        }
        let v = p.value.trim().trim_matches('"');
        let num = || v.parse::<usize>().map_err(|_| format!("{}: {} expects a number, got {v:?}", p.at, p.name));
        let yes = || matches!(v.to_ascii_lowercase().as_str(), "yes" | "on" | "true" | "1");
        match name.as_str() {
            "listen" => {
                // `listen=proto:ip:port [advertise ip:port] [name "x"]`
                let addr = v.split_whitespace().next().unwrap_or("").replace('"', "");
                let addr = addr.as_str();
                let addr =
                    if addr.contains(':') && addr.split(':').count() >= 2 && addr.split(':').next().is_some_and(|x| x.parse::<std::net::IpAddr>().is_err()) {
                        addr.to_string()
                    } else {
                        format!("udp:{addr}")
                    };
                let addr = if addr.matches(':').count() == 1 { format!("{addr}:5060") } else { addr };
                o.cfg.listen.push(Listen::parse(&addr).map_err(|e| format!("{}: listen={v}: {e}", p.at))?);
            }
            "children" => o.cfg.udp_workers = num()?.max(1),
            "tcp_children" => o.cfg.tcp.readers = num()?.max(1),
            "tcp_max_connections" => o.cfg.tcp.max_connections = num()?,
            "tcp_accept_iplimit" => o.cfg.tcp.accept_iplimit = num()?,
            "tcp_connection_lifetime" => o.cfg.tcp.connection_lifetime = Duration::from_secs(num()? as u64),
            "tcp_connect_timeout" => o.cfg.tcp.connect_timeout = Duration::from_secs(num()? as u64),
            "tcp_conn_wq_max" => o.cfg.tcp.conn_wq_max = num()?,
            "tcp_accept_aliases" => o.cfg.tcp.accept_aliases = yes(),
            "force_rport" => sip_core::module::set_force_rport(yes()),
            // Kamailio core dset.c init_dst_set() / tm.c mod_init(): 1..30.
            "max_branches" => match num()? {
                n @ 1..=30 => sip_core::module::set_max_branches(n),
                n => return Err(format!("{}: max_branches = {n}: must be 1..30", p.at)),
            },
            "tcp_keepalive" if !yes() => o.cfg.tcp.keepalive = None,
            "tcp_keepidle" => o.cfg.tcp.keepalive = Some(Duration::from_secs(num()? as u64)),
            "debug" => {
                let l = v.parse::<i32>().map_err(|_| format!("{}: debug expects a number", p.at))?;
                sip_core::log::set_level(l.min(sip_core::log::L_DBG));
            }
            "alias" => {
                let host = v.trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_start_matches(':');
                let host = if v.contains(':') && v.split(':').next().is_some_and(|x| matches!(x, "udp" | "tcp" | "tls" | "ws" | "wss")) { host } else { v };
                sip_core::net::add_alias(host.split(':').next().unwrap_or(host));
            }
            // No equivalent: logging/process/memory knobs, or features that are
            // always on or configured elsewhere (TLS files, transports by listen).
            "log_stderror"
            | "log_facility"
            | "log_prefix"
            | "log_name"
            | "log_color"
            | "memdbg"
            | "memlog"
            | "mem_join"
            | "mem_safety"
            | "fork"
            | "mhomed"
            | "auto_aliases"
            | "dns"
            | "rev_dns"
            | "dns_try_ipv6"
            | "dns_cache_init"
            | "use_dns_cache"
            | "use_dns_failover"
            | "enable_tls"
            | "enable_sctp"
            | "disable_tcp"
            | "tcp_async"
            | "tcp_keepalive"
            | "tcp_keepintvl"
            | "tcp_keepcnt"
            | "tcp_rd_buf_size"
            | "tcp_wq_blk_size"
            | "tcp_send_timeout"
            | "tcp_source_ipv4"
            | "server_header"
            | "user_agent_header"
            | "server_signature"
            | "sip_warning"
            | "latency_cfg_log"
            | "latency_log"
            | "latency_limit_action"
            | "latency_limit_db"
            | "corelog"
            | "async_workers"
            | "port"
            | "mpath"
            | "loadpath"
            | "pv_buffer_size"
            | "pv_buffer_slots"
            | "max_while_loops"
            | "maxbuffer"
            | "phone2tel"
            | "stats_name_separator"
            | "tos"
            | "shm_mem_size"
            | "pkg_mem_size"
            | "socket_workers"
            | "udp_mtu"
            | "udp_mtu_try_proto"
            | "enable_tls_verify_client"
            | "xavp_via_params"
            | "xavp_via_fields"
            | "advertised_address"
            | "advertised_port"
            | "check_via"
            | "dst_blocklist_init"
            | "use_dst_blocklist"
            | "dst_blocklist_expire"
            | "cfgengine"
            | "flags"
            | "children_per_sock"
            | "tls_threads_mode"
            | "tls_max_connections" => ignored.push(name),
            // `group.name = value [desc "…"]`: a custom config variable.
            n if n.contains('.') => {
                let (val, desc) = sip_core::cfgvars::parse_decl(&p.value).map_err(|e| format!("{}: {}: {e}", p.at, p.name))?;
                sip_core::cfgvars::declare(&p.name, val, desc);
            }
            _ => sip_core::elog!("ferrosip: {}: warning: unknown core parameter {:?} (ignored)", p.at, p.name),
        }
    }
    if !ignored.is_empty() {
        ignored.sort();
        ignored.dedup();
        sip_core::elog!("ferrosip: note: core parameters without a ferrosip equivalent, ignored: {}", ignored.join(", "));
    }
    Ok(())
}

/// The namespace a module's functions are in for `.fsr`: its ferrosip
/// name (`registrar` → `location`), else its own.
fn fsr_namespace(m: &str) -> &str {
    config::ALIASES.iter().find(|a| a.always.contains(&m) || a.optional.contains(&m)).map_or(m, |a| a.name)
}

/// Every function signature in this build, by namespace.
fn fsr_env(features: std::collections::BTreeMap<String, fsr::Feature>) -> fsr::Env {
    let mut env = fsr::Env { features, ..Default::default() };
    for m in all_modules() {
        if let Some(sigs) = module_by_name(m).and_then(|x| x.functions()) {
            env.add_from(m, fsr_namespace(m), sigs);
        }
    }
    env
}

/// Preprocess and parse the script (errors as `file:line`); a `.fsr`
/// entry is compiled to the same tree.
fn load_script(file: &str, defines: &[(String, String)], features: &Features) -> Result<(sip_script::preprocess::Preprocessed, sip_script::Ast), String> {
    if file.ends_with(".fsr") {
        let mut env = fsr_env(features.clone());
        env.toml_tables = lock(&TOML_TABLES).clone();
        let extra = TEST_FILES.get();
        env.tests = extra.is_some();
        let out = fsr::compile_with(std::path::Path::new(file), extra.map_or(&[], Vec::as_slice), &env).map_err(|e| {
            let n = e.0.len();
            format!("{n} error{} in the routing:\n{e}", if n == 1 { "" } else { "s" })
        })?;
        let _ = TESTS.set(out.tests);
        return Ok((sip_script::preprocess::Preprocessed::plain(file), out.ast));
    }
    let pp = sip_script::preprocess::preprocess_file(file, defines)?;
    let ast = sip_script::parse(&pp.text).map_err(|e| pp.locate_error(&e))?;
    Ok((pp, ast))
}

type Features = std::collections::BTreeMap<String, fsr::Feature>;

/// Tables ferrosip.toml declares: a `.fsr` `shared table` of that name uses
/// it rather than declaring another.
static TOML_TABLES: std::sync::Mutex<std::collections::BTreeSet<String>> = std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Set when testing: compile the `test` blocks, from these extra files too.
static TEST_FILES: std::sync::OnceLock<Vec<std::path::PathBuf>> = std::sync::OnceLock::new();
/// The tests the routing defines (with TEST_FILES).
static TESTS: std::sync::OnceLock<Vec<fsr::TestDef>> = std::sync::OnceLock::new();

/// `ferrosip test`: one child process per test (modules keep process-wide
/// state), each the same command line with `--run-test N`.
fn run_tests(cfg_file: &str, test: &Test) -> Result<(), String> {
    if !cfg_file.ends_with(".fsr") {
        return Err(format!("ferrosip test: {cfg_file} is not a .fsr routing (tests are `test` blocks in .fsr files)"));
    }
    let tests = TESTS.get().cloned().unwrap_or_default();
    let picked: Vec<(usize, &fsr::TestDef)> =
        (1..).zip(tests.iter()).filter(|(_, t)| test.filter.as_ref().is_none_or(|f| t.name.contains(f.as_str()))).collect();
    if picked.is_empty() {
        return Err(if tests.is_empty() { "no `test \"…\" { … }` blocks found".into() } else { "no test matches --filter".into() });
    }
    // The command line, minus `test`, its files and --filter.
    let mut args: Vec<String> = Vec::new();
    let mut it = env::args().skip(1).peekable();
    if it.peek().is_some_and(|a| a == "test") {
        it.next();
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--filter" => {
                it.next();
            }
            f if !f.starts_with('-') && test.files.iter().any(|p| p.as_os_str() == f) => {}
            _ => args.push(a),
        }
    }
    for f in &test.files {
        args.extend(["--test-file".into(), f.display().to_string()]);
    }
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    let (mut passed, mut failed): (usize, usize) = (0, 0);
    let start = Instant::now();
    for (n, t) in &picked {
        let t0 = Instant::now();
        let out = process::Command::new(&exe).args(&args).args(["--run-test", &n.to_string()]).output().map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let ms = t0.elapsed().as_millis();
        if out.status.success() {
            passed = passed.saturating_add(1);
            println!("ok    {} ({ms} ms)", t.name);
        } else {
            failed = failed.saturating_add(1);
            println!("FAIL  {}  ({})", t.name, t.at);
            for l in stdout.lines() {
                println!("      {l}");
            }
            if stdout.trim().is_empty() {
                let err = String::from_utf8_lossy(&out.stderr);
                for l in err.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev() {
                    println!("      {l}");
                }
            }
        }
    }
    println!("\n{passed} passed, {failed} failed ({} ms)", start.elapsed().as_millis());
    if failed > 0 { Err(format!("{failed} test(s) failed")) } else { Ok(()) }
}

/// `ferrosip fmt [--check] PATH…`: format `.fsr` files in place
/// (directories: every `.fsr` under them). `--check` only lists the files
/// that would change, and fails if there are any.
fn fmt_fsr(args: &[String]) -> Result<(), String> {
    fn walk(p: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        if p.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(p).map_err(|e| format!("{}: {e}", p.display()))?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
            entries.sort();
            for e in entries {
                walk(&e, out)?;
            }
        } else if p.extension().is_some_and(|x| x == "fsr") {
            out.push(p.to_path_buf());
        }
        Ok(())
    }
    let check = args.iter().any(|a| a == "--check");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if paths.is_empty() {
        return Err("usage: ferrosip fmt [--check] FILE.fsr|DIR…".into());
    }
    let mut files = Vec::new();
    for p in paths {
        let p = std::path::Path::new(p);
        if !p.exists() {
            return Err(format!("{}: no such file or directory", p.display()));
        }
        walk(p, &mut files)?;
    }
    let (mut changed, mut errs) = (Vec::new(), Vec::new());
    for f in files {
        let name = f.display().to_string();
        let src = std::fs::read_to_string(&f).map_err(|e| format!("{name}: {e}"))?;
        match fsr::parse(&src) {
            Err(e) => errs.push(fsr::render_error(&name, &src, e.span, &e.msg)),
            Ok(file) => {
                let out = fsr::fmt::format(&file);
                if out != src {
                    if !check {
                        std::fs::write(&f, &out).map_err(|e| format!("{name}: {e}"))?;
                    }
                    changed.push(name);
                }
            }
        }
    }
    for c in &changed {
        println!("{}{c}", if check { "would format " } else { "formatted " });
    }
    if !errs.is_empty() {
        return Err(errs.join("\n"));
    }
    if check && !changed.is_empty() {
        return Err(format!("{} file(s) need formatting", changed.len()));
    }
    Ok(())
}

/// What `cfg.reload` must not change: modules and their parameters.
fn signature(ast: &sip_script::Ast) -> Vec<String> {
    let mut v: Vec<String> = ast.modules.iter().map(|m| format!("loadmodule {m:?}")).collect();
    v.extend(ast.modparams.iter().map(|p| format!("modparam({:?}, {:?}, {:?})", p.module, p.name, p.value)));
    v
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    // After a subcommand: its own arguments.
    let rest = args.get(1..).unwrap_or_default();
    if args.first().is_some_and(|a| a == "schema") {
        return print_schema(rest);
    }
    if args.first().is_some_and(|a| a == "fmt") {
        return fmt_fsr(rest);
    }
    if args.first().is_some_and(|a| a == "import") {
        let code = import::main(rest)?;
        process::exit(code);
    }
    if args.first().is_some_and(|a| a == "lint") {
        let code = lint::main(rest)?;
        process::exit(code);
    }
    let mut o = opts()?;
    let toml = apply_toml(&mut o)?;
    let features = toml.as_ref().map(|(l, _)| config::features(l)).unwrap_or_default();
    if let Some((l, _)) = &toml {
        *lock(&TOML_TABLES) = config::htables(l);
    }
    if o.test.parent || o.test.run.is_some() {
        let _ = TEST_FILES.set(o.test.files.clone());
    }
    let (pp, ast) = load_script(&o.cfg_file, &o.defines, &features)?;
    if o.test.parent {
        return run_tests(&o.cfg_file, &o.test);
    }
    apply_core(&pp.core, &mut o)?;
    if o.cfg.listen.is_empty() {
        o.cfg.listen = vec![Listen::parse("udp:127.0.0.1:5060")?, Listen::parse("tcp:127.0.0.1:5060")?];
    }
    // modparam("tls", …) → TLS settings (before the transports start).
    let tls_params: Vec<(String, String)> = ast
        .modparams
        .iter()
        .filter(|p| p.module == "tls")
        .filter_map(|p| match &p.value {
            sip_script::RawArg::Str(s) => Some((p.name.clone(), s.clone())),
            sip_script::RawArg::Int(i) => Some((p.name.clone(), i.to_string())),
            sip_script::RawArg::Pv(_) => None,
        })
        .collect();
    compat::tls_settings(&tls_params, &mut o.cfg.tls);
    let Opts { cfg_file, cfg, rpc_socket, shutdown_timeout, check, defines, explain, lowered, test, toml: toml_file, overlays, sets, .. } = o;
    let toml_inputs = toml_file.map(|f| (f, overlays, sets));
    // A check opens no databases (like `kamailio -c`); nor do tests.
    sip_db::set_check_only(check || test.run.is_some());
    let (layered, mut plan) = match toml {
        Some((l, m)) => (Some(l), m),
        None => (None, Vec::new()),
    };
    // A .fsr names the modules it uses (with or without ferrosip.toml):
    // they load with their dependencies (registrar after usrloc). A .cfg
    // without ferrosip.toml loads exactly its own `loadmodule`s.
    if layered.is_some() || cfg_file.ends_with(".fsr") {
        plan = implicit_modules(plan, &ast, cfg_file.ends_with(".fsr"))?;
    }
    let toml_inputs = toml_inputs.filter(|_| layered.is_some());

    let mut reg = Registry::default();
    reg.load(Arc::new(CoreModule))?;
    // ferrosip.toml's modules (dependency order), then the script's own
    // `loadmodule`s (script order).
    let mut order: Vec<String> = plan.iter().map(|m| m.name.clone()).collect();
    for m in &ast.modules {
        if !order.contains(m) {
            order.push(m.clone());
        }
    }
    // Kamailio allows `modparam("nathelper|registrar", …)`: the parameter
    // goes to each listed module that is loaded (at least one must be).
    let targets = |pm: &str, m: &str| pm.split('|').any(|n| n == m);
    if let Some(p) = ast.modparams.iter().find(|p| !order.iter().any(|m| targets(&p.module, m))) {
        return Err(format!("{}: modparam for module {:?} which is not loaded", pp.locate(p.line), p.module));
    }
    // Same order as Kamailio: modparams are applied, then mod_init runs, in
    // load order (so registrar must come after usrloc).
    for m in &order {
        let module = module_by_name(m).ok_or_else(|| match feature_for(m) {
            Some(f) => format!("module {m:?} was left out of this build (cargo feature `{f}`)"),
            None => format!("unknown module {m:?}"),
        })?;
        if let Some(pl) = plan.iter().find(|x| &x.name == m) {
            for (k, args, src, _) in &pl.params {
                // Parameters that add (tables, timers) take values from both.
                let adds = matches!((m.as_str(), k.as_str()), ("htable", "htable") | ("rtimer", "timer" | "exec"));
                if let Some(c) = ast.modparams.iter().find(|p| targets(&p.module, m) && p.name == *k).filter(|_| !adds) {
                    return Err(format!("{m} parameter {k:?} is set twice, in {src} and at {}: keep one", pp.locate(c.line)));
                }
                for a in args {
                    module.set_param(k, a).map_err(|e| format!("{src}: [modules] {m}.{k}: {e}"))?;
                }
            }
        }
        for p in ast.modparams.iter().filter(|p| targets(&p.module, m)) {
            let value = match &p.value {
                sip_script::RawArg::Str(s) => sip_core::Arg::Str(s.clone()),
                sip_script::RawArg::Int(i) => sip_core::Arg::Int(*i),
                sip_script::RawArg::Pv(v) => return Err(format!("{}: modparam values can't be variables ({v})", pp.locate(p.line))),
            };
            if let Err(e) = module.set_param(&p.name, &value) {
                if !compat::no_effect(m, &p.name) {
                    return Err(format!("{}: {e}", pp.locate(p.line)));
                }
                sip_core::module::param_no_effect(m, &p.name);
            }
        }
        reg.load(module).map_err(|e| format!("{cfg_file}: {m}: {e}"))?;
    }
    // A test: its functions, and the mocks it asks for.
    let harness = match test.run {
        Some(n) => {
            let t = TESTS.get().and_then(|t| t.get(n.checked_sub(1)?)).ok_or(format!("--run-test {n}: no such test"))?;
            let h = testing::Harness::new();
            testing::register(&mut reg, &h, &t.mocks).map_err(|e| format!("{}: {e}", t.at))?;
            Some((h, t.route.clone()))
        }
        None => None,
    };
    // All fixups run here; any config error aborts before we bind a socket.
    reg.check()?;
    let reg = Arc::new(reg);
    let engine = Live::new(Engine::compile(&ast, reg.clone()).map_err(|e| pp.locate_error(&e))?);
    if let Some((h, route)) = harness {
        engine.install();
        h.set_handler(engine.clone());
        for m in &reg.modules {
            m.clone().spawn(h.net.clone() as Arc<dyn Outbound>).map_err(|e| format!("{}: {e}", m.name()))?;
        }
        if reg.hub.run_route_with(&route, &*h.net, None, |_| {}).is_none() {
            return Err(format!("route[{route}] did not run"));
        }
        let (asserts, failures) = h.result();
        for f in &failures {
            println!("{f}");
        }
        if failures.is_empty() {
            sip_core::elog!("ferrosip: test passed ({asserts} assert(s))");
            process::exit(0);
        }
        process::exit(1);
    }
    if check {
        // Kamailio `-c`: everything up to (not including) binding sockets.
        // The TLS files are read, as startup would: missing ones fail a
        // ferrosip.toml check, and are a warning for a Kamailio .cfg (whose
        // tls.cfg usually names paths of the machine it runs on) and for
        // the check `ferrosip import` runs on what it wrote.
        if let Err(e) = sip_transport::load_tls(&cfg) {
            if toml_inputs.is_some() && std::env::var_os("FERROSIP_IMPORT_CHECK").is_none() {
                return Err(e);
            }
            sip_core::elog!("ferrosip: warning: {e} (startup would fail)");
        }
        if explain && let Some(l) = &layered {
            print!("{}", config::explain(l, &plan, &schema_of));
            let extra: Vec<&String> = ast.modules.iter().filter(|m| !plan.iter().any(|p| &p.name == *m)).collect();
            if !extra.is_empty() {
                println!("# Loaded by {cfg_file}: {}", extra.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
        }
        if lowered {
            if !cfg_file.ends_with(".fsr") {
                return Err(format!("--lowered: {cfg_file} is not a .fsr file"));
            }
            print!("{}", fsr::print::to_cfg(&ast));
        }
        sip_core::elog!("ferrosip: {cfg_file}: config OK");
        return Ok(());
    }
    engine.install(); // failure_route / onreply_route callable from tm
    // cfg.reload: re-parse the script and swap in new routes (modules and
    // their parameters must be unchanged — they were applied at startup).
    let (live, file, sig) = (engine.clone(), cfg_file.clone(), signature(&ast));
    // With ferrosip.toml it also re-reads the file(s): parameters marked
    // reloadable are set on the running modules, the rest is reported as
    // needing a restart (and keeps its running value).
    let running = layered.as_ref().map(|l| Arc::new(std::sync::Mutex::new(config::Running::of(l, &plan))));
    let live_reg = reg.clone();
    reg.rpc.add("cfg.reload", "Reload routes, and the reloadable ferrosip.toml parameters", move |_| {
        let toml = match &toml_inputs {
            Some((f, overlays, sets)) => {
                let l = config::load(f, overlays, sets)?;
                let (s, m) = (config::settings(&l), config::modules(&l, &schema_of));
                match (s, m) {
                    (Ok(_), Ok(m)) => Some((l, m)),
                    (s, m) => return Err(errors(f, s.err().unwrap_or_default().into_iter().chain(m.err().unwrap_or_default()).collect())),
                }
            }
            None => None,
        };
        let features = toml.as_ref().map(|(l, _)| config::features(l)).unwrap_or_default();
        let (pp, new) = load_script(&file, &defines, &features)?;
        let now = signature(&new);
        if now != sig {
            let diff: Vec<String> = now
                .iter()
                .filter(|x| !sig.contains(x))
                .map(|x| format!("+ {x}"))
                .chain(sig.iter().filter(|x| !now.contains(x)).map(|x| format!("- {x}")))
                .collect();
            return Err(format!("loadmodule/modparam changed, restart needed: {}", diff.join("; ")));
        }
        let plan = match toml {
            Some((l, m)) => Some((l, implicit_modules(m, &new, file.ends_with(".fsr"))?)),
            None => None,
        };
        // Routes first: if they don't compile, nothing changes.
        let r = live.reload(&new).map_err(|e| pp.locate_error(&e))?;
        let (Some((l, mods)), Some(running)) = (plan, &running) else {
            sip_core::log::log(sip_core::log::L_INFO, &format!("cfg.reload: {file} reloaded"));
            return Ok(r);
        };
        let mut run = lock(running);
        let diff = config::reload_diff(&run, &l, &mods, &schema_of);
        let (mut applied, mut restart) = (Vec::new(), diff.restart);
        for (m, k, args, shown) in diff.apply {
            let Some(module) = live_reg.modules.iter().find(|x| x.name() == m) else { continue };
            match args.iter().try_for_each(|a| module.set_param(&k, a)) {
                Ok(()) => {
                    applied.push(format!("{m}.{k} = {shown}"));
                    run.mods.entry(m).or_default().insert(
                        k,
                        args.iter().map(|a| a.str().map(|s| format!("{s:?}")).unwrap_or_else(|_| a.int().map(|i| i.to_string()).unwrap_or_default())).collect(),
                    );
                }
                Err(e) => restart.push(format!("{m}.{k} (not applied: {e})")),
            }
        }
        sip_core::log::log(
            sip_core::log::L_INFO,
            &format!(
                "cfg.reload: routes reloaded; applied: {}; needs restart: {}",
                if applied.is_empty() { "nothing".into() } else { applied.join(", ") },
                if restart.is_empty() { "nothing".into() } else { restart.join(", ") }
            ),
        );
        Ok(sip_core::serde_json::json!({"routes": r, "applied": applied, "needs_restart": restart}))
    });
    if rpc_socket != "none" {
        reg.rpc.serve_unix(&rpc_socket).map_err(|e| format!("rpc socket {rpc_socket}: {e}"))?;
    }

    // Registered before the transports start, so a signal during startup is
    // handled the same way.
    let mut signals = Signals::new([SIGTERM, SIGINT]).map_err(|e| format!("signal handlers: {e}"))?;
    let (net, _handles) = sip_transport::start(&cfg, engine.clone())?;
    for m in &reg.modules {
        m.clone().spawn(net.clone() as Arc<dyn Outbound>).map_err(|e| format!("{}: {e}", m.name()))?;
    }
    let mut listeners = Vec::new();
    for l in &cfg.listen {
        let workers = match l.proto {
            sip_core::Proto::Udp => format!("{} workers", cfg.udp_workers),
            _ => format!("{} readers", cfg.tcp.readers),
        };
        sip_core::elog!("ferrosip: listening on {}:{} ({workers})", l.proto.via_name().to_lowercase(), l.addr);
        listeners.push(sip_core::serde_json::json!({"proto": l.proto.via_name().to_lowercase(), "addr": l.addr.to_string(), "workers": workers}));
    }
    register_info_rpcs(&reg, &net, &cfg_file, listeners);
    // Transport and module threads run until the process exits; a panic in
    // one of them aborts (sip_core::panic). The main thread waits for a signal.
    let sig = signals.forever().next().unwrap_or(SIGTERM);
    graceful_shutdown(sig, signals, &reg, &net, shutdown_timeout, &rpc_socket);
    Ok(())
}

/// `core.info` (process, script, listeners, modules) and `core.connections`
/// (open TCP/TLS/WS connections): read-only views for ferroctl and the web UI.
fn register_info_rpcs(reg: &Registry, net: &Arc<sip_transport::Net>, cfg_file: &str, listeners: Vec<sip_core::serde_json::Value>) {
    use sip_core::serde_json::json;
    let modules: Vec<String> = reg.modules.iter().map(|m| m.name().to_string()).collect();
    let cfg_path = std::fs::canonicalize(cfg_file).map_or_else(|_| cfg_file.to_string(), |p| p.display().to_string());
    let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    reg.rpc.add("core.info", "Process, script, listeners and modules", move |_| {
        // VmRSS / Threads from /proc (Linux); absent elsewhere.
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str| -> Option<u64> { status.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.split_whitespace().next()?.parse().ok()) };
        Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": process::id(),
            "started": started,
            "rss_kb": field("VmRSS:"),
            "threads": field("Threads:"),
            "config": cfg_path,
            "listeners": listeners,
            "modules": modules,
            "log_level": sip_core::log::level(),
        }))
    });
    let net = net.clone();
    reg.rpc.add("core.connections", "Open TCP/TLS/WS connections", move |_| {
        let tcp = net.tcp();
        let (max, iplimit, lifetime) = tcp.limits();
        let conns: Vec<sip_core::serde_json::Value> = tcp
            .connections()
            .into_iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "proto": c.proto.via_name().to_lowercase(),
                    "peer": c.peer.to_string(),
                    "local": c.local.map(|a| a.to_string()),
                    "direction": if c.outbound { "out" } else { "in" },
                    "established": c.established,
                    "age_s": c.age_ms / 1000,
                    "idle_s": c.idle_ms / 1000,
                    "aliases": c.aliases.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "tls_version": c.tls_version,
                    "sni": c.sni,
                })
            })
            .collect();
        Ok(json!({
            "active": tcp.active_connections(),
            "max_connections": max,
            "accept_iplimit": iplimit,
            "lifetime_s": lifetime.as_secs(),
            "connections": conns,
        }))
    });
}

/// When a graceful shutdown stops waiting; `None`: a timeout too long to
/// represent (`--shutdown-timeout 18446744073709551615`) waits for as long as
/// work is in flight, instead of panicking on the overflow.
fn shutdown_deadline(timeout: Duration) -> Option<Instant> {
    Instant::now().checked_add(timeout)
}

/// SIGTERM/SIGINT: stop taking new work (new connections refused, initial
/// requests answered 503), let transactions in flight finish for up to
/// `timeout`, persist module state, close connections (TLS close_notify),
/// remove the control socket and exit 0. A second signal exits at once.
fn graceful_shutdown(sig: i32, mut signals: Signals, reg: &Registry, net: &sip_transport::Net, timeout: Duration, rpc_socket: &str) {
    let busy = || reg.modules.iter().map(|m| m.busy()).sum::<usize>();
    sip_core::elog!("ferrosip: signal {sig}: shutting down, {} transaction(s) in flight (waiting up to {}s)", busy(), timeout.as_secs());
    sip_core::shutdown::begin();
    std::thread::spawn(move || {
        if let Some(s) = signals.forever().next() {
            sip_core::elog!("ferrosip: signal {s} again: exiting now");
            process::exit(1);
        }
    });
    let deadline = shutdown_deadline(timeout);
    let mut left = busy();
    while left > 0 && deadline.is_none_or(|d| Instant::now() < d) {
        std::thread::sleep(Duration::from_millis(50));
        left = busy();
    }
    for m in &reg.modules {
        if sip_core::panic::catch(|| m.shutdown()).is_err() {
            sip_core::elog!("ferrosip: module {} failed to shut down cleanly", m.name());
        }
    }
    net.tcp().close_all();
    if rpc_socket != "none" {
        let _ = fs::remove_file(rpc_socket);
    }
    match left {
        0 => sip_core::elog!("ferrosip: stopped"),
        n => sip_core::elog!("ferrosip: stopped with {n} transaction(s) unfinished after {}s", timeout.as_secs()),
    }
    process::exit(0);
}

fn main() {
    // Panics outside a recoverable section (per message, RPC call, route
    // callback) abort instead of leaving the server half-running.
    sip_core::panic::install_hook();
    if let Err(e) = run() {
        sip_core::elog!("ferrosip: {e}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn huge_shutdown_timeout_does_not_overflow() {
        // Instant + Duration would overflow on SIGTERM with this timeout.
        assert_eq!(super::shutdown_deadline(std::time::Duration::from_secs(u64::MAX)), None);
        assert!(super::shutdown_deadline(std::time::Duration::from_secs(5)).is_some());
    }

    use super::*;
    use sip_core::schema::{self, Ty, Value};

    /// A value of the right type for `ty`, for probing `set_param`.
    fn sample(ty: &Ty) -> Value {
        match ty {
            Ty::Str => Value::Str("x".into()),
            Ty::Int { min, max } => Value::Int((*min).max(0).min(*max)),
            Ty::Bool => Value::Bool(true),
            Ty::Duration(_) => Value::Str("2s".into()),
            Ty::Enum(v) => Value::Str(v[0].0.into()),
            Ty::List(t) => Value::List(vec![sample(t)]),
        }
    }

    #[test]
    fn every_module_has_a_schema() {
        let missing: Vec<&str> = all_modules().into_iter().filter(|m| schema_of(m).flatten().is_none()).collect();
        assert!(missing.is_empty(), "{} module(s) without a schema: {}", missing.len(), missing.join(" "));
    }

    #[test]
    fn schemas_match_the_modules() {
        for m in all_modules() {
            let Some(params) = schema_of(m).flatten() else { continue };
            let mut seen = std::collections::HashSet::new();
            for p in &params {
                assert!(seen.insert(p.name), "{m}.{}: declared twice", p.name);
                // The module knows the parameter (other errors are about the sample value).
                for a in schema::convert(p, &sample(&p.ty)).unwrap() {
                    if let Err(e) = module_by_name(m).unwrap().set_param(p.name, &a) {
                        assert!(!(e.contains("unknown") && e.contains("parameter")), "{m}.{}: the module doesn't know it: {e}", p.name);
                    }
                }
                // A default written as a value is a valid value.
                let typed = matches!(p.ty, Ty::Duration(_) | Ty::Bool | Ty::Enum(_)) || (matches!(p.ty, Ty::Int { .. }) && p.default.parse::<i64>().is_ok());
                if typed && !p.default.is_empty() {
                    let v = match p.default.parse::<i64>() {
                        Ok(i) => Value::Int(i),
                        Err(_) => Value::Str(p.default.into()),
                    };
                    let args = schema::convert(p, &v).unwrap_or_else(|e| panic!("{m}.{} default {:?}: {e}", p.name, p.default));
                    for a in args {
                        module_by_name(m).unwrap().set_param(p.name, &a).unwrap_or_else(|e| panic!("{m}.{} = default: {e}", p.name));
                    }
                }
            }
        }
    }

    /// A sample `.fsr` value for an argument.
    fn fsr_sample(p: &sip_core::sig::Param) -> String {
        use sip_core::sig::ArgTy;
        if !p.eg.is_empty() {
            return p.eg.to_string();
        }
        match p.ty {
            ArgTy::Str | ArgTy::Any => "\"x\"".into(),
            ArgTy::Int => "1".into(),
            ArgTy::Bool => "true".into(),
            ArgTy::Duration(_) => "2s".into(),
            ArgTy::Uri => "\"sip:alice@example.com\"".into(),
            ArgTy::Flag => "F".into(),
            ArgTy::Var => "v".into(),
            ArgTy::Enum(v) => format!("\"{}\"", v[0]),
        }
    }

    /// Every signature names a function its module exports, and a sample
    /// call (all arguments, and only the required ones) lowers to
    /// something the function's own fixup accepts.
    #[test]
    fn signatures_match_the_functions() {
        sip_db::set_check_only(true);
        let mut problems = Vec::new();
        for m in all_modules() {
            let Some(sigs) = module_by_name(m).and_then(|x| x.functions()) else { continue };
            let mut reg = Registry::default();
            reg.load(Arc::new(CoreModule)).unwrap();
            let mut chain = Vec::new();
            dep_chain(m, &mut chain);
            for d in chain {
                reg.load(index_module(d).unwrap()).unwrap();
            }
            reg.load(index_module(m).unwrap()).unwrap();
            let reg = Arc::new(reg);
            let mut seen = std::collections::HashSet::new();
            for s in &sigs {
                if !seen.insert((s.name, s.fsr)) {
                    problems.push(format!("{m}: {} ({}) declared twice", s.name, s.fsr));
                }
                if !reg.exports().any(|(n, _)| n == s.name) {
                    problems.push(format!("{m}: {}: no such function in the module", s.name));
                    continue;
                }
                if s.fsr.is_empty() {
                    continue;
                }
                let ns = s.ns.unwrap_or(fsr_namespace(m));
                let mut env = fsr::Env::default();
                env.add(fsr_namespace(m), [sip_core::sig::FnSig { allowed: sip_core::sig::ctx::ANY, ..*s }]);
                let required = s.params.iter().take_while(|p| !p.optional).count();
                for n in [s.params.len(), required] {
                    let args: Vec<String> = s.params[..n].iter().map(fsr_sample).collect();
                    let call = format!("{ns}.{}({})", s.fsr, args.join(", "));
                    let call = if matches!(s.ret, sip_core::sig::Ret::Await(_)) { format!("let r = await {call}") } else { call };
                    let src = format!("import {ns}\nflag F\nroute main(msg: Request) {{\n    {call}\n}}\n");
                    let ast = match fsr::compile_source("sig.fsr", &src, &env) {
                        Ok(o) => o.ast,
                        Err(e) => {
                            problems.push(format!("{m}: {ns}.{}: {e}", s.fsr));
                            continue;
                        }
                    };
                    if let Err(e) = Engine::compile(&ast, reg.clone()) {
                        problems.push(format!(
                            "{m}: {ns}.{}({}) → {}: {e}",
                            s.fsr,
                            args.join(", "),
                            fsr::print::to_cfg(&ast).lines().nth(3).unwrap_or("").trim()
                        ));
                    }
                }
            }
        }
        assert!(problems.is_empty(), "{} problem(s):\n{}", problems.len(), problems.join("\n"));
    }

    /// Every exported function (functions.txt) has a signature in its
    /// module, offered to `.fsr` or `hidden` with a reason.
    #[test]
    fn every_function_has_a_signature() {
        let mut missing: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for l in FUNCTIONS.lines() {
            let mut w = l.split_whitespace();
            let (Some("fn"), Some(f), Some(m)) = (w.next(), w.next(), w.next()) else { continue };
            let Some(module) = module_by_name(m) else { continue };
            if !module.functions().unwrap_or_default().iter().any(|s| s.name == f) {
                missing.entry(m).or_default().push(f);
            }
        }
        let n: usize = missing.values().map(Vec::len).sum();
        let list: Vec<String> = missing.iter().map(|(m, fs)| format!("{m}: {}", fs.join(" "))).collect();
        assert!(missing.is_empty(), "{n} function(s) without a signature:\n{}", list.join("\n"));
    }

    #[test]
    fn aliases_and_deps_name_real_modules() {
        for a in config::ALIASES {
            for m in a.always.iter().chain(a.optional) {
                assert!(module_by_name(m).is_some() || feature_for(m).is_some(), "alias {} → unknown module {m}", a.name);
            }
        }
        for (m, ds) in config::DEPS {
            for x in std::iter::once(m).chain(ds.iter()) {
                assert!(module_by_name(x).is_some() || feature_for(x).is_some(), "DEPS names unknown module {x}");
            }
        }
    }
    #[test]
    fn dep_chain_is_deepest_first() {
        let chain = |m: &str| {
            let mut out = Vec::new();
            dep_chain(m, &mut out);
            out
        };
        assert_eq!(chain("pua_dialoginfo"), ["tm", "pua", "dialog"]);
        assert_eq!(chain("ims_registrar_scscf"), ["ims_usrloc_scscf", "cdp", "tm"]);
        assert_eq!(chain("rls"), ["tm", "presence"]);
        assert!(chain("sl").is_empty());
    }

    /// The modules a script's functions and variables load (with
    /// ferrosip.toml), dependencies first.
    fn implicit(src: &str, fsr: bool) -> Vec<(String, String)> {
        let ast = sip_script::parse(src).unwrap();
        implicit_modules(Vec::new(), &ast, fsr).unwrap().into_iter().map(|m| (m.name, m.why)).collect()
    }

    #[test]
    fn functions_and_variables_load_their_modules() {
        let got = implicit("request_route { sl_send_reply(\"404\", \"x\"); $sht(t=>k) = 1; t_relay(); }", false);
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"sl") && names.contains(&"htable") && names.contains(&"tm"), "{got:?}");
        let why = |m: &str| got.iter().find(|(n, _)| n == m).map(|(_, w)| w.as_str()).unwrap_or_default();
        assert_eq!(why("sl"), "loaded for sl_send_reply()");
        assert_eq!(why("htable"), "loaded for $sht");
        // registrar's lookup() needs usrloc, loaded before it.
        let got = implicit("request_route { if (lookup(\"location\")) { exit; } }", false);
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        let pos = |m: &str| names.iter().position(|n| *n == m);
        assert!(pos("usrloc").is_some() && pos("usrloc") < pos("registrar"), "{names:?}");
        assert!(implicit("request_route { exit; }", false).is_empty());
    }

    #[test]
    fn a_loaded_module_that_provides_a_function_is_the_one_used() {
        // ims_registrar_scscf has its own save(): registrar is not added.
        let got = implicit("loadmodule \"ims_registrar_scscf\"\nrequest_route { save(\"location\"); }", false);
        assert!(!got.iter().any(|(n, _)| n == "registrar"), "{got:?}");
        // A .cfg's loadmodules are its own; an .fsr's are loaded like the others.
        assert!(implicit("loadmodule \"sl\"\nrequest_route { exit; }", false).is_empty());
        assert_eq!(implicit("loadmodule \"sl\"\nrequest_route { exit; }", true), [("sl".to_string(), "used by the routing".to_string())]);
    }
}
