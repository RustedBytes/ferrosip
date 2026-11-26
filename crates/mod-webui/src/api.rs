//! The read-only JSON API under `/api/v1/`.
//!
//! Every route maps to one read-only RPC with parameters fixed here or taken
//! from named query arguments: the client never chooses a method. Lists are
//! filtered (`q`), sorted (`sort=field` / `sort=-field`) and paged
//! (`offset`, `limit` ≤ 500) here, after the call, because no RPC pages.
//! Results are cached for a second, so several open browsers cost one dump.

use sip_core::rpc::RpcTable;
use sip_core::serde_json::{Map, Value, json};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_LIMIT: usize = 500;
const CACHE_TTL: Duration = Duration::from_secs(1);

/// Where a route's RPC parameters come from.
pub enum Params {
    None,
    /// Constant parameters (e.g. `pike.top ALL`).
    Fixed(&'static [&'static str]),
    /// Required query arguments, in order (e.g. `?table=` for `htable.dump`).
    Query(&'static [&'static str]),
}

pub struct Route {
    pub path: &'static str,
    /// UI section it belongs to (shown only when the RPC exists).
    pub section: &'static str,
    /// The read-only RPC it calls.
    pub rpc: &'static str,
    pub params: Params,
    /// Turns the RPC result into table rows (or an object).
    pub shape: fn(Value) -> Value,
}

fn same(v: Value) -> Value {
    v
}

/// `ul.dump` (`{aor: [contact]}`) → one row per AoR.
fn registrations(v: Value) -> Value {
    let Value::Object(m) = v else { return json!([]) };
    let rows: Vec<Value> = m
        .into_iter()
        .filter_map(|(aor, cs)| {
            let cs = cs.as_array()?.clone();
            let first = cs.first().cloned().unwrap_or(Value::Null);
            let expires = cs.iter().filter_map(|c| c.get("expires")?.as_i64()).min();
            Some(json!({
                "aor": aor,
                "contacts": cs.len(),
                "contact": first.get("contact"),
                "received": first.get("received"),
                "user_agent": first.get("user_agent"),
                "expires": expires,
            }))
        })
        .collect();
    Value::Array(rows)
}

/// `dlg.list`: state as a word, duration in seconds.
fn dialogs(v: Value) -> Value {
    let now = unix_secs();
    let rows = v.as_array().cloned().unwrap_or_default().into_iter().map(|mut d| {
        let state = match d.get("state").and_then(Value::as_u64) {
            Some(1) => "unconfirmed",
            Some(2) => "early",
            Some(3) => "confirmed",
            Some(4) => "established",
            Some(5) => "ended",
            _ => "unknown",
        };
        let start = d.get("start_ts").and_then(Value::as_u64).unwrap_or(0);
        if let Some(o) = d.as_object_mut() {
            o.insert("state_name".into(), json!(state));
            o.insert("duration".into(), json!(if start > 0 { now.saturating_sub(start) } else { 0 }));
        }
        d
    });
    Value::Array(rows.collect())
}

/// `dispatcher.list` → one row per destination, flags as words.
fn dispatcher(v: Value) -> Value {
    let mut rows = Vec::new();
    for set in v.get("RECORDS").and_then(Value::as_array).into_iter().flatten() {
        for t in set.get("TARGETS").and_then(Value::as_array).into_iter().flatten() {
            let f = t.get("FLAGS").and_then(Value::as_str).unwrap_or("");
            let state = match f.chars().next() {
                Some('A') => "active",
                Some('I') => "inactive",
                Some('T') => "trying",
                Some('D') => "disabled",
                _ => "unknown",
            };
            rows.push(json!({
                "set": set.get("ID"),
                "uri": t.get("URI"),
                "state": state,
                "probing": f.ends_with('P'),
                "priority": t.get("PRIORITY"),
                "attrs": t.get("ATTRS"),
                "load": t.get("LOAD"),
                "latency_avg": t.pointer("/LATENCY/AVG"),
                "latency_max": t.pointer("/LATENCY/MAX"),
                "timeouts": t.pointer("/LATENCY/TIMEOUT"),
            }));
        }
    }
    Value::Array(rows)
}

/// `core.connections` → the list, with the totals beside it.
fn connections(v: Value) -> Value {
    v
}

/// The routes. Each RPC here only reads state; `ro_allow_list` checks it.
pub const ROUTES: &[Route] = &[
    // Overview
    Route { path: "info", section: "overview", rpc: "core.info", params: Params::None, shape: same },
    Route { path: "uptime", section: "overview", rpc: "core.uptime", params: Params::None, shape: same },
    // Registrations and calls
    Route { path: "registrations", section: "registrations", rpc: "ul.dump", params: Params::None, shape: registrations },
    Route { path: "registrations/contacts", section: "registrations", rpc: "ul.lookup", params: Params::Query(&["aor"]), shape: same },
    Route { path: "uac-registrations", section: "registrations", rpc: "uac.reg_dump", params: Params::None, shape: same },
    Route { path: "dialogs", section: "calls", rpc: "dlg.list", params: Params::None, shape: dialogs },
    Route { path: "dialogs/stats", section: "calls", rpc: "dlg.stats_active", params: Params::None, shape: same },
    Route { path: "dlgs", section: "calls", rpc: "dlgs.list", params: Params::None, shape: same },
    Route { path: "dlgs/stats", section: "calls", rpc: "dlgs.stats", params: Params::None, shape: same },
    Route { path: "cnxcc", section: "calls", rpc: "cnxcc.active_clients", params: Params::None, shape: same },
    Route { path: "cnxcc/client", section: "calls", rpc: "cnxcc.check_client", params: Params::Query(&["client"]), shape: same },
    Route { path: "ai-calls", section: "calls", rpc: "ai.list", params: Params::None, shape: same },
    Route { path: "ai-calls/recent", section: "calls", rpc: "ai.recent", params: Params::None, shape: same },
    // Transactions and DNS
    Route { path: "tm", section: "transactions", rpc: "tm.stats", params: Params::None, shape: same },
    Route { path: "blocklist", section: "transactions", rpc: "dst_blocklist.list", params: Params::None, shape: same },
    Route { path: "tsilo", section: "transactions", rpc: "ts.dump", params: Params::None, shape: same },
    // Connections
    Route { path: "connections", section: "connections", rpc: "core.connections", params: Params::None, shape: connections },
    // Routing
    Route { path: "dispatcher", section: "routing", rpc: "dispatcher.list", params: Params::None, shape: dispatcher },
    Route { path: "lcr/gateways", section: "routing", rpc: "lcr.dump_gws", params: Params::None, shape: same },
    Route { path: "lcr/rules", section: "routing", rpc: "lcr.dump_rules", params: Params::None, shape: same },
    Route { path: "dialplan", section: "routing", rpc: "dialplan.dump", params: Params::Query(&["dpid"]), shape: same },
    Route { path: "mtree", section: "routing", rpc: "mtree.list", params: Params::None, shape: same },
    Route { path: "prefix-route", section: "routing", rpc: "prefix_route.dump", params: Params::None, shape: same },
    // Health
    Route { path: "keepalive", section: "health", rpc: "keepalive.list", params: Params::None, shape: same },
    Route { path: "rtpengine", section: "health", rpc: "rtpengine.show", params: Params::Fixed(&["all"]), shape: same },
    Route { path: "cdp-peers", section: "health", rpc: "cdp.list_peers", params: Params::None, shape: same },
    Route { path: "ims/pcscf", section: "health", rpc: "ulpcscf.showcontacts", params: Params::None, shape: same },
    Route { path: "ims/scscf", section: "health", rpc: "ulscscf.status", params: Params::None, shape: same },
    Route { path: "ims/ro", section: "health", rpc: "ro.sessions", params: Params::None, shape: same },
    Route { path: "ims/ipsec", section: "health", rpc: "ipsec.list", params: Params::None, shape: same },
    // Security
    Route { path: "pike", section: "security", rpc: "pike.top", params: Params::Fixed(&["ALL"]), shape: same },
    Route { path: "ratelimit", section: "security", rpc: "rl.get_pipes", params: Params::None, shape: same },
    Route { path: "pipelimit", section: "security", rpc: "pl.list", params: Params::None, shape: same },
    Route { path: "secfilter", section: "security", rpc: "secfilter.print", params: Params::None, shape: same },
    Route { path: "secfilter/stats", section: "security", rpc: "secfilter.stats", params: Params::None, shape: same },
    Route { path: "userblocklist", section: "security", rpc: "userblocklist.dump_blocklist", params: Params::None, shape: same },
    Route { path: "permissions/address", section: "security", rpc: "permissions.addressDump", params: Params::None, shape: same },
    Route { path: "permissions/trusted", section: "security", rpc: "permissions.trustedDump", params: Params::None, shape: same },
    Route { path: "domains", section: "security", rpc: "domain.dump", params: Params::None, shape: same },
    // Data
    Route { path: "htable", section: "data", rpc: "htable.listTables", params: Params::None, shape: same },
    Route { path: "htable/items", section: "data", rpc: "htable.dump", params: Params::Query(&["table"]), shape: same },
    Route { path: "cfg", section: "data", rpc: "cfg.list", params: Params::None, shape: same },
    Route { path: "siptrace", section: "data", rpc: "siptrace.status", params: Params::Fixed(&["check"]), shape: same },
    Route { path: "sipdump", section: "data", rpc: "sipdump.enable", params: Params::None, shape: same },
    // Presence
    Route { path: "presence/presentities", section: "presence", rpc: "presence.presentity_list", params: Params::None, shape: same },
    Route { path: "presence/watchers", section: "presence", rpc: "presence.watcher_list", params: Params::None, shape: same },
    Route { path: "sca/subscriptions", section: "presence", rpc: "sca.all_subscriptions", params: Params::None, shape: same },
    Route { path: "sca/appearances", section: "presence", rpc: "sca.all_appearances", params: Params::None, shape: same },
    // Logs
    Route { path: "logs", section: "logs", rpc: "core.log_tail", params: Params::Query(&["after"]), shape: same },
];

/// Query arguments of a request.
pub type Query = HashMap<String, String>;

pub struct Api {
    rpc: std::sync::Arc<RpcTable>,
    cache: Mutex<HashMap<String, (Instant, Value)>>,
    pub refresh_ms: u64,
}

/// An API answer: HTTP status and JSON body.
pub type Answer = (u16, Value);

impl Api {
    pub fn new(rpc: std::sync::Arc<RpcTable>, refresh_ms: u64) -> Self {
        Api { rpc, cache: Mutex::new(HashMap::new()), refresh_ms }
    }

    fn available(&self) -> std::collections::HashSet<String> {
        self.rpc.names().into_iter().map(|(n, _)| n).collect()
    }

    /// `path` without the `/api/v1/` prefix.
    pub fn handle(&self, path: &str, q: &Query) -> Answer {
        match path {
            "meta" => (200, self.meta()),
            "stats" => (200, stats()),
            _ => match ROUTES.iter().find(|r| r.path == path) {
                Some(r) => self.route(r, q),
                None => (404, json!({"error": "no such API path"})),
            },
        }
    }

    fn meta(&self) -> Value {
        let have = self.available();
        let mut sections: Map<String, Value> = Map::new();
        for r in ROUTES.iter().filter(|r| have.contains(r.rpc)) {
            let e = sections.entry(r.section).or_insert_with(|| json!([]));
            if let Value::Array(a) = e {
                a.push(json!(r.path));
            }
        }
        sections.insert("statistics".into(), json!(["stats"]));
        json!({"version": env!("CARGO_PKG_VERSION"), "refresh_ms": self.refresh_ms, "sections": sections})
    }

    fn route(&self, r: &Route, q: &Query) -> Answer {
        let params: Vec<Value> = match r.params {
            Params::None => vec![],
            Params::Fixed(p) => p.iter().map(|s| json!(s)).collect(),
            Params::Query(keys) => {
                let mut v = Vec::new();
                for k in keys {
                    match q.get(*k) {
                        Some(x) if !x.is_empty() => v.push(json!(x)),
                        // The log tail starts from the beginning.
                        _ if *k == "after" => v.push(json!("0")),
                        _ => return (400, json!({"error": format!("missing query argument {k}")})),
                    }
                }
                v
            }
        };
        let key = format!("{}{}", r.rpc, Value::Array(params.clone()));
        // The log tail and lookups are cheap and must be fresh.
        let cacheable = matches!(r.params, Params::None | Params::Fixed(_));
        let cached = cacheable.then(|| lock(&self.cache).get(&key).filter(|(t, _)| t.elapsed() < CACHE_TTL).map(|(_, v)| v.clone())).flatten();
        let result = match cached {
            Some(v) => v,
            None => {
                let resp = self.rpc.call(&json!({"jsonrpc": "2.0", "id": 1, "method": r.rpc, "params": params}));
                if let Some(e) = resp.get("error") {
                    let code = if e.get("code").and_then(Value::as_i64) == Some(-32601) { 404 } else { 502 };
                    return (code, json!({"error": e.get("message")}));
                }
                let v = (r.shape)(resp.get("result").cloned().unwrap_or_default());
                if cacheable {
                    let mut c = lock(&self.cache);
                    if c.len() > 256 {
                        c.retain(|_, (t, _)| t.elapsed() < CACHE_TTL);
                    }
                    c.insert(key, (Instant::now(), v.clone()));
                }
                v
            }
        };
        (200, page(result, q))
    }
}

/// Every statistic with its kind, for the statistics page and the tiles.
fn stats() -> Value {
    let rows: Vec<Value> = sip_core::stats::get_kinds("all")
        .into_iter()
        .map(|(g, n, v, counter)| json!({"group": g, "name": n, "value": v, "kind": if counter { "counter" } else { "gauge" }}))
        .collect();
    json!({"ts_ms": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)), "rows": rows})
}

/// Filter, sort and page an array result; other results pass through.
pub fn page(v: Value, q: &Query) -> Value {
    let Value::Array(mut rows) = v else { return v };
    if let Some(needle) = q.get("q").map(|s| s.to_lowercase()).filter(|s| !s.is_empty()) {
        rows.retain(|r| r.to_string().to_lowercase().contains(&needle));
    }
    if let Some(field) = q.get("sort").filter(|s| !s.is_empty()) {
        let (desc, field) = match field.strip_prefix('-') {
            Some(f) => (true, f),
            None => (false, field.as_str()),
        };
        // Rows without the field stay last in both directions.
        rows.sort_by(|a, b| match (a[field].is_null(), b[field].is_null()) {
            (false, false) => {
                let o = cmp_json(&a[field], &b[field]);
                if desc { o.reverse() } else { o }
            }
            (x, y) => x.cmp(&y),
        });
    }
    let total = rows.len();
    let offset = q.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0usize).min(total);
    let limit = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100usize).clamp(1, MAX_LIMIT);
    let rows: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
    json!({"total": total, "offset": offset, "limit": limit, "rows": rows})
}

/// Numbers by value, everything else by its text; missing values last.
fn cmp_json(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match (a, b) {
        (Value::Null, Value::Null) => Equal,
        (Value::Null, _) => Greater,
        (_, Value::Null) => Less,
        (Value::Number(x), Value::Number(y)) => x.as_f64().partial_cmp(&y.as_f64()).unwrap_or(Equal),
        (Value::String(x), Value::String(y)) => x.to_lowercase().cmp(&y.to_lowercase()),
        _ => a.to_string().cmp(&b.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words that mark an RPC which changes state.
    const MUTATING: &[&str] = &[
        "reload", "set", "add", "del", "rm", "flush", "store", "end", "kill", "reset", "ping", "enable", "defunct", "refresh", "cleanup", "publish", "release",
    ];

    #[test]
    fn ro_allow_list() {
        // "addressDump" → ["address", "dump"]; "end_dlg" → ["end", "dlg"].
        let words = |method: &str| -> Vec<String> {
            let mut out = vec![String::new()];
            for c in method.chars() {
                if c == '_' || c == '.' || c.is_ascii_uppercase() {
                    out.push(String::new());
                }
                if c != '_' && c != '.' {
                    out.last_mut().unwrap().push(c.to_ascii_lowercase());
                }
            }
            out.into_iter().filter(|w| !w.is_empty()).collect()
        };
        assert_eq!(words("permissions.addressDump"), ["permissions", "address", "dump"]);
        for r in ROUTES {
            // sipdump.enable without a parameter only reads (`{enable}`).
            if r.rpc == "sipdump.enable" {
                assert!(matches!(r.params, Params::None), "sipdump.enable must take no parameter here");
                continue;
            }
            let w = words(r.rpc);
            assert!(!w.iter().any(|w| MUTATING.contains(&w.as_str())), "{} looks mutating", r.rpc);
        }
        // The two toggles are only called in their read form.
        let st = ROUTES.iter().find(|r| r.rpc == "siptrace.status").unwrap();
        assert!(matches!(st.params, Params::Fixed(["check"])));
        let mut paths: Vec<_> = ROUTES.iter().map(|r| r.path).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), ROUTES.len(), "route paths are unique");
    }

    #[test]
    fn paging() {
        let rows = json!([{"n": 3, "s": "c"}, {"n": 1, "s": "a"}, {"n": 2, "s": "b"}, {"s": "z"}]);
        let q = |s: &str| -> Query { s.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').map(|(k, v)| (k.into(), v.into())).unwrap()).collect() };
        let p = page(rows.clone(), &q("sort=n"));
        assert_eq!(p["rows"].as_array().unwrap().iter().map(|r| r["s"].as_str().unwrap()).collect::<String>(), "abcz");
        let p = page(rows.clone(), &q("sort=-n&limit=2"));
        assert_eq!(p["total"], 4);
        assert_eq!(p["rows"][0]["n"], 3);
        assert_eq!(p["rows"].as_array().unwrap().len(), 2);
        let p = page(rows.clone(), &q("q=B"));
        assert_eq!(p["total"], 1);
        let p = page(rows, &q("offset=3&limit=100000"));
        assert_eq!((p["rows"].as_array().unwrap().len(), p["limit"].as_u64()), (1, Some(MAX_LIMIT as u64)));
        assert_eq!(page(json!({"a": 1}), &Query::new()), json!({"a": 1}), "objects pass through");
    }

    #[test]
    fn shapes() {
        let r = registrations(json!({"alice": [{"contact": "sip:a@1", "expires": 30, "received": "1.2.3.4:5", "user_agent": "X"}, {"expires": 10}]}));
        assert_eq!(r[0]["contacts"], 2);
        assert_eq!(r[0]["expires"], 10);
        let d = dispatcher(json!({"RECORDS": [{"ID": 1, "TARGETS": [{"URI": "sip:gw", "FLAGS": "IP", "PRIORITY": 0, "LOAD": 0}]}]}));
        assert_eq!((d[0]["state"].as_str(), d[0]["probing"].as_bool()), (Some("inactive"), Some(true)));
        let g = dialogs(json!([{"state": 4, "start_ts": 0}]));
        assert_eq!(g[0]["state_name"], "established");
    }

    fn q(pairs: &[(&str, &str)]) -> Query {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    fn api() -> Api {
        let rpc = std::sync::Arc::new(RpcTable::default());
        rpc.add("core.uptime", "", |_| Ok(json!({"uptime": 1})));
        rpc.add("htable.dump", "", |p| Ok(json!([{"params": p}])));
        rpc.add("core.log_tail", "", |p| Ok(json!({"after": p})));
        rpc.add("pike.top", "", |p| Ok(json!({"params": p})));
        rpc.add("ul.dump", "", |_| Err("boom".into()));
        Api::new(rpc, 1500)
    }

    #[test]
    fn meta_lists_only_sections_whose_rpc_exists() {
        let (code, m) = api().handle("meta", &Query::new());
        assert_eq!(code, 200);
        assert_eq!(m["refresh_ms"], 1500);
        assert_eq!(m["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(m["sections"]["overview"], json!(["uptime"]));
        assert_eq!(m["sections"]["data"], json!(["htable/items"]));
        assert_eq!(m["sections"]["statistics"], json!(["stats"]));
        assert!(m["sections"].get("presence").is_none());
    }

    #[test]
    fn routes_pass_parameters_and_map_errors() {
        let a = api();
        assert_eq!(a.handle("uptime", &Query::new()), (200, json!({"uptime": 1})));
        assert_eq!(a.handle("nope", &Query::new()).0, 404);
        assert_eq!(a.handle("", &Query::new()).0, 404);
        assert_eq!(a.handle("uptime/", &Query::new()).0, 404);
        let (code, e) = a.handle("htable/items", &Query::new());
        assert_eq!((code, e), (400, json!({"error": "missing query argument table"})));
        assert_eq!(a.handle("htable/items", &q(&[("table", "")])).0, 400, "an empty argument is missing");
        let (code, v) = a.handle("htable/items", &q(&[("table", "t1")]));
        assert_eq!(code, 200);
        assert_eq!(v["rows"][0]["params"], json!(["t1"]));
        assert_eq!(v["total"], 1);
        assert_eq!(a.handle("logs", &Query::new()).1, json!({"after": ["0"]}), "the log tail defaults to the start");
        assert_eq!(a.handle("logs", &q(&[("after", "42")])).1, json!({"after": ["42"]}));
        assert_eq!(a.handle("pike", &q(&[("x", "y")])).1, json!({"params": ["ALL"]}), "fixed parameters ignore the query");
        assert_eq!(a.handle("registrations", &Query::new()), (502, json!({"error": "boom"})));
        assert_eq!(a.handle("dialogs", &Query::new()).0, 404, "an RPC that isn't loaded");
        let (code, s) = a.handle("stats", &Query::new());
        assert_eq!(code, 200);
        assert!(s["ts_ms"].as_u64().is_some_and(|t| t > 0) && s["rows"].is_array());
    }

    #[test]
    fn page_wraps_rows_with_total_offset_and_limit() {
        let rows = json!([1, 2, 3, 4, 5]);
        // (query, total, offset, limit, rows)
        type Case = (&'static [(&'static str, &'static str)], usize, usize, usize, Value);
        let cases: &[Case] = &[
            (&[], 5, 0, 100, json!([1, 2, 3, 4, 5])),
            (&[("limit", "2")], 5, 0, 2, json!([1, 2])),
            (&[("offset", "3")], 5, 3, 100, json!([4, 5])),
            (&[("offset", "9")], 5, 5, 100, json!([])),
            (&[("offset", "-1")], 5, 0, 100, json!([1, 2, 3, 4, 5])),
            (&[("limit", "0")], 5, 0, 1, json!([1])),
            (&[("limit", "x")], 5, 0, 100, json!([1, 2, 3, 4, 5])),
            (&[("limit", "501")], 5, 0, 500, json!([1, 2, 3, 4, 5])),
            (&[("q", "4")], 1, 0, 100, json!([4])),
            (&[("q", "")], 5, 0, 100, json!([1, 2, 3, 4, 5])),
        ];
        for (query, total, offset, limit, want) in cases {
            let p = page(rows.clone(), &q(query));
            assert_eq!(p, json!({"total": total, "offset": offset, "limit": limit, "rows": want}), "{query:?}");
        }
        assert_eq!(page(json!("s"), &q(&[("limit", "1")])), json!("s"));
        assert_eq!(page(Value::Null, &Query::new()), Value::Null);
    }

    #[test]
    fn sort_orders_numbers_by_value_strings_case_insensitively_and_missing_last() {
        let rows = json!([{"k": 10}, {"k": 9}, {}, {"k": 9.5}, {"k": null}, {"k": -1}]);
        let ks = |p: &Value| p["rows"].as_array().unwrap().iter().map(|r| r.get("k").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>();
        assert_eq!(ks(&page(rows.clone(), &q(&[("sort", "k")]))), [json!(-1), json!(9), json!(9.5), json!(10), Value::Null, Value::Null]);
        assert_eq!(ks(&page(rows, &q(&[("sort", "-k")]))), [json!(10), json!(9.5), json!(9), json!(-1), Value::Null, Value::Null]);
        let names = json!([{"n": "bob"}, {"n": "Alice"}, {"n": "carol"}]);
        let ns = |p: &Value| p["rows"].as_array().unwrap().iter().map(|r| r["n"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(ns(&page(names.clone(), &q(&[("sort", "n")]))), ["Alice", "bob", "carol"]);
        assert_eq!(ns(&page(names.clone(), &q(&[("sort", "-n")]))), ["carol", "bob", "Alice"]);
        assert_eq!(ns(&page(names, &q(&[("sort", "missing")]))), ["bob", "Alice", "carol"], "a stable sort keeps the order");
        let mixed = page(json!(["b", 3, "a"]), &q(&[("sort", "x")]));
        assert_eq!(mixed["total"], 3, "rows that aren't objects don't break sorting");
    }

    #[test]
    fn shapes_cover_every_state_and_missing_field() {
        let states: Vec<Value> = (0..=6).map(|s| json!({"state": s})).chain([json!({}), json!({"state": "x"})]).collect();
        let d = dialogs(Value::Array(states));
        let names: Vec<&str> = d.as_array().unwrap().iter().map(|r| r["state_name"].as_str().unwrap()).collect();
        assert_eq!(names, ["unknown", "unconfirmed", "early", "confirmed", "established", "ended", "unknown", "unknown", "unknown"]);
        assert!(d.as_array().unwrap().iter().all(|r| r["duration"] == 0), "no start_ts: duration 0");
        let running = dialogs(json!([{"start_ts": 1}]));
        assert!(running[0]["duration"].as_u64().is_some_and(|s| s > 1_000_000), "{running}");
        assert_eq!(dialogs(json!({"not": "a list"})), json!([]));

        assert_eq!(registrations(json!([])), json!([]));
        let r = registrations(json!({"a": [], "b": "not a list"}));
        assert_eq!(r, json!([{"aor": "a", "contacts": 0, "contact": null, "received": null, "user_agent": null, "expires": null}]));

        let flags = ["AP", "A", "IP", "TP", "DX", "", "XP"];
        let targets: Vec<Value> = flags.iter().map(|f| json!({"URI": "sip:x", "FLAGS": f, "LATENCY": {"AVG": 1.5, "MAX": 3, "TIMEOUT": 0}})).collect();
        let d = dispatcher(json!({"RECORDS": [{"ID": 7, "TARGETS": targets}, {"ID": 8}]}));
        let got: Vec<(&str, bool)> = d.as_array().unwrap().iter().map(|r| (r["state"].as_str().unwrap(), r["probing"].as_bool().unwrap())).collect();
        assert_eq!(
            got,
            [("active", true), ("active", false), ("inactive", true), ("trying", true), ("disabled", false), ("unknown", false), ("unknown", true)]
        );
        assert_eq!((d[0]["set"].clone(), d[0]["latency_avg"].clone(), d[0]["latency_max"].clone()), (json!(7), json!(1.5), json!(3)));
        assert_eq!(dispatcher(json!(null)), json!([]));
    }
}
