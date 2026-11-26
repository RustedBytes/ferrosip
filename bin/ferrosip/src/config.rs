//! ferrosip.toml: the declarative layer (what runs). Routing stays in the
//! `.cfg` named by `[routing] entry`.
//!
//! Loading: base file → `--overlay` files (deep merge) → `--set` values →
//! `${ENV}` / `${ENV:-default}` / `${feature.x}` interpolation (a feature
//! that holds placeholders is interpolated too). Every leaf
//! remembers where it came from (`check --explain`). Module sections are
//! resolved against the modules' schemas (`Module::params`), by ferrosip
//! or Kamailio name, and ordered by their dependencies.

use sip_core::Arg;
use sip_core::schema::{self, ParamSpec, Ty, Unit, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use toml::{Table, Value as T};

// ------------------------------------------------------------- loading ---

/// The merged file, before interpretation.
pub struct Layered {
    pub table: Table,
    /// Dotted path of each leaf → where its value came from.
    pub sources: BTreeMap<String, String>,
    /// Directory of the base file (relative paths are relative to it).
    pub dir: PathBuf,
}

fn read(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.parse::<Table>().map_err(|e| format!("{}: {}", path.display(), e.to_string().trim_end()))
}

fn record(sources: &mut BTreeMap<String, String>, prefix: &str, v: &T, label: &str) {
    match v {
        // Arrays of tables ([[listen]]) are one value: replaced as a whole.
        T::Table(t) => {
            for (k, x) in t {
                record(sources, &join(prefix, k), x, label);
            }
        }
        _ => {
            sources.retain(|k, _| !(k == prefix || k.starts_with(&format!("{prefix}."))));
            sources.insert(prefix.to_string(), label.to_string());
        }
    }
}

fn join(prefix: &str, k: &str) -> String {
    if prefix.is_empty() { k.to_string() } else { format!("{prefix}.{k}") }
}

/// Tables merge key by key; anything else (arrays included) replaces.
fn merge(into: &mut Table, from: Table, prefix: &str, label: &str, sources: &mut BTreeMap<String, String>) {
    for (k, v) in from {
        let path = join(prefix, &k);
        match (into.get_mut(&k), v) {
            (Some(T::Table(a)), T::Table(b)) => merge(a, b, &path, label, sources),
            (_, v) => {
                record(sources, &path, &v, label);
                into.insert(k, v);
            }
        }
    }
}

/// `a.b.c=value`: TOML syntax if it parses (`10`, `true`, `"x"`, `[1, 2]`),
/// else a plain string (`--set modules.txn.fr_timer=10s`).
fn parse_set(s: &str) -> Result<(Vec<String>, T), String> {
    let (path, raw) = s.split_once('=').ok_or_else(|| format!("--set {s:?}: expected path=value"))?;
    let keys: Vec<String> = path.trim().split('.').map(str::to_string).collect();
    if keys.iter().any(|k| k.is_empty()) {
        return Err(format!("--set {s:?}: bad path"));
    }
    let v = format!("v = {raw}").parse::<Table>().ok().and_then(|mut t| t.remove("v")).unwrap_or_else(|| T::String(raw.to_string()));
    Ok((keys, v))
}

pub fn load(base: &Path, overlays: &[PathBuf], sets: &[String]) -> Result<Layered, String> {
    load_with_env(base, overlays, sets, &|name| std::env::var(name).ok())
}

/// The environment `${NAME}` placeholders read: the process environment in
/// [`load`], a closure in tests (no `std::env::set_var`, which is unsafe).
type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn load_with_env(base: &Path, overlays: &[PathBuf], sets: &[String], env: Env) -> Result<Layered, String> {
    let mut sources = BTreeMap::new();
    let mut table = Table::new();
    merge(&mut table, read(base)?, "", &base.display().to_string(), &mut sources);
    for o in overlays {
        merge(&mut table, read(o)?, "", &o.display().to_string(), &mut sources);
    }
    for s in sets {
        let (keys, v) = parse_set(s)?;
        let mut t = Table::new();
        let mut cur = &mut t;
        // `parse_set` gives at least one key.
        let (last, path) = keys.split_last().ok_or("--set: empty path")?;
        for k in path {
            cur = cur.entry(k.clone()).or_insert_with(|| T::Table(Table::new())).as_table_mut().ok_or("--set: path through a non-table")?;
        }
        cur.insert(last.clone(), v);
        merge(&mut table, t, "", "--set", &mut sources);
    }
    let snapshot = table.clone();
    interpolate_table(&mut table, &snapshot, "", env)?;
    let dir = base.parent().map(Path::to_path_buf).unwrap_or_default();
    Ok(Layered { table, sources, dir })
}

// ------------------------------------------------------- interpolation ---

fn lookup<'a>(root: &'a Table, dotted: &str) -> Option<&'a T> {
    let mut parts = dotted.split('.');
    let mut cur = root.get(parts.next()?)?;
    for p in parts {
        cur = cur.as_table()?.get(p)?;
    }
    Some(cur)
}

/// How deep `${feature.x}` may lead through other placeholders (a cycle
/// stops here).
const MAX_INDIRECTION: usize = 8;

/// One `${…}`: `ENV`, `ENV:-default`, or a dotted path into the config
/// (`path:-default` too). A configured string that holds placeholders of
/// its own is interpolated in turn.
fn resolve(expr: &str, root: &Table, at: &str, env: Env, depth: usize) -> Result<T, String> {
    let (name, default) = match expr.split_once(":-") {
        Some((n, d)) => (n, Some(d)),
        None => (expr, None),
    };
    if name.contains('.') {
        return match (lookup(root, name), default) {
            (Some(T::String(s)), _) if s.contains("${") => {
                if depth >= MAX_INDIRECTION {
                    return Err(format!("{at}: ${{{name}}} refers to itself"));
                }
                interpolate_at(s, root, at, env, depth.saturating_add(1))
            }
            (Some(v), _) => Ok(v.clone()),
            (None, Some(d)) => Ok(T::String(d.to_string())),
            (None, None) => Err(format!("{at}: ${{{name}}} refers to nothing in the configuration")),
        };
    }
    match (env(name), default) {
        (Some(v), _) if !v.is_empty() => Ok(T::String(v)),
        (_, Some(d)) => Ok(T::String(d.to_string())),
        _ => Err(format!("{at}: environment variable {name} is not set (write ${{{name}:-default}} for a fallback)")),
    }
}

fn interpolate_str(s: &str, root: &Table, at: &str, env: Env) -> Result<T, String> {
    interpolate_at(s, root, at, env, 0)
}

fn interpolate_at(s: &str, root: &Table, at: &str, env: Env, depth: usize) -> Result<T, String> {
    if !s.contains("${") {
        return Ok(T::String(s.to_string()));
    }
    // Exactly one placeholder: keep the referenced value's type (a
    // `${feature.nat}` bool stays a bool).
    if let Some(inner) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}'))
        && !inner.contains("${")
        && !inner.contains('}')
    {
        return resolve(inner, root, at, env, depth);
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some((before, after)) = rest.split_once("${") {
        out.push_str(before);
        let (name, after) = after.split_once('}').ok_or_else(|| format!("{at}: unclosed ${{ in {s:?}"))?;
        match resolve(name, root, at, env, depth)? {
            T::String(v) => out.push_str(&v),
            T::Integer(n) => out.push_str(&n.to_string()),
            T::Boolean(b) => out.push_str(&b.to_string()),
            other => return Err(format!("{at}: ${{{name}}} is not a scalar ({other})")),
        }
        rest = after;
    }
    out.push_str(rest);
    Ok(T::String(out))
}

fn interpolate_table(t: &mut Table, root: &Table, prefix: &str, env: Env) -> Result<(), String> {
    for (k, v) in t.iter_mut() {
        interpolate_value(v, root, &join(prefix, k), env)?;
    }
    Ok(())
}

fn interpolate_value(v: &mut T, root: &Table, at: &str, env: Env) -> Result<(), String> {
    match v {
        T::String(s) => *v = interpolate_str(s, root, at, env)?,
        T::Table(t) => interpolate_table(t, root, at, env)?,
        T::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                interpolate_value(x, root, &format!("{at}[{i}]"), env)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// TOML → the schema's neutral value.
pub fn neutral(v: &T) -> Result<Value, String> {
    Ok(match v {
        T::String(s) => Value::Str(s.clone()),
        T::Integer(i) => Value::Int(*i),
        T::Float(f) => Value::Float(*f),
        T::Boolean(b) => Value::Bool(*b),
        T::Array(a) => Value::List(a.iter().map(neutral).collect::<Result<_, _>>()?),
        T::Datetime(d) => Value::Str(d.to_string()),
        T::Table(_) => return Err("a table is not a parameter value".into()),
    })
}

// ------------------------------------------------------------- modules ---

/// A ferrosip module name over one or more Kamailio modules.
pub struct Alias {
    pub name: &'static str,
    /// Loaded whenever the section is present.
    pub always: &'static [&'static str],
    /// Loaded when one of their parameters is set.
    pub optional: &'static [&'static str],
}

pub const ALIASES: &[Alias] = &[
    Alias { name: "txn", always: &["tm"], optional: &["tmx"] },
    Alias { name: "location", always: &["usrloc", "registrar"], optional: &[] },
    Alias { name: "route_set", always: &["rr"], optional: &[] },
    Alias { name: "auth", always: &["auth"], optional: &["auth_db"] },
    Alias { name: "nat", always: &["nathelper"], optional: &[] },
    Alias { name: "media", always: &["rtpengine"], optional: &[] },
    Alias { name: "balancer", always: &["dispatcher"], optional: &[] },
    Alias { name: "carriers", always: &["lcr"], optional: &[] },
    Alias { name: "limits", always: &[], optional: &["pike", "ratelimit"] },
    Alias { name: "cdr", always: &["acc"], optional: &[] },
    Alias { name: "acl", always: &["permissions"], optional: &[] },
    Alias { name: "client", always: &["uac"], optional: &[] },
    Alias { name: "admin", always: &["jsonrpcs"], optional: &[] },
    Alias { name: "topology", always: &["topoh"], optional: &[] },
    Alias { name: "http", always: &["xhttp"], optional: &["http_async_client"] },
    Alias { name: "shared_tables", always: &["htable"], optional: &[] },
    Alias { name: "sql", always: &["sqlops"], optional: &[] },
    Alias { name: "trace", always: &["siptrace"], optional: &[] },
    // Groups of related modules (no function or parameter in common).
    Alias { name: "sip", always: &[], optional: &["siputils", "sanity", "maxfwd"] },
    Alias { name: "text", always: &["textops"], optional: &["textopsx"] },
    Alias { name: "vars", always: &["pv"], optional: &["avpops"] },
    Alias { name: "utils", always: &[], optional: &["cfgutils", "corex", "kex"] },
    Alias { name: "blocklist", always: &[], optional: &["blst", "userblocklist"] },
    Alias { name: "dialog", always: &["dialog"], optional: &["dlgs"] },
    Alias { name: "presence", always: &["presence"], optional: &["presence_xml", "presence_dialoginfo"] },
    Alias { name: "presence_client", always: &["pua"], optional: &["pua_dialoginfo"] },
    Alias { name: "diameter", always: &["cdp"], optional: &["cdp_avp"] },
    // One module each.
    Alias { name: "stateless", always: &["sl"], optional: &[] },
    Alias { name: "log", always: &["xlog"], optional: &[] },
    Alias { name: "ip", always: &["ipops"], optional: &[] },
    Alias { name: "stats", always: &["statistics"], optional: &[] },
    Alias { name: "timers", always: &["rtimer"], optional: &[] },
    Alias { name: "pipe_limits", always: &["pipelimit"], optional: &[] },
    Alias { name: "security_filter", always: &["secfilter"], optional: &[] },
    Alias { name: "prefix_tree", always: &["mtree"], optional: &[] },
    Alias { name: "prefix_routes", always: &["prefix_route"], optional: &[] },
    Alias { name: "domains", always: &["domain"], optional: &[] },
    Alias { name: "aliases", always: &["alias_db"], optional: &[] },
    Alias { name: "groups", always: &["group"], optional: &[] },
    Alias { name: "speed_dial", always: &["speeddial"], optional: &[] },
    Alias { name: "redirect", always: &["uac_redirect"], optional: &[] },
    Alias { name: "credit", always: &["cnxcc"], optional: &[] },
    Alias { name: "resource_lists", always: &["rls"], optional: &[] },
    Alias { name: "shared_lines", always: &["sca"], optional: &[] },
    Alias { name: "offline_messages", always: &["msilo"], optional: &[] },
    Alias { name: "pending_calls", always: &["tsilo"], optional: &[] },
    Alias { name: "json_doc", always: &["jansson"], optional: &[] },
    Alias { name: "redis", always: &["ndb_redis"], optional: &[] },
    Alias { name: "events", always: &["evapi"], optional: &[] },
    Alias { name: "sip_dump", always: &["sipdump"], optional: &[] },
    Alias { name: "lua", always: &["app_lua"], optional: &[] },
];

/// Hard dependencies: these must be loaded (and are, implicitly) first.
pub const DEPS: &[(&str, &[&str])] = &[
    ("registrar", &["usrloc"]),
    ("dialog", &["tm"]),
    ("dlgs", &["tm"]),
    ("tmx", &["tm"]),
    ("tsilo", &["tm", "usrloc"]),
    ("ai", &["tm"]),
    ("async", &["tm"]),
    ("http_async_client", &["tm"]),
    ("uac", &["tm"]),
    ("acc", &["tm"]),
    ("lcr", &["tm"]),
    ("dispatcher", &["tm"]),
    ("keepalive", &["tm"]),
    ("msilo", &["tm"]),
    ("presence", &["tm"]),
    ("presence_xml", &["presence"]),
    ("presence_dialoginfo", &["presence"]),
    ("pua", &["tm"]),
    ("pua_dialoginfo", &["pua", "dialog"]),
    ("rls", &["presence", "tm"]),
    ("sca", &["tm"]),
    ("cnxcc", &["dialog"]),
    ("xhttp_prom", &["xhttp"]),
    ("auth_db", &["auth"]),
    ("auth_ephemeral", &["auth"]),
    ("ims_isc", &["ims_usrloc_scscf"]),
    ("ims_registrar_scscf", &["ims_usrloc_scscf", "cdp", "tm"]),
    ("ims_registrar_pcscf", &["ims_usrloc_pcscf"]),
    ("ims_auth", &["cdp"]),
    ("ims_charging", &["cdp", "dialog"]),
    ("ims_icscf", &["cdp"]),
    ("ims_qos", &["cdp"]),
    ("ims_ipsec_pcscf", &["tm"]),
    ("ims_diameter_server", &["cdp"]),
];

/// Ordering only: when both are loaded, the second loads first (a module
/// that uses the other's API when it's there).
pub const AFTER: &[(&str, &[&str])] = &[("nathelper", &["usrloc"]), ("dispatcher", &["dialog"]), ("acc", &["dialog"]), ("tsilo", &["registrar"])];

fn after(m: &str) -> Vec<&'static str> {
    deps(m).iter().chain(AFTER.iter().filter(|(n, _)| *n == m).flat_map(|(_, d)| d.iter())).copied().collect()
}

pub fn deps(m: &str) -> &'static [&'static str] {
    DEPS.iter().find(|(n, _)| *n == m).map_or(&[], |(_, d)| d)
}

/// What a module looks like to the loader: `None` = unknown module;
/// `Some(None)` = no schema; `Some(Some(params))`.
pub type SchemaOf<'a> = &'a dyn Fn(&str) -> Option<Option<Vec<ParamSpec>>>;

/// One module to load, with its parameters from ferrosip.toml.
#[derive(Debug, Default)]
pub struct ModLoad {
    pub name: String,
    /// (parameter, values for `set_param`, source, schema-checked).
    pub params: Vec<(String, Vec<Arg>, String, bool)>,
    /// The values as written, for `check --explain`.
    pub written: Vec<String>,
    /// Why it loads: the section, or "needed by X".
    pub why: String,
}

/// A value not covered by a schema: as close to a `modparam` as it gets.
fn raw_args(v: &Value) -> Result<Vec<Arg>, String> {
    Ok(match v {
        Value::Str(s) => vec![Arg::Str(s.clone())],
        Value::Int(i) => vec![Arg::Int(*i)],
        Value::Bool(b) => vec![Arg::Int(i64::from(*b))],
        Value::Float(f) => return Err(format!("{f}: a fractional number is not a module parameter")),
        Value::List(items) => items.iter().map(raw_args).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect(),
    })
}

/// `[modules.*]` → modules to load, in dependency order. All errors at once.
pub fn modules(l: &Layered, schema_of: SchemaOf<'_>) -> Result<Vec<ModLoad>, Vec<String>> {
    let mut errors = Vec::new();
    let mut loads: BTreeMap<String, ModLoad> = BTreeMap::new();
    let Some(T::Table(sections)) = l.table.get("modules") else { return order(loads, schema_of).map_err(|e| vec![e]) };
    for (sec, body) in sections {
        let at = format!("modules.{sec}");
        let Some(body) = body.as_table() else {
            errors.push(format!("{at}: expected a table ([modules.{sec}])"));
            continue;
        };
        let (always, optional): (Vec<&str>, Vec<&str>) = match ALIASES.iter().find(|a| a.name == sec) {
            Some(a) => (a.always.to_vec(), a.optional.to_vec()),
            None if schema_of(sec).is_some() => (vec![sec.as_str()], vec![]),
            None => {
                let known: Vec<&str> = ALIASES
                    .iter()
                    .map(|a| a.name)
                    .chain(ALIASES.iter().flat_map(|a| a.always.iter().chain(a.optional).copied()))
                    .chain(DEPS.iter().flat_map(|(m, d)| std::iter::once(*m).chain(d.iter().copied())))
                    .collect();
                errors.push(format!("{at}: unknown module {sec:?}{}", schema::suggest(sec, known)));
                continue;
            }
        };
        match body.get("enabled") {
            None => {}
            Some(T::Boolean(true)) => {}
            Some(T::Boolean(false)) => continue,
            Some(other) => {
                errors.push(format!("{at}.enabled: expected true or false, got {other}"));
                continue;
            }
        }
        let members: Vec<&str> = always.iter().chain(&optional).copied().collect();
        let schemas: Vec<(&str, Option<Vec<ParamSpec>>)> = members.iter().map(|m| (*m, schema_of(m).flatten())).collect();
        for m in &always {
            loads.entry(m.to_string()).or_insert_with(|| ModLoad { name: m.to_string(), why: format!("[{at}]"), ..Default::default() });
        }
        // `[modules.x.kamailio]`: parameters passed to the module as given,
        // like a `modparam` (no schema check; what `ferrosip import` writes
        // for parameters the schema doesn't list).
        if let Some(raw) = body.get("kamailio") {
            let Some(raw) = raw.as_table() else {
                errors.push(format!("{at}.kamailio: expected a table ([{at}.kamailio] param = value)"));
                continue;
            };
            let Some(target) = always.first().copied() else {
                errors.push(format!("{at}.kamailio: set it under the module's own section"));
                continue;
            };
            for (key, v) in raw {
                let path = format!("{at}.kamailio.{key}");
                let source = l.sources.get(&path).cloned().unwrap_or_default();
                match neutral(v).and_then(|v| raw_args(&v)) {
                    Ok(args) => {
                        loads
                            .entry(target.to_string())
                            .or_insert_with(|| ModLoad { name: target.to_string(), why: format!("[{at}]"), ..Default::default() })
                            .params
                            .push((key.clone(), args, source, false));
                        if let Some(m) = loads.get_mut(target) {
                            m.written.push(display(v));
                        }
                    }
                    Err(e) => errors.push(format!("{path}: {e}")),
                }
            }
        }
        for (key, v) in body.iter().filter(|(k, _)| k.as_str() != "enabled" && k.as_str() != "kamailio") {
            let path = format!("{at}.{key}");
            let source = l.sources.get(&path).cloned().unwrap_or_default();
            let val = match neutral(v) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("{path}: {e}"));
                    continue;
                }
            };
            let typed = schemas.iter().find_map(|(m, s)| s.as_ref()?.iter().find(|p| p.name == key).map(|p| (*m, *p)));
            let (module, args, checked) = match typed {
                Some((m, spec)) => match schema::convert(&spec, &val) {
                    Ok(a) => (m, a, true),
                    Err(e) => {
                        errors.push(format!("{path}: {e}"));
                        continue;
                    }
                },
                None => {
                    // Only a member that always loads and has no schema yet
                    // takes keys as given (an optional one would swallow typos).
                    let unschema: Vec<&str> = schemas.iter().filter(|(m, s)| s.is_none() && always.contains(m)).map(|(m, _)| *m).collect();
                    let optional_raw: Vec<&str> = schemas.iter().filter(|(m, s)| s.is_none() && !always.contains(m)).map(|(m, _)| *m).collect();
                    if let [only] = unschema[..] {
                        match raw_args(&val) {
                            Ok(a) => (only, a, false),
                            Err(e) => {
                                errors.push(format!("{path}: {e}"));
                                continue;
                            }
                        }
                    } else {
                        let names: Vec<&str> = schemas.iter().filter_map(|(_, s)| s.as_ref()).flatten().map(|p| p.name).collect();
                        let direct: Vec<&str> = unschema.iter().chain(&optional_raw).copied().collect();
                        let hint =
                            if direct.is_empty() { String::new() } else { format!(" (or set it under [modules.{}] directly)", direct.join("] / [modules.")) };
                        errors.push(format!("{path}: unknown parameter {key:?} for {sec}{}{hint}", schema::suggest(key, names)));
                        continue;
                    }
                }
            };
            loads
                .entry(module.to_string())
                .or_insert_with(|| ModLoad { name: module.to_string(), why: format!("[{at}]"), ..Default::default() })
                .params
                .push((key.clone(), args, source, checked));
            if let Some(m) = loads.get_mut(module) {
                m.written.push(display(v));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    order(loads, schema_of).map_err(|e| vec![e])
}

/// More modules (loaded for what the routing script uses), merged into the
/// plan and re-ordered with their dependencies.
pub fn add_modules(plan: Vec<ModLoad>, extra: &[(String, String)], schema_of: SchemaOf<'_>) -> Result<Vec<ModLoad>, String> {
    let mut map: BTreeMap<String, ModLoad> = plan.into_iter().map(|m| (m.name.clone(), m)).collect();
    for (m, why) in extra {
        map.entry(m.clone()).or_insert_with(|| ModLoad { name: m.clone(), why: why.clone(), ..Default::default() });
    }
    order(map, schema_of)
}

/// Add implicit dependencies, then order so each module follows the ones
/// it needs (ties by name, for a stable order).
fn order(mut loads: BTreeMap<String, ModLoad>, schema_of: SchemaOf<'_>) -> Result<Vec<ModLoad>, String> {
    let mut queue: Vec<String> = loads.keys().cloned().collect();
    while let Some(m) = queue.pop() {
        for d in deps(&m) {
            if !loads.contains_key(*d) {
                if schema_of(d).is_none() {
                    return Err(format!("{m} needs {d}, which this build doesn't have"));
                }
                loads.insert(d.to_string(), ModLoad { name: d.to_string(), why: format!("needed by {m}"), ..Default::default() });
                queue.push(d.to_string());
            }
        }
    }
    let mut out = Vec::new();
    let mut done: BTreeSet<String> = BTreeSet::new();
    while !loads.is_empty() {
        let ready: Vec<String> = loads.keys().filter(|m| after(m).iter().all(|d| done.contains(*d) || !loads.contains_key(*d))).cloned().collect();
        if ready.is_empty() {
            return Err(format!("dependency cycle among {}", loads.keys().cloned().collect::<Vec<_>>().join(", ")));
        }
        for m in ready {
            done.insert(m.clone());
            out.push(loads.remove(&m).unwrap_or_default());
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- core ---

/// `[core]`: keys, types and docs (also printed by `ferrosip schema core`).
pub const CORE: &[ParamSpec] = &[
    schema::p("workers", Ty::Int { min: 1, max: 1024 }, "CPUs", "UDP worker threads per UDP socket (Kamailio children)"),
    schema::p("tcp_readers", Ty::Int { min: 1, max: 1024 }, "CPUs / 2", "TCP/TLS reader threads (tcp_children)"),
    schema::p(
        "log_level",
        Ty::Enum(&[("alert", "-5"), ("crit", "-2"), ("err", "-1"), ("warn", "0"), ("notice", "1"), ("info", "2"), ("debug", "3")]),
        "info",
        "Log level",
    ),
    schema::p("rpc_socket", Ty::Str, "/tmp/ferrosip-rpc.sock", "Unix socket for ferroctl (\"none\": off)"),
    schema::p("shutdown_timeout", Ty::Duration(Unit::Sec), "5s", "Graceful shutdown: wait this long for transactions"),
    schema::p("advertise", Ty::Str, "", "IP put in Via/Contact instead of the bind addresses"),
    schema::p("aliases", Ty::List(&Ty::Str), "", "Other host names that mean this proxy (myself checks)"),
    schema::p("tcp_max_connections", schema::UINT, "", "Most TCP/TLS/WS connections"),
    schema::p("tcp_accept_iplimit", schema::UINT, "", "Most connections from one IP address"),
    schema::p("tcp_connection_lifetime", Ty::Duration(Unit::Sec), "", "Idle connections close after this"),
    schema::p("tcp_connect_timeout", Ty::Duration(Unit::Sec), "", "Outbound connect timeout"),
    schema::p("tcp_keepalive", Ty::Duration(Unit::Sec), "", "TCP keep-alive idle time"),
    schema::p("tcp_conn_wq_max", schema::UINT, "", "Bytes queued per connection before it's closed"),
    schema::p("tcp_accept_aliases", Ty::Bool, "false", "RFC 5923 connection reuse"),
    schema::p("force_rport", Ty::Bool, "true", "UDP replies go to the source port even without ;rport (false: the Via sent-by port, as in Kamailio)"),
    schema::p("ws_origins", Ty::List(&Ty::Str), "", "Allowed WebSocket Origin values (empty: any)"),
    schema::p("ws_deflate", Ty::Bool, "false", "permessage-deflate for WebSocket"),
];

pub const LISTEN: &[ParamSpec] = &[
    schema::p("proto", Ty::Enum(&[("udp", "udp"), ("tcp", "tcp"), ("tls", "tls"), ("ws", "ws"), ("wss", "wss")]), "", "Transport"),
    schema::p("addr", Ty::Str, "", "ip:port to bind"),
    schema::p("advertise", Ty::Str, "", "ip:port for Via/Contact instead of addr"),
    schema::p("tls", Ty::Str, "default", "[tls.<name>] section for tls/wss listeners"),
];

pub const TLS: &[ParamSpec] = &[
    schema::p("cert", Ty::Str, "", "Certificate chain (PEM)"),
    schema::p("key", Ty::Str, "", "Private key (PEM)"),
    schema::p("ca", Ty::Str, "", "CA bundle (PEM): verifies servers, and clients with verify_client"),
    schema::p("verify_client", Ty::Bool, "false", "Require and verify client certificates (mutual TLS)"),
    schema::p("sni", Ty::List(&Ty::Str), "", "Extra certificates by SNI name: \"name=cert.pem,key.pem\" (default section only)"),
    schema::p("session_cache", schema::UINT, "", "Server session cache entries (0: no resumption; default section only)"),
    schema::p("tickets", Ty::Bool, "false", "Stateless session tickets (default section only)"),
    schema::p("profile", Ty::Str, "", "Kamailio tls.cfg file: per-listener / per-peer profiles (default section only)"),
];

/// Typed `[core]` (only what the file sets).
#[derive(Debug, Default)]
pub struct Core(pub BTreeMap<String, Vec<Arg>>);

impl Core {
    pub fn int(&self, k: &str) -> Option<i64> {
        self.0.get(k)?.first()?.int().ok()
    }
    /// A count or size (`CORE` keeps these at 0 or more).
    pub fn count(&self, k: &str) -> Option<usize> {
        usize::try_from(self.int(k)?).ok()
    }
    /// A duration in seconds (never negative after the schema).
    pub fn secs(&self, k: &str) -> Option<std::time::Duration> {
        u64::try_from(self.int(k)?).ok().map(std::time::Duration::from_secs)
    }
    pub fn str(&self, k: &str) -> Option<String> {
        self.0.get(k)?.first()?.str().ok().map(str::to_string)
    }
    pub fn strs(&self, k: &str) -> Vec<String> {
        self.0.get(k).map(|v| v.iter().filter_map(|a| a.str().ok().map(str::to_string)).collect()).unwrap_or_default()
    }
}

fn typed_section(t: Option<&T>, specs: &[ParamSpec], at: &str, errors: &mut Vec<String>) -> BTreeMap<String, Vec<Arg>> {
    let mut out = BTreeMap::new();
    let Some(t) = t else { return out };
    let Some(t) = t.as_table() else {
        errors.push(format!("{at}: expected a table"));
        return out;
    };
    for (k, v) in t {
        let path = format!("{at}.{k}");
        let Some(spec) = specs.iter().find(|s| s.name == k) else {
            errors.push(format!("{path}: unknown key{}", schema::suggest(k, specs.iter().map(|s| s.name))));
            continue;
        };
        match neutral(v).and_then(|v| schema::convert(spec, &v)) {
            Ok(a) => {
                out.insert(k.clone(), a);
            }
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    out
}

pub struct ListenSpec {
    pub proto: String,
    pub addr: String,
    pub advertise: Option<String>,
    pub tls: Option<String>,
}

/// Everything but the modules.
pub struct Settings {
    pub core: Core,
    pub listen: Vec<ListenSpec>,
    pub tls: BTreeMap<String, BTreeMap<String, Vec<Arg>>>,
    pub entry: Option<PathBuf>,
    /// `[cfg_vars.group] name = value` (or `{ value = …, desc = "…" }`):
    /// Kamailio custom config variables (`$sel(cfg_get.group.name)`).
    pub cfg_vars: Vec<(String, sip_core::pv::Val, String)>,
}

const TOP: &[&str] = &["core", "listen", "tls", "modules", "feature", "routing", "lint", "cfg_vars"];

/// `[feature]` values, as `.fsr` constants (`import { features } from config`).
pub fn features(l: &Layered) -> BTreeMap<String, fsr::Feature> {
    let mut out = BTreeMap::new();
    for (name, v) in l.table.get("feature").and_then(|f| f.as_table()).into_iter().flatten() {
        let f = match v {
            T::Boolean(b) => fsr::Feature::Bool(*b),
            T::Integer(i) => fsr::Feature::Int(*i),
            T::String(s) => fsr::Feature::Str(s.clone()),
            _ => continue,
        };
        out.insert(name.clone(), f);
    }
    out
}

/// Tables ferrosip.toml declares (`[modules.shared_tables] htable`).
pub fn htables(l: &Layered) -> std::collections::BTreeSet<String> {
    let mods = l.table.get("modules").and_then(|m| m.as_table());
    let specs = ["shared_tables", "htable"].iter().filter_map(|n| mods?.get(*n)?.as_table()?.get("htable"));
    let mut out = std::collections::BTreeSet::new();
    for v in specs {
        let items: Vec<&str> = match v {
            T::String(s) => vec![s.as_str()],
            T::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
            _ => vec![],
        };
        out.extend(items.into_iter().filter_map(|s| s.split_once("=>").map(|(n, _)| n.trim().to_string())));
    }
    out
}

pub fn settings(l: &Layered) -> Result<Settings, Vec<String>> {
    let mut errors = Vec::new();
    for k in l.table.keys() {
        if !TOP.contains(&k.as_str()) {
            errors.push(format!("{k}: unknown section{}", schema::suggest(k, TOP.iter().copied())));
        }
    }
    let core = Core(typed_section(l.table.get("core"), CORE, "core", &mut errors));
    let mut listen = Vec::new();
    match l.table.get("listen") {
        None => {}
        Some(T::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let at = format!("listen[{i}]");
                let before = errors.len();
                let s = typed_section(Some(item), LISTEN, &at, &mut errors);
                if errors.len() > before {
                    continue;
                }
                let get = |k: &str| s.get(k).and_then(|a| a.first()).and_then(|a| a.str().ok()).map(str::to_string);
                match (get("proto"), get("addr")) {
                    (Some(proto), Some(addr)) => listen.push(ListenSpec { proto, addr, advertise: get("advertise"), tls: get("tls") }),
                    _ => errors.push(format!("{at}: needs proto and addr")),
                }
            }
        }
        Some(_) => errors.push("listen: use [[listen]] entries".into()),
    }
    let mut tls = BTreeMap::new();
    if let Some(t) = l.table.get("tls") {
        match t.as_table() {
            Some(t) => {
                for (name, body) in t {
                    tls.insert(name.clone(), typed_section(Some(body), TLS, &format!("tls.{name}"), &mut errors));
                }
            }
            None => errors.push("tls: expected [tls.<name>] sections".into()),
        }
    }
    let entry = match l.table.get("routing").and_then(|r| r.as_table()) {
        None => None,
        Some(r) => {
            for k in r.keys().filter(|k| k.as_str() != "entry") {
                errors.push(format!("routing.{k}: unknown key"));
            }
            match r.get("entry") {
                Some(T::String(e)) => Some(l.dir.join(e)),
                Some(_) => {
                    errors.push("routing.entry: expected a file name".into());
                    None
                }
                None => None,
            }
        }
    };
    for (name, body) in l.table.get("feature").and_then(|f| f.as_table()).into_iter().flatten() {
        if !matches!(body, T::Boolean(_) | T::String(_) | T::Integer(_)) {
            errors.push(format!("feature.{name}: expected a value, not a table or list"));
        }
    }
    let mut cfg_vars = Vec::new();
    match l.table.get("cfg_vars") {
        None => {}
        Some(T::Table(groups)) => {
            for (g, vars) in groups {
                let Some(vars) = vars.as_table() else {
                    errors.push(format!("cfg_vars.{g}: expected a table ([cfg_vars.{g}] name = value)"));
                    continue;
                };
                for (n, v) in vars {
                    let (val, desc) = match v {
                        T::Table(t) => (t.get("value"), t.get("desc").and_then(|d| d.as_str()).unwrap_or("").to_string()),
                        other => (Some(other), String::new()),
                    };
                    let val = match val {
                        Some(T::String(s)) => sip_core::pv::Val::Str(s.clone()),
                        Some(T::Integer(i)) => sip_core::pv::Val::Int(*i),
                        _ => {
                            errors.push(format!("cfg_vars.{g}.{n}: expected a string or integer (or {{ value = …, desc = \"…\" }})"));
                            continue;
                        }
                    };
                    cfg_vars.push((format!("{g}.{n}"), val, desc));
                }
            }
        }
        Some(_) => errors.push("cfg_vars: expected [cfg_vars.<group>] sections".into()),
    }
    if errors.is_empty() { Ok(Settings { core, listen, tls, entry, cfg_vars }) } else { Err(errors) }
}

// -------------------------------------------------------------- reload ---

fn arg_text(a: &Arg) -> String {
    a.str().map(|s| format!("{s:?}")).unwrap_or_else(|_| a.int().map(|i| i.to_string()).unwrap_or_default())
}

/// What is running: module parameters as applied, and every setting
/// outside `[modules]` / `[feature]` (those need a restart to change).
#[derive(Debug, Default, Clone)]
pub struct Running {
    pub mods: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub settings: BTreeMap<String, String>,
}

impl Running {
    pub fn of(l: &Layered, mods: &[ModLoad]) -> Self {
        let mods = mods.iter().map(|m| (m.name.clone(), m.params.iter().map(|(k, a, ..)| (k.clone(), a.iter().map(arg_text).collect())).collect())).collect();
        let mut all = Vec::new();
        leaves("", &T::Table(l.table.clone()), &mut all);
        let settings = all.into_iter().filter(|(k, _)| !k.starts_with("modules.") && !k.starts_with("feature.")).collect();
        Running { mods, settings }
    }
}

/// What `cfg.reload` does with a changed ferrosip.toml.
#[derive(Debug, Default)]
pub struct ReloadPlan {
    /// (module, parameter, values, as shown) to apply with `set_param`.
    pub apply: Vec<(String, String, Vec<Arg>, String)>,
    /// Changes that take a restart (not applied).
    pub restart: Vec<String>,
}

/// Compare a freshly loaded configuration with what is running.
pub fn reload_diff(running: &Running, new: &Layered, new_mods: &[ModLoad], schema_of: SchemaOf<'_>) -> ReloadPlan {
    let mut plan = ReloadPlan::default();
    for m in new_mods.iter().filter(|m| !running.mods.contains_key(&m.name)) {
        plan.restart.push(format!("module {} added", m.name));
    }
    for m in running.mods.keys().filter(|m| !new_mods.iter().any(|n| &n.name == *m)) {
        plan.restart.push(format!("module {m} removed"));
    }
    for m in new_mods {
        let Some(old) = running.mods.get(&m.name) else { continue };
        let specs = schema_of(&m.name).flatten().unwrap_or_default();
        let new: BTreeMap<&str, &Vec<Arg>> = m.params.iter().map(|(k, a, ..)| (k.as_str(), a)).collect();
        let keys: BTreeSet<&str> = old.keys().map(String::as_str).chain(new.keys().copied()).collect();
        for k in keys {
            let new_text: Option<Vec<String>> = new.get(k).map(|a| a.iter().map(arg_text).collect());
            if new_text.as_ref() == old.get(k) {
                continue;
            }
            let spec = specs.iter().find(|p| p.name == k);
            let live = spec.is_some_and(|p| p.reload && !matches!(p.ty, Ty::List(_)));
            let what = format!("{}.{k}", m.name);
            match (live, new.get(k)) {
                (false, _) => plan.restart.push(what),
                (true, Some(args)) => {
                    plan.apply.push((m.name.clone(), k.to_string(), (*args).clone(), args.iter().map(arg_text).collect::<Vec<_>>().join(", ")))
                }
                // Removed from the file: back to the default, when it has one.
                (true, None) => match spec.filter(|p| !p.default.is_empty()).map(|p| {
                    let v = p.default.parse::<i64>().map(Value::Int).unwrap_or_else(|_| Value::Str(p.default.into()));
                    schema::convert(p, &v)
                }) {
                    Some(Ok(args)) => plan.apply.push((m.name.clone(), k.to_string(), args, format!("default {}", spec.map_or("", |p| p.default)))),
                    _ => plan.restart.push(what),
                },
            }
        }
    }
    let now = Running::of(new, new_mods).settings;
    let paths: BTreeSet<&String> = running.settings.keys().chain(now.keys()).collect();
    for p in paths {
        if running.settings.get(p) != now.get(p) {
            plan.restart.push(p.clone());
        }
    }
    plan
}

// ------------------------------------------------------------- explain ---

fn display(v: &T) -> String {
    match v {
        T::String(s) => format!("{s:?}"),
        T::Table(t) => format!("{{ {} }}", t.iter().map(|(k, v)| format!("{k} = {}", display(v))).collect::<Vec<_>>().join(", ")),
        T::Array(a) => format!("[{}]", a.iter().map(display).collect::<Vec<_>>().join(", ")),
        other => other.to_string(),
    }
}

fn leaves(prefix: &str, v: &T, out: &mut Vec<(String, String)>) {
    match v {
        T::Table(t) => t.iter().for_each(|(k, x)| leaves(&join(prefix, k), x, out)),
        other => out.push((prefix.to_string(), display(other))),
    }
}

/// The effective configuration, one line per value, with its source; then
/// the modules in load order with their parameters (and schema defaults).
pub fn explain(l: &Layered, mods: &[ModLoad], schema_of: SchemaOf<'_>) -> String {
    let mut out = String::from("# Effective configuration (value  # source)\n");
    let mut all = Vec::new();
    leaves("", &T::Table(l.table.clone()), &mut all);
    let w = all.iter().map(|(k, v)| k.len().saturating_add(v.len())).max().unwrap_or(0).min(80);
    for (k, v) in &all {
        let src = l.sources.get(k).map(String::as_str).unwrap_or("?");
        out.push_str(&format!("{:<w$}  # {src}\n", format!("{k} = {v}"), w = w.saturating_add(3)));
    }
    out.push_str("\n# Modules, in load order\n");
    for m in mods {
        let spec = schema_of(&m.name).flatten();
        let alias = ALIASES
            .iter()
            .find(|a| a.always.contains(&m.name.as_str()) || a.optional.contains(&m.name.as_str()))
            .map(|a| format!(" ({})", a.name))
            .unwrap_or_default();
        out.push_str(&format!("{}{alias}  # {}{}\n", m.name, m.why, if spec.is_none() { "; no schema: values passed as given" } else { "" }));
        for (i, (k, args, src, checked)) in m.params.iter().enumerate() {
            let given = args
                .iter()
                .map(|a| a.str().map(|s| format!("{s:?}")).unwrap_or_else(|_| a.int().map(|i| i.to_string()).unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(", ");
            let written = m.written.get(i).cloned().unwrap_or_else(|| given.clone());
            let conv = if written == given { String::new() } else { format!(" (→ {given})") };
            let reload = spec.iter().flatten().any(|p| p.name == k && p.reload);
            out.push_str(&format!(
                "  {k} = {written}{conv}  # {src}{}{}\n",
                if *checked { "" } else { ", unchecked" },
                if reload { ", reloadable" } else { "" }
            ));
        }
        for p in spec.iter().flatten().filter(|p| !p.default.is_empty() && !m.params.iter().any(|(k, ..)| k == p.name)) {
            out.push_str(&format!("  {} = {}  # default{}\n", p.name, p.default, if p.reload { ", reloadable" } else { "" }));
        }
    }
    out
}

/// Text for a generated Markdown table cell or heading: `|` would end the
/// cell, and a placeholder such as `<name>` would be read as an HTML tag
/// and vanish (on GitHub and on the docs site alike).
pub fn md_text(s: &str) -> String {
    s.replace('|', "\\|").replace('<', "&lt;").replace('>', "&gt;")
}

/// `ferrosip schema`: Markdown reference of the given modules.
pub fn reference(modules: &[(&str, Vec<ParamSpec>)], markdown: bool, sections: &[&str]) -> String {
    let mut out = String::new();
    let section = |out: &mut String, title: &str, params: &[ParamSpec]| {
        if markdown {
            out.push_str(&format!("## {}\n\n| Name | Type | Default | Description |\n|---|---|---|---|\n", md_text(title)));
            for p in params {
                let d = if p.default.is_empty() { "—".to_string() } else { format!("`{}`", p.default) };
                out.push_str(&format!("| `{}` | {} | {d} | {}{} |\n", p.name, p.ty.describe(), md_text(p.doc), if p.reload { " (reloadable)" } else { "" }));
            }
            out.push('\n');
        } else {
            out.push_str(&format!("[{title}]\n"));
            for p in params {
                out.push_str(&format!(
                    "  {:<28} {}{}\n      {}\n",
                    p.name,
                    p.ty.describe(),
                    if p.default.is_empty() { String::new() } else { format!(", default {}", p.default) },
                    p.doc
                ));
            }
            out.push('\n');
        }
    };
    if markdown {
        out.push_str("# ferrosip.toml reference\n\nGenerated by `ferrosip schema --markdown`: do not edit.\n\n");
    }
    for (name, title, specs) in [("core", "core", CORE), ("listen", "[listen]", LISTEN), ("tls", "tls.<name>", TLS)] {
        if sections.contains(&name) {
            section(&mut out, title, specs);
        }
    }
    for (name, params) in modules {
        let title = match ALIASES.iter().find(|a| a.always.contains(name) || a.optional.contains(name)) {
            Some(a) => format!("modules.{} (Kamailio {name})", a.name),
            None => format!("modules.{name}"),
        };
        section(&mut out, &title, params);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, text: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ferrosip-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    const TM: &[ParamSpec] = &[schema::p("fr_timer", Ty::Duration(Unit::Ms), "30s", ""), schema::p("max_branches", schema::UINT, "", "")];
    const UL: &[ParamSpec] = &[schema::p("db_mode", Ty::Enum(&[("off", "0"), ("write-back", "2")]), "off", "")];
    const REG: &[ParamSpec] = &[schema::p("max_expires", Ty::Duration(Unit::Sec), "", "")];

    fn schema_of(m: &str) -> Option<Option<Vec<ParamSpec>>> {
        match m {
            "tm" => Some(Some(TM.to_vec())),
            "usrloc" => Some(Some(UL.to_vec())),
            "registrar" => Some(Some(REG.to_vec())),
            "dialog" | "pike" | "ratelimit" => Some(None),
            _ => None,
        }
    }

    #[test]
    fn layers_interpolation_and_sources() {
        let env = |name: &str| (name == "FERROSIP_TEST_IP").then(|| "192.0.2.7".to_string());
        let base = write(
            "base.toml",
            "[core]\nworkers = 2\n[[listen]]\nproto = \"udp\"\naddr = \"${FERROSIP_TEST_IP}:5060\"\n\n[feature]\nnat = true\n\
             [modules.txn]\nfr_timer = \"30s\"\n[modules.dialog]\nenabled = \"${feature.nat}\"\ndb_url = \"${FERROSIP_TEST_UNSET:-text:///tmp}\"\n",
        );
        let prod = write("prod.toml", "[core]\nworkers = 32\n[modules.txn]\nmax_branches = 4\n");
        let l = load_with_env(&base, std::slice::from_ref(&prod), &["modules.txn.fr_timer=10s".into(), "feature.nat=false".into()], &env).unwrap();
        assert_eq!(l.table["core"]["workers"].as_integer(), Some(32));
        assert_eq!(l.sources["core.workers"], prod.display().to_string());
        assert_eq!(l.sources["modules.txn.fr_timer"], "--set");
        assert_eq!(l.table["listen"][0]["addr"].as_str(), Some("192.0.2.7:5060"));
        assert_eq!(l.table["modules"]["dialog"]["enabled"].as_bool(), Some(false), "${{feature.x}} keeps its type, after --set");
        assert_eq!(l.table["modules"]["dialog"]["db_url"].as_str(), Some("text:///tmp"));
        let mods = modules(&l, &schema_of).unwrap();
        let names: Vec<&str> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["tm"], "dialog disabled by the feature switch");
        let tm = &mods[0];
        assert_eq!(tm.params.iter().find(|p| p.0 == "fr_timer").unwrap().1[0].int().unwrap(), 10_000);
        let e = load_with_env(&write("bad.toml", "[core]\nrpc_socket = \"${FERROSIP_TEST_NOPE}\"\n"), &[], &[], &env).err().unwrap();
        assert!(e.contains("FERROSIP_TEST_NOPE is not set"), "{e}");
    }

    #[test]
    fn module_resolution() {
        let l =
            load(&write("m.toml", "[modules.location]\ndb_mode = \"write-back\"\nmax_expires = \"1h\"\n[modules.dialog]\nanything = 5\n"), &[], &[]).unwrap();
        let mods = modules(&l, &schema_of).unwrap();
        let names: Vec<&str> = mods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["tm", "usrloc", "dialog", "registrar"], "dependencies first, implicit tm for dialog");
        assert_eq!(mods[1].params[0].1[0].int().unwrap(), 2);
        assert_eq!(mods[3].params[0].1[0].int().unwrap(), 3600);
        assert!(!mods[2].params[0].3, "dialog has no schema: unchecked");
        assert_eq!(mods[0].why, "needed by dialog");

        let l = load(
            &write("e.toml", "[modules.txn]\nfr_timr = \"1s\"\n[modules.location]\ndb_mode = \"fast\"\n[modules.dialgo]\n[modules.limits]\nx = 1\n[sip]\n"),
            &[],
            &[],
        )
        .unwrap();
        let errs = modules(&l, &schema_of).unwrap_err();
        let all = errs.join("\n");
        assert!(all.contains("modules.txn.fr_timr: unknown parameter \"fr_timr\" for txn (did you mean \"fr_timer\"?)"), "{all}");
        assert!(all.contains("modules.location.db_mode: \"fast\" is not one of"), "{all}");
        assert!(all.contains("modules.dialgo: unknown module \"dialgo\" (did you mean \"dialog\"?)"), "{all}");
        assert!(all.contains("modules.limits.x: unknown parameter") && all.contains("[modules.pike] / [modules.ratelimit]"), "{all}");
        let s = settings(&l).err().unwrap().join("\n");
        assert!(s.contains("sip: unknown section"), "{s}");
    }

    #[test]
    fn reload_plan() {
        const TMR: &[ParamSpec] = &[schema::pr("fr_timer", Ty::Duration(Unit::Ms), "30s", ""), schema::p("max_branches", schema::UINT, "", "")];
        let of = |m: &str| match m {
            "tm" => Some(Some(TMR.to_vec())),
            _ => schema_of(m),
        };
        let a = load(&write("r1.toml", "[core]\nworkers = 2\n[modules.txn]\nfr_timer = \"10s\"\nmax_branches = 2\n"), &[], &[]).unwrap();
        let running = Running::of(&a, &modules(&a, &of).unwrap());
        let b = load(&write("r2.toml", "[core]\nworkers = 4\n[modules.txn]\nfr_timer = \"5s\"\nmax_branches = 3\n[modules.dialog]\n"), &[], &[]).unwrap();
        let p = reload_diff(&running, &b, &modules(&b, &of).unwrap(), &of);
        assert_eq!(p.apply.len(), 1);
        assert_eq!((p.apply[0].1.as_str(), p.apply[0].2[0].int().unwrap()), ("fr_timer", 5000));
        assert!(
            p.restart.contains(&"tm.max_branches".to_string())
                && p.restart.contains(&"core.workers".to_string())
                && p.restart.contains(&"module dialog added".to_string()),
            "{:?}",
            p.restart
        );
        // fr_timer taken out of the file: back to its default.
        let c = load(&write("r3.toml", "[core]\nworkers = 2\n[modules.txn]\nmax_branches = 2\n"), &[], &[]).unwrap();
        let p = reload_diff(&running, &c, &modules(&c, &of).unwrap(), &of);
        assert_eq!((p.apply[0].2[0].int().unwrap(), p.restart.len()), (30_000, 0), "{p:?}");
        // Nothing changed: nothing to do.
        let p = reload_diff(&running, &a, &modules(&a, &of).unwrap(), &of);
        assert!(p.apply.is_empty() && p.restart.is_empty());
    }

    #[test]
    fn core_listen_tls_routing() {
        let l = load(
            &write("c.toml", "[core]\nlog_level = \"debug\"\nshutdown_timeout = \"10s\"\n[[listen]]\nproto = \"tls\"\naddr = \"0.0.0.0:5061\"\ntls = \"edge\"\n[tls.edge]\ncert = \"c.pem\"\nkey = \"k.pem\"\n[routing]\nentry = \"routes/main.cfg\"\n"),
            &[],
            &[],
        )
        .unwrap();
        let s = settings(&l).unwrap();
        assert_eq!(s.core.int("log_level"), Some(3));
        assert_eq!(s.core.int("shutdown_timeout"), Some(10));
        assert_eq!((s.listen[0].proto.as_str(), s.listen[0].tls.as_deref()), ("tls", Some("edge")));
        assert!(s.tls["edge"].contains_key("cert"));
        assert!(s.entry.unwrap().ends_with("routes/main.cfg"));
        let l = load(&write("f.toml", "[routing]\nentry = \"main.fsr\"\n[core]\nworkerz = 1\n"), &[], &[]).unwrap();
        let e = settings(&l).err().unwrap().join("\n");
        assert!(e.contains("core.workerz: unknown key (did you mean \"workers\"?)"), "{e}");
        let out = explain(
            &load(&write("x.toml", "[modules.txn]\nmax_branches = 2\n"), &[], &[]).unwrap(),
            &modules(&load(&write("x.toml", "[modules.txn]\nmax_branches = 2\n"), &[], &[]).unwrap(), &schema_of).unwrap(),
            &schema_of,
        );
        assert!(out.contains("modules.txn.max_branches = 2") && out.contains("tm (txn)") && out.contains("fr_timer = 30s  # default"), "{out}");
    }
    /// The config `text` loaded with `env` (no overlays or `--set`).
    fn load_text(name: &str, text: &str, env: Env) -> Result<Layered, String> {
        load_with_env(&write(name, text), &[], &[], env)
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn interpolation_forms() {
        let env = |n: &str| match n {
            "HOST" => Some("h.example".to_string()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        let l = load_text(
            "i.toml",
            "[feature]\nport = 5070\nnat = true\nname = \"edge\"\n[x]\n\
             env = \"${HOST}\"\nboth = \"sip:${HOST}:${feature.port}\"\nint = \"${feature.port}\"\nbool = \"${feature.nat}\"\n\
             default = \"${NOPE:-fallback}\"\nempty_default = \"${EMPTY:-d}\"\nempty_default_value = \"${NOPE:-}\"\n\
             list = [\"${feature.name}\", \"${HOST}\"]\nliteral = \"no placeholder $HOST {x}\"\nbool_in_text = \"nat=${feature.nat}\"\n",
            &env,
        )
        .unwrap();
        let x = &l.table["x"];
        assert_eq!(x["env"].as_str(), Some("h.example"));
        assert_eq!(x["both"].as_str(), Some("sip:h.example:5070"));
        assert_eq!(x["int"].as_integer(), Some(5070), "one placeholder keeps the int");
        assert_eq!(x["bool"].as_bool(), Some(true));
        assert_eq!(x["default"].as_str(), Some("fallback"));
        assert_eq!(x["empty_default"].as_str(), Some("d"), "an empty variable takes the default");
        assert_eq!(x["empty_default_value"].as_str(), Some(""));
        assert_eq!(x["list"].as_array().map(|a| a.iter().filter_map(T::as_str).collect::<Vec<_>>()), Some(vec!["edge", "h.example"]));
        assert_eq!(x["literal"].as_str(), Some("no placeholder $HOST {x}"));
        assert_eq!(x["bool_in_text"].as_str(), Some("nat=true"));
    }

    #[test]
    fn interpolation_errors_name_the_key() {
        let cases = [
            ("[a]\nb = \"${UNSET_X}\"\n", "a.b: environment variable UNSET_X is not set (write ${UNSET_X:-default} for a fallback)"),
            ("[a]\nb = \"x${feature.none}\"\n", "a.b: ${feature.none} refers to nothing in the configuration"),
            ("[a]\nb = \"x${UNCLOSED\"\n", "a.b: unclosed ${ in \"x${UNCLOSED\""),
            ("[a]\nb = [\"ok\", \"${UNSET_Y}\"]\n", "a.b[1]: environment variable UNSET_Y is not set"),
            ("[feature]\nt = { k = 1 }\n[a]\nb = \"x${feature.t}\"\n", "a.b: ${feature.t} is not a scalar"),
        ];
        for (text, want) in cases {
            let e = load_text("ie.toml", text, &no_env).err().unwrap_or_default();
            assert!(e.contains(want), "{text}: {e}");
        }
    }

    #[test]
    fn a_feature_read_through_interpolation_is_interpolated_too() {
        let env = |n: &str| (n == "PUBLIC_IP").then(|| "198.51.100.4".to_string());
        let l = load_text(
            "chain.toml",
            "[feature]\nip = \"${PUBLIC_IP}\"\nport = \"${SIP_PORT:-5060}\"\n[core]\nadvertise = \"${feature.ip}\"\n[x]\naddr = \"${feature.ip}:${feature.port}\"\n",
            &env,
        )
        .unwrap();
        assert_eq!(l.table["core"]["advertise"].as_str(), Some("198.51.100.4"));
        assert_eq!(l.table["x"]["addr"].as_str(), Some("198.51.100.4:5060"));
        let e = load_text("cycle.toml", "[feature]\na = \"${feature.b}\"\nb = \"${feature.a}\"\n", &no_env).err().unwrap_or_default();
        assert!(e.contains("refers to itself"), "{e}");
    }

    #[test]
    fn a_config_path_with_a_default() {
        let l = load_text("pd.toml", "[feature]\nport = 5070\n[x]\nset = \"${feature.port:-5060}\"\nunset = \"${feature.nope:-5060}\"\n", &no_env).unwrap();
        assert_eq!(l.table["x"]["set"].as_integer(), Some(5070), "the configured value wins over the default");
        assert_eq!(l.table["x"]["unset"].as_str(), Some("5060"));
    }

    #[test]
    fn set_values_are_toml_or_strings() {
        let cases: [(&str, T); 9] = [
            ("a.b=10", T::Integer(10)),
            ("a.b= 4", T::Integer(4)),
            ("a.b=true", T::Boolean(true)),
            ("a.b=\"q\"", T::String("q".into())),
            ("a.b=10s", T::String("10s".into())),
            ("a.b=10.0.0.1", T::String("10.0.0.1".into())),
            ("a.b=", T::String(String::new())),
            ("a.b=x=y", T::String("x=y".into())),
            ("a.b=[1, 2]", T::Array(vec![T::Integer(1), T::Integer(2)])),
        ];
        for (s, want) in cases {
            let (keys, v) = parse_set(s).unwrap();
            assert_eq!(keys, ["a", "b"], "{s}");
            assert_eq!(v, want, "{s}");
        }
        for bad in ["novalue", "a..b=1", "=1", ".a=1"] {
            assert!(parse_set(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn layers_merge_tables_and_replace_the_rest() {
        let base = write(
            "lb.toml",
            "[core]\nworkers = 2\naliases = [\"a\", \"b\"]\n[[listen]]\nproto = \"udp\"\naddr = \"1.1.1.1:5060\"\n[modules.txn]\nfr_timer = \"5s\"\n",
        );
        let o1 = write("lo1.toml", "[core]\naliases = [\"c\"]\n[[listen]]\nproto = \"tcp\"\naddr = \"2.2.2.2:5060\"\n");
        let o2 = write("lo2.toml", "[core]\nworkers = 3\n");
        let l = load_with_env(&base, &[o1.clone(), o2.clone()], &["core.workers=9".into(), "modules.txn.max_branches=2".into()], &no_env).unwrap();
        assert_eq!(l.table["core"]["workers"].as_integer(), Some(9), "--set comes last");
        assert_eq!(l.table["core"]["aliases"].as_array().map(Vec::len), Some(1), "arrays are replaced");
        assert_eq!(l.table["listen"].as_array().map(Vec::len), Some(1), "[[listen]] is replaced as a whole");
        assert_eq!(l.table["modules"]["txn"]["fr_timer"].as_str(), Some("5s"), "tables merge key by key");
        let src = |k: &str| l.sources.get(k).cloned().unwrap_or_default();
        assert_eq!(src("core.workers"), "--set");
        assert_eq!(src("core.aliases"), o1.display().to_string());
        assert_eq!(src("listen"), o1.display().to_string());
        assert_eq!(src("modules.txn.fr_timer"), base.display().to_string());
        assert_eq!(src("modules.txn.max_branches"), "--set");
        assert!(l.dir.ends_with(base.parent().unwrap().file_name().unwrap()));
    }

    #[test]
    fn unknown_keys_suggest_the_closest() {
        let cases = [
            ("[core]\nworkrs = 1\n", "core.workrs: unknown key (did you mean \"workers\"?)"),
            ("[modules.txn]\nmax_brances = 2\n", "unknown parameter \"max_brances\" for txn (did you mean \"max_branches\"?)"),
            ("[modules.locaton]\n", "unknown module \"locaton\" (did you mean \"location\"?)"),
            ("[modules.txn]\nenabled = \"yes\"\n", "modules.txn.enabled: expected true or false"),
            ("[modules]\ntxn = 1\n", "modules.txn: expected a table"),
            ("[modules.txn]\nkamailio = 1\n", "modules.txn.kamailio: expected a table"),
            ("[modules.dialog]\nx = 1.5\n", "modules.dialog.x: 1.5: a fractional number is not a module parameter"),
        ];
        for (text, want) in cases {
            let l = load_text("uk.toml", text, &no_env).unwrap();
            let errs = match modules(&l, &schema_of) {
                Ok(_) => settings(&l).err().unwrap_or_default(),
                Err(e) => e,
            }
            .join("\n");
            assert!(errs.contains(want), "{text}: {errs}");
        }
    }

    #[test]
    fn dependency_order_is_stable_and_complete() {
        let of = |m: &str| -> Option<Option<Vec<ParamSpec>>> {
            matches!(m, "tm" | "usrloc" | "registrar" | "dialog" | "dispatcher" | "acc" | "nathelper" | "presence" | "presence_xml" | "pua" | "pua_dialoginfo")
                .then_some(None)
        };
        let extra: Vec<(String, String)> =
            ["presence_xml", "pua_dialoginfo", "acc", "dispatcher", "nathelper", "registrar"].iter().map(|m| (m.to_string(), "script".to_string())).collect();
        let plan = add_modules(Vec::new(), &extra, &of).unwrap();
        let names: Vec<&str> = plan.iter().map(|m| m.name.as_str()).collect();
        let pos = |m: &str| names.iter().position(|n| *n == m).unwrap_or_else(|| panic!("{m} missing from {names:?}"));
        for (m, before) in [
            ("registrar", "usrloc"),
            ("dialog", "tm"),
            ("acc", "dialog"),
            ("dispatcher", "dialog"),
            ("nathelper", "usrloc"),
            ("presence_xml", "presence"),
            ("pua_dialoginfo", "pua"),
            ("pua_dialoginfo", "dialog"),
        ] {
            assert!(pos(before) < pos(m), "{before} before {m}: {names:?}");
        }
        assert_eq!(plan[pos("usrloc")].why, "needed by registrar");
        let again: Vec<String> = add_modules(Vec::new(), &extra, &of).unwrap().into_iter().map(|m| m.name).collect();
        assert_eq!(again, names, "the same order every time");
        let e = add_modules(Vec::new(), &[("registrar".into(), "x".into())], &|m| (m == "registrar").then_some(None)).err().unwrap_or_default();
        assert_eq!(e, "registrar needs usrloc, which this build doesn't have");
    }

    #[test]
    fn aliases_and_deps_are_consistent() {
        let mut seen = BTreeSet::new();
        for a in ALIASES {
            assert!(seen.insert(a.name), "{} twice", a.name);
            assert!(!a.always.is_empty() || !a.optional.is_empty(), "{} loads nothing", a.name);
        }
        for (m, ds) in DEPS {
            assert!(!ds.contains(m), "{m} depends on itself");
        }
        assert_eq!(deps("registrar"), ["usrloc"]);
        assert!(deps("nothing").is_empty());
    }
}
