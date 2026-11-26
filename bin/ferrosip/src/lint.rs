//! `ferrosip lint`: clippy-style lints for ferrosip.toml and the routing
//! (`.fsr` or `.cfg`). The catalogue and the `.fsr` lints are in
//! `fsr::lint`; here: ferrosip.toml and `.cfg` lints, the routing-wide
//! ones (open relay, …), levels, `lint: allow(…)` comments, output and
//! `--fix`.

use crate::config;
use fsr::lint::{self as fl, Finding, Fix, Group, LINTS, Level};
use sip_core::schema::{self, ParamSpec, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

const USAGE: &str = "usage: ferrosip lint [--config ferrosip.toml] [-f ROUTING] [options]
       ferrosip lint --explain LINT | --list [--markdown]
  --config FILE        ferrosip.toml (default: ./ferrosip.toml when there is one); its
                       [routing] entry is linted too
  -f FILE              routing script (.fsr or .cfg) without --config
  --overlay FILE       merged over --config, as when running (repeatable)
  --set KEY=VALUE      a value over --config, as when running (repeatable)
  -W NAME, -A NAME, -D NAME
                       warn / allow / deny a lint or a group (correctness, suspicious,
                       security, style, pedantic); `-D warnings` turns warnings into errors
  --fix                apply the suggested fixes, then lint again
  --format json        one JSON object per finding (for editors and CI)
  --define NAME[=VAL]  preprocessor define for a .cfg (repeatable)
Silence one place with a comment on the line before it (or at its end):
  // lint: allow(unused_variable)        (.fsr)      # lint: allow(open_relay)   (.cfg, toml)
or everywhere with [lint] allow = [\"…\"] / warn = […] / deny = […] in ferrosip.toml.";

struct Opts {
    toml: Option<PathBuf>,
    routing: Option<String>,
    levels: Vec<(String, Level)>,
    fix: bool,
    json: bool,
    defines: Vec<(String, String)>,
    overlays: Vec<PathBuf>,
    sets: Vec<String>,
}

/// A source file as read, for positions and fixes.
struct Files(BTreeMap<String, String>);

impl Files {
    fn text(&mut self, f: &str) -> &str {
        self.0.entry(f.to_string()).or_insert_with(|| std::fs::read_to_string(f).unwrap_or_default())
    }

    /// Byte span of line `n` (1-based), without the newline.
    fn line(&mut self, f: &str, n: usize) -> (usize, usize) {
        let t = self.text(f);
        let start: usize = t.split_inclusive('\n').take(n.saturating_sub(1)).map(str::len).sum();
        let end = t.get(start..).and_then(|r| r.find('\n')).map_or(t.len(), |i| start.saturating_add(i));
        (start, end)
    }

    /// Byte span of a whole line, with its newline (to delete it).
    fn whole_line(&mut self, f: &str, n: usize) -> (usize, usize) {
        let (s, e) = self.line(f, n);
        let len = self.text(f).len();
        (s, e.saturating_add(1).min(len))
    }
}

fn finding(lint: &'static str, file: &str, span: (usize, usize), msg: String, help: Option<String>, fixes: Vec<Fix>) -> Finding {
    Finding { lint, file: file.to_string(), start: span.0, end: span.1, msg, help, fixes }
}

// --------------------------------------------------------- ferrosip.toml ---

/// The schema of `[modules.<sec>] <key>`.
fn spec_of(sec: &str, key: &str) -> Option<ParamSpec> {
    let members: Vec<&str> = match config::ALIASES.iter().find(|a| a.name == sec) {
        Some(a) => a.always.iter().chain(a.optional).copied().collect(),
        None => vec![sec],
    };
    members.iter().find_map(|m| crate::schema_of(m).flatten()?.into_iter().find(|p| p.name == key))
}

/// A schema default (as written in ferrosip.toml) as a value.
fn default_value(spec: &ParamSpec) -> Option<Value> {
    if spec.default.is_empty() {
        return None;
    }
    let v = format!("v = {}", spec.default).parse::<toml::Table>().ok().and_then(|t| t.get("v").cloned());
    match v {
        Some(v) => config::neutral(&v).ok(),
        None => Some(Value::Str(spec.default.to_string())),
    }
}

fn same_value(spec: &ParamSpec, a: &Value, b: &Value) -> bool {
    match (schema::convert(spec, a), schema::convert(spec, b)) {
        (Ok(x), Ok(y)) => format!("{x:?}") == format!("{y:?}"),
        _ => false,
    }
}

/// The line of `key` in `[sec_path]` (`modules.txn`), or of a dotted
/// `sec.key =` anywhere.
fn toml_line(text: &str, sec_path: &str, key: &str) -> Option<usize> {
    let mut in_sec = false;
    let starts = |l: &str, k: &str| l.strip_prefix(k).is_some_and(|r| r.trim_start().starts_with('='));
    for (i, raw) in text.lines().enumerate() {
        let l = raw.trim();
        if l.starts_with('[') {
            let head = l.split('#').next().unwrap_or("").trim();
            in_sec = head.trim_matches(['[', ']']).trim() == sec_path;
            continue;
        }
        if (in_sec && (starts(l, key) || starts(l, &format!("\"{key}\"")))) || starts(l, &format!("{sec_path}.{key}")) {
            return Some(i.saturating_add(1));
        }
    }
    None
}

fn is_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    let skip = ["_file", "_column", "_col", "_path", "_avp", "_header", "_param", "_flag", "_len", "_size", "_type", "_mode", "_name"];
    if skip.iter().any(|s| k.ends_with(s)) {
        return false;
    }
    ["password", "passwd", "secret", "token", "api_key", "apikey"].iter().any(|w| k.contains(w)) || k.ends_with("_key")
}

/// `scheme://user:password@host` with a password.
fn url_password(v: &str) -> bool {
    let Some((_, rest)) = v.split_once("://") else { return false };
    let auth = rest.split('/').next().unwrap_or("");
    let Some((cred, _)) = auth.rsplit_once('@') else { return false };
    cred.split_once(':').is_some_and(|(_, p)| !p.is_empty())
}

fn lint_toml(path: &Path, l: &config::Layered, used_features: Option<&BTreeSet<String>>, files: &mut Files, out: &mut Vec<Finding>) {
    let name = path.display().to_string();
    let text = files.text(&name).to_string();
    // The file as written (values before ${…} interpolation).
    let raw: toml::Table = text.parse().unwrap_or_default();
    let modules = raw.get("modules").and_then(|m| m.as_table());
    for (sec, body) in modules.into_iter().flatten() {
        for (key, v) in body.as_table().into_iter().flatten() {
            let line = toml_line(&text, &format!("modules.{sec}"), key);
            let at = |files: &mut Files| line.map_or((0, 0), |n| files.line(&name, n));
            // redundant_default (on the interpolated value).
            let effective = l.table.get("modules").and_then(|m| m.get(sec)).and_then(|b| b.get(key));
            if let (Some(spec), Some(eff)) = (spec_of(sec, key), effective)
                && let (Some(d), Ok(val)) = (default_value(&spec), config::neutral(eff))
                && same_value(&spec, &val, &d)
                && !matches!(v, toml::Value::String(s) if s.contains("${"))
            {
                let fixes = match line {
                    Some(n) if n.checked_sub(1).and_then(|k| text.lines().nth(k)).is_some_and(|t| t.trim_start().starts_with(key.as_str())) => {
                        let (s, e) = files.whole_line(&name, n);
                        vec![Fix { start: s, end: e, text: String::new() }]
                    }
                    _ => vec![],
                };
                out.push(finding(
                    "redundant_default",
                    &name,
                    at(files),
                    format!("modules.{sec}.{key} is set to its default ({})", spec.default),
                    Some("remove the line".into()),
                    fixes,
                ));
            }
            secrets(&name, &format!("modules.{sec}"), key, v, &text, files, out);
        }
    }
    for (sec, body) in raw.get("tls").and_then(|t| t.as_table()).into_iter().flatten() {
        for (key, v) in body.as_table().into_iter().flatten() {
            secrets(&name, &format!("tls.{sec}"), key, v, &text, files, out);
        }
    }
    // unused_feature
    if let Some(used) = used_features {
        for key in raw.get("feature").and_then(|f| f.as_table()).into_iter().flatten().map(|(k, _)| k) {
            if used.contains(key) || text.contains(&format!("${{feature.{key}")) {
                continue;
            }
            let at = toml_line(&text, "feature", key).map_or((0, 0), |n| files.line(&name, n));
            out.push(finding(
                "unused_feature",
                &name,
                at,
                format!("feature `{key}` is never read"),
                Some(format!("read it as `features.{key}`, or remove it")),
                vec![],
            ));
        }
    }
}

fn secrets(name: &str, sec: &str, key: &str, v: &toml::Value, text: &str, files: &mut Files, out: &mut Vec<Finding>) {
    let strs: Vec<&str> = match v {
        toml::Value::String(s) => vec![s],
        toml::Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
        _ => vec![],
    };
    for s in strs {
        if s.is_empty() || s.contains("${") {
            continue;
        }
        let looks_like_path = s.starts_with('/') || s.starts_with("./") || s.ends_with(".pem") || s.ends_with(".key");
        let hit = if url_password(s) {
            Some(format!("{sec}.{key} has a password in its URL"))
        } else if is_secret_key(key) && !looks_like_path {
            Some(format!("{sec}.{key} is written in the file"))
        } else {
            None
        };
        if let Some(msg) = hit {
            let at = toml_line(text, sec, key).map_or((0, 0), |n| files.line(name, n));
            out.push(finding("plaintext_secret", name, at, msg, Some("read it from the environment: `\"${DB_PASSWORD}\"`".into()), vec![]));
        }
    }
}

// ------------------------------------------------------------------ .cfg ---

/// `file:line` (from `Preprocessed::locate`) → (file, line).
fn split_loc(loc: &str) -> Option<(String, usize)> {
    let (f, n) = loc.rsplit_once(':')?;
    Some((f.to_string(), n.parse().ok()?))
}

/// Route names used: (route kind, name); [`ANY_ROUTE`] when the kind is
/// unknown, which counts for every kind.
type Used = BTreeSet<(&'static str, String)>;
const ANY_ROUTE: &str = "*";

struct CfgFacts {
    facts: Vec<fl::Fact>,
}

fn cfg_walk(stmts: &[sip_script::Stmt], loc: &dyn Fn(usize) -> Option<(String, usize)>, files: &mut Files, f: &mut CfgFacts, used: &mut Used) {
    use sip_script::{Expr, RawArg, Stmt};
    fn expr(e: &Expr, loc: &dyn Fn(usize) -> Option<(String, usize)>, files: &mut Files, f: &mut CfgFacts, used: &mut Used) {
        match e {
            Expr::Call { name, args, line } => {
                // t_on_* arm a route of their own kind; a name given to any
                // other function (t_continue, async_route, …) may be any kind.
                let kind = match name.as_str() {
                    "t_on_failure" => "failure_route",
                    "t_on_branch" => "branch_route",
                    "t_on_reply" => "onreply_route",
                    _ => ANY_ROUTE,
                };
                for a in args {
                    if let RawArg::Str(s) = a {
                        used.insert((kind, s.clone()));
                    }
                }
                if let Some((file, n)) = loc(*line) {
                    let (s, e) = files.line(&file, n);
                    let what = if name.starts_with("mf_process") || name == "maxfwd_process" { "@max_forwards".to_string() } else { name.clone() };
                    // A check called on the source address (`is_in_subnet("$si", …)`).
                    if args.iter().any(|a| matches!(a, RawArg::Str(s) | RawArg::Pv(s) if s.contains("$si") || s.contains("$srcip"))) {
                        f.facts.push(fl::Fact { what: "@src_check".into(), file: file.clone(), start: s, end: e });
                    }
                    f.facts.push(fl::Fact { what, file, start: s, end: e });
                }
            }
            Expr::Route(n, _) => {
                used.insert(("route", n.clone()));
            }
            Expr::Not(x) | Expr::Neg(x) => expr(x, loc, files, f, used),
            Expr::Bin(op, a, b) => {
                use sip_script::BinOp::*;
                let si = |x: &Expr| matches!(x, Expr::Pv(p, _) if p == "$si" || p == "$srcip");
                if matches!(op, Eq | Ne | Match | NoMatch)
                    && (si(a) || si(b))
                    && let Some((file, n)) = [a, b].iter().find_map(|x| if let Expr::Pv(_, l) = &***x { loc(*l) } else { None })
                {
                    let (s, e) = files.line(&file, n);
                    f.facts.push(fl::Fact { what: "@src_check".into(), file, start: s, end: e });
                }
                expr(a, loc, files, f, used);
                expr(b, loc, files, f, used);
            }
            Expr::Str(_) | Expr::Int(_) | Expr::Pv(..) | Expr::Myself => {}
        }
    }
    for s in stmts {
        match s {
            Stmt::If(c, a, b) => {
                expr(c, loc, files, f, used);
                cfg_walk(a, loc, files, f, used);
                cfg_walk(b, loc, files, f, used);
            }
            Stmt::While(c, b) => {
                expr(c, loc, files, f, used);
                cfg_walk(b, loc, files, f, used);
            }
            Stmt::Switch(e, cases) => {
                expr(e, loc, files, f, used);
                for (v, b) in cases {
                    if let Some(v) = v {
                        expr(v, loc, files, f, used);
                    }
                    cfg_walk(b, loc, files, f, used);
                }
            }
            Stmt::Assign(_, e, _) | Stmt::Expr(e) | Stmt::Return(Some(e)) => expr(e, loc, files, f, used),
            Stmt::Exit | Stmt::Drop | Stmt::Return(None) | Stmt::Break => {}
        }
    }
}

struct Routing {
    facts: Vec<fl::Fact>,
    allows: Vec<fl::Allow>,
    entry: Option<(String, usize, usize)>,
    features: Option<BTreeSet<String>>,
}

fn lint_cfg(file: &str, defines: &[(String, String)], files: &mut Files, out: &mut Vec<Finding>) -> Result<Routing, String> {
    let pp = sip_script::preprocess::preprocess_file(file, defines)?;
    let ast = sip_script::parse(&pp.text).map_err(|e| pp.locate_error(&e))?;
    let loc = |n: usize| split_loc(&pp.locate(n));
    let mut facts = CfgFacts { facts: vec![] };
    let mut used = BTreeSet::new();
    cfg_walk(&ast.request_route, &loc, files, &mut facts, &mut used);
    for (_, body) in ast.routes.iter().chain(&ast.failure_routes).chain(&ast.onreply_routes).chain(&ast.branch_routes).chain(&ast.event_routes) {
        cfg_walk(body, &loc, files, &mut facts, &mut used);
    }
    if let Some(r) = &ast.reply_route {
        cfg_walk(r, &loc, files, &mut facts, &mut used);
    }
    for p in &ast.modparams {
        if let sip_script::RawArg::Str(s) = &p.value {
            // rtimer exec "route=NAME", …
            used.extend(s.split([';', '=', ' ', ',']).map(|w| (ANY_ROUTE, w.to_string())));
        }
    }
    // The line each route header is on.
    let header = |kind: &str, name: &str| -> Option<usize> {
        let pat = format!("{kind}[{name}]");
        // `route[X]` is not the end of `failure_route[X]`.
        let found =
            |l: &str| l.match_indices(&pat).any(|(i, _)| !l.get(..i).and_then(|b| b.chars().last()).is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'));
        pp.text.lines().position(|l| found(&l.replace(' ', ""))).map(|i| i.saturating_add(1))
    };
    for (kind, list) in
        [("route", &ast.routes), ("failure_route", &ast.failure_routes), ("branch_route", &ast.branch_routes), ("onreply_route", &ast.onreply_routes)]
    {
        for (name, _) in list.iter().filter(|(n, _)| !used.contains(&(kind, n.clone())) && !used.contains(&(ANY_ROUTE, n.clone()))) {
            let Some((f, n)) = header(kind, name).and_then(loc) else { continue };
            let at = files.line(&f, n);
            out.push(finding("unused_route", &f, at, format!("{kind}[{name}] is never used"), Some("nothing calls or arms it: remove it".into()), vec![]));
        }
    }
    // modparam set to its default.
    for p in &ast.modparams {
        let Some(spec) = crate::schema_of(&p.module).flatten().and_then(|s| s.into_iter().find(|s| s.name == p.name)) else { continue };
        let val = match &p.value {
            sip_script::RawArg::Str(s) => Value::Str(s.clone()),
            sip_script::RawArg::Int(i) => Value::Int(*i),
            sip_script::RawArg::Pv(_) => continue,
        };
        let Some(d) = default_value(&spec) else { continue };
        // A modparam passes Kamailio's raw value; the default is in
        // ferrosip.toml's terms (Bool → 1/0, durations…): compare converted.
        let as_toml = match (&spec.ty, &val) {
            (schema::Ty::Bool, Value::Int(i)) => Value::Bool(*i != 0),
            _ => val.clone(),
        };
        if same_value(&spec, &as_toml, &d)
            && let Some((f, n)) = loc(p.line)
        {
            let at = files.line(&f, n);
            let whole = files.whole_line(&f, n);
            let only = files.text(&f).get(at.0..at.1).is_some_and(|l| l.trim().starts_with("modparam"));
            out.push(finding(
                "redundant_default",
                &f,
                at,
                format!("modparam {}.{} is set to its default ({})", p.module, p.name, spec.default),
                Some("remove the line".into()),
                if only { vec![Fix { start: whole.0, end: whole.1, text: String::new() }] } else { vec![] },
            ));
        }
    }
    let entry = pp.text.lines().position(|l| l.trim_start().starts_with("request_route")).and_then(|i| loc(i.saturating_add(1))).map(|(f, n)| {
        let (s, e) = files.line(&f, n);
        (f, s, e)
    });
    let mut srcs: BTreeSet<String> = BTreeSet::new();
    for i in 1..=pp.text.lines().count() {
        if let Some((f, _)) = loc(i) {
            srcs.insert(f);
        }
    }
    let allows = srcs.iter().flat_map(|f| line_allows(f, files)).collect();
    Ok(Routing { facts: facts.facts, allows, entry, features: None })
}

/// `# lint: allow(x)` / `// lint: allow(x)`: that line and the next.
fn line_allows(file: &str, files: &mut Files) -> Vec<fl::Allow> {
    let text = files.text(file).to_string();
    let mut out = vec![];
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    // Byte offsets into `text`: the saturating adds never clamp.
    let mut off: usize = 0;
    for (i, l) in lines.iter().enumerate() {
        let c = l.find("lint:").and_then(|p| l.get(p..));
        if let Some(names) = c.and_then(|c| fl::parse_allow(c.trim_end())) {
            let mut end = off.saturating_add(l.len());
            // A comment on its own line covers the next line.
            if l.trim_start().starts_with(['#', '/']) {
                end = end.saturating_add(lines.get(i.saturating_add(1)).map_or(0, |n| n.len()));
            }
            out.push(fl::Allow { file: file.to_string(), start: off, end, names });
        }
        off = off.saturating_add(l.len());
    }
    out
}

// ----------------------------------------------------------- .fsr glue ---

fn lint_fsr(file: &str, features: &crate::Features, toml_tables: BTreeSet<String>, out: &mut Vec<Finding>, files: &mut Files) -> Result<Routing, String> {
    let mut env = crate::fsr_env(features.clone());
    env.toml_tables = toml_tables;
    let path = Path::new(file);
    // Lints assume code that compiles.
    fsr::compile_file(path, &env).map_err(|e| {
        let n = e.0.len();
        format!("{n} error{} in the routing (fix them first):\n{e}", if n == 1 { "" } else { "s" })
    })?;
    let (sources, _) = fsr::load(path).map_err(|e| e.to_string())?;
    for s in &sources {
        files.0.insert(s.name.clone(), s.text.clone());
    }
    let mut r = fl::lint(&sources, &env);
    out.extend(r.findings);
    // Also by line: `while true {  // lint: allow(infinite_loop)`.
    for s in &sources {
        r.allows.extend(line_allows(&s.name, files));
    }
    Ok(Routing { facts: r.facts, allows: r.allows, entry: r.entry, features: Some(r.features) })
}

// ------------------------------------------------------- routing-wide ---

fn is_relay(f: &str) -> bool {
    f.starts_with("t_relay") || f == "forward" || f.starts_with("t_forward") || f == "forward_tcp" || f == "forward_udp" || f == "forward_tls"
}

fn is_auth(f: &str) -> bool {
    f.contains("authorize")
        || f.contains("authorization")
        || f.contains("authenticate")
        || f.contains("auth_check")
        || f.contains("auth_challenge")
        || f.starts_with("autheph")
}

fn is_restriction(f: &str) -> bool {
    is_auth(f) || f == "@src_check" || f.starts_with("allow_") || f == "ds_is_from_list" || f.starts_with("is_from_") || f == "check_route_param"
}

fn lint_routing(r: &Routing, out: &mut Vec<Finding>) {
    let has = |p: &dyn Fn(&str) -> bool| r.facts.iter().find(|f| p(&f.what));
    let at = |f: &fl::Fact| (f.start, f.end);
    let Some(relay) = has(&|f| is_relay(f)) else {
        // Nothing relayed: only REGISTER matters.
        if let Some(save) = has(&|f| f == "save")
            && has(&|f| is_restriction(f)).is_none()
        {
            out.push(finding(
                "register_without_auth",
                &save.file,
                at(save),
                "registrations are saved without authentication".into(),
                Some("challenge REGISTER first (auth.www_challenge / auth.check)".into()),
                vec![],
            ));
        }
        return;
    };
    if has(&|f| f == "@max_forwards").is_none() {
        let (file, s, e) = r.entry.clone().unwrap_or((relay.file.clone(), relay.start, relay.end));
        out.push(finding(
            "missing_max_forwards",
            &file,
            (s, e),
            "requests are relayed without checking Max-Forwards".into(),
            Some("start with `guard msg.max_forwards > 0 else reply(TooManyHops)` (.cfg: `if (!mf_process_maxfwd_header(10)) { sl_send_reply(483, \"Too Many Hops\"); exit; }`)".into()),
            vec![],
        ));
    }
    if let Some(save) = has(&|f| f == "save")
        && has(&|f| is_restriction(f)).is_none()
    {
        out.push(finding(
            "register_without_auth",
            &save.file,
            at(save),
            "registrations are saved without authentication".into(),
            Some("challenge REGISTER first (auth.www_challenge / auth.check)".into()),
            vec![],
        ));
    }
    if has(&|f| is_restriction(f)).is_none() {
        out.push(finding(
            "open_relay",
            &relay.file,
            at(relay),
            "anyone can send requests through this relay".into(),
            Some("authenticate callers, or check msg.src.ip / permissions / the dispatcher list first".into()),
            vec![],
        ));
    }
    if let Some(rr) = has(&|f| f.starts_with("record_route"))
        && has(&|f| f == "loose_route").is_none()
    {
        out.push(finding(
            "record_route_without_loose_route",
            &rr.file,
            at(rr),
            "Record-Route is added, but in-dialog requests never follow Route headers".into(),
            Some("handle in-dialog requests with `rr.follow()` (.cfg: `loose_route()`)".into()),
            vec![],
        ));
    }
}

// ---------------------------------------------------------------- levels ---

struct Levels(Vec<(String, Level)>);

impl Levels {
    fn of(&self, lint: &fl::LintInfo) -> Level {
        let mut lvl = lint.group.level();
        for (n, l) in &self.0 {
            if n == lint.name || n == lint.group.name() || (n == "warnings" && lvl == Level::Warn && *l == Level::Deny) {
                lvl = *l;
            }
        }
        lvl
    }

    fn check(names: &[(String, Level)]) -> Result<(), String> {
        let known: Vec<&str> = LINTS.iter().map(|l| l.name).chain(Group::ALL.iter().map(|g| g.name())).chain(["warnings"]).collect();
        for (n, _) in names {
            if !known.contains(&n.as_str()) {
                return Err(format!("unknown lint {n:?}{}", schema::suggest(n, known.iter().copied())));
            }
        }
        Ok(())
    }
}

fn toml_levels(l: &config::Layered) -> Result<Vec<(String, Level)>, String> {
    let mut out = vec![];
    let Some(t) = l.table.get("lint") else { return Ok(out) };
    let t = t.as_table().ok_or("lint: expected a table ([lint])")?;
    for (k, v) in t {
        let lvl = match k.as_str() {
            "allow" => Level::Allow,
            "warn" => Level::Warn,
            "deny" => Level::Deny,
            _ => return Err(format!("lint.{k}: expected allow, warn or deny")),
        };
        let names = v.as_array().ok_or(format!("lint.{k}: expected a list of lint names"))?;
        for n in names {
            out.push((n.as_str().ok_or(format!("lint.{k}: expected names"))?.to_string(), lvl));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- output ---

struct Paint(bool);

impl Paint {
    fn c(&self, code: &str, s: &str) -> String {
        if self.0 { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
}

fn line_col(text: &str, at: usize) -> (usize, usize) {
    fsr::lexer::line_col(text, at)
}

fn render(f: &Finding, lvl: Level, first: bool, files: &mut Files, p: &Paint) -> String {
    let text = files.text(&f.file).to_string();
    let (line, col) = line_col(&text, f.start);
    let src = text.lines().nth(line.saturating_sub(1)).unwrap_or("");
    let width = text.get(f.start..f.end.max(f.start)).and_then(|s| s.lines().next()).map_or(1, |l| l.chars().count().max(1));
    let gutter = line.to_string().len();
    let pad = " ".repeat(gutter);
    let bar = p.c("1;34", "|");
    let (label, color) = if lvl == Level::Deny { ("error", "1;31") } else { ("warning", "1;33") };
    let mut s = format!("{}{} {}\n", p.c(color, label), p.c("1", ":"), p.c("1", &f.msg));
    s.push_str(&format!("{pad}{} {}:{line}:{col}\n", p.c("1;34", "-->"), f.file));
    s.push_str(&format!("{pad} {bar}\n"));
    s.push_str(&format!("{} {bar} {src}\n", p.c("1;34", &line.to_string())));
    s.push_str(&format!("{pad} {bar} {}{}\n", " ".repeat(col.saturating_sub(1)), p.c(color, &"^".repeat(width.min(src.chars().count().max(1))))));
    s.push_str(&format!("{pad} {bar}\n"));
    if let Some(h) = &f.help {
        s.push_str(&format!("{pad} {} {}: {h}{}\n", p.c("1;34", "="), p.c("1", "help"), if f.fixes.is_empty() { "" } else { " (fixable)" }));
    }
    if first && let Some(i) = fl::info(f.lint) {
        let why = if i.group.level() == lvl { format!("on by default ({})", i.group.name()) } else { format!("set to {} ({})", lvl.name(), i.group.name()) };
        s.push_str(&format!("{pad} {} {}: `{}` {why}; more: `ferrosip lint --explain {}`\n", p.c("1;34", "="), p.c("1", "note"), i.name, i.name));
    }
    s
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json(f: &Finding, lvl: Level, files: &mut Files) -> String {
    let text = files.text(&f.file).to_string();
    let (l1, c1) = line_col(&text, f.start);
    let (l2, c2) = line_col(&text, f.end);
    format!(
        "{{\"lint\":{},\"level\":{},\"group\":{},\"file\":{},\"line\":{l1},\"column\":{c1},\"end_line\":{l2},\"end_column\":{c2},\"message\":{},\"help\":{},\"fixable\":{}}}",
        json_str(f.lint),
        json_str(lvl.name()),
        json_str(fl::info(f.lint).map_or("", |i| i.group.name())),
        json_str(&f.file),
        json_str(&f.msg),
        f.help.as_deref().map_or("null".into(), json_str),
        !f.fixes.is_empty()
    )
}

// ------------------------------------------------------------------ main ---

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts { toml: None, routing: None, levels: vec![], fix: false, json: false, defines: vec![], overlays: vec![], sets: vec![] };
    let mut it = args.iter();
    let next = |it: &mut std::slice::Iter<'_, String>, flag: &str| -> Result<String, String> { it.next().cloned().ok_or(format!("{flag} needs a value")) };
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => o.toml = Some(next(&mut it, "--config")?.into()),
            "-f" => o.routing = Some(next(&mut it, "-f")?),
            "--overlay" => o.overlays.push(next(&mut it, "--overlay")?.into()),
            "--set" => o.sets.push(next(&mut it, "--set")?),
            "-W" => o.levels.push((next(&mut it, "-W")?, Level::Warn)),
            "-A" => o.levels.push((next(&mut it, "-A")?, Level::Allow)),
            "-D" => o.levels.push((next(&mut it, "-D")?, Level::Deny)),
            "--fix" => o.fix = true,
            "--format" => match next(&mut it, "--format")?.as_str() {
                "json" => o.json = true,
                "human" => o.json = false,
                f => return Err(format!("--format {f}: json or human")),
            },
            "--define" => {
                let d = next(&mut it, "--define")?;
                let (n, v) = d.split_once('=').unwrap_or((&d, ""));
                o.defines.push((n.to_string(), v.to_string()));
            }
            a if a.ends_with(".toml") => o.toml = Some(a.into()),
            a if a.ends_with(".fsr") || a.ends_with(".cfg") => o.routing = Some(a.into()),
            a => return Err(format!("unknown option {a:?}\n{USAGE}")),
        }
    }
    Levels::check(&o.levels)?;
    if (!o.overlays.is_empty() || !o.sets.is_empty()) && o.routing.is_some() && o.toml.is_none() {
        return Err("--overlay and --set need ferrosip.toml (--config)".into());
    }
    Ok(o)
}

fn explain(name: &str) -> Result<(), String> {
    if let Some(g) = Group::ALL.iter().find(|g| g.name() == name) {
        println!("{} (default: {})", g.name(), g.level().name());
        for l in LINTS.iter().filter(|l| l.group == *g) {
            println!("  {:<34} {}", l.name, l.summary);
        }
        return Ok(());
    }
    let i = fl::info(name).ok_or_else(|| format!("unknown lint {name:?}{}", schema::suggest(name, LINTS.iter().map(|l| l.name))))?;
    let on = match i.on {
        "fsr" => ".fsr routing",
        "cfg" => ".cfg routing",
        "routing" => "the routing (.fsr and .cfg)",
        _ => "ferrosip.toml (and modparams)",
    };
    println!("{}\n\n  group: {} (default: {})\n  checks: {on}\n\n{}\n\n{}", i.name, i.group.name(), i.group.level().name(), i.summary, wrap(i.why, 76));
    Ok(())
}

/// docs/lints-reference.md (`ferrosip lint --list --markdown`).
fn reference() -> String {
    let mut s = String::from(
        "# Lint reference\n\nGenerated by `ferrosip lint --list --markdown`; see [lint.md](lint.md) for how to run \
         the linter and silence a lint.\n",
    );
    for g in Group::ALL {
        let what = match g {
            Group::Correctness => "almost certainly a bug",
            Group::Suspicious => "probably a mistake",
            Group::Security => "leaves the server open to abuse",
            Group::Style => "works, but can be simpler",
            Group::Pedantic => "opinionated; turn on with `-W pedantic`",
        };
        s.push_str(&format!("\n## {} (default: {})\n\n{}.\n\n| lint | checks | what |\n|---|---|---|\n", g.name(), g.level().name(), {
            let mut c = what.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        }));
        for l in LINTS.iter().filter(|l| l.group == g) {
            let on = match l.on {
                "fsr" => "`.fsr`",
                "cfg" => "`.cfg`",
                "routing" => "`.fsr`, `.cfg`",
                _ => "ferrosip.toml, modparam",
            };
            s.push_str(&format!("| `{}` | {on} | {}. {} |\n", l.name, l.summary, l.why.replace('|', "\\|")));
        }
    }
    s
}

fn wrap(s: &str, w: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if !line.is_empty() && line.len().saturating_add(1).saturating_add(word.len()) > w {
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    out + &line
}

/// One pass: every finding with its level (allowed ones removed).
fn collect(o: &Opts, files: &mut Files) -> Result<Vec<(Finding, Level)>, String> {
    let toml_path = o.toml.clone().or_else(|| (o.routing.is_none() && Path::new("ferrosip.toml").exists()).then(|| "ferrosip.toml".into()));
    let layered = match &toml_path {
        Some(p) => {
            let l = config::load(p, &o.overlays, &o.sets)?;
            let mut errs = config::settings(&l).err().unwrap_or_default();
            errs.extend(config::modules(&l, &crate::schema_of).err().unwrap_or_default());
            if !errs.is_empty() {
                return Err(crate::errors(p, errs));
            }
            Some(l)
        }
        None => None,
    };
    let routing = o.routing.clone().or_else(|| {
        let l = layered.as_ref()?;
        config::settings(l).ok()?.entry.map(|e| e.display().to_string())
    });
    let Some(routing) = routing.or_else(|| layered.is_none().then(|| "etc/ferrosip.cfg".to_string())) else {
        return Err(format!("nothing to lint: no [routing] entry in the config, and no -f\n{USAGE}"));
    };
    let mut findings = vec![];
    let features = layered.as_ref().map(config::features).unwrap_or_default();
    let tables = layered.as_ref().map(config::htables).unwrap_or_default();
    let r = if routing.ends_with(".fsr") {
        lint_fsr(&routing, &features, tables, &mut findings, files)?
    } else {
        lint_cfg(&routing, &o.defines, files, &mut findings)?
    };
    lint_routing(&r, &mut findings);
    let mut allows = r.allows;
    let mut levels = vec![];
    if let (Some(p), Some(l)) = (&toml_path, &layered) {
        let used = r.features.clone().unwrap_or_default();
        lint_toml(p, l, Some(&used), files, &mut findings);
        allows.extend(line_allows(&p.display().to_string(), files));
        levels = toml_levels(l)?;
        Levels::check(&levels).map_err(|e| format!("{}: [lint] {e}", p.display()))?;
    }
    levels.extend(o.levels.iter().cloned());
    let levels = Levels(levels);
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for f in findings {
        let Some(info) = fl::info(f.lint) else { continue };
        let lvl = levels.of(info);
        if lvl == Level::Allow {
            continue;
        }
        let allowed = allows.iter().any(|a| {
            a.file == f.file
                && a.start <= f.start
                && f.start < a.end.max(a.start.saturating_add(1))
                && a.names.iter().any(|n| n == f.lint || n == info.group.name())
        });
        if allowed || !seen.insert((f.file.clone(), f.start, f.lint, f.msg.clone())) {
            continue;
        }
        out.push((f, lvl));
    }
    out.sort_by(|a, b| (&a.0.file, a.0.start).cmp(&(&b.0.file, b.0.start)));
    Ok(out)
}

/// Apply the fixes; per file, later ones first, skipping overlaps.
fn apply_fixes(found: &[(Finding, Level)], files: &mut Files) -> Result<usize, String> {
    let mut by_file: BTreeMap<&str, Vec<&Fix>> = BTreeMap::new();
    for (f, _) in found {
        by_file.entry(&f.file).or_default().extend(&f.fixes);
    }
    let mut n: usize = 0;
    for (file, mut fixes) in by_file {
        if fixes.is_empty() {
            continue;
        }
        let orig = files.text(file).to_string();
        fixes.sort_by_key(|f| std::cmp::Reverse((f.start, f.end)));
        let mut text = orig.clone();
        let mut floor = usize::MAX;
        for fx in fixes {
            // Fix spans come from token spans; one that isn't on character
            // boundaries would be a bug: skip it rather than panic.
            if fx.end > floor || fx.start > fx.end || !text.is_char_boundary(fx.start) || !text.is_char_boundary(fx.end) {
                continue;
            }
            text.replace_range(fx.start..fx.end, &fx.text);
            floor = fx.start;
            n = n.saturating_add(1);
        }
        // A file that was formatted stays formatted.
        if file.ends_with(".fsr")
            && fsr::parse(&orig).is_ok_and(|a| fsr::fmt::format(&a) == orig)
            && let Ok(a) = fsr::parse(&text)
        {
            text = fsr::fmt::format(&a);
        }
        std::fs::write(file, &text).map_err(|e| format!("{file}: {e}"))?;
        files.0.insert(file.to_string(), text);
    }
    Ok(n)
}

pub fn main(args: &[String]) -> Result<i32, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(0);
    }
    if let Some(i) = args.iter().position(|a| a == "--explain") {
        explain(args.get(i.saturating_add(1)).ok_or("--explain needs a lint name")?)?;
        return Ok(0);
    }
    if args.iter().any(|a| a == "--list") && args.iter().any(|a| a == "--markdown") {
        print!("{}", reference());
        return Ok(0);
    }
    if args.iter().any(|a| a == "--list") {
        for g in Group::ALL {
            println!("{} (default: {})", g.name(), g.level().name());
            for l in LINTS.iter().filter(|l| l.group == g) {
                println!("  {:<34} {:<8} {}", l.name, l.on, l.summary);
            }
        }
        return Ok(0);
    }
    let o = parse_args(args)?;
    let mut files = Files(BTreeMap::new());
    let mut found = collect(&o, &mut files)?;
    if o.fix {
        // Overlapping fixes (two names of one import list) wait for the
        // next round, as with clippy.
        let mut total: usize = 0;
        for _ in 0..10 {
            let n = apply_fixes(&found, &mut files)?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n);
            files = Files(BTreeMap::new());
            found = collect(&o, &mut files)?;
        }
        if total > 0 {
            eprintln!("ferrosip lint: applied {total} fix{}", if total == 1 { "" } else { "es" });
        }
    }
    let paint = Paint(!o.json && std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none());
    let mut noted = BTreeSet::new();
    let mut stdout = std::io::stdout().lock();
    for (f, lvl) in &found {
        if o.json {
            // A closed pipe (`| head`) is not an error.
            if writeln!(stdout, "{}", json(f, *lvl, &mut files)).is_err() {
                break;
            }
        } else {
            eprintln!("{}", render(f, *lvl, noted.insert(f.lint), &mut files, &paint));
        }
    }
    let errors = found.iter().filter(|(_, l)| *l == Level::Deny).count();
    let warnings = found.len().saturating_sub(errors);
    let fixable = found.iter().filter(|(f, _)| !f.fixes.is_empty()).count();
    if !o.json {
        let plural = |n: usize, w: &str| format!("{n} {w}{}", if n == 1 { "" } else { "s" });
        let fix = if fixable > 0 && !o.fix { format!(" ({fixable} fixable with `ferrosip lint --fix`)") } else { String::new() };
        match (errors, warnings) {
            (0, 0) => eprintln!("ferrosip lint: no problems found"),
            (0, w) => eprintln!("{}: {} emitted{fix}", paint.c("1;33", "warning"), plural(w, "warning")),
            (e, w) => eprintln!("{}: could not pass lint: {}, {}{fix}", paint.c("1;31", "error"), plural(e, "error"), plural(w, "warning")),
        }
    }
    Ok(if errors > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_and_urls() {
        assert!(url_password("mysql://ferrosip:s3cret@db/ferrosip"));
        assert!(!url_password("mysql://ferrosip@db/ferrosip"));
        assert!(!url_password("sqlite:///var/lib/x.db"));
        assert!(is_secret_key("password") && is_secret_key("openai_api_key") && is_secret_key("secret"));
        assert!(!is_secret_key("password_column") && !is_secret_key("users_file") && !is_secret_key("openai_key_file"));
    }

    #[test]
    fn toml_lines() {
        let t = "[core]\nx = 1\n\n[modules.txn]   # tm\n# c\nfr_timer = \"30s\"\n[modules.auth]\nfr_timer = 1\nmodules.location.max_expires = 3\n";
        assert_eq!(toml_line(t, "modules.txn", "fr_timer"), Some(6));
        assert_eq!(toml_line(t, "modules.auth", "fr_timer"), Some(8));
        assert_eq!(toml_line(t, "modules.location", "max_expires"), Some(9));
        assert_eq!(toml_line(t, "modules.txn", "nope"), None);
    }

    #[test]
    fn levels_resolve_like_clippy() {
        let i = fl::info("unused_variable").unwrap();
        assert_eq!(Levels(vec![]).of(i), Level::Warn);
        assert_eq!(Levels(vec![("warnings".into(), Level::Deny)]).of(i), Level::Deny);
        assert_eq!(Levels(vec![("suspicious".into(), Level::Allow), ("unused_variable".into(), Level::Warn)]).of(i), Level::Warn);
        let p = fl::info("table_without_ttl").unwrap();
        assert_eq!(Levels(vec![("warnings".into(), Level::Deny)]).of(p), Level::Allow, "-D warnings leaves allowed lints alone");
        assert_eq!(Levels(vec![("pedantic".into(), Level::Warn)]).of(p), Level::Warn);
        assert!(Levels::check(&[("unused_varible".into(), Level::Warn)]).unwrap_err().contains("unused_variable"));
    }
    /// A fresh directory for one test's files.
    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ferrosip-lint-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn opts(routing: &Path) -> Opts {
        Opts {
            toml: None,
            routing: Some(routing.display().to_string()),
            levels: vec![],
            fix: false,
            json: false,
            defines: vec![],
            overlays: vec![],
            sets: vec![],
        }
    }

    const UNTIDY: &str = "import nat, txn, location\nroute main(msg: Request) {\n    let a = 1\n    let ok = msg.src.port == 5060\n    if ok == true {\n        if msg.ruri.user == \"x\" || msg.ruri.user == \"y\" {\n            exit\n        }\n    }\n    if location.lookup() { exit } else {\n    }\n    reply(404, \"Not Found\")\n}\n";

    #[test]
    fn fix_rewrites_the_file_exactly() {
        let d = dir("fix");
        let f = d.join("main.fsr");
        std::fs::write(&f, UNTIDY).unwrap();
        let rc = main(&["-f".into(), f.display().to_string(), "--fix".into()]).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "import location\nroute main(msg: Request) {\n    let _a = 1\n    let ok = msg.src.port == 5060\n    if ok && (msg.ruri.user == \"x\" || msg.ruri.user == \"y\") {\n            exit\n        }\n    if location.lookup() { exit }\n    reply(404)\n}\n"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fix_keeps_a_formatted_file_formatted() {
        let d = dir("fmt");
        let f = d.join("main.fsr");
        let src = fsr::fmt::format(&fsr::parse(UNTIDY).unwrap());
        std::fs::write(&f, &src).unwrap();
        main(&["-f".into(), f.display().to_string(), "--fix".into()]).unwrap();
        let out = std::fs::read_to_string(&f).unwrap();
        assert_eq!(out, fsr::fmt::format(&fsr::parse(&out).unwrap()), "still canonical:\n{out}");
        assert!(out.contains("    if ok && (msg.ruri.user == \"x\" || msg.ruri.user == \"y\") {\n        exit\n    }\n"), "{out}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn findings_render_like_clippy() {
        let d = dir("render");
        let f = d.join("main.fsr");
        std::fs::write(&f, UNTIDY).unwrap();
        let mut files = Files(BTreeMap::new());
        let found = collect(&opts(&f), &mut files).unwrap();
        let lints: Vec<&str> = found.iter().map(|(f, _)| f.lint).collect();
        assert_eq!(
            lints,
            ["unused_import", "needless_import", "unused_variable", "collapsible_if", "bool_comparison", "empty_block", "redundant_reply_reason"],
            "in file order"
        );
        let (first, lvl) = &found[0];
        let name = f.display().to_string();
        assert_eq!(
            render(first, *lvl, true, &mut files, &Paint(false)),
            format!(
                "warning: `nat` is imported but never used\n --> {name}:1:8\n  |\n1 | import nat, txn, location\n  |        ^^^\n  |\n  = help: remove this import (fixable)\n  = note: `unused_import` on by default (suspicious); more: `ferrosip lint --explain unused_import`\n"
            )
        );
        let (reason, lvl) = &found[6];
        assert_eq!(
            json(reason, *lvl, &mut files),
            format!(
                "{{\"lint\":\"redundant_reply_reason\",\"level\":\"warn\",\"group\":\"style\",\"file\":{},\"line\":12,\"column\":16,\"end_line\":12,\"end_column\":27,\"message\":\"\\\"Not Found\\\" is the reason 404 gets anyway\",\"help\":\"write `reply(404)`\",\"fixable\":true}}",
                json_str(&name)
            )
        );
        // Levels from the command line.
        let mut o = opts(&f);
        o.levels = vec![("style".into(), Level::Allow), ("unused_import".into(), Level::Deny)];
        let found = collect(&o, &mut Files(BTreeMap::new())).unwrap();
        let got: Vec<(&str, Level)> = found.iter().map(|(f, l)| (f.lint, *l)).collect();
        assert_eq!(got, [("unused_import", Level::Deny), ("unused_variable", Level::Warn)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_routing_that_does_not_compile_is_not_linted() {
        let d = dir("broken");
        let f = d.join("main.fsr");
        std::fs::write(&f, "route main(msg: Request) {\n    nope()\n}\n").unwrap();
        let e = collect(&opts(&f), &mut Files(BTreeMap::new())).err().unwrap_or_default();
        assert!(e.starts_with("1 error in the routing (fix them first):\n") && e.contains("unknown function nope()"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cfg_lints_point_at_their_lines() {
        let d = dir("cfg");
        let f = d.join("main.cfg");
        std::fs::write(
            &f,
            "loadmodule \"tm\"\nloadmodule \"sl\"\nmodparam(\"tm\", \"fr_timer\", 30000)\nrequest_route {\n    t_on_failure(\"F\");\n    t_relay();\n}\nfailure_route[U] {\n    exit;\n}\nfailure_route[F] {\n    exit;\n}\nroute[U] {\n    exit;\n}\n# lint: allow(unused_route)\nroute[QUIET] {\n    exit;\n}\n",
        )
        .unwrap();
        let mut files = Files(BTreeMap::new());
        let found = collect(&opts(&f), &mut files).unwrap();
        let text = std::fs::read_to_string(&f).unwrap();
        let at: Vec<(&str, usize)> = found.iter().map(|(x, _)| (x.lint, line_col(&text, x.start).0)).collect();
        // route[U] is on its own line, not failure_route[U]'s.
        for want in [("redundant_default", 3), ("missing_max_forwards", 4), ("open_relay", 6), ("unused_route", 8), ("unused_route", 14)] {
            assert!(at.contains(&want), "{want:?} in {at:?}");
        }
        assert!(!at.contains(&("unused_route", 11)), "failure_route[F] is armed: {at:?}");
        assert_eq!(at.iter().filter(|(l, _)| *l == "unused_route").count(), 2, "route[QUIET] is allowed: {at:?}");
        let n = apply_fixes(&found, &mut files).unwrap();
        assert_eq!(n, 1);
        assert!(!std::fs::read_to_string(&f).unwrap().contains("modparam"), "the default modparam line is removed");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_route_is_used_only_by_uses_of_its_kind() {
        let d = dir("cfg-kinds");
        let f = d.join("main.cfg");
        let cfg = [
            "loadmodule \"tm\"",
            "request_route {",
            "    t_on_failure(\"F\");",
            "    t_on_reply(\"R\");",
            "    t_on_branch(\"B\");",
            "    route(C);",
            "    t_continue(\"1\", \"2\", \"RESUME\");",
            "    t_relay();",
            "}",
            "failure_route[F] { exit; }",
            "route[F] { exit; }",
            "onreply_route[R] { exit; }",
            "failure_route[R] { exit; }",
            "branch_route[B] { exit; }",
            "route[B] { exit; }",
            "route[C] { exit; }",
            "failure_route[C] { exit; }",
            "route[RESUME] { exit; }",
            "failure_route[RESUME] { exit; }",
        ]
        .join("\n");
        std::fs::write(&f, format!("{cfg}\n")).unwrap();
        let found = collect(&opts(&f), &mut Files(BTreeMap::new())).unwrap();
        let text = std::fs::read_to_string(&f).unwrap();
        let unused: Vec<usize> = found.iter().filter(|(x, _)| x.lint == "unused_route").map(|(x, _)| line_col(&text, x.start).0).collect();
        // route[F] (armed only as a failure route), failure_route[R],
        // route[B] and failure_route[C]; a name given to another function
        // (t_continue) may be any kind.
        assert_eq!(unused, [11, 13, 15, 17], "{found:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn toml_lints() {
        let d = dir("toml");
        std::fs::write(d.join("main.fsr"), "route main(msg: Request) {\n    drop\n}\n").unwrap();
        let toml = d.join("ferrosip.toml");
        std::fs::write(
            &toml,
            "[feature]\nused_nowhere = 1\n[modules.txn]\nfr_timer = \"30s\"\n[modules.location]\ndb_url = \"mysql://u:pw@db/x\"\n[routing]\nentry = \"main.fsr\"\n[lint]\nallow = [\"needless_import\"]\n",
        )
        .unwrap();
        let mut o = opts(&d.join("main.fsr"));
        o.routing = None;
        o.toml = Some(toml.clone());
        let mut files = Files(BTreeMap::new());
        let found = collect(&o, &mut files).unwrap();
        let text = std::fs::read_to_string(&toml).unwrap();
        let at: Vec<(&str, usize)> = found.iter().filter(|(x, _)| x.file.ends_with(".toml")).map(|(x, _)| (x.lint, line_col(&text, x.start).0)).collect();
        assert_eq!(at, [("unused_feature", 2), ("redundant_default", 4), ("plaintext_secret", 6)]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn options() {
        let e = |a: &[&str]| parse_args(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).err().unwrap_or_default();
        assert!(e(&["-W"]).contains("-W needs a value"));
        assert!(e(&["-D", "unused_varible"]).contains("did you mean \"unused_variable\""));
        assert!(e(&["--format", "xml"]).contains("--format xml: json or human"));
        assert!(e(&["--bogus"]).starts_with("unknown option \"--bogus\""));
        assert!(e(&["x.fsr", "--set", "a=1"]).contains("--set need ferrosip.toml"));
        let o = parse_args(&["routes/x.fsr".to_string(), "ferrosip.toml".into(), "--define".into(), "A=1".into(), "-A".into(), "style".into()]).unwrap();
        assert_eq!((o.routing.as_deref(), o.toml.as_deref()), (Some("routes/x.fsr"), Some(Path::new("ferrosip.toml"))));
        assert_eq!(o.defines, [("A".to_string(), "1".to_string())]);
        assert_eq!(o.levels, [("style".to_string(), Level::Allow)]);
        assert_eq!(json_str("a\"b\\\n\u{1}"), "\"a\\\"b\\\\\\n\\u0001\"");
        assert_eq!(wrap("aaa bbb ccc", 7), "aaa bbb\nccc");
    }
}
