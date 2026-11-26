//! `ferrosip lint`: clippy-style lints. This module holds the catalogue
//! (every lint, its group and default level, and its explanation) and the
//! `.fsr` lints, which work on the syntax tree after a successful compile.
//! ferrosip.toml and `.cfg` lints, and the routing-wide ones, are in the
//! binary; they share the catalogue and the `Finding` shape.
//!
//! A lint never changes what a configuration means: it points at code that
//! works but is probably not what was meant, is risky, or can be simpler.

use crate::ast::*;
use crate::compile::{Env, Source};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Allow,
    Warn,
    Deny,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Allow => "allow",
            Level::Warn => "warn",
            Level::Deny => "deny",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// Almost certainly a bug: an error by default.
    Correctness,
    /// Probably a mistake.
    Suspicious,
    /// Leaves the server open to abuse.
    Security,
    /// Works, but can be written more simply.
    Style,
    /// Opinionated; off by default (`-W pedantic`).
    Pedantic,
}

impl Group {
    pub const ALL: [Group; 5] = [Group::Correctness, Group::Suspicious, Group::Security, Group::Style, Group::Pedantic];

    pub fn name(self) -> &'static str {
        match self {
            Group::Correctness => "correctness",
            Group::Suspicious => "suspicious",
            Group::Security => "security",
            Group::Style => "style",
            Group::Pedantic => "pedantic",
        }
    }

    pub fn level(self) -> Level {
        match self {
            Group::Correctness => Level::Deny,
            Group::Pedantic => Level::Allow,
            _ => Level::Warn,
        }
    }
}

/// One lint of the catalogue.
pub struct LintInfo {
    pub name: &'static str,
    pub group: Group,
    /// What it checks: `fsr`, `cfg`, `routing` (both languages) or `toml`.
    pub on: &'static str,
    pub summary: &'static str,
    /// Why it matters, and what to do (`ferrosip lint --explain NAME`).
    pub why: &'static str,
}

const fn l(name: &'static str, group: Group, on: &'static str, summary: &'static str, why: &'static str) -> LintInfo {
    LintInfo { name, group, on, summary, why }
}

use Group::*;

pub static LINTS: &[LintInfo] = &[
    // ---- .fsr
    l(
        "infinite_loop",
        Correctness,
        "fsr",
        "`while true` that nothing leaves",
        "The loop has no `break`, `return`, `exit`, `drop` or `await`, so it spins until the engine's \
       loop guard (10000 rounds) stops it and the request is left unanswered. Add a way out.",
    ),
    l(
        "unused_variable",
        Suspicious,
        "fsr",
        "a `let`, `for` or match binding that is never read",
        "A value that is computed and never used is usually a typo or a leftover. If the call is wanted \
       for its effect, keep it and name the variable `_name` (or bind `_` in a match pattern).",
    ),
    l("unused_function", Suspicious, "fsr", "a `fn` that nothing calls", "Dead code: remove it, or call it from a route."),
    l("unused_flag", Suspicious, "fsr", "a `flag` that is never set or tested", "Every flag takes one of the 32 message flags. Remove the declaration."),
    l(
        "unused_import",
        Suspicious,
        "fsr",
        "an `import` of a module the file never calls",
        "Importing a module that is not used makes readers look for it. Remove it from the list.",
    ),
    l(
        "unused_state",
        Suspicious,
        "fsr",
        "a `shared table` or `dialog var` that is never used",
        "A declared table still takes shared memory, and a dialog var is part of every dialog. Remove it.",
    ),
    l(
        "constant_condition",
        Suspicious,
        "fsr",
        "`if`/`guard`/`while` on a literal `true` or `false`",
        "One branch can never run. For a switch you set per deployment, use a `[feature]` in ferrosip.toml \
       (`import { features } from config`); otherwise remove the dead branch.",
    ),
    l(
        "unreachable_arm",
        Suspicious,
        "fsr",
        "a match arm that an earlier arm already covers",
        "Arms are tried in order: one after `_`, or one that repeats an earlier pattern without a guard, never matches.",
    ),
    l(
        "number_interpolation",
        Suspicious,
        "fsr",
        "`{4}` or `{2,3}` inside a string",
        "Braces in a string interpolate: `\"[0-9]{4}\"` is the text `[0-9]4`, not a regex quantifier. \
       Write `\\{4\\}` for literal braces (the fix does that).",
    ),
    l(
        "timer_too_frequent",
        Suspicious,
        "fsr",
        "`on timer(every: …)` below 100ms",
        "Each run takes a worker. Timers that fire many times a second rarely need to; poll less often.",
    ),
    l(
        "unknown_reply_reason",
        Suspicious,
        "fsr",
        "`reply(code)` with a code that has no standard reason phrase",
        "Without a reason ferrosip sends the standard phrase for the code; this code has none, so the phrase \
       would be \"Unknown\". Pass one: `reply(499, \"Rejected\")`.",
    ),
    l("needless_import", Style, "fsr", "`import log` / `import txn`", "`log` and `txn` are always available; the import does nothing."),
    l("bool_comparison", Style, "fsr", "comparing with `true` or `false`", "`x == true` is `x`, and `x == false` is `!x`."),
    l(
        "redundant_reply_reason",
        Style,
        "fsr",
        "`reply(code, reason)` with the reason ferrosip would send anyway",
        "`reply(404)` sends \"Not Found\" by itself.",
    ),
    l("collapsible_if", Style, "fsr", "`if a { if b { … } }` with no else", "Write `if a && b { … }`: one level of nesting less."),
    l("collapsible_else_if", Style, "fsr", "`else { if … }`", "Write `else if …`."),
    l("empty_block", Style, "fsr", "an empty `if` body or `else {}`", "Remove the empty branch (or invert the condition)."),
    l("needless_return", Style, "fsr", "`return` as the last statement", "The route ends there anyway."),
    l(
        "table_without_ttl",
        Pedantic,
        "fsr",
        "a `shared table` with no `ttl`",
        "Entries stay until removed. Keyed by something callers choose (an IP, a user), the table can grow \
       without bound; add `ttl 10m` unless every key is removed explicitly.",
    ),
    l(
        "relay_without_timeout",
        Pedantic,
        "fsr",
        "`await txn.relay(msg)` without `timeout:`",
        "The wait is then the tm module's default (fr_inv_timer for INVITE). Say how long the route waits.",
    ),
    l(
        "raw_kamailio",
        Pedantic,
        "fsr",
        "`pv(\"$…\")`, `kamailio.call(…)` or a `kamailio.*_route` handler",
        "The escape hatch to Kamailio (what `ferrosip import` writes when there is no typed form) is not \
         checked: a typo in a variable or function name, a wrong argument, a call where it can't run only show \
         at run time. Replace it with the typed form where there is one (`msg.ruri.user` for `$rU`, a `let` for \
         `$var(x)`, `await txn.relay` for a failure_route).",
    ),
    l(
        "hardcoded_address",
        Pedantic,
        "fsr",
        "an IP address written in the routing",
        "Addresses change per deployment. Put it in ferrosip.toml (`[feature] pstn = \"sip:10.0.0.9\"`) and \
       read it with `features.pstn`.",
    ),
    // ---- both routing languages
    l(
        "missing_max_forwards",
        Security,
        "routing",
        "requests are relayed without a Max-Forwards check",
        "Without it a request can loop between proxies until something breaks. Start the request route with \
       `guard msg.max_forwards > 0 else reply(TooManyHops)` (.cfg: `mf_process_maxfwd_header(10)`).",
    ),
    l(
        "register_without_auth",
        Security,
        "routing",
        "REGISTER is saved, but nothing authenticates",
        "Anyone can register any user and receive their calls. Challenge first (`auth.www_challenge`, \
       `auth.check`…) or limit who may register (permissions).",
    ),
    l(
        "sql_injection",
        Security,
        "fsr",
        "a value interpolated into the text of an `sql.*` query without `sql.quote`",
        "`\"… WHERE user = '{msg.ruri.user}'\"` puts the value into SQL as it is: a quote in it (legal in a SIP \
       user part) breaks the query or changes what it does. Write `{sql.quote(msg.ruri.user)}` (no quotes \
       around it); numbers may stay as they are.",
    ),
    l(
        "open_relay",
        Security,
        "routing",
        "requests are relayed, but no caller is authenticated or checked",
        "Nothing in the routing authenticates callers or checks where requests come from, so anyone can send \
       calls through this proxy (toll fraud). Authenticate, or check `msg.src.ip` / permissions / the \
       dispatcher list before relaying.",
    ),
    l(
        "record_route_without_loose_route",
        Suspicious,
        "routing",
        "Record-Route is added, but Route headers are never followed",
        "Record-Route asks the endpoints to send in-dialog requests through this proxy; without \
       `rr.follow()` (.cfg: `loose_route()`) those requests are routed like new ones.",
    ),
    // ---- .cfg
    l("unused_route", Suspicious, "cfg", "a `route[NAME]` (or failure/branch/onreply route) that nothing uses", "Nothing calls or arms it. Remove it."),
    // ---- ferrosip.toml / modparam
    l(
        "redundant_default",
        Style,
        "toml",
        "a parameter set to its default value",
        "The line does nothing; `ferrosip check --explain` still shows the value. Remove it.",
    ),
    l(
        "plaintext_secret",
        Security,
        "toml",
        "a password or key written in ferrosip.toml",
        "Configuration files end up in repositories and backups. Use `${ENV_VAR}` (or a `*_file` parameter \
       where the module has one).",
    ),
    l("unused_feature", Suspicious, "toml", "a `[feature]` value that the routing never reads", "Remove it, or read it with `features.name` in the routing."),
];

pub fn info(name: &str) -> Option<&'static LintInfo> {
    LINTS.iter().find(|l| l.name == name)
}

/// A replacement of `start..end` (bytes) in a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fix {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub lint: &'static str,
    pub file: String,
    pub start: usize,
    pub end: usize,
    pub msg: String,
    pub help: Option<String>,
    /// Applied together by `--fix` (empty: nothing to apply).
    pub fixes: Vec<Fix>,
}

/// What the routing does, for the routing-wide lints: a function it calls
/// (by its Kamailio name), or `@max_forwards` / `@sanity` / `@src_check`.
#[derive(Clone, Debug)]
pub struct Fact {
    pub what: String,
    pub file: String,
    pub start: usize,
    pub end: usize,
}

/// `// lint: allow(a, b)` before (or after) an item, statement or arm:
/// those lints are off inside it.
#[derive(Clone, Debug)]
pub struct Allow {
    pub file: String,
    pub start: usize,
    pub end: usize,
    pub names: Vec<String>,
}

#[derive(Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub facts: Vec<Fact>,
    pub allows: Vec<Allow>,
    /// Where the request route starts (`route main`), for routing-wide lints.
    pub entry: Option<(String, usize, usize)>,
    /// `features.x` the routing reads.
    pub features: BTreeSet<String>,
}

/// The lint names in a `lint: allow(a, b)` comment (`//` or `#`).
pub fn parse_allow(comment: &str) -> Option<Vec<String>> {
    let c = comment.trim_start_matches(['/', '#', ' ', '\t']);
    let rest = c.strip_prefix("lint:")?.trim_start().strip_prefix("allow(")?;
    let (inner, _) = rest.split_once(')')?;
    Some(inner.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

// ------------------------------------------------------------- walking ---

fn each_expr<'a>(e: &'a Expr, f: &mut dyn FnMut(&'a Expr)) {
    f(e);
    match &e.kind {
        ExprKind::Field(a, _) | ExprKind::Unary(_, a) | ExprKind::Await(a) | ExprKind::Paren(a) => each_expr(a, f),
        ExprKind::Index(a, b) | ExprKind::Binary(_, a, b) | ExprKind::Range(a, b) => {
            each_expr(a, f);
            each_expr(b, f);
        }
        ExprKind::Call(c, args) => {
            each_expr(c, f);
            for a in args {
                each_expr(&a.value, f);
            }
        }
        ExprKind::List(xs) => xs.iter().for_each(|x| each_expr(x, f)),
        ExprKind::Str(parts) => {
            for p in parts {
                if let StrPart::Expr(x) = p {
                    each_expr(x, f);
                }
            }
        }
        ExprKind::Int(_) | ExprKind::Bool(_) | ExprKind::Duration(..) | ExprKind::Ident(_) => {}
    }
}

/// Every statement (nested ones too) and every expression of a block.
#[derive(Default)]
struct Flat<'a> {
    stmts: Vec<&'a Stmt>,
    exprs: Vec<&'a Expr>,
    blocks: Vec<&'a Block>,
    arms: Vec<&'a [Arm]>,
}

impl<'a> Flat<'a> {
    fn expr(&mut self, e: &'a Expr) {
        each_expr(e, &mut |x| self.exprs.push(x));
    }

    fn block(&mut self, b: &'a Block) {
        self.blocks.push(b);
        for s in &b.stmts {
            self.stmt(s);
        }
    }

    fn stmt(&mut self, s: &'a Stmt) {
        self.stmts.push(s);
        match &s.kind {
            StmtKind::Let { value, otherwise, .. } => {
                self.expr(value);
                if let Some(o) = otherwise {
                    self.stmt(o);
                }
            }
            StmtKind::Assign(a, b) => {
                self.expr(a);
                self.expr(b);
            }
            StmtKind::If(c, t, e) => {
                self.expr(c);
                self.block(t);
                match e {
                    Some(Else::Block(b)) => self.block(b),
                    Some(Else::If(s)) => self.stmt(s),
                    None => {}
                }
            }
            StmtKind::While(c, b) => {
                self.expr(c);
                self.block(b);
            }
            StmtKind::For(_, e, b) => {
                self.expr(e);
                self.block(b);
            }
            StmtKind::Guard(c, s) => {
                self.expr(c);
                self.stmt(s);
            }
            StmtKind::Match(e, arms) => {
                self.expr(e);
                self.arms.push(arms);
                for a in arms {
                    for p in &a.pats {
                        if let Pat::Lit(x) = p {
                            self.expr(x);
                        }
                    }
                    if let Some(g) = &a.guard {
                        self.expr(g);
                    }
                    match &a.body {
                        ArmBody::Block(b) => self.block(b),
                        ArmBody::Stmt(s) => self.stmt(s),
                    }
                }
            }
            StmtKind::Return(Some(e)) | StmtKind::Expr(e) => self.expr(e),
            StmtKind::Return(None) | StmtKind::Drop | StmtKind::Exit | StmtKind::Break => {}
        }
    }
}

/// The bodies of an item (and whether it is a test).
fn bodies(item: &Item) -> (Vec<&Block>, Vec<&Expr>, bool) {
    match &item.kind {
        ItemKind::Route(f) | ItemKind::Fn(f) => (vec![&f.body], vec![], false),
        ItemKind::On(on) => (vec![&on.body], on.cond.iter().chain(on.args.iter().map(|a| &a.value)).collect(), false),
        ItemKind::Test(_, b) => (vec![b], vec![], true),
        ItemKind::Table { ttl, .. } => (vec![], ttl.iter().collect(), false),
        _ => (vec![], vec![], false),
    }
}

/// `pv("$x")` → `$x`.
fn pv_arg(e: &Expr) -> Option<&str> {
    let ExprKind::Call(c, args) = &e.kind else { return None };
    if ident(c) != Some("pv") {
        return None;
    }
    lit_str(&args.first()?.value)
}

fn lit_str(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Str(p) => match p.as_slice() {
            [StrPart::Lit(s)] => Some(s),
            _ => None,
        },
        _ => None,
    }
}

/// `kamailio.call("fn", …)` → `fn`.
fn kamailio_fn(c: &Expr, args: &[CallArg]) -> Option<String> {
    match &c.kind {
        ExprKind::Field(b, n) if ident(b) == Some("kamailio") && n.text == "call" => lit_str(&args.first()?.value).map(str::to_string),
        ExprKind::Field(b, n) if ident(b) == Some("kamailio") && matches!(n.text.as_str(), "bitor" | "bitand") => Some(format!("kamailio.{}", n.text)),
        _ => None,
    }
}

fn ident(e: &Expr) -> Option<&str> {
    match &e.kind {
        ExprKind::Ident(n) => Some(n),
        _ => None,
    }
}

fn unparen(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Paren(x) => unparen(x),
        _ => e,
    }
}

/// `msg.src.ip`-like: a `.src.ip` access.
fn is_src_ip(e: &Expr) -> bool {
    let mut found = false;
    each_expr(e, &mut |x| {
        if pv_arg(x).is_some_and(|p| p == "$si" || p == "$srcip") {
            found = true;
        }
        if let ExprKind::Field(a, n) = &x.kind
            && n.text == "ip"
            && matches!(&a.kind, ExprKind::Field(_, s) if s.text == "src")
        {
            found = true;
        }
    });
    found
}

// --------------------------------------------------------------- lints ---

struct Cx<'a> {
    src: &'a Source,
    out: &'a mut Vec<Finding>,
}

impl Cx<'_> {
    fn text(&self, s: Span) -> &str {
        let t = &self.src.text;
        t.get(t.floor_char_boundary(s.start)..t.ceil_char_boundary(s.end.max(s.start))).unwrap_or_default()
    }

    fn emit(&mut self, lint: &'static str, span: Span, msg: impl Into<String>, help: Option<String>, fixes: Vec<Fix>) {
        self.out.push(Finding { lint, file: self.src.name.clone(), start: span.start, end: span.end, msg: msg.into(), help, fixes });
    }

    /// `start..end` widened to whole lines (with the newline), for deleting a line.
    fn line_span(&self, s: Span) -> Span {
        let t = &self.src.text;
        let (before, _) = t.split_at(t.floor_char_boundary(s.start));
        let end = t.ceil_char_boundary(s.end);
        let start = before.rfind('\n').map_or(0, |i| i.saturating_add(1));
        let end = t.get(end..).and_then(|r| r.find('\n')).map_or(t.len(), |i| end.saturating_add(i).saturating_add(1));
        Span { start, end }
    }

    fn has_comments(b: &Block) -> bool {
        !b.tail.is_empty() || b.stmts.iter().any(|s| !s.trivia.leading.is_empty() || s.trivia.trailing.is_some())
    }
}

/// Unused `let` / `for` / match bindings, with proper scopes.
struct Unused<'a, 'b> {
    cx: &'a mut Cx<'b>,
    scopes: Vec<Vec<(String, Span, bool, bool)>>,
}

impl Unused<'_, '_> {
    fn declare(&mut self, n: &Name, pattern: bool) {
        if !n.text.starts_with('_') {
            // There is always a scope: the walk starts with the function's.
            if let Some(scope) = self.scopes.last_mut() {
                scope.push((n.text.clone(), n.span, false, pattern));
            }
        }
    }

    fn use_(&mut self, name: &str) {
        for s in self.scopes.iter_mut().rev() {
            if let Some(v) = s.iter_mut().rev().find(|v| v.0 == name) {
                v.2 = true;
                return;
            }
        }
    }

    fn pop(&mut self) {
        for (name, span, used, pattern) in self.scopes.pop().unwrap_or_default() {
            if used {
                continue;
            }
            let (help, text) = if pattern {
                ("if the value isn't needed, match it with `_`".to_string(), "_".to_string())
            } else {
                (format!("if this is intentional, prefix it with an underscore: `_{name}`"), format!("_{name}"))
            };
            self.cx.emit("unused_variable", span, format!("`{name}` is never read"), Some(help), vec![Fix { start: span.start, end: span.end, text }]);
        }
    }

    fn expr(&mut self, e: &Expr) {
        let mut names = Vec::new();
        each_expr(e, &mut |x| {
            if let Some(n) = ident(x) {
                names.push(n.to_string());
            }
        });
        for n in names {
            self.use_(&n);
        }
    }

    fn block(&mut self, b: &Block) {
        self.scopes.push(Vec::new());
        for s in &b.stmts {
            self.stmt(s);
        }
        self.pop();
    }

    fn stmt(&mut self, s: &Stmt) {
        match &s.kind {
            StmtKind::Let { name, value, otherwise, .. } => {
                self.expr(value);
                if let Some(o) = otherwise {
                    self.stmt(o);
                }
                self.declare(name, false);
            }
            StmtKind::Assign(t, v) => {
                // Writing a variable is not reading it.
                if ident(t).is_none() {
                    self.expr(t);
                }
                self.expr(v);
            }
            StmtKind::If(c, t, e) => {
                self.expr(c);
                self.block(t);
                match e {
                    Some(Else::Block(b)) => self.block(b),
                    Some(Else::If(s)) => self.stmt(s),
                    None => {}
                }
            }
            StmtKind::While(c, b) => {
                self.expr(c);
                self.block(b);
            }
            StmtKind::For(n, e, b) => {
                self.expr(e);
                self.scopes.push(Vec::new());
                self.declare(n, false);
                self.block(b);
                self.pop();
            }
            StmtKind::Guard(c, s) => {
                self.expr(c);
                self.stmt(s);
            }
            StmtKind::Match(e, arms) => {
                self.expr(e);
                for a in arms {
                    self.scopes.push(Vec::new());
                    for p in &a.pats {
                        match p {
                            Pat::Variant(_, Some(b)) if b.text != "_" => self.declare(b, true),
                            Pat::Lit(x) => self.expr(x),
                            _ => {}
                        }
                    }
                    if let Some(g) = &a.guard {
                        self.expr(g);
                    }
                    match &a.body {
                        ArmBody::Block(b) => self.block(b),
                        ArmBody::Stmt(s) => self.stmt(s),
                    }
                    self.pop();
                }
            }
            StmtKind::Return(Some(e)) | StmtKind::Expr(e) => self.expr(e),
            StmtKind::Return(None) | StmtKind::Drop | StmtKind::Exit | StmtKind::Break => {}
        }
    }
}

/// Does the loop body leave (break out of this loop, or end the route)?
fn leaves(stmts: &[Stmt]) -> bool {
    let mut f = Flat::default();
    for s in stmts {
        f.stmt(s);
    }
    let in_inner_loop = |s: &Stmt| {
        // A `break` inside a nested loop leaves only that loop.
        stmts.iter().any(|top| {
            let mut inner = Flat::default();
            match &top.kind {
                StmtKind::While(_, b) | StmtKind::For(_, _, b) => inner.block(b),
                _ => return false,
            }
            inner.stmts.iter().any(|x| std::ptr::eq(*x, s))
        })
    };
    f.stmts.iter().any(|s| match s.kind {
        StmtKind::Return(_) | StmtKind::Exit | StmtKind::Drop => true,
        StmtKind::Break => !in_inner_loop(s),
        _ => false,
    }) || f.exprs.iter().any(|e| matches!(e.kind, ExprKind::Await(_)))
}

fn pat_key(p: &Pat) -> Option<String> {
    match p {
        Pat::Lit(e) => match &e.kind {
            ExprKind::Int(i) => Some(i.to_string()),
            ExprKind::Str(parts) if parts.iter().all(|p| matches!(p, StrPart::Lit(_))) => {
                Some(format!("{:?}", parts.iter().map(|p| if let StrPart::Lit(s) = p { s.as_str() } else { "" }).collect::<String>()))
            }
            ExprKind::Ident(n) => Some(n.clone()),
            _ => None,
        },
        Pat::Variant(n, None) => Some(n.text.clone()),
        Pat::Range(a, b, _) => Some(format!("{}..{}", crate::fmt::expr(a), crate::fmt::expr(b))),
        _ => None,
    }
}

fn has_ipv4(s: &str) -> Option<&str> {
    // A dotted quad that is a whole word: not inside a longer run of
    // letters, digits and dots.
    let word = |c: char| c.is_ascii_alphanumeric() || c == '.';
    let octet = |p: &str| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|v| v <= 255);
    let mut prev_word = false;
    for (start, c) in s.char_indices() {
        if c.is_ascii_digit() && !prev_word {
            let rest = s.get(start..).unwrap_or_default();
            let run = rest.split(|c: char| !word(c)).next().unwrap_or(rest);
            if run.split('.').count() == 4 && run.split('.').all(octet) {
                return Some(run);
            }
        }
        prev_word = word(c);
    }
    None
}

fn lint_block(cx: &mut Cx, body: &Block, is_test: bool) {
    let mut f = Flat::default();
    f.block(body);
    // needless_return: `return` (no value) last in the route.
    if let Some(last) = body.stmts.last()
        && matches!(last.kind, StmtKind::Return(None))
        && last.trivia.leading.is_empty()
        && last.trivia.trailing.is_none()
    {
        let sp = cx.line_span(last.span);
        cx.emit(
            "needless_return",
            last.span,
            "unneeded `return`",
            Some("the route ends here anyway: remove it".into()),
            vec![Fix { start: sp.start, end: sp.end, text: String::new() }],
        );
    }
    for s in &f.stmts {
        match &s.kind {
            StmtKind::If(c, then, els) => {
                if let ExprKind::Bool(b) = unparen(c).kind {
                    cx.emit(
                        "constant_condition",
                        c.span,
                        format!("this condition is always {b}"),
                        Some(format!("the {} branch never runs", if b { "else" } else { "if" })),
                        vec![],
                    );
                }
                if then.stmts.is_empty() && then.tail.is_empty() && els.is_none() {
                    cx.emit("empty_block", s.span, "this `if` has an empty body", Some("remove it".into()), vec![]);
                }
                if let Some(Else::Block(b)) = els
                    && b.stmts.is_empty()
                    && b.tail.is_empty()
                {
                    let sp = Span { start: then.span.end, end: b.span.end };
                    cx.emit(
                        "empty_block",
                        Span { start: b.span.start, end: b.span.end },
                        "empty `else`",
                        Some("remove it".into()),
                        vec![Fix { start: sp.start, end: sp.end, text: String::new() }],
                    );
                }
                // collapsible_if
                if els.is_none()
                    && let [inner] = then.stmts.as_slice()
                    && let StmtKind::If(c2, then2, None) = &inner.kind
                    && !Cx::has_comments(then)
                    && inner.trivia.leading.is_empty()
                {
                    let wrap = |e: &Expr, t: &str| if matches!(e.kind, ExprKind::Binary(BinOp::Or, ..)) { format!("({t})") } else { t.to_string() };
                    let a = wrap(c, cx.text(c.span));
                    let b = wrap(c2, cx.text(c2.span));
                    let text = format!("if {a} && {b} {}", cx.text(then2.span));
                    cx.emit(
                        "collapsible_if",
                        s.span,
                        "this `if` can be merged with the one inside it",
                        Some(format!("write `if {a} && {b} {{ … }}`")),
                        vec![Fix { start: s.span.start, end: s.span.end, text }],
                    );
                }
                // collapsible_else_if
                if let Some(Else::Block(b)) = els
                    && let [inner] = b.stmts.as_slice()
                    && matches!(inner.kind, StmtKind::If(..))
                    && !Cx::has_comments(b)
                {
                    let text = cx.text(inner.span).to_string();
                    cx.emit(
                        "collapsible_else_if",
                        b.span,
                        "`else { if … }` can be `else if …`",
                        Some("write `else if …`".into()),
                        vec![Fix { start: b.span.start, end: b.span.end, text }],
                    );
                }
            }
            StmtKind::Guard(c, _) => {
                if let ExprKind::Bool(b) = unparen(c).kind {
                    cx.emit("constant_condition", c.span, format!("this guard is always {b}"), None, vec![]);
                }
            }
            StmtKind::While(c, b) => match unparen(c).kind {
                ExprKind::Bool(false) => cx.emit("constant_condition", c.span, "this loop never runs", None, vec![]),
                ExprKind::Bool(true) if !leaves(&b.stmts) => {
                    cx.emit("infinite_loop", c.span, "this loop never ends", Some("nothing in it breaks out, returns, exits, drops or awaits".into()), vec![])
                }
                _ => {}
            },
            _ => {}
        }
    }
    for arms in &f.arms {
        let mut seen: BTreeMap<String, Span> = BTreeMap::new();
        let mut wild: Option<Span> = None;
        for a in arms.iter() {
            if let Some(w) = wild {
                let (l, _) = crate::lexer::line_col(&cx.src.text, w.start);
                cx.emit("unreachable_arm", a.span, "this arm never matches", Some(format!("the `_` arm on line {l} matches everything before it")), vec![]);
                continue;
            }
            for p in &a.pats {
                if let Some(k) = pat_key(p) {
                    if let Some(prev) = seen.get(&k) {
                        let (l, _) = crate::lexer::line_col(&cx.src.text, prev.start);
                        cx.emit("unreachable_arm", a.span, format!("`{k}` is already matched"), Some(format!("by the arm on line {l}")), vec![]);
                    } else if a.guard.is_none() {
                        seen.insert(k, a.span);
                    }
                }
            }
            if a.guard.is_none() && a.pats.iter().any(|p| matches!(p, Pat::Wild(_))) {
                wild = Some(a.span);
            }
        }
    }
    for e in &f.exprs {
        match &e.kind {
            ExprKind::Binary(op @ (BinOp::Eq | BinOp::Ne), a, b) => {
                let (other, lit) = match (&unparen(a).kind, &unparen(b).kind) {
                    (_, ExprKind::Bool(v)) => (a, *v),
                    (ExprKind::Bool(v), _) => (b, *v),
                    _ => continue,
                };
                let t = cx.text(other.span).to_string();
                let positive = (*op == BinOp::Eq) == lit;
                let text = if positive {
                    t
                } else if matches!(other.kind, ExprKind::Ident(_) | ExprKind::Field(..) | ExprKind::Call(..) | ExprKind::Paren(_)) {
                    format!("!{t}")
                } else {
                    format!("!({t})")
                };
                cx.emit(
                    "bool_comparison",
                    e.span,
                    format!("comparison with `{lit}`"),
                    Some(format!("write `{text}`")),
                    vec![Fix { start: e.span.start, end: e.span.end, text }],
                );
            }
            ExprKind::Call(c, args) if ident(c) == Some("reply") => {
                let Some(first) = args.first() else { continue };
                let code = match &first.value.kind {
                    ExprKind::Int(i) => Some((*i, first.value.span)),
                    ExprKind::Ident(n) => crate::msg::status_code(n).map(|c| (c, first.value.span)),
                    _ => None,
                };
                let Some((code, code_span)) = code else { continue };
                let std = crate::msg::reason(code);
                match args.get(1) {
                    None if std == "Unknown" => cx.emit(
                        "unknown_reply_reason",
                        e.span,
                        format!("{code} has no standard reason phrase"),
                        Some(format!("pass one: `reply({code}, \"…\")`")),
                        vec![],
                    ),
                    Some(r) => {
                        if let ExprKind::Str(parts) = &r.value.kind
                            && let [StrPart::Lit(s)] = parts.as_slice()
                            && s == std
                        {
                            cx.emit(
                                "redundant_reply_reason",
                                r.value.span,
                                format!("\"{s}\" is the reason {code} gets anyway"),
                                Some(format!("write `reply({})`", crate::fmt::expr(&first.value))),
                                vec![Fix { start: code_span.end, end: r.value.span.end, text: String::new() }],
                            );
                        }
                    }
                    None => {}
                }
            }
            ExprKind::Call(c, args)
                if matches!(&c.kind, ExprKind::Field(ns, _) if ident(ns) == Some("sql"))
                    && let Some(q) = args.iter().filter(|a| a.name.is_none()).nth(1)
                    && let ExprKind::Str(parts) = &q.value.kind =>
            {
                for p in parts {
                    if let StrPart::Expr(x) = p
                        && !matches!(x.kind, ExprKind::Int(_))
                        && !matches!(&x.kind, ExprKind::Call(f, _) if matches!(&f.kind, ExprKind::Field(ns, n) if ident(ns) == Some("sql") && n.text == "quote"))
                    {
                        cx.emit(
                            "sql_injection",
                            x.span,
                            format!("`{}` goes into the SQL text unescaped", cx.text(x.span)),
                            Some(format!("write `{{sql.quote({})}}` (without quotes around it)", cx.text(x.span))),
                            vec![],
                        );
                    }
                }
            }
            ExprKind::Call(c, args) if pv_arg(e).is_some() || kamailio_fn(c, args).is_some() => {
                let what = match pv_arg(e) {
                    Some(p) => format!("`{p}` is read or written unchecked"),
                    None => format!("`{}()` is called unchecked", kamailio_fn(c, args).unwrap_or_default()),
                };
                cx.emit("raw_kamailio", e.span, what, Some("use the typed form where there is one (ferrosip lint --explain raw_kamailio)".into()), vec![]);
            }
            ExprKind::Await(inner) => {
                if let ExprKind::Call(c, args) = &inner.kind
                    && matches!(&c.kind, ExprKind::Field(ns, n) if ident(ns) == Some("txn") && n.text == "relay")
                    && !args.iter().any(|a| a.name.as_ref().is_some_and(|n| n.text == "timeout"))
                {
                    cx.emit("relay_without_timeout", e.span, "no `timeout:` for this relay", Some("add `timeout: 30s` (or the wait you want)".into()), vec![]);
                }
            }
            ExprKind::Str(parts) => {
                for p in parts {
                    // `{4}` interpolates the number 4: almost always a regex
                    // quantifier written without escapes.
                    if let StrPart::Expr(x) = p
                        && matches!(x.kind, ExprKind::Int(_))
                    {
                        let (a, b) = (x.span.start.saturating_sub(1), x.span.end.saturating_add(1));
                        let inner = cx.text(x.span).to_string();
                        cx.emit(
                            "number_interpolation",
                            Span { start: a, end: b },
                            format!("`{{{inner}}}` puts the number {inner} into the string"),
                            Some(format!("for a regex quantifier write `\\{{{inner}\\}}`")),
                            vec![Fix { start: a, end: b, text: format!("\\{{{inner}\\}}") }],
                        );
                    }
                }
                for p in parts.iter().filter(|_| !is_test) {
                    if let StrPart::Lit(s) = p
                        && let Some(ip) = has_ipv4(s)
                        && !ip.starts_with("127.")
                        && ip != "0.0.0.0"
                    {
                        cx.emit(
                            "hardcoded_address",
                            e.span,
                            format!("{ip} is written in the routing"),
                            Some("move it to [feature] in ferrosip.toml".into()),
                            vec![],
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// Lint parsed, successfully compiled sources (entry first).
pub fn lint(sources: &[Source], env: &Env) -> Report {
    let mut r = Report::default();
    let file_ns: BTreeSet<&str> = sources.iter().map(|s| s.ns.as_str()).filter(|n| !n.is_empty()).collect();
    // What is used where: calls of user functions (ns, name), namespaces,
    // identifiers and field names (flags, tables, dialog vars).
    let mut called: BTreeSet<(String, String)> = BTreeSet::new();
    let mut ns_used: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut idents: BTreeSet<String> = BTreeSet::new();
    let mut fields: BTreeSet<String> = BTreeSet::new();
    for src in sources {
        for item in &src.file.items {
            // Allow comments.
            let mut allow = |trivia: &Trivia, span: Span| {
                let names: Vec<String> = trivia.leading.iter().chain(&trivia.trailing).filter_map(|c| parse_allow(c)).flatten().collect();
                if !names.is_empty() {
                    r.allows.push(Allow { file: src.name.clone(), start: span.start, end: span.end, names });
                }
            };
            allow(&item.trivia, item.span);
            let (blocks, exprs, is_test) = bodies(item);
            let mut f = Flat::default();
            for b in &blocks {
                f.block(b);
            }
            for e in &exprs {
                f.expr(e);
            }
            for s in &f.stmts {
                allow(&s.trivia, s.span);
            }
            for arms in &f.arms {
                for a in arms.iter() {
                    allow(&a.trivia, a.span);
                }
            }
            if let ItemKind::Route(func) = &item.kind
                && func.name.text == "main"
                && src.ns.is_empty()
            {
                r.entry = Some((src.name.clone(), func.name.span.start, func.name.span.end));
            }
            for e in &f.exprs {
                match &e.kind {
                    ExprKind::Ident(n) => {
                        idents.insert(n.clone());
                    }
                    ExprKind::Field(a, n) => {
                        fields.insert(n.text.clone());
                        if let Some(ns) = ident(a) {
                            ns_used.entry(src.name.clone()).or_default().insert(ns.to_string());
                            if ns == "features" {
                                r.features.insert(n.text.clone());
                            }
                        }
                    }
                    _ => {}
                }
                if let ExprKind::Call(c, _) = &e.kind {
                    match &c.kind {
                        ExprKind::Ident(n) => {
                            called.insert((src.ns.clone(), n.clone()));
                        }
                        ExprKind::Field(a, n) => {
                            if let Some(ns) = ident(a).filter(|ns| file_ns.contains(ns)) {
                                called.insert((ns.to_string(), n.text.clone()));
                            }
                        }
                        _ => {}
                    }
                }
                if is_test {
                    continue;
                }
                // Facts for the routing-wide lints.
                let mut fact = |what: &str| r.facts.push(Fact { what: what.into(), file: src.name.clone(), start: e.span.start, end: e.span.end });
                // A check called on the source address (`ip.in_subnet(msg.src.ip, …)`)
                // restricts who gets through, like a comparison does.
                if let ExprKind::Call(_, args) = &e.kind
                    && args.iter().any(|a| is_src_ip(&a.value))
                {
                    fact("@src_check");
                }
                // By its Kamailio name, raw or typed (`sip.process(10)`).
                let mut fn_fact = |f: &str| {
                    fact(if f.starts_with("mf_process") {
                        "@max_forwards"
                    } else if f == "sanity_check" {
                        "@sanity"
                    } else {
                        f
                    })
                };
                match &e.kind {
                    ExprKind::Call(c, args) => match &c.kind {
                        _ if kamailio_fn(c, args).is_some() => fn_fact(&kamailio_fn(c, args).unwrap_or_default()),
                        ExprKind::Ident(n) if n == "relay" => fn_fact("t_relay"),
                        ExprKind::Field(a, n) => {
                            if n.text == "is_sane" {
                                fn_fact("sanity_check");
                            } else if let Some(sig) = ident(a).and_then(|ns| env.namespaces.get(ns)).and_then(|m| m.get(&n.text)) {
                                fn_fact(sig.name);
                            }
                        }
                        _ => {}
                    },
                    ExprKind::Field(_, n) if n.text == "max_forwards" => fn_fact("@max_forwards"),
                    ExprKind::Binary(BinOp::Eq | BinOp::Ne | BinOp::In | BinOp::Match, a, b) if is_src_ip(a) || is_src_ip(b) => fn_fact("@src_check"),
                    _ => {}
                }
            }
        }
    }
    for src in sources {
        let mut cx = Cx { src, out: &mut r.findings };
        for item in &src.file.items {
            let (blocks, _, is_test) = bodies(item);
            for b in &blocks {
                lint_block(&mut cx, b, is_test);
                let mut u = Unused { cx: &mut cx, scopes: vec![] };
                u.block(b);
            }
            match &item.kind {
                ItemKind::Modules(names) => {
                    let used = ns_used.get(&src.name);
                    for (i, n) in names.iter().enumerate() {
                        let needless = n.text == "log" || n.text == "txn";
                        let unused = !used.is_some_and(|u| u.contains(&n.text));
                        if !needless && !unused {
                            continue;
                        }
                        // Remove the name (with a comma), or the whole line.
                        let sp = if names.len() == 1 {
                            cx.line_span(item.span)
                        } else if let Some(next) = names.get(i.saturating_add(1)) {
                            Span { start: n.span.start, end: next.span.start }
                        } else {
                            // The last of several: from the end of the one before.
                            let prev = i.checked_sub(1).and_then(|k| names.get(k));
                            Span { start: prev.map_or(n.span.start, |p| p.span.end), end: n.span.end }
                        };
                        let fix = vec![Fix { start: sp.start, end: sp.end, text: String::new() }];
                        if needless {
                            cx.emit("needless_import", n.span, format!("`{}` is always available", n.text), Some("remove this import".into()), fix);
                        } else {
                            cx.emit("unused_import", n.span, format!("`{}` is imported but never used", n.text), Some("remove this import".into()), fix);
                        }
                    }
                }
                ItemKind::Fn(func) if !called.contains(&(src.ns.clone(), func.name.text.clone())) => {
                    cx.emit("unused_function", func.name.span, format!("function `{}` is never called", func.name.text), None, vec![]);
                }
                ItemKind::Flag(n, ..) if !idents.contains(&n.text) => {
                    cx.emit("unused_flag", n.span, format!("flag `{}` is never set or tested", n.text), Some("remove it".into()), vec![]);
                }
                ItemKind::Table { name, ttl, .. } => {
                    if !idents.contains(&name.text) {
                        cx.emit("unused_state", name.span, format!("table `{}` is never used", name.text), Some("remove it".into()), vec![]);
                    }
                    if ttl.is_none() {
                        cx.emit(
                            "table_without_ttl",
                            name.span,
                            format!("entries of `{}` never expire", name.text),
                            Some("add `ttl 10m` (or the lifetime you want)".into()),
                            vec![],
                        );
                    }
                }
                ItemKind::DialogVar { name, .. } if !fields.contains(&name.text) => {
                    cx.emit("unused_state", name.span, format!("dialog var `{}` is never used", name.text), Some("remove it".into()), vec![]);
                }
                ItemKind::On(on) if on.event.text.starts_with("kamailio.") => {
                    cx.emit(
                        "raw_kamailio",
                        on.event.span,
                        format!("`on {}` is a Kamailio route", on.event.text),
                        Some("a failure_route is usually `await txn.relay` + match; an event_route has a typed `on` handler for dialogs, http, timers…".into()),
                        vec![],
                    );
                }
                ItemKind::On(on) if on.event.text == "timer" => {
                    for a in &on.args {
                        if let ExprKind::Duration(ms, _) = a.value.kind
                            && ms < 100
                        {
                            cx.emit(
                                "timer_too_frequent",
                                a.value.span,
                                format!("this timer runs every {ms}ms"),
                                Some("run it less often (every: 1s)".into()),
                                vec![],
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str) -> Vec<Finding> {
        let file = crate::parse(text).unwrap();
        let src = Source { name: "t.fsr".into(), ns: String::new(), text: text.into(), file };
        lint(&[src], &Env::default()).findings
    }

    fn names(text: &str) -> Vec<&'static str> {
        run(text).iter().map(|f| f.lint).collect()
    }

    fn apply(text: &str, lint: &str) -> String {
        let mut out = text.to_string();
        let mut fixes: Vec<Fix> = run(text).into_iter().filter(|f| f.lint == lint).flat_map(|f| f.fixes).collect();
        fixes.sort_by_key(|f| std::cmp::Reverse(f.start));
        for f in fixes {
            out.replace_range(f.start..f.end, &f.text);
        }
        out
    }

    #[test]
    fn unused_variables_and_bindings() {
        let src = "route main(msg: Request) {\n    let a = 1\n    let b = 2\n    let _c = 3\n    log.info(\"{b}\")\n    for x in [1, 2] { exit }\n}\n";
        assert_eq!(names(src), vec!["unused_variable", "unused_variable"]);
        let fixed = apply(src, "unused_variable");
        assert!(fixed.contains("let _a = 1") && fixed.contains("for _x in"), "{fixed}");
        // Assignment is not a read; sibling scopes are separate.
        let src = "route main(msg: Request) {\n    if true { let a = 1\n log.info(\"{a}\") } else { let a = 2\n a = 3 }\n}\n";
        let f = run(src);
        assert_eq!(f.iter().filter(|f| f.lint == "unused_variable").count(), 1);
        let src = "route main(msg: Request) {\n    let r = await txn.relay(msg, timeout: 5s)\n    match r {\n        Final(x) => exit\n        Timeout => drop\n    }\n}\n";
        assert_eq!(apply(src, "unused_variable").matches("Final(_)").count(), 1);
    }

    #[test]
    fn sql_values_need_quote() {
        let t = "import sql\nroute main(msg: Request) {\n    let c = \"\"\n    let n = 5\n    if sql.query_value(\"db\", \"SELECT a FROM t WHERE u = '{msg.ruri.user}' AND v = {sql.quote(msg.from.user)} LIMIT {n}\", c) {\n        reply(200)\n    }\n    reply(404)\n}\n";
        let f = run(t);
        let hits: Vec<&Finding> = f.iter().filter(|f| f.lint == "sql_injection").collect();
        assert_eq!(hits.len(), 2, "{f:?}");
    }

    #[test]
    fn number_interpolation_in_a_regex() {
        let t = "route main(msg: Request) {\n    if msg.ruri.user =~ \"^[0-9]{4}$\" {\n        reply(200)\n    }\n    reply(404)\n}\n";
        assert!(names(t).contains(&"number_interpolation"), "{:?}", names(t));
        let fixed = apply(t, "number_interpolation");
        assert!(fixed.contains(r#""^[0-9]\{4\}$""#), "{fixed}");
        assert!(!names(&fixed).contains(&"number_interpolation"));
    }

    #[test]
    fn style_fixes() {
        let src =
            "route main(msg: Request) {\n    if x == true { exit }\n    if y != true { exit }\n    reply(404, \"Not Found\")\n    reply(499)\n    return\n}\n";
        let n = names(src);
        assert!(
            n.contains(&"bool_comparison") && n.contains(&"redundant_reply_reason") && n.contains(&"unknown_reply_reason") && n.contains(&"needless_return"),
            "{n:?}"
        );
        let fixed = apply(src, "bool_comparison");
        assert!(fixed.contains("if x { exit }") && fixed.contains("if !y { exit }"), "{fixed}");
        assert!(apply(src, "redundant_reply_reason").contains("reply(404)\n"));
        assert!(!apply(src, "needless_return").contains("return"));
        let src = "route main(msg: Request) {\n    if a {\n        if b || c {\n            exit\n        }\n    } else {\n    }\n}\n";
        assert!(names(src).contains(&"empty_block"));
        let src = "route main(msg: Request) {\n    if a {\n        if b || c {\n            exit\n        }\n    }\n}\n";
        assert!(apply(src, "collapsible_if").contains("if a && (b || c) {\n            exit\n        }"));
        let src = "route main(msg: Request) {\n    if a { exit } else {\n        if b { drop }\n    }\n}\n";
        assert!(apply(src, "collapsible_else_if").contains("} else if b { drop }"));
    }

    #[test]
    fn items_and_imports() {
        let src = "import txn, location, nat\nflag A\nflag B\nshared table t: Map<Str, Int>\nroute main(msg: Request) {\n    msg.set(A)\n    location.lookup(msg.ruri)\n}\nfn helper(msg: Request) { exit }\n";
        let n = names(src);
        for want in ["needless_import", "unused_import", "unused_flag", "unused_state", "table_without_ttl", "unused_function"] {
            assert!(n.contains(&want), "{want} in {n:?}");
        }
        let fixed = apply(src, "unused_import");
        assert!(fixed.starts_with("import txn, location\n"), "{fixed}");
        assert!(apply(&fixed, "needless_import").starts_with("import location\n"));
        assert!(apply("import nat\nroute main(msg: Request) { exit }\n", "unused_import").starts_with("route main"));
    }

    #[test]
    fn loops_matches_and_conditions() {
        let src = "route main(msg: Request) {\n    while true { log.info(\"x\") }\n    while true { while true { break }\n }\n    while true { if a { break } }\n    if false { exit }\n}\n";
        let n = names(src);
        assert_eq!(n.iter().filter(|n| **n == "infinite_loop").count(), 2, "{n:?}");
        assert!(n.contains(&"constant_condition"));
        let src = "route main(msg: Request) {\n    match msg.method {\n        INVITE => exit\n        INVITE => drop\n        _ => exit\n        BYE => exit\n    }\n}\n";
        assert_eq!(names(src).iter().filter(|n| **n == "unreachable_arm").count(), 2);
    }

    #[test]
    fn pedantic_ones() {
        let src = "route main(msg: Request) {\n    let r = await txn.relay(msg)\n    msg.ruri = \"sip:x@10.1.2.3:5060\"\n    log.info(\"{r}\")\n}\non timer(every: 50ms) { log.info(\"t\") }\n";
        let n = names(src);
        assert!(n.contains(&"relay_without_timeout") && n.contains(&"hardcoded_address") && n.contains(&"timer_too_frequent"), "{n:?}");
        assert_eq!(has_ipv4("v1.2.3.4.5"), None);
        assert_eq!(has_ipv4("a 192.168.0.1:5060"), Some("192.168.0.1"));
    }

    #[test]
    fn allow_comments() {
        assert_eq!(parse_allow("// lint: allow(unused_variable, open_relay)"), Some(vec!["unused_variable".into(), "open_relay".into()]));
        assert_eq!(parse_allow("# lint: allow(redundant_default)"), Some(vec!["redundant_default".into()]));
        assert_eq!(parse_allow("// allow it"), None);
        let file = crate::parse("route main(msg: Request) {\n    // lint: allow(unused_variable)\n    let a = 1\n}\n").unwrap();
        let text = "route main(msg: Request) {\n    // lint: allow(unused_variable)\n    let a = 1\n}\n";
        let r = lint(&[Source { name: "t".into(), ns: String::new(), text: text.into(), file }], &Env::default());
        assert_eq!(r.allows.len(), 1);
        assert!(r.allows[0].start <= r.findings[0].start && r.findings[0].end <= r.allows[0].end);
    }

    #[test]
    fn a_check_on_the_source_address_restricts() {
        let text = "import ip\nroute main(msg: Request) {\n    guard ip.in_subnet(msg.src.ip, \"10.0.0.0/8\") else reply(403)\n    relay(msg)\n}\n";
        let file = crate::parse(text).unwrap();
        let r = lint(&[Source { name: "t".into(), ns: String::new(), text: text.into(), file }], &Env::default());
        assert!(r.facts.iter().any(|f| f.what == "@src_check"), "{:?}", r.facts.iter().map(|f| &f.what).collect::<Vec<_>>());
    }

    #[test]
    fn typed_max_forwards_and_sanity_checks_count() {
        use sip_core::sig::{Ret, sig};
        let mut env = Env::default();
        env.add("sip", [sig("mf_process_maxfwd_header", "process", &[], Ret::Bool, ""), sig("sanity_check", "check", &[], Ret::Bool, "")]);
        let text = "import sip\nroute main(msg: Request) {\n    if !sip.process(10) { reply(483) }\n    if !sip.check() { exit }\n    relay(msg)\n}\n";
        let file = crate::parse(text).unwrap();
        let r = lint(&[Source { name: "t".into(), ns: String::new(), text: text.into(), file }], &env);
        let what: Vec<&String> = r.facts.iter().map(|f| &f.what).collect();
        assert!(what.iter().any(|w| *w == "@max_forwards") && what.iter().any(|w| *w == "@sanity"), "{what:?}");
    }

    #[test]
    fn catalogue_is_consistent() {
        let mut seen = BTreeSet::new();
        for l in LINTS {
            assert!(seen.insert(l.name), "{} twice", l.name);
            assert!(["fsr", "cfg", "routing", "toml"].contains(&l.on));
        }
    }
    /// Every fix applied, later ones first, overlapping ones skipped (as
    /// `ferrosip lint --fix` does in one round).
    fn apply_all(text: &str) -> String {
        let mut out = text.to_string();
        let mut fixes: Vec<Fix> = run(text).into_iter().flat_map(|f| f.fixes).collect();
        fixes.sort_by_key(|f| std::cmp::Reverse((f.start, f.end)));
        let mut floor = usize::MAX;
        for f in fixes {
            if f.end <= floor {
                out.replace_range(f.start..f.end, &f.text);
                floor = f.start;
            }
        }
        out
    }

    #[test]
    fn fixes_give_exact_text() {
        let cases = [
            ("unused_variable", "route main(msg: Request) {\n    let a = 1\n    exit\n}\n", "route main(msg: Request) {\n    let _a = 1\n    exit\n}\n"),
            ("needless_return", "fn f(msg: Request) {\n    drop\n    return\n}\n", "fn f(msg: Request) {\n    drop\n}\n"),
            ("empty_block", "route main(msg: Request) {\n    if a { exit } else {\n    }\n}\n", "route main(msg: Request) {\n    if a { exit }\n}\n"),
            (
                "collapsible_if",
                "route main(msg: Request) {\n    if a || b {\n        if c { exit }\n    }\n}\n",
                "route main(msg: Request) {\n    if (a || b) && c { exit }\n}\n",
            ),
            (
                "collapsible_else_if",
                "route main(msg: Request) {\n    if a { exit } else {\n        if b { drop } else { exit }\n    }\n}\n",
                "route main(msg: Request) {\n    if a { exit } else if b { drop } else { exit }\n}\n",
            ),
            (
                "bool_comparison",
                "route main(msg: Request) {\n    if a == false && (b || c) == true && false != d && (x < 1) == false { exit }\n}\n",
                "route main(msg: Request) {\n    if !a && (b || c) && d && !(x < 1) { exit }\n}\n",
            ),
            (
                "redundant_reply_reason",
                "route main(msg: Request) {\n    reply(NotFound, \"Not Found\")\n    reply(404, \"Gone away\")\n}\n",
                "route main(msg: Request) {\n    reply(NotFound)\n    reply(404, \"Gone away\")\n}\n",
            ),
            (
                "number_interpolation",
                "route main(msg: Request) {\n    if msg.ruri.user =~ \"^[0-9]\\{3\\}x{2}$\" { exit }\n}\n",
                "route main(msg: Request) {\n    if msg.ruri.user =~ \"^[0-9]\\{3\\}x\\{2\\}$\" { exit }\n}\n",
            ),
            (
                "unused_import",
                "import location, nat, auth\nroute main(msg: Request) {\n    location.lookup()\n    auth.check()\n}\n",
                "import location, auth\nroute main(msg: Request) {\n    location.lookup()\n    auth.check()\n}\n",
            ),
            ("needless_import", "import log\nroute main(msg: Request) {\n    log.info(\"x\")\n}\n", "route main(msg: Request) {\n    log.info(\"x\")\n}\n"),
        ];
        for (lint, src, want) in cases {
            assert_eq!(apply(src, lint), want, "{lint}");
        }
    }

    #[test]
    fn several_names_of_one_import_need_two_rounds() {
        let src = "import txn, nat, auth\nroute main(msg: Request) {\n    exit\n}\n";
        let once = apply_all(src);
        assert_eq!(once, "import nat\nroute main(msg: Request) {\n    exit\n}\n", "the fix of `nat` overlaps the others: it waits");
        assert_eq!(apply_all(&once), "route main(msg: Request) {\n    exit\n}\n");
    }

    #[test]
    fn findings_have_spans_on_their_code() {
        let src = "import nat\nflag F\nroute main(msg: Request) {\n    let v = 1\n    while true { log.info(\"x\") }\n    if false { exit }\n}\nfn helper(msg: Request) { exit }\n";
        let spans: Vec<(&str, &str)> = run(src).iter().map(|f| (f.lint, src.get(f.start..f.end).unwrap_or_default())).collect();
        for want in [
            ("unused_import", "nat"),
            ("unused_flag", "F"),
            ("unused_variable", "v"),
            ("infinite_loop", "true"),
            ("constant_condition", "false"),
            ("unused_function", "helper"),
        ] {
            assert!(spans.contains(&want), "{want:?} in {spans:?}");
        }
    }
}
