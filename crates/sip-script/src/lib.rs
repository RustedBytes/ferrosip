//! Routing-script language, Kamailio-style:
//!
//! ```text
//! loadmodule "tm"
//! request_route {
//!     if ($rm == "OPTIONS") { sl_send_reply(200, "OK"); exit; }
//!     $var(target) = "sip:" + $rU + "@10.0.0.5";
//!     route(RELAY);
//! }
//! route[RELAY] { $du = $var(target); t_relay(); }
//! ```
//!
//! Pipeline (same as Kamailio's cfg.y → route.c fixups → action.c):
//!   text → tokens → AST → **compile** (resolve every function name to a
//!   function pointer, run its fixup on the literal args, resolve every
//!   `$variable` and `route(NAME)`, compile constant regexes, turn
//!   `$rm == "INVITE"` into an enum compare) → action trees.
//! At runtime nothing is looked up by name and no literal is re-parsed.
#![forbid(unsafe_code)]

pub mod fmt;
mod lexer;
mod parser;
pub mod preprocess;

pub use parser::{Ast, BinOp, Expr, ModParam, RawArg, Stmt, parse};

/// Names the script uses that modules provide: functions it calls, and
/// pseudo-variables (`$sht`, `$dlg_var`…, also inside strings). For
/// loading modules on demand (ferrosip.toml).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Uses {
    pub functions: std::collections::BTreeSet<String>,
    pub pvs: std::collections::BTreeSet<String>,
}

/// `$name`, `$name(…)`, `$(name…)` and `${name}`-style references in a string.
fn pv_names(s: &str, out: &mut std::collections::BTreeSet<String>) {
    // Names hold no `$`, so each piece after one starts a reference.
    for piece in s.split('$').skip(1) {
        let name = piece.trim_start_matches(['(', '{']);
        let end = name.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(name.len());
        if let Some(name) = name.get(..end).filter(|n| n.starts_with(|c: char| !c.is_ascii_digit())) {
            out.insert(name.to_string());
        }
    }
}

fn uses_expr(e: &Expr, u: &mut Uses) {
    match e {
        Expr::Str(s) => pv_names(s, &mut u.pvs),
        Expr::Pv(p, _) => pv_names(p, &mut u.pvs),
        Expr::Call { name, args, .. } => {
            u.functions.insert(name.clone());
            for a in args {
                match a {
                    RawArg::Str(s) | RawArg::Pv(s) => pv_names(s, &mut u.pvs),
                    RawArg::Int(_) => {}
                }
            }
        }
        Expr::Not(x) | Expr::Neg(x) => uses_expr(x, u),
        Expr::Bin(_, a, b) => {
            uses_expr(a, u);
            uses_expr(b, u);
        }
        Expr::Int(_) | Expr::Route(..) | Expr::Myself => {}
    }
}

fn uses_stmts(stmts: &[Stmt], u: &mut Uses) {
    for s in stmts {
        match s {
            Stmt::If(c, a, b) => {
                uses_expr(c, u);
                uses_stmts(a, u);
                uses_stmts(b, u);
            }
            Stmt::While(c, body) => {
                uses_expr(c, u);
                uses_stmts(body, u);
            }
            Stmt::Switch(e, cases) => {
                uses_expr(e, u);
                for (v, body) in cases {
                    if let Some(v) = v {
                        uses_expr(v, u);
                    }
                    uses_stmts(body, u);
                }
            }
            Stmt::Assign(target, e, _) => {
                pv_names(target, &mut u.pvs);
                uses_expr(e, u);
            }
            Stmt::Expr(e) | Stmt::Return(Some(e)) => uses_expr(e, u),
            Stmt::Exit | Stmt::Drop | Stmt::Return(None) | Stmt::Break => {}
        }
    }
}

/// Everything module-provided that `ast`'s routes use.
pub fn uses(ast: &Ast) -> Uses {
    let mut u = Uses::default();
    uses_stmts(&ast.request_route, &mut u);
    for (_, body) in ast.routes.iter().chain(&ast.failure_routes).chain(&ast.onreply_routes).chain(&ast.branch_routes).chain(&ast.event_routes) {
        uses_stmts(body, &mut u);
    }
    if let Some(r) = &ast.reply_route {
        uses_stmts(r, &mut u);
    }
    u
}

use regex::Regex;
use sip_core::pv::{PvRef, Val, parse_fmt, parse_pv};
use sip_core::{Arg, AsyncPending, Continuation, Ctx, ExportFn, Fixed, Handler, Registry, RouteNames, RouteRoot, RouteRunner, TransportEvent};
use sip_parser::Method;
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

/// Kamailio's `max_while_loops`-style guard, and a recursion limit for route().
const MAX_LOOPS: usize = 10_000;
const MAX_DEPTH: usize = 100;

pub struct Bound {
    pub name: String,
    func: ExportFn,
    arg: Fixed,
}

enum Re {
    Static(Regex),
    Dynamic(Box<CExpr>),
}

enum CExpr {
    Lit(Val),
    Pv(PvRef),
    Call(Bound),
    Route(usize),
    Not(Box<CExpr>),
    Neg(Box<CExpr>),
    Bin(BinOp, Box<CExpr>, Box<CExpr>),
    Match(Box<CExpr>, Re, bool),
    /// `$rm == "INVITE"` fast path.
    Method(Method, bool),
    /// `X == myself` / `X != myself`.
    Myself(Box<CExpr>, bool),
}

enum Act {
    If(CExpr, Vec<Act>, Vec<Act>),
    While(CExpr, Vec<Act>),
    Switch(CExpr, Vec<(Option<Val>, Vec<Act>)>),
    Assign(PvRef, CExpr),
    Eval(CExpr),
    Exit,
    Drop,
    Return(Option<CExpr>),
    Break,
}

#[derive(PartialEq, Debug)]
enum Flow {
    Next,
    Exit,
    Drop,
    Return(i32),
    Break,
    /// A function suspended the message (`AsyncPending` in the Ctx).
    Suspend(Box<Susp>),
}

/// Where a suspended script continues, built while unwinding: one frame
/// per route, innermost first. The last frame is the route still
/// unwinding (its `root` is set when it is left).
#[derive(PartialEq, Debug)]
struct Susp {
    frames: Vec<SFrame>,
    /// A route suspended where its caller needs its value (`if
    /// (route(x))`): only that route resumes, not its callers.
    sealed: bool,
}

#[derive(PartialEq, Debug)]
struct SFrame {
    root: Option<RouteRoot>,
    path: Vec<(usize, usize)>,
    at: usize,
}

impl Susp {
    fn at(at: usize) -> Box<Susp> {
        Box::new(Susp { frames: vec![SFrame { root: None, path: Vec::new(), at }], sealed: false })
    }

    /// The frame of the route being unwound, if it is still open.
    fn open(&mut self) -> Option<&mut SFrame> {
        self.frames.last_mut().filter(|f| f.root.is_none())
    }
}

/// A suspension inside arm `arm` of the action at `i`: record the step.
fn nest(f: Flow, i: usize, arm: usize) -> Flow {
    match f {
        Flow::Suspend(mut s) => {
            if let Some(o) = s.open() {
                o.path.insert(0, (i, arm));
            }
            Flow::Suspend(s)
        }
        f => f,
    }
}

pub fn convert_arg(a: &RawArg, reg: &Registry) -> Result<Arg, String> {
    Ok(match a {
        RawArg::Int(i) => Arg::Int(*i),
        RawArg::Str(s) if !s.contains('$') => Arg::Str(s.clone()),
        RawArg::Str(s) => {
            let f = parse_fmt(s, reg.pvs())?;
            if f.has_pv() { Arg::Fmt(Arc::new(f)) } else { Arg::Str(f.literal()) }
        }
        RawArg::Pv(p) => Arg::Fmt(Arc::new(parse_fmt(p, reg.pvs())?)),
    })
}

struct Compiler<'r> {
    reg: &'r Registry,
    routes: HashMap<String, usize>,
}

impl Compiler<'_> {
    fn bind(&self, name: &str, args: &[RawArg], line: usize) -> Result<Bound, String> {
        let e = self.reg.get(name).ok_or_else(|| format!("line {line}: unknown function {name}() (module not loaded?)"))?;
        let args = args.iter().map(|a| convert_arg(a, self.reg)).collect::<Result<Vec<_>, _>>().map_err(|e| format!("line {line}: {name}(): {e}"))?;
        let arg = (e.fixup)(&args).map_err(|err| format!("line {line}: {name}(): {err}"))?;
        Ok(Bound { name: name.to_string(), func: e.func.clone(), arg })
    }

    fn pv(&self, s: &str, line: usize) -> Result<PvRef, String> {
        parse_pv(s, self.reg.pvs()).map_err(|e| format!("line {line}: {e}"))
    }

    fn block(&self, stmts: &[Stmt]) -> Result<Vec<Act>, String> {
        stmts.iter().map(|s| self.stmt(s)).collect()
    }

    fn stmt(&self, s: &Stmt) -> Result<Act, String> {
        Ok(match s {
            Stmt::Exit => Act::Exit,
            Stmt::Drop => Act::Drop,
            Stmt::Break => Act::Break,
            Stmt::Return(e) => Act::Return(e.as_ref().map(|e| self.expr(e)).transpose()?),
            Stmt::Expr(e) => Act::Eval(self.expr(e)?),
            Stmt::If(c, t, e) => Act::If(self.expr(c)?, self.block(t)?, self.block(e)?),
            Stmt::While(c, b) => Act::While(self.expr(c)?, self.block(b)?),
            Stmt::Switch(v, cases) => {
                let mut out = Vec::new();
                for (label, body) in cases {
                    let l = match label {
                        None => None,
                        Some(Expr::Int(i)) => Some(Val::Int(*i)),
                        Some(Expr::Str(s)) => Some(Val::Str(s.clone())),
                        Some(e) => return Err(format!("case labels must be literals, got {e:?}")),
                    };
                    out.push((l, self.block(body)?));
                }
                Act::Switch(self.expr(v)?, out)
            }
            Stmt::Assign(pv, e, line) => {
                let r = self.pv(pv, *line)?;
                if !r.settable() {
                    return Err(format!("line {line}: {pv} can't be assigned"));
                }
                Act::Assign(r, self.expr(e)?)
            }
        })
    }

    fn expr(&self, e: &Expr) -> Result<CExpr, String> {
        Ok(match e {
            Expr::Str(s) if !s.contains('$') => CExpr::Lit(Val::Str(s.clone())),
            // Strings with variables in expressions concatenate (templates).
            Expr::Str(s) => {
                let f = parse_fmt(s, self.reg.pvs())?;
                let mut it = f.0.into_iter().map(|p| match p {
                    sip_core::pv::FmtPart::Lit(l) => CExpr::Lit(Val::Str(l)),
                    sip_core::pv::FmtPart::Pv(r) => CExpr::Pv(r),
                });
                let first = it.next().unwrap_or(CExpr::Lit(Val::Str(String::new())));
                let first = CExpr::Bin(BinOp::Add, Box::new(CExpr::Lit(Val::Str(String::new()))), Box::new(first));
                it.fold(first, |acc, p| CExpr::Bin(BinOp::Add, Box::new(acc), Box::new(p)))
            }
            Expr::Int(i) => CExpr::Lit(Val::Int(*i)),
            Expr::Pv(p, line) => CExpr::Pv(self.pv(p, *line)?),
            Expr::Call { name, args, line } => CExpr::Call(self.bind(name, args, *line)?),
            Expr::Route(n, line) => CExpr::Route(*self.routes.get(n).ok_or_else(|| format!("line {line}: no route[{n}]"))?),
            Expr::Not(x) => CExpr::Not(Box::new(self.expr(x)?)),
            Expr::Neg(x) => CExpr::Neg(Box::new(self.expr(x)?)),
            Expr::Myself => return Err("myself can only be compared with == or !=".into()),
            Expr::Bin(op @ (BinOp::Eq | BinOp::Ne), a, b) if matches!(**a, Expr::Myself) || matches!(**b, Expr::Myself) => {
                let other = if matches!(**a, Expr::Myself) { b } else { a };
                CExpr::Myself(Box::new(self.expr(other)?), *op == BinOp::Ne)
            }
            Expr::Bin(op @ (BinOp::Eq | BinOp::Ne), a, b)
                if let (Expr::Pv(p, _), Expr::Str(m)) = (&**a, &**b)
                    && p == "$rm"
                    && Method::from_bytes(m.as_bytes()) != Method::Other =>
            {
                CExpr::Method(Method::from_bytes(m.as_bytes()), *op == BinOp::Ne)
            }
            Expr::Bin(op @ (BinOp::Match | BinOp::NoMatch), a, b) => {
                let re = match &**b {
                    Expr::Str(s) if !s.contains('$') => Re::Static(Regex::new(s).map_err(|e| format!("bad regex {s:?}: {e}"))?),
                    other => Re::Dynamic(Box::new(self.expr(other)?)),
                };
                CExpr::Match(Box::new(self.expr(a)?), re, *op == BinOp::NoMatch)
            }
            Expr::Bin(op, a, b) => CExpr::Bin(*op, Box::new(self.expr(a)?), Box::new(self.expr(b)?)),
        })
    }
}

pub struct Engine {
    reg: Arc<Registry>,
    /// Route names by kind, in index order (kept stable across reloads).
    names: AllNames,
    request_route: Vec<Act>,
    routes: Vec<Vec<Act>>,
    failure_routes: Vec<Vec<Act>>,
    onreply_routes: Vec<Vec<Act>>,
    branch_routes: Vec<Vec<Act>>,
    event_routes: Vec<Vec<Act>>,
    reply_route: Option<Vec<Act>>,
    /// Modules with `observes()` (dialog…).
    observers: Vec<Arc<dyn sip_core::Module>>,
    route_names: HashMap<String, usize>,
}

/// Route names by kind, in index order.
#[derive(Clone, Default)]
struct AllNames {
    routes: Vec<String>,
    failure: Vec<String>,
    onreply: Vec<String>,
    branch: Vec<String>,
    event: Vec<String>,
}

/// Routes of a reloaded script in the old index order: a name keeps its
/// index (an empty body if it was removed), new names go at the end. Live
/// transactions and suspended requests hold route indices.
fn align(old: &[String], new: &[(String, Vec<Stmt>)]) -> Vec<(String, Vec<Stmt>)> {
    let mut out: Vec<(String, Vec<Stmt>)> =
        old.iter().map(|n| (n.clone(), new.iter().find(|(m, _)| m == n).map_or_else(Vec::new, |(_, b)| b.clone()))).collect();
    out.extend(new.iter().filter(|(n, _)| !old.contains(n)).cloned());
    out
}

impl Engine {
    /// Compile a reloaded script against the same modules, keeping route
    /// indices stable (see `align`).
    pub fn recompile(&self, ast: &Ast) -> Result<Self, String> {
        let n = &self.names;
        let aligned = Ast {
            modules: Vec::new(),
            modparams: Vec::new(),
            request_route: ast.request_route.clone(),
            routes: align(&n.routes, &ast.routes),
            failure_routes: align(&n.failure, &ast.failure_routes),
            onreply_routes: align(&n.onreply, &ast.onreply_routes),
            branch_routes: align(&n.branch, &ast.branch_routes),
            event_routes: align(&n.event, &ast.event_routes),
            reply_route: ast.reply_route.clone(),
        };
        Self::compile(&aligned, self.reg.clone())
    }

    pub fn compile(ast: &Ast, reg: Arc<Registry>) -> Result<Self, String> {
        // Names first, so `t_on_failure("x")` & co. resolve during fixups.
        let names = |l: &[(String, Vec<Stmt>)]| l.iter().map(|(n, _)| n.clone()).collect();
        reg.hub.set_names(RouteNames {
            failure: names(&ast.failure_routes),
            onreply: names(&ast.onreply_routes),
            branch: names(&ast.branch_routes),
            event: names(&ast.event_routes),
        });
        // Kamailio exports these for REQUEST_ROUTE only (sl.c:103-111): the
        // parser refuses them in a failure_route block ("Command cannot be
        // used in the block", cfg.y:4056-4061). A route[] that a failure
        // route calls is parsed as a request route: there they run, and
        // statelessly (tm then still relays the best reply).
        for (n, body) in &ast.failure_routes {
            let mut u = Uses::default();
            uses_stmts(body, &mut u);
            if let Some(f) = ["sl_send_reply", "sl_reply", "sl_reply_error"].into_iter().find(|f| u.functions.contains(*f)) {
                return Err(format!(
                    "failure_route[{n}]: {f}() cannot be used in this block (request_route only, as in Kamailio; send_reply() or t_reply() answer the transaction)"
                ));
            }
        }
        let c = Compiler { reg: &reg, routes: ast.routes.iter().enumerate().map(|(i, (n, _))| (n.clone(), i)).collect() };
        let many = |l: &[(String, Vec<Stmt>)], kind: &str| -> Result<Vec<Vec<Act>>, String> {
            l.iter().map(|(n, b)| c.block(b).map_err(|e| format!("{kind}[{n}]: {e}"))).collect()
        };
        let request_route = c.block(&ast.request_route)?;
        let routes = many(&ast.routes, "route")?;
        let failure_routes = many(&ast.failure_routes, "failure_route")?;
        let onreply_routes = many(&ast.onreply_routes, "onreply_route")?;
        let branch_routes = many(&ast.branch_routes, "branch_route")?;
        let event_routes = many(&ast.event_routes, "event_route")?;
        let reply_route = ast.reply_route.as_ref().map(|b| c.block(b)).transpose()?;
        drop(c);
        let observers = reg.modules.iter().filter(|m| m.observes()).cloned().collect();
        let route_names = ast.routes.iter().enumerate().map(|(i, (n, _))| (n.clone(), i)).collect();
        let list = |l: &[(String, Vec<Stmt>)]| l.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        let names = AllNames {
            routes: list(&ast.routes),
            failure: list(&ast.failure_routes),
            onreply: list(&ast.onreply_routes),
            branch: list(&ast.branch_routes),
            event: list(&ast.event_routes),
        };
        Ok(Self { reg, names, request_route, routes, failure_routes, onreply_routes, branch_routes, event_routes, reply_route, observers, route_names })
    }

    /// Make the compiled routes callable from modules (tm, events).
    pub fn install(self: &Arc<Self>) {
        self.reg.hub.set_runner(self.clone());
    }

    /// Number of compiled routes of each kind (for `cfg.reload`).
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "routes": self.routes.len(), "failure_routes": self.failure_routes.len(), "onreply_routes": self.onreply_routes.len(),
            "branch_routes": self.branch_routes.len(), "event_routes": self.event_routes.len()
        })
    }

    pub fn registry(&self) -> &Registry {
        &self.reg
    }

    fn run(&self, acts: &[Act], ctx: &mut Ctx<'_, '_>) -> Flow {
        self.run_from(acts, 0, ctx)
    }

    /// Run `acts` from action `start` (indices stay those of `acts`, so a
    /// suspension records where it really is).
    fn run_from(&self, acts: &[Act], start: usize, ctx: &mut Ctx<'_, '_>) -> Flow {
        for (i, a) in acts.iter().enumerate().skip(start) {
            let f = match a {
                Act::Exit => Flow::Exit,
                Act::Drop => Flow::Drop,
                Act::Break => Flow::Break,
                Act::Return(e) => match e {
                    None => Flow::Return(1),
                    Some(e) => match self.eval(e, ctx) {
                        Ok(v) => Flow::Return(return_code(v.as_int().unwrap_or(0))),
                        Err(f) => f,
                    },
                },
                Act::Eval(e) => match self.eval(e, ctx) {
                    Ok(_) => Flow::Next,
                    Err(f) => f,
                },
                Act::Assign(pv, e) => match self.eval(e, ctx) {
                    Ok(v) => {
                        if let Err(err) = pv.set(ctx, v) {
                            sip_core::elog!("script: assigning {pv:?}: {err}");
                        }
                        Flow::Next
                    }
                    Err(f) => f,
                },
                Act::If(c, t, e) => match self.truth(c, ctx) {
                    Err(f) => f,
                    Ok(true) => nest(self.run(t, ctx), i, 0),
                    Ok(false) => nest(self.run(e, ctx), i, 1),
                },
                Act::While(c, body) => {
                    let mut f = Flow::Next;
                    for n in 0.. {
                        if n == MAX_LOOPS {
                            sip_core::elog!("script: while loop stopped after {MAX_LOOPS} iterations");
                            break;
                        }
                        match self.truth(c, ctx) {
                            Err(x) => {
                                f = x;
                                break;
                            }
                            Ok(false) => break,
                            Ok(true) => {}
                        }
                        match self.run(body, ctx) {
                            Flow::Next => {}
                            Flow::Break => break,
                            x => {
                                f = nest(x, i, 0);
                                break;
                            }
                        }
                    }
                    f
                }
                Act::Switch(v, cases) => match self.eval(v, ctx) {
                    Err(f) => f,
                    Ok(v) => {
                        let start =
                            cases.iter().position(|(l, _)| l.as_ref().is_some_and(|l| equal(&v, l))).or_else(|| cases.iter().position(|(l, _)| l.is_none()));
                        let mut f = Flow::Next;
                        if let Some(s) = start {
                            for (k, (_, body)) in cases.iter().enumerate().skip(s) {
                                match self.run(body, ctx) {
                                    Flow::Next => {}
                                    Flow::Break => break,
                                    x => {
                                        f = nest(x, i, k);
                                        break;
                                    }
                                }
                            }
                        }
                        f
                    }
                },
            };
            // The innermost block sees the plain `exit` of a suspending
            // function: continue after it.
            if f == Flow::Exit && ctx.ext.iter().any(|e| e.is::<AsyncPending>()) {
                return Flow::Suspend(Susp::at(i.saturating_add(1)));
            }
            // A route called here suspended: after it, this route goes on
            // after `route(x);`. Called for its value, it can't.
            let f = match f {
                Flow::Suspend(mut s) if !s.sealed && s.frames.last().is_some_and(|l| l.root.is_some()) => {
                    if matches!(a, Act::Eval(CExpr::Route(_))) {
                        s.frames.push(SFrame { root: None, path: Vec::new(), at: i.saturating_add(1) });
                    } else {
                        s.sealed = true;
                    }
                    Flow::Suspend(s)
                }
                f => f,
            };
            if f != Flow::Next {
                return f;
            }
        }
        Flow::Next
    }

    /// End of a top-level run: hand a suspension's continuation to the
    /// function that suspended (`root`: the route the run started in).
    fn settle(&self, f: Flow, root: RouteRoot, ctx: &mut Ctx<'_, '_>) {
        let pending = ctx.ext.iter().position(|e| e.is::<AsyncPending>()).map(|i| ctx.ext.remove(i));
        let (Flow::Suspend(mut s), Some(p)) = (f, pending) else { return };
        let Ok(p) = p.downcast::<AsyncPending>() else { return };
        if let Some(o) = s.open() {
            o.root = Some(root);
        }
        let mut frames = s.frames.into_iter().map(|f| sip_core::route::Frame { root: f.root.unwrap_or(RouteRoot::Request), path: f.path, at: f.at });
        let Some(first) = frames.next() else { return };
        let script = sip_core::route::ScriptRef(RUNNING.with(|r| r.borrow().clone()).map(|e| e as std::sync::Arc<dyn std::any::Any + Send + Sync>));
        (p.0)(Continuation { root: first.root, path: first.path, at: first.at, callers: frames.collect(), script });
    }

    fn root_acts(&self, root: &RouteRoot) -> Option<&[Act]> {
        match root {
            RouteRoot::Request => Some(&self.request_route),
            RouteRoot::Route(i) => self.routes.get(*i).map(Vec::as_slice),
        }
    }

    /// The block reached from `acts` through `path`.
    fn block_at<'a>(mut acts: &'a [Act], path: &[(usize, usize)]) -> Option<&'a [Act]> {
        for &(i, arm) in path {
            acts = match acts.get(i)? {
                Act::If(_, t, e) => {
                    if arm == 0 {
                        t
                    } else {
                        e
                    }
                }
                Act::While(_, b) => b,
                Act::Switch(_, cases) => &cases.get(arm)?.1,
                _ => return None,
            };
        }
        Some(acts)
    }

    /// Continue one route from a frame: the rest of its block, then outward
    /// as if it had never stopped — after an `if`, around a `while` again
    /// (its condition is checked first), after a `switch` case. `None`: the
    /// position doesn't exist (the routes were reloaded).
    fn resume_frame(&self, fr: &sip_core::route::Frame, ctx: &mut Ctx<'_, '_>) -> Option<Flow> {
        let top = self.root_acts(&fr.root)?;
        let (mut level, mut pos) = (fr.path.len(), fr.at);
        let mut breaking = false;
        loop {
            let f = if breaking {
                breaking = false;
                Flow::Break
            } else {
                self.run_from(Self::block_at(top, fr.path.get(..level)?)?, pos, ctx)
            };
            match f {
                Flow::Suspend(mut s) => {
                    if let Some(o) = s.open() {
                        let mut path = fr.path.get(..level)?.to_vec();
                        path.append(&mut o.path);
                        o.path = path;
                        o.root = Some(fr.root.clone());
                    }
                    return Some(Flow::Suspend(s));
                }
                Flow::Next | Flow::Break if level > 0 => {
                    let (&(idx, _), outer) = fr.path.get(..level)?.split_last()?;
                    level = outer.len();
                    let parent = Self::block_at(top, outer)?;
                    match (parent.get(idx)?, &f) {
                        (Act::While(..), Flow::Next) => pos = idx,
                        (Act::While(..) | Act::Switch(..), Flow::Break) => pos = idx.saturating_add(1),
                        // `break` in an `if`: it leaves the loop around it.
                        (_, Flow::Break) => breaking = true,
                        _ => pos = idx.saturating_add(1),
                    }
                }
                f => return Some(f),
            }
        }
    }

    fn call_route(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> Result<i32, Flow> {
        thread_local!(static DEPTH: Cell<usize> = const { Cell::new(0) });
        if DEPTH.get() >= MAX_DEPTH {
            sip_core::elog!("script: route() recursion deeper than {MAX_DEPTH}");
            return Err(Flow::Exit);
        }
        // Compiled route indexes always exist.
        let Some(route) = self.routes.get(idx) else { return Err(Flow::Exit) };
        DEPTH.set(DEPTH.get().saturating_add(1));
        let f = self.run(route, ctx);
        DEPTH.set(DEPTH.get().saturating_sub(1));
        let f = match f {
            Flow::Suspend(mut s) => {
                if let Some(o) = s.open() {
                    o.root = Some(RouteRoot::Route(idx));
                }
                Flow::Suspend(s)
            }
            f => f,
        };
        match f {
            Flow::Return(n) => {
                ctx.rc = n;
                if n == 0 {
                    Err(Flow::Exit) // return(0) ends the script, as in Kamailio
                } else {
                    Ok(n)
                }
            }
            Flow::Next | Flow::Break => {
                ctx.rc = 1;
                Ok(1)
            }
            other => Err(other),
        }
    }

    /// Condition truth: function/route results are true when > 0.
    fn truth(&self, e: &CExpr, ctx: &mut Ctx<'_, '_>) -> Result<bool, Flow> {
        Ok(match e {
            CExpr::Call(_) | CExpr::Route(_) => self.eval(e, ctx)?.as_int().unwrap_or(0) > 0,
            CExpr::Not(x) => !self.truth(x, ctx)?,
            CExpr::Bin(BinOp::And, a, b) => self.truth(a, ctx)? && self.truth(b, ctx)?,
            CExpr::Bin(BinOp::Or, a, b) => self.truth(a, ctx)? || self.truth(b, ctx)?,
            CExpr::Method(m, neg) => (msg_method(ctx) == Some(*m)) != *neg,
            e => self.eval(e, ctx)?.truthy(),
        })
    }

    fn eval(&self, e: &CExpr, ctx: &mut Ctx<'_, '_>) -> Result<Val, Flow> {
        Ok(match e {
            CExpr::Lit(v) => v.clone(),
            CExpr::Pv(p) => p.get(ctx),
            CExpr::Call(b) => {
                ctx.rc = (b.func)(ctx, &*b.arg);
                if ctx.rc == 0 {
                    return Err(Flow::Exit);
                }
                Val::Int(i64::from(ctx.rc))
            }
            CExpr::Route(i) => Val::Int(i64::from(self.call_route(*i, ctx)?)),
            CExpr::Not(_) | CExpr::Method(..) | CExpr::Bin(BinOp::And | BinOp::Or, ..) => Val::Int(i64::from(self.truth(e, ctx)?)),
            CExpr::Neg(x) => Val::Int(self.eval(x, ctx)?.as_int().unwrap_or(0).wrapping_neg()),
            CExpr::Myself(x, neg) => {
                let v = self.eval(x, ctx)?;
                Val::Int(i64::from(sip_core::net::is_myself(ctx.net, &v.as_str()) != *neg))
            }
            CExpr::Match(x, re, neg) => {
                let s = self.eval(x, ctx)?;
                let m = match re {
                    Re::Static(r) => r.is_match(&s.as_str()),
                    Re::Dynamic(p) => {
                        let pat = self.eval(p, ctx)?;
                        Regex::new(&pat.as_str()).is_ok_and(|r| r.is_match(&s.as_str()))
                    }
                };
                Val::Int(i64::from(m != *neg))
            }
            CExpr::Bin(op, a, b) => {
                let (x, y) = (self.eval(a, ctx)?, self.eval(b, ctx)?);
                binop(*op, x, y)
            }
        })
    }
}

/// `==` semantics: integers compare numerically (a string that parses as an
/// integer counts), otherwise as strings; `$null` only equals `$null`.
fn equal(x: &Val, y: &Val) -> bool {
    match (x, y) {
        (Val::Null, Val::Null) => true,
        (Val::Null, _) | (_, Val::Null) => false,
        (Val::Int(a), b) | (b, Val::Int(a)) if b.as_int().is_some() => Some(*a) == b.as_int(),
        _ => x.as_str() == y.as_str(),
    }
}

/// A route's `return(n)` code. Kamailio's are C `int`s: an out-of-range value
/// saturates so it keeps its sign (positive = true, negative = false) rather
/// than wrapping, possibly to 0 (= exit).
fn return_code(v: i64) -> i32 {
    i32::try_from(v).unwrap_or(if v < 0 { i32::MIN } else { i32::MAX })
}

fn binop(op: BinOp, x: Val, y: Val) -> Val {
    let ints = || match (&x, &y) {
        (Val::Int(_), _) | (_, Val::Int(_)) => x.as_int().zip(y.as_int()),
        _ => None,
    };
    let cmp = || match ints() {
        Some((a, b)) => a.cmp(&b),
        None => x.as_str().cmp(&y.as_str()),
    };
    let b = |v: bool| Val::Int(i64::from(v));
    let (a, c) = (x.as_int().unwrap_or(0), y.as_int().unwrap_or(0));
    match op {
        BinOp::Eq => b(equal(&x, &y)),
        BinOp::Ne => b(!equal(&x, &y)),
        BinOp::Lt => b(cmp().is_lt()),
        BinOp::Gt => b(cmp().is_gt()),
        BinOp::Le => b(cmp().is_le()),
        BinOp::Ge => b(cmp().is_ge()),
        // + is typed by its left operand (Kamailio rvalue rules): int adds,
        // string concatenates, $null takes the right side (so
        // `$var(n) = $var(n) + 1` counts from nothing).
        BinOp::Add => match (&x, &y) {
            (Val::Int(p), _) => Val::Int(p.wrapping_add(y.as_int().unwrap_or(0))),
            (Val::Null, _) => y,
            _ => Val::Str(format!("{}{}", x.as_str(), y.as_str())),
        },
        BinOp::Sub => Val::Int(a.wrapping_sub(c)),
        BinOp::Mul => Val::Int(a.wrapping_mul(c)),
        // Division by zero gives 0 (Kamailio logs an error and yields 0).
        #[allow(clippy::arithmetic_side_effects, reason = "c != 0 is checked first; MIN / -1 wraps")]
        BinOp::Div => Val::Int(if c == 0 { 0 } else { a.wrapping_div(c) }),
        #[allow(clippy::arithmetic_side_effects, reason = "c != 0 is checked first; MIN % -1 wraps")]
        BinOp::Mod => Val::Int(if c == 0 { 0 } else { a.wrapping_rem(c) }),
        BinOp::BitOr => Val::Int(a | c),
        BinOp::BitAnd => Val::Int(a & c),
        BinOp::And => b(x.truthy() && y.truthy()),
        BinOp::Or => b(x.truthy() || y.truthy()),
        // Compiled to `CExpr::Match` (cached regex); this is the same test
        // done the slow way, so `binop` stays total.
        BinOp::Match | BinOp::NoMatch => b(Regex::new(&y.as_str()).is_ok_and(|r| r.is_match(&x.as_str())) == (op == BinOp::Match)),
    }
}

impl RouteRunner for Engine {
    fn run_failure(&self, idx: usize, ctx: &mut Ctx<'_, '_>) {
        if let Some(r) = self.failure_routes.get(idx) {
            self.run(r, ctx);
        }
    }

    fn run_onreply(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        self.onreply_routes.get(idx).is_none_or(|r| self.run(r, ctx) != Flow::Drop)
    }

    fn run_branch(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        self.branch_routes.get(idx).is_none_or(|r| self.run(r, ctx) != Flow::Drop)
    }

    fn run_event(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        self.event_routes.get(idx).is_none_or(|r| self.run(r, ctx) != Flow::Drop)
    }

    fn route_index(&self, name: &str) -> Option<usize> {
        self.route_names.get(name).copied()
    }

    fn resume(&self, c: &Continuation, ctx: &mut Ctx<'_, '_>) -> i32 {
        ctx.rc = 1;
        let frames: Vec<sip_core::route::Frame> =
            std::iter::once(sip_core::route::Frame { root: c.root.clone(), path: c.path.clone(), at: c.at }).chain(c.callers.iter().cloned()).collect();
        let mut pending = frames.as_slice();
        let f = loop {
            let Some((frame, callers)) = pending.split_first() else { return -1 };
            let Some(f) = self.resume_frame(frame, ctx) else { return -1 };
            let more = !callers.is_empty();
            match f {
                Flow::Suspend(mut s) => {
                    // Suspended again: the callers not run yet still wait.
                    if !s.sealed {
                        s.frames.extend(callers.iter().map(|f| SFrame { root: Some(f.root.clone()), path: f.path.clone(), at: f.at }));
                    }
                    break Flow::Suspend(s);
                }
                // The route returned: its caller goes on, as after route(x).
                Flow::Return(n) if more && n != 0 => ctx.rc = n,
                Flow::Next | Flow::Break if more => ctx.rc = 1,
                Flow::Return(0) => break Flow::Exit,
                f => break f,
            }
            pending = callers;
        };
        let rc = match &f {
            Flow::Return(n) => *n,
            Flow::Next | Flow::Break => 1,
            _ => 0,
        };
        self.settle(f, c.root.clone(), ctx);
        rc
    }

    fn run_route(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> i32 {
        if idx >= self.routes.len() {
            return -1;
        }
        self.call_route(idx, ctx).unwrap_or(0)
    }

    fn export(&self, name: &str) -> Option<sip_core::Export> {
        self.reg.get(name).cloned()
    }

    fn pv_table(&self) -> Option<&sip_core::pv::PvTable> {
        Some(self.reg.pvs())
    }
}

/// A method's request counter and `request_route` timing, looked up once.
fn route_metrics(m: Method) -> (&'static std::sync::atomic::AtomicI64, &'static sip_core::stats::Histogram) {
    use sip_core::stats::{buckets, histogram, labeled_counter};
    static M: std::sync::OnceLock<[(&'static std::sync::atomic::AtomicI64, &'static sip_core::stats::Histogram); 8]> = std::sync::OnceLock::new();
    let [invite, ack, bye, cancel, register, options, message, other] = M.get_or_init(|| {
        const NAMES: [&str; 8] = ["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "MESSAGE", "other"];
        NAMES.map(|m| {
            (
                labeled_counter("sip_requests_received", "SIP requests received, by method", &[("method", m)]),
                histogram("request_route_seconds", "Time to run request_route for one request, by method", &[("method", m)], buckets::ROUTE),
            )
        })
    });
    // The methods with their own label; every other one under "other".
    *match m {
        Method::Invite => invite,
        Method::Ack => ack,
        Method::Bye => bye,
        Method::Cancel => cancel,
        Method::Register => register,
        Method::Options => options,
        Method::Message => message,
        _ => other,
    }
}

impl Handler for Engine {
    fn handle(&self, ctx: &mut Ctx<'_, '_>) {
        if ctx.msg.is_request() {
            let (count, time) = route_metrics(ctx.msg.method().unwrap_or(Method::Other));
            sip_core::stats::inc(count);
            let start = std::time::Instant::now();
            for m in &self.observers {
                m.observe_request(ctx);
            }
            let f = self.run(&self.request_route, ctx);
            time.observe(start.elapsed());
            if matches!(f, Flow::Suspend(_)) {
                self.settle(f, RouteRoot::Request, ctx);
            } else {
                // Kamailio's POST_SCRIPT_CB (tm's t_unref(): a delayed
                // relay error reply, t_lookup.c:2093-2125).
                ctx.run_script_end();
            }
        } else {
            for m in &self.observers {
                m.observe_reply(ctx);
            }
            // Global reply route first (Kamailio `reply_route`); `drop` stops
            // provisional replies only — finals belong to the transaction.
            if let Some(r) = &self.reply_route {
                if self.run(r, ctx) == Flow::Drop && ctx.msg.status().is_some_and(|c| c < 200) {
                    return;
                }
                ctx.rc = 1;
            }
            for m in &self.reg.modules {
                if m.on_reply(ctx) {
                    return;
                }
            }
            // No module claimed it: drop (Kamailio would forward statelessly via Via2).
        }
    }

    fn transport_event(&self, ev: &TransportEvent) {
        for m in &self.reg.modules {
            m.on_transport_event(ev);
        }
    }

    /// `event_route[websocket:handshake]`: the HTTP upgrade request as a
    /// faked SIP request — its headers via `$hdr(...)` (Origin, Host,
    /// User-Agent, Cookie…), the path in `$hdr(X-WS-Path)`, the peer in
    /// `$si` / `$sp` / `$proto`. `drop` refuses the upgrade (403).
    fn ws_handshake(&self, net: &dyn sip_core::Outbound, req: &[u8], src: sip_core::Dest) -> bool {
        const EV: &str = "websocket:handshake";
        if !self.reg.hub.has_event(EV) {
            return true;
        }
        let head = String::from_utf8_lossy(req);
        let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
        let path = lines.next().and_then(|rl| rl.split_whitespace().nth(1)).unwrap_or("/").to_string();
        let mut fake = format!(
            "OPTIONS sip:ws@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/{} {};branch=z9hG4bKwshandshake\r\nFrom: <sip:ws@{}>;tag=ws\r\n\
             To: <sip:ws@127.0.0.1>\r\nCall-ID: ws-handshake\r\nCSeq: 1 OPTIONS\r\nX-WS-Path: {path}\r\n",
            src.proto.via_name(),
            src.addr,
            src.addr.ip()
        );
        for l in lines.filter(|l| l.contains(':')) {
            fake.push_str(l);
            fake.push_str("\r\n");
        }
        fake.push_str("Content-Length: 0\r\n\r\n");
        self.reg.hub.run_event_with(EV, net, Some(fake.as_bytes()), |ctx| ctx.src = src)
    }
}

/// The running script, swappable at run time (`cfg.reload`): transports
/// and modules hold this; every message loads the current engine (one
/// atomic load, no lock).
pub struct Live {
    cur: arc_swap::ArcSwap<Engine>,
    /// Shared by every engine version.
    reg: Arc<Registry>,
}

impl Live {
    pub fn new(e: Engine) -> Arc<Self> {
        let reg = e.reg.clone();
        Arc::new(Self { cur: arc_swap::ArcSwap::from_pointee(e), reg })
    }

    pub fn registry(&self) -> &Registry {
        &self.reg
    }

    pub fn load(&self) -> Arc<Engine> {
        self.cur.load_full()
    }

    /// Route callbacks from modules go through the live engine.
    pub fn install(self: &Arc<Self>) {
        self.reg.hub.set_runner(self.clone());
    }

    /// Re-parse and swap: only the routes may change (same `loadmodule`s
    /// and `modparam`s — those were applied at startup); messages already
    /// being processed finish on the old engine.
    pub fn reload(&self, ast: &Ast) -> Result<serde_json::Value, String> {
        let new = self.cur.load().recompile(ast)?;
        let summary = new.summary();
        self.cur.store(Arc::new(new));
        Ok(summary)
    }
}

thread_local! {
    /// The engine version running on this thread (stamped on the
    /// continuations it creates).
    static RUNNING: std::cell::RefCell<Option<Arc<Engine>>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` on `e`, with `e` as this thread's running engine.
fn running<R>(e: Arc<Engine>, f: impl FnOnce(&Engine) -> R) -> R {
    let prev = RUNNING.with(|r| r.replace(Some(e.clone())));
    struct Restore(Option<Arc<Engine>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let p = self.0.take();
            RUNNING.with(|r| *r.borrow_mut() = p);
        }
    }
    let _restore = Restore(prev);
    f(&e)
}

impl Handler for Live {
    fn handle(&self, ctx: &mut Ctx<'_, '_>) {
        running(self.cur.load_full(), |e| e.handle(ctx))
    }
    fn transport_event(&self, ev: &TransportEvent) {
        self.cur.load().transport_event(ev)
    }
    fn ws_handshake(&self, net: &dyn sip_core::Outbound, req: &[u8], src: sip_core::Dest) -> bool {
        self.cur.load().ws_handshake(net, req, src)
    }
}

impl RouteRunner for Live {
    fn run_failure(&self, idx: usize, ctx: &mut Ctx<'_, '_>) {
        running(self.cur.load_full(), |e| e.run_failure(idx, ctx))
    }
    fn run_onreply(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        running(self.cur.load_full(), |e| e.run_onreply(idx, ctx))
    }
    fn run_branch(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        running(self.cur.load_full(), |e| e.run_branch(idx, ctx))
    }
    fn run_event(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool {
        running(self.cur.load_full(), |e| e.run_event(idx, ctx))
    }
    fn route_index(&self, name: &str) -> Option<usize> {
        self.cur.load().route_index(name)
    }
    fn run_route(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> i32 {
        running(self.cur.load_full(), |e| e.run_route(idx, ctx))
    }
    fn resume(&self, c: &Continuation, ctx: &mut Ctx<'_, '_>) -> i32 {
        // A position means something only in the script version that
        // suspended: resume there, even after a cfg.reload.
        let e = c.script.0.clone().and_then(|a| a.downcast::<Engine>().ok()).unwrap_or_else(|| self.cur.load_full());
        running(e, |e| e.resume(c, ctx))
    }
    fn export(&self, name: &str) -> Option<sip_core::Export> {
        self.cur.load().reg.get(name).cloned()
    }
    fn pv_table(&self) -> Option<&sip_core::pv::PvTable> {
        Some(self.reg.pvs())
    }
}

/// The method a `$rm == "X"` test compares: the request's, or for a reply
/// its CSeq method (as `$rm` gives in reply routes).
fn msg_method(ctx: &mut Ctx<'_, '_>) -> Option<Method> {
    if let Some(m) = ctx.msg.method() {
        return Some(m);
    }
    ctx.msg.parse_headers(sip_parser::HdrFlags::EOH).ok()?;
    Some(Method::from_cseq(ctx.msg.get(sip_parser::HdrKind::CSeq)?.body))
}

#[cfg(test)]
mod tests {
    #[test]
    fn script_uses() {
        let ast = super::parse(
            "request_route { if (is_method(\"INVITE\")) { dlg_manage(); $dlg_var(x) = \"v\"; } xlog(\"L_INFO\", \"$sht(t=>k) $ru\"); route(R); }\n\
             route[R] { if ($var(n) > 1 && !has_totag()) { t_relay(); } }\n\
             failure_route[F] { switch ($T_reply_code) { case 486: sl_send_reply(\"404\", \"x\"); } }",
        )
        .unwrap();
        let u = super::uses(&ast);
        let f: Vec<&str> = u.functions.iter().map(String::as_str).collect();
        assert_eq!(f, ["dlg_manage", "has_totag", "is_method", "sl_send_reply", "t_relay", "xlog"]);
        for pv in ["dlg_var", "sht", "ru", "var", "T_reply_code"] {
            assert!(u.pvs.contains(pv), "{pv} in {:?}", u.pvs);
        }
    }

    use super::*;

    /// Kamailio's parser refuses sl_send_reply / sl_reply_error in a
    /// failure_route block (sl.c:103-111, cfg.y:4056-4061); from a route[]
    /// a failure route calls they are accepted.
    #[test]
    fn sl_functions_not_in_a_failure_route_block() {
        let compile = |src: &str| Engine::compile(&parse(src).unwrap(), Arc::new(Registry::default())).err().unwrap_or_default();
        for f in ["sl_send_reply(\"404\", \"x\")", "sl_reply_error()"] {
            let e = compile(&format!("request_route {{ exit; }}\nfailure_route[F] {{ if ($T_reply_code == 486) {{ {f}; }} }}"));
            assert!(e.starts_with("failure_route[F]: sl_") && e.contains("cannot be used in this block"), "{e}");
        }
        let e = compile("request_route { exit; }\nfailure_route[F] { route(R); }\nroute[R] { sl_send_reply(\"404\", \"x\"); }");
        assert!(e.contains("unknown function sl_send_reply"), "{e}");
    }

    #[test]
    fn value_semantics() {
        let s = |x: &str| Val::Str(x.into());
        assert!(equal(&Val::Int(5), &s("5")));
        assert!(!equal(&Val::Null, &s("")));
        assert_eq!(binop(BinOp::Add, Val::Int(2), Val::Int(3)), Val::Int(5));
        assert_eq!(binop(BinOp::Add, s("sip:"), s("bob")), s("sip:bob"));
        assert_eq!(binop(BinOp::Add, s("n"), Val::Int(1)), s("n1"));
        assert_eq!(binop(BinOp::Add, Val::Null, Val::Int(1)), Val::Int(1), "$null + 1 counts");
        assert_eq!(binop(BinOp::Add, Val::Int(1), s("2")), Val::Int(3), "left int adds");
        assert_eq!(binop(BinOp::Lt, s("10"), Val::Int(9)), Val::Int(0), "numeric when an int is involved");
        assert_eq!(binop(BinOp::Lt, s("10"), s("9")), Val::Int(1), "string order otherwise");
        assert_eq!(binop(BinOp::Div, Val::Int(1), Val::Int(0)), Val::Int(0));
        // i64::MIN / -1 overflows: it wraps (like + - *) instead of panicking.
        assert_eq!(binop(BinOp::Div, Val::Int(i64::MIN), Val::Int(-1)), Val::Int(i64::MIN));
        assert_eq!(binop(BinOp::Mod, Val::Int(i64::MIN), Val::Int(-1)), Val::Int(0));
        assert_eq!(binop(BinOp::Match, s("sip:bob@x"), s("^sip:b")), Val::Int(1));
        assert_eq!(binop(BinOp::NoMatch, s("sip:bob@x"), s("^sip:b")), Val::Int(0));
    }

    #[test]
    fn return_codes_saturate() {
        assert_eq!(return_code(-3), -3);
        assert_eq!(return_code(1 << 32), i32::MAX, "not wrapped to 0 (exit)");
        assert_eq!(return_code(-(1 << 40)), i32::MIN);
    }
}
