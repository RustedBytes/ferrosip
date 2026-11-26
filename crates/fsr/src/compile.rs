//! Type checking and lowering: `.fsr` → `sip_script::Ast`, the tree a
//! Kamailio-style `.cfg` parses to (and the engine compiles).
//!
//! One pass checks and lowers together and collects every error. Values:
//! - locals and extra fn parameters are AVPs (`$avp(l__<fn>__<x>)`), so
//!   they live as long as the transaction (they survive `await`);
//! - true/false are 1/-1 in variables; conditions use calls and
//!   comparisons directly;
//! - a call that handles the message (an `Action`) ends the route
//!   (`exit` after it); a failed one answers with `sl_reply_error()`.

#![allow(clippy::too_many_arguments, reason = "lowering threads the same context (function, spans, output) through every step")]

use crate::ast::{self, BinOp, Expr, ExprKind, Pat, Span, Stmt, StmtKind, StrPart, UnOp};
use crate::msg::{self, FieldTy};
use sip_core::schema::{Unit, suggest};
use sip_core::sig::{ArgTy, FnSig, Ret, ctx};
use sip_script as S;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, PartialEq)]
pub struct Diag {
    pub file: String,
    pub span: Span,
    pub msg: String,
}

/// A `[feature]` value (`import { features } from config`).
#[derive(Clone, Debug, PartialEq)]
pub enum Feature {
    Bool(bool),
    Int(i64),
    Str(String),
}

/// What the compiler knows about the outside world.
#[derive(Default)]
pub struct Env {
    /// Namespace (`txn`, `location`, `log`…) → `.fsr` name → signature.
    pub namespaces: BTreeMap<String, BTreeMap<String, FnSig>>,
    pub features: BTreeMap<String, Feature>,
    /// Flag numbers ferrosip.toml parameters already use.
    pub used_flags: BTreeSet<u32>,
    /// Compile `test` blocks too (`ferrosip test`); else they're skipped.
    pub tests: bool,
    /// (namespace, `.fsr` name) → the module the function belongs to (a
    /// call loads it: `ims_registrar_scscf.save()`, not registrar's).
    pub modules: BTreeMap<(String, String), String>,
    /// Tables ferrosip.toml already declares (htable specs): a `shared
    /// table` of that name types it instead of declaring it again.
    pub toml_tables: BTreeSet<String>,
}

impl Env {
    /// Group signatures by namespace (`default_ns`: the module's ferrosip
    /// name, unless the signature names another).
    /// `add`, remembering the module of each function.
    pub fn add_from(&mut self, module: &str, default_ns: &str, sigs: impl IntoIterator<Item = FnSig>) {
        for s in sigs {
            if s.fsr.is_empty() {
                continue;
            }
            let ns = s.ns.unwrap_or(default_ns).to_string();
            self.modules.entry((ns.clone(), s.fsr.to_string())).or_insert_with(|| module.to_string());
            self.namespaces.entry(ns).or_default().entry(s.fsr.to_string()).or_insert(s);
        }
    }

    pub fn add(&mut self, default_ns: &str, sigs: impl IntoIterator<Item = FnSig>) {
        for s in sigs {
            if s.fsr.is_empty() {
                continue;
            }
            let ns = s.ns.unwrap_or(default_ns).to_string();
            self.namespaces.entry(ns).or_default().entry(s.fsr.to_string()).or_insert(s);
        }
    }
}

pub struct Output {
    pub ast: S::Ast,
    /// Flag name → number.
    pub flags: BTreeMap<String, u32>,
    /// Branch flag name → number (`branch flag`).
    pub branch_flags: BTreeMap<String, u32>,
    /// `test` blocks (with `Env::tests`), in source order.
    pub tests: Vec<TestDef>,
}

/// A `test "name" { … }`: its route, and the functions it mocks.
#[derive(Clone, Debug)]
pub struct TestDef {
    pub name: String,
    pub route: String,
    /// `file:line` of the test.
    pub at: String,
    /// (function, what it returns): `location.lookup = false`.
    pub mocks: Vec<(String, i64)>,
}

/// One parsed source file and its namespace (`""` for the entry).
pub struct Source {
    pub name: String,
    pub ns: String,
    pub text: String,
    pub file: ast::File,
}

#[derive(Clone, Debug, PartialEq)]
enum Ty {
    Int,
    Str,
    Bool,
    Duration,
    Method,
    Transport,
    Request,
    Reply,
    /// An `await` result: `Final(r)` / `Timeout`.
    Result,
    /// `r` in `Final(r)`: the transaction's final reply.
    Final,
    /// Event parameters: `d: Dialog`, `req: HttpRequest`, `e: Destination`,
    /// `e: Source`.
    Dialog,
    Http,
    Dest,
    Source,
    /// `req: DiameterRequest` (`on diameter.request`), `ans:
    /// DiameterAnswer` (`on diameter.response`).
    DiamReq,
    DiamAns,
    /// An awaited call's result (`let r = await http.get(url)`).
    Record(&'static sip_core::sig::AwaitTy),
    Action,
    Void,
    Flag,
    /// A `branch flag` (setbflag …).
    BranchFlag,
    /// A Kamailio value (`pv("$avp(x)")`, `kamailio.call(…)`): Str or Int
    /// at run time, checked by nobody (the escape hatch).
    Any,
    /// Already reported.
    Error,
}

impl Ty {
    fn name(&self) -> String {
        match self {
            Ty::Int => "Int".into(),
            Ty::Str => "Str".into(),
            Ty::Bool => "Bool".into(),
            Ty::Duration => "Duration".into(),
            Ty::Method => "Method".into(),
            Ty::Transport => "Transport".into(),
            Ty::Request => "Request".into(),
            Ty::Reply => "Reply".into(),
            Ty::Result => "Result".into(),
            Ty::Final => "Reply".into(),
            Ty::Dialog => "Dialog".into(),
            Ty::Http => "HttpRequest".into(),
            Ty::Dest => "Destination".into(),
            Ty::Source => "Source".into(),
            Ty::DiamReq => "DiameterRequest".into(),
            Ty::DiamAns => "DiameterAnswer".into(),
            Ty::Record(a) => a.name.into(),
            Ty::Action => "Action".into(),
            Ty::Void => "nothing".into(),
            Ty::Flag => "Flag".into(),
            Ty::BranchFlag => "branch Flag".into(),
            Ty::Any => "a Kamailio value".into(),
            Ty::Error => "?".into(),
        }
    }
}

/// A lowered value.
#[derive(Clone)]
struct V {
    e: S::Expr,
    ty: Ty,
}

impl V {
    fn err() -> V {
        V { e: S::Expr::Int(0), ty: Ty::Error }
    }
}

/// A user function (or route) and what lowering needs about it.
struct UserFn {
    route: String,
    params: Vec<(String, Ty)>,
    ret: Ty,
    /// `ctx` bits it can run in (from the call graph).
    ctx: u8,
    is_main: bool,
    /// Its first parameter is the request (else it's a helper that
    /// doesn't touch one: event handlers can call it).
    has_msg: bool,
}

struct Local {
    avp: String,
    ty: Ty,
}

struct Fx<'a> {
    src: &'a Source,
    /// The user-function key (`ns::name`) being lowered.
    key: String,
    ctx: u8,
    /// The message parameter's name and type.
    msg_name: String,
    msg_ty: Ty,
    locals: HashMap<String, Local>,
    after_await: bool,
    /// Block nesting (1 = the function's own body).
    depth: usize,
    /// The handler's event (`dialog.ended`…), `""` in routes.
    event: &'static str,
}

pub struct Compiler<'e> {
    env: &'e Env,
    diags: Vec<Diag>,
    fns: BTreeMap<String, UserFn>,
    flags: BTreeMap<String, u32>,
    branch_flags: BTreeMap<String, u32>,
    temps: usize,
    /// Namespaces brought in with `import a, b`.
    imported: BTreeSet<String>,
    /// `import { features } from config` names.
    config_names: BTreeSet<String>,
    /// `shared table` name → value type (Bool, Int, Str, Counter).
    tables: BTreeMap<String, TableVal>,
    /// `dialog var` name → type.
    dlg_vars: BTreeMap<String, Ty>,
    /// Modules and parameters the routing needs (timers, tables).
    modules: Vec<String>,
    modparams: Vec<S::ModParam>,
    timers: usize,
    tests: Vec<TestDef>,
    /// The call being lowered is the operand of an `await`.
    awaiting: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TableVal {
    Bool,
    Int,
    Str,
    Counter,
}

impl TableVal {
    fn ty(self) -> Ty {
        match self {
            TableVal::Bool => Ty::Bool,
            TableVal::Int | TableVal::Counter => Ty::Int,
            TableVal::Str => Ty::Str,
        }
    }
}

/// An event a handler can be written for.
struct Event {
    /// `.fsr` name (`on dialog.ended`).
    name: &'static str,
    /// The event route it lowers to (`""`: reply_route / a timer route).
    route: &'static str,
    /// The parameter's type name (`""`: none).
    param: &'static str,
    /// The module that raises it (loaded with the routing).
    module: &'static str,
}

/// A Kamailio route kind written as `on kamailio.<kind>(…, name: "X")`.
#[derive(Clone, Copy)]
struct KRoute {
    event: &'static str,
    ctx: u8,
    /// The message parameter's type (`""`: none).
    param: &'static str,
}

const KROUTES: &[KRoute] = &[
    KRoute { event: "kamailio.failure_route", ctx: ctx::FAILURE, param: "Request" },
    KRoute { event: "kamailio.branch_route", ctx: ctx::BRANCH, param: "Request" },
    KRoute { event: "kamailio.onreply_route", ctx: ctx::REPLY, param: "Reply" },
    KRoute { event: "kamailio.event_route", ctx: ctx::EVENT, param: "" },
];

fn kamailio_route(event: &str) -> Option<KRoute> {
    KROUTES.iter().find(|k| k.event == event).copied()
}

const EVENTS: &[Event] = &[
    Event { name: "reply", route: "", param: "Reply", module: "" },
    Event { name: "dialog.started", route: "dialog:start", param: "Dialog", module: "dialog" },
    Event { name: "dialog.ended", route: "dialog:end", param: "Dialog", module: "dialog" },
    Event { name: "dialog.failed", route: "dialog:failed", param: "Dialog", module: "dialog" },
    Event { name: "http", route: "xhttp:request", param: "HttpRequest", module: "xhttp" },
    Event { name: "timer", route: "", param: "", module: "rtimer" },
    Event { name: "balancer.up", route: "dispatcher:dst-up", param: "Destination", module: "dispatcher" },
    Event { name: "balancer.down", route: "dispatcher:dst-down", param: "Destination", module: "dispatcher" },
    Event { name: "keepalive.up", route: "keepalive:dst-up", param: "Destination", module: "keepalive" },
    Event { name: "keepalive.down", route: "keepalive:dst-down", param: "Destination", module: "keepalive" },
    Event { name: "limits.blocked", route: "pike:blocked", param: "Source", module: "pike" },
    Event { name: "diameter.request", route: "diameter:request", param: "DiameterRequest", module: "ims_diameter_server" },
    Event { name: "diameter.response", route: "diameter:response", param: "DiameterAnswer", module: "ims_diameter_server" },
];

/// Fields of the event parameters: (type, field, pseudo-variable, type).
const EVENT_FIELDS: &[(&str, &str, &str, FieldTy)] = &[
    ("Dialog", "call_id", "$dlg(callid)", FieldTy::Str),
    ("Dialog", "from_uri", "$dlg(from_uri)", FieldTy::Str),
    ("Dialog", "to_uri", "$dlg(to_uri)", FieldTy::Str),
    ("Dialog", "from_tag", "$dlg(from_tag)", FieldTy::Str),
    ("Dialog", "to_tag", "$dlg(to_tag)", FieldTy::Str),
    ("Dialog", "state", "$dlg(state)", FieldTy::Int),
    ("Dialog", "started_at", "$dlg(start_ts)", FieldTy::Int),
    ("Dialog", "timeout", "$dlg(timeout)", FieldTy::Int),
    ("Dialog", "duration", "$dlg(duration)", FieldTy::Int),
    ("Dialog", "end_reason", "$dlg(end_reason)", FieldTy::Str),
    ("Dialog", "code", "$rs", FieldTy::Int),
    ("HttpRequest", "method", "$hm", FieldTy::Str),
    ("HttpRequest", "url", "$hu", FieldTy::Str),
    ("HttpRequest", "path", "$hp", FieldTy::Str),
    ("HttpRequest", "query", "$hq", FieldTy::Str),
    ("HttpRequest", "body", "$rb", FieldTy::Str),
    ("Destination", "uri", "$ru", FieldTy::Str),
    ("Source", "ip", "$si", FieldTy::Str),
    ("Source", "port", "$sp", FieldTy::Int),
    ("DiameterRequest", "command", "$diameter_command", FieldTy::Int),
    ("DiameterRequest", "application", "$diameter_application", FieldTy::Int),
    ("DiameterRequest", "avps", "$diameter_request", FieldTy::Str),
    ("DiameterRequest", "answer_avps", "$diameter_response", FieldTy::Str),
    ("DiameterAnswer", "avps", "$diameter_response", FieldTy::Str),
];

fn line_of(src: &Source, span: Span) -> usize {
    crate::lexer::line_col(&src.text, span.start).0
}

/// A duration (ms, or s) as a script integer. Durations saturate when
/// lexed (`99999999999d`); they stay at the top instead of wrapping negative.
fn clamp_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn key(ns: &str, name: &str) -> String {
    if ns.is_empty() { name.to_string() } else { format!("{ns}::{name}") }
}

fn s_str(s: &str) -> S::Expr {
    S::Expr::Str(s.replace('$', "$$"))
}

fn not(e: S::Expr) -> S::Expr {
    match const_bool(&e) {
        Some(b) => truth(!b),
        None => S::Expr::Not(Box::new(e)),
    }
}

/// A constant condition (`1 == 1` / `1 == 0`).
fn truth(b: bool) -> S::Expr {
    bin(S::BinOp::Eq, S::Expr::Int(1), S::Expr::Int(i64::from(b)))
}

fn const_bool(e: &S::Expr) -> Option<bool> {
    match e {
        S::Expr::Bin(S::BinOp::Eq, a, b) => match (a.as_ref(), b.as_ref()) {
            (S::Expr::Int(1), S::Expr::Int(x)) => Some(*x == 1),
            _ => None,
        },
        _ => None,
    }
}

/// `a && b` / `a || b`, folding constants (`features.x`).
fn logic(op: S::BinOp, a: S::Expr, b: S::Expr) -> S::Expr {
    match (op, const_bool(&a), const_bool(&b)) {
        (S::BinOp::And, Some(false), _) | (S::BinOp::And, _, Some(false)) => truth(false),
        (S::BinOp::Or, Some(true), _) | (S::BinOp::Or, _, Some(true)) => truth(true),
        (_, Some(_), _) => b,
        (_, _, Some(_)) => a,
        _ => bin(op, a, b),
    }
}

fn bin(op: S::BinOp, a: S::Expr, b: S::Expr) -> S::Expr {
    S::Expr::Bin(op, Box::new(a), Box::new(b))
}

fn call(name: &str, args: Vec<S::RawArg>, line: usize) -> S::Expr {
    S::Expr::Call { name: name.to_string(), args, line }
}

fn sop(op: BinOp) -> Option<S::BinOp> {
    Some(match op {
        BinOp::Or => S::BinOp::Or,
        BinOp::And => S::BinOp::And,
        BinOp::Eq => S::BinOp::Eq,
        BinOp::Ne => S::BinOp::Ne,
        BinOp::Lt => S::BinOp::Lt,
        BinOp::Le => S::BinOp::Le,
        BinOp::Gt => S::BinOp::Gt,
        BinOp::Ge => S::BinOp::Ge,
        BinOp::Match => S::BinOp::Match,
        BinOp::Add => S::BinOp::Add,
        BinOp::Sub => S::BinOp::Sub,
        BinOp::Mul => S::BinOp::Mul,
        BinOp::Div => S::BinOp::Div,
        BinOp::Mod => S::BinOp::Mod,
        BinOp::In => return None,
    })
}

impl<'e> Compiler<'e> {
    pub fn new(env: &'e Env) -> Self {
        Compiler {
            env,
            diags: Vec::new(),
            fns: BTreeMap::new(),
            flags: BTreeMap::new(),
            branch_flags: BTreeMap::new(),
            temps: 0,
            imported: BTreeSet::new(),
            config_names: BTreeSet::new(),
            tables: BTreeMap::new(),
            dlg_vars: BTreeMap::new(),
            modules: Vec::new(),
            modparams: Vec::new(),
            timers: 0,
            tests: Vec::new(),
            awaiting: false,
        }
    }

    fn err(&mut self, src: &Source, span: Span, msg: impl Into<String>) {
        self.diags.push(Diag { file: src.name.clone(), span, msg: msg.into() });
    }

    fn temp(&mut self) -> String {
        self.temps = self.temps.saturating_add(1);
        format!("$avp(t__{})", self.temps)
    }

    /// Compile every source (the entry first) into one route tree.
    pub fn compile(mut self, sources: &[Source]) -> Result<Output, Vec<Diag>> {
        self.declare(sources);
        self.contexts(sources);
        let mut out = S::Ast::default();
        // Event route → its handlers' code, in source order.
        let mut events: Vec<(String, Vec<S::Stmt>)> = Vec::new();
        for src in sources {
            for item in &src.file.items {
                match &item.kind {
                    ast::ItemKind::Route(f) | ast::ItemKind::Fn(f) => {
                        let k = key(&src.ns, &f.name.text);
                        let Some(uf) = self.fns.get(&k) else { continue };
                        let (route, is_main, ctx) = (uf.route.clone(), uf.is_main, uf.ctx);
                        let mut fx = Self::fx(src, &k, uf, f, ctx);
                        let body = self.block(&mut fx, &f.body.stmts);
                        if is_main {
                            out.request_route = body;
                        } else {
                            out.routes.push((route, body));
                        }
                    }
                    ast::ItemKind::On(on) => self.handler(src, on, &mut out, &mut events),
                    ast::ItemKind::Test(name, body) if self.env.tests => self.test(src, name, body, item.span, &mut out),
                    _ => {}
                }
            }
        }
        for (route, mut body) in events {
            if route == "xhttp:request" {
                // No handler matched (or none replied).
                body.push(S::Stmt::Expr(call(
                    "xhttp_reply",
                    vec![S::RawArg::Int(404), S::RawArg::Str("Not Found".into()), S::RawArg::Str("text/plain".into()), S::RawArg::Str(String::new())],
                    0,
                )));
            }
            out.event_routes.push((route, body));
        }
        out.modules = std::mem::take(&mut self.modules);
        out.modparams = std::mem::take(&mut self.modparams);
        if !self.fns.values().any(|f| f.is_main)
            && let Some(src) = sources.first()
        {
            self.err(src, Span::default(), "no `route main(msg: Request)`: it is where requests start");
        }
        if self.diags.is_empty() { Ok(Output { ast: out, flags: self.flags, branch_flags: self.branch_flags, tests: self.tests }) } else { Err(self.diags) }
    }

    /// `test "name" { … }` → `route[test__N]`, run by `ferrosip test`.
    fn test(&mut self, src: &Source, name: &str, body: &ast::Block, span: Span, out: &mut S::Ast) {
        let route = format!("test__{}", self.tests.len().saturating_add(1));
        let mut fx = Fx {
            src,
            key: format!("test {name}"),
            ctx: ctx::EVENT,
            msg_name: String::new(),
            msg_ty: Ty::Void,
            locals: HashMap::new(),
            after_await: false,
            depth: 0,
            event: "test",
        };
        self.tests.push(TestDef { name: name.to_string(), route: route.clone(), at: format!("{}:{}", src.name, line_of(src, span)), mocks: Vec::new() });
        let code = self.block(&mut fx, &body.stmts);
        out.routes.push((route, code));
    }

    /// The test builtins: send, answer, wait, assert and the outcome.
    fn test_builtin(&mut self, fx: &mut Fx, name: &str, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> Option<V> {
        let mut pos = Vec::new();
        let mut named: Vec<(&str, &Expr)> = Vec::new();
        for a in args {
            match &a.name {
                Some(n) => named.push((n.text.as_str(), &a.value)),
                None => pos.push(&a.value),
            }
        }
        let usage = |this: &mut Self, u: &str| {
            this.err(fx.src, span, u.to_string());
            Some(V::err())
        };
        let pv = |p: String| S::Expr::Pv(p, line);
        Some(match name {
            "send" => {
                let ([text], true) = (pos.as_slice(), named.iter().all(|(n, _)| *n == "from")) else {
                    return usage(self, "send(\"\"\"<SIP message>\"\"\"[, from: \"ip:port\"])");
                };
                let t = self.expr(fx, text, out);
                let t = self.raw(fx, t, line, out);
                let from = match named.first() {
                    Some((_, e)) => {
                        let v = self.expr(fx, e, out);
                        self.raw(fx, v, line, out)
                    }
                    None => S::RawArg::Str("127.0.0.1:5060".into()),
                };
                out.push(S::Stmt::Expr(call("fsr_test_send", vec![t, from], line)));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            "answer" => {
                let (Some(code), true) = (pos.first(), pos.len() <= 2 && named.is_empty()) else {
                    return usage(self, "answer(code[, reason])");
                };
                let c = self.expr(fx, code, out);
                let reason = match (pos.get(1), &c.e) {
                    (Some(r), _) => {
                        let v = self.expr(fx, r, out);
                        self.raw(fx, v, line, out)
                    }
                    (None, S::Expr::Int(n)) => S::RawArg::Str(msg::reason(*n).into()),
                    (None, _) => S::RawArg::Str("Reply".into()),
                };
                let c = self.raw(fx, c, line, out);
                out.push(S::Stmt::Expr(call("fsr_test_answer", vec![c, reason], line)));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            "wait" => {
                let [d] = pos.as_slice() else { return usage(self, "wait(duration)") };
                let v = self.expr(fx, d, out);
                if !matches!(v.ty, Ty::Duration | Ty::Error) {
                    self.err(fx.src, d.span, "wait(2s): a duration");
                }
                let v = self.raw(fx, v, line, out);
                out.push(S::Stmt::Expr(call("fsr_test_wait", vec![v], line)));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            "assert" => {
                let [c] = pos.as_slice() else { return usage(self, "assert(condition)") };
                let v = self.cond(fx, c, out);
                let t = self.temp();
                self.store(&t, V { e: v, ty: Ty::Bool }, line, out);
                let what = format!("{}:{}: assert({})", fx.src.name, line, crate::fmt::expr(c)).replace('$', "$$");
                // For a comparison, also what the left side was.
                let actual = match &c.kind {
                    ExprKind::Binary(op, a, _) if !matches!(op, BinOp::And | BinOp::Or) => {
                        let v = self.expr(fx, a, out);
                        match self.raw(fx, v, line, out) {
                            S::RawArg::Pv(p) => format!(": {} is \"{p}\"", crate::fmt::expr(a).replace('$', "$$")),
                            _ => String::new(),
                        }
                    }
                    _ => String::new(),
                };
                out.push(S::Stmt::Expr(call("fsr_test_assert", vec![S::RawArg::Pv(t), S::RawArg::Str(what + &actual)], line)));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            "reply_code" | "relays" if pos.is_empty() => V { e: pv(format!("$fsrtest({})", if name == "relays" { "relays" } else { "code" })), ty: Ty::Int },
            "reply_reason" if pos.is_empty() => V { e: pv("$fsrtest(reason)".into()), ty: Ty::Str },
            "relay_uri" | "relay_dest" => {
                let n = match pos.as_slice() {
                    [] => 0,
                    [e] => match e.kind {
                        ExprKind::Int(n) if n >= 1 => n,
                        _ => return usage(self, &format!("{name}(n): n is a number from 1 (or none: the last)")),
                    },
                    _ => return usage(self, &format!("{name}([n])")),
                };
                V { e: pv(format!("$fsrtest({}.{n})", if name == "relay_uri" { "uri" } else { "dest" })), ty: Ty::Str }
            }
            "calls" => {
                let [e] = pos.as_slice() else { return usage(self, "calls(module.function)") };
                match self.sig_of(e) {
                    Some(f) => V { e: pv(format!("$fsrtest(calls.{f})")), ty: Ty::Int },
                    None => return usage(self, "calls(module.function): a module function"),
                }
            }
            _ => return None,
        })
    }

    /// `ns.name` → the function it lowers to.
    fn sig_of(&self, e: &Expr) -> Option<String> {
        let ExprKind::Field(b, n) = &e.kind else { return None };
        let ExprKind::Ident(ns) = &b.kind else { return None };
        self.env.namespaces.get(ns)?.get(&n.text).map(|s| s.name.to_string())
    }

    fn need_module(&mut self, m: &str) {
        if !m.is_empty() && !self.modules.iter().any(|x| x == m) {
            self.modules.push(m.to_string());
        }
    }

    fn modparam(&mut self, module: &str, name: &str, value: String, line: usize) {
        self.modparams.push(S::ModParam { module: module.into(), name: name.into(), value: S::RawArg::Str(value), line });
    }

    /// One `on <event>(…) [where …] { … }`.
    fn handler(&mut self, src: &Source, on: &ast::On, out: &mut S::Ast, events: &mut Vec<(String, Vec<S::Stmt>)>) {
        if let Some(k) = kamailio_route(&on.event.text) {
            return self.kamailio_handler(src, on, k, out);
        }
        let Some(ev) = EVENTS.iter().find(|e| e.name == on.event.text) else {
            let known: Vec<&str> = EVENTS.iter().map(|e| e.name).collect();
            self.err(src, on.event.span, format!("unknown event {:?}{}", on.event.text, suggest(&on.event.text, known)));
            return;
        };
        let line = line_of(src, on.event.span);
        let (msg_name, msg_ty) = match (ev.param, on.params.as_slice()) {
            ("", []) => (String::new(), Ty::Void),
            (want, [p]) if p.ty.name.text == want => {
                let ty = match want {
                    "Reply" => Ty::Reply,
                    "Dialog" => Ty::Dialog,
                    "HttpRequest" => Ty::Http,
                    "Destination" => Ty::Dest,
                    "DiameterRequest" => Ty::DiamReq,
                    "DiameterAnswer" => Ty::DiamAns,
                    _ => Ty::Source,
                };
                (p.name.text.clone(), ty)
            }
            ("", _) => {
                self.err(src, on.event.span, format!("`on {}` takes no parameter", ev.name));
                return;
            }
            (want, _) => {
                self.err(src, on.event.span, format!("`on {}` takes one parameter: (x: {want})", ev.name));
                return;
            }
        };
        // Settings: only `on timer(every: …)` has one.
        let mut every = None;
        for a in &on.args {
            let n = a.name.as_ref().map_or("", |n| n.text.as_str());
            match (ev.name, n, &a.value.kind) {
                ("timer", "every", ExprKind::Duration(ms, _)) if *ms > 0 => every = Some(*ms),
                ("timer", "every", _) => self.err(src, a.value.span, "every: a duration (30s, 500ms)"),
                ("timer", "cron", _) => self.err(src, a.value.span, "cron schedules are not supported yet; use every:"),
                _ => self.err(src, a.value.span, format!("`on {}` has no setting {n:?}", ev.name)),
            }
        }
        if ev.name == "timer" && every.is_none() && on.args.is_empty() {
            self.err(src, on.event.span, "on timer(every: 30s)");
        }
        let ctx = if ev.name == "reply" { ctx::REPLY } else { ctx::EVENT };
        let mut fx = Fx { src, key: format!("on {}", ev.name), ctx, msg_name, msg_ty, locals: HashMap::new(), after_await: false, depth: 0, event: ev.name };
        self.need_module(ev.module);
        let mut code = Vec::new();
        let cond = on.cond.as_ref().map(|c| self.cond(&mut fx, c, &mut code));
        let mut body = self.block(&mut fx, &on.body.stmts);
        if ev.name == "http" {
            // First match answers: the rest don't run.
            body.push(S::Stmt::Exit);
        }
        match cond {
            Some(c) => code.push(S::Stmt::If(c, body, vec![])),
            None => code.extend(body),
        }
        match ev.name {
            "reply" => out.reply_route.get_or_insert_with(Vec::new).extend(code),
            "timer" => {
                let Some(ms) = every else { return };
                self.timers = self.timers.saturating_add(1);
                let (name, route) = (format!("fsr_timer_{}", self.timers), format!("timer__{}", self.timers));
                self.modparam("rtimer", "timer", format!("name={name};interval={ms}ms"), line);
                self.modparam("rtimer", "exec", format!("timer={name};route={route}"), line);
                out.routes.push((route, code));
            }
            _ => match events.iter_mut().find(|(r, _)| r == ev.route) {
                Some((_, b)) => b.extend(code),
                None => events.push((ev.route.to_string(), code)),
            },
        }
    }

    /// `on kamailio.failure_route(msg: Request, name: "X") { … }` and the
    /// other Kamailio route kinds: the route itself, armed as in a .cfg
    /// (`kamailio.call("t_on_failure", "X")`).
    fn kamailio_handler(&mut self, src: &Source, on: &ast::On, k: KRoute, out: &mut S::Ast) {
        let mut name = None;
        for a in &on.args {
            match (a.name.as_ref().map(|n| n.text.as_str()), &a.value.kind) {
                (Some("name"), ExprKind::Str(p)) if matches!(p.as_slice(), [StrPart::Lit(_)]) => {
                    if let [StrPart::Lit(n)] = p.as_slice() {
                        name = Some(n.clone());
                    }
                }
                _ => self.err(src, a.value.span, format!("`on {}` takes name: \"…\"", on.event.text)),
            }
        }
        let Some(name) = name.filter(|n| !n.is_empty()) else {
            self.err(src, on.event.span, format!("`on {}(…, name: \"X\")`: the route's name", on.event.text));
            return;
        };
        let (msg_name, msg_ty) = match (k.param, on.params.as_slice()) {
            (_, []) => (String::new(), Ty::Void),
            (want, [p]) if !want.is_empty() && p.ty.name.text == want => (p.name.text.clone(), if want == "Reply" { Ty::Reply } else { Ty::Request }),
            ("", _) => {
                self.err(src, on.event.span, format!("`on {}` takes no message parameter", on.event.text));
                return;
            }
            (want, _) => {
                self.err(src, on.event.span, format!("`on {}` takes one parameter: (msg: {want})", on.event.text));
                return;
            }
        };
        let mut fx = Fx {
            src,
            key: format!("on {}", on.event.text),
            ctx: k.ctx,
            msg_name,
            msg_ty,
            locals: HashMap::new(),
            after_await: false,
            depth: 0,
            event: k.event,
        };
        let mut code = Vec::new();
        let cond = on.cond.as_ref().map(|c| self.cond(&mut fx, c, &mut code));
        let body = self.block(&mut fx, &on.body.stmts);
        match cond {
            Some(c) => code.push(S::Stmt::If(c, body, vec![])),
            None => code.extend(body),
        }
        let list = match k.event {
            "kamailio.failure_route" => &mut out.failure_routes,
            "kamailio.branch_route" => &mut out.branch_routes,
            "kamailio.onreply_route" => &mut out.onreply_routes,
            _ => &mut out.event_routes,
        };
        match list.iter_mut().find(|(n, _)| *n == name) {
            Some((_, b)) => b.extend(code),
            None => list.push((name, code)),
        }
    }

    fn ty_of(&mut self, src: &Source, t: &ast::TypeRef) -> Ty {
        match t.name.text.as_str() {
            "Request" => Ty::Request,
            "Reply" => Ty::Reply,
            "Int" => Ty::Int,
            "Str" | "String" => Ty::Str,
            "Bool" => Ty::Bool,
            "Duration" => Ty::Duration,
            "Action" => Ty::Action,
            "Method" => Ty::Method,
            other => {
                self.err(
                    src,
                    t.name.span,
                    format!("unknown type {other:?}{}", suggest(other, ["Request", "Reply", "Int", "Str", "Bool", "Duration", "Action", "Method"])),
                );
                Ty::Error
            }
        }
    }

    /// A message or branch flag of this name exists.
    fn flag_declared(&self, n: &str) -> bool {
        self.flags.contains_key(n) || self.branch_flags.contains_key(n)
    }

    /// First pass: imports, flags, and every route/fn signature.
    fn declare(&mut self, sources: &[Source]) {
        // Next free bit, counting down from 31 (`None`: all taken).
        let (mut next_msg_flag, mut next_branch_flag): (Option<u32>, Option<u32>) = (Some(31), Some(31));
        // Flags with a fixed bit (`flag FLT_ACC = 1`) first: the others skip
        // them. Message flags and branch flags are separate sets of bits.
        let (mut pinned_msg, mut pinned_branch): (BTreeMap<u32, String>, BTreeMap<u32, String>) = Default::default();
        for src in sources {
            for item in &src.file.items {
                let ast::ItemKind::Flag(n, Some((bit, span)), branch) = &item.kind else { continue };
                let kind = if *branch { "branch flag" } else { "flag" };
                let pinned = if *branch { &mut pinned_branch } else { &mut pinned_msg };
                match u32::try_from(*bit).ok().filter(|b| *b <= 31) {
                    None => self.err(src, *span, format!("{kind} bit {bit} is out of range (0..31)")),
                    Some(b) => match pinned.get(&b) {
                        Some(other) => self.err(src, *span, format!("{kind} bit {b} is already {other}")),
                        None if self.flag_declared(&n.text) => self.err(src, n.span, format!("flag {} declared twice", n.text)),
                        None => {
                            pinned.insert(b, n.text.clone());
                            if *branch { &mut self.branch_flags } else { &mut self.flags }.insert(n.text.clone(), b);
                        }
                    },
                }
            }
        }
        for src in sources {
            for item in &src.file.items {
                match &item.kind {
                    ast::ItemKind::Modules(names) => {
                        for n in names {
                            if self.env.namespaces.contains_key(&n.text) {
                                self.imported.insert(n.text.clone());
                            } else {
                                let known: Vec<&str> = self.env.namespaces.keys().map(String::as_str).collect();
                                self.err(src, n.span, format!("unknown module {:?}{}", n.text, suggest(&n.text, known)));
                            }
                        }
                    }
                    ast::ItemKind::FromConfig(names, from) => {
                        if from.text != "config" {
                            self.err(src, from.span, "only `from config` is supported");
                        }
                        for n in names {
                            if n.text != "features" {
                                self.err(src, n.span, format!("config has `features` ([feature] in ferrosip.toml), not {:?}", n.text));
                            }
                            self.config_names.insert(n.text.clone());
                        }
                    }
                    ast::ItemKind::File(..) => {}
                    ast::ItemKind::Flag(_, Some(_), _) => {}
                    ast::ItemKind::Flag(n, None, branch) => {
                        let (next_flag, pinned) = if *branch { (&mut next_branch_flag, &pinned_branch) } else { (&mut next_msg_flag, &pinned_msg) };
                        // The bits ferrosip.toml parameters use are message flags.
                        let used = |f: u32| (!*branch && self.env.used_flags.contains(&f)) || pinned.contains_key(&f);
                        while let Some(f) = *next_flag
                            && used(f)
                        {
                            *next_flag = f.checked_sub(1);
                        }
                        match *next_flag {
                            None => self.err(src, n.span, if *branch { "no branch flag left (0..31)" } else { "no message flag left (0..31)" }),
                            Some(_) if self.flag_declared(&n.text) => self.err(src, n.span, format!("flag {} declared twice", n.text)),
                            Some(f) => {
                                if *branch { &mut self.branch_flags } else { &mut self.flags }.insert(n.text.clone(), f);
                                *next_flag = f.checked_sub(1);
                            }
                        }
                    }
                    ast::ItemKind::Route(f) | ast::ItemKind::Fn(f) => {
                        let is_route = matches!(item.kind, ast::ItemKind::Route(_));
                        let is_main = is_route && src.ns.is_empty() && f.name.text == "main";
                        let k = key(&src.ns, &f.name.text);
                        if self.fns.contains_key(&k) {
                            self.err(src, f.name.span, format!("{} is defined twice", f.name.text));
                            continue;
                        }
                        let mut params = Vec::new();
                        for (i, p) in f.params.iter().enumerate() {
                            let t = self.ty_of(src, &p.ty);
                            if t == Ty::Request && i > 0 {
                                self.err(src, p.ty.span, "the message is the first parameter: (msg: Request, …)");
                            }
                            if t != Ty::Request && !matches!(t, Ty::Int | Ty::Str | Ty::Bool | Ty::Duration | Ty::Method | Ty::Error) {
                                self.err(src, p.ty.span, format!("a parameter can't be a {}", t.name()));
                            }
                            params.push((p.name.text.clone(), t));
                        }
                        let has_msg = params.first().is_some_and(|(_, t)| *t == Ty::Request);
                        if is_route && !has_msg {
                            self.err(src, f.name.span, format!("route {} needs the message parameter: (msg: Request)", f.name.text));
                        }
                        if !has_msg && f.ret.as_ref().is_some_and(|t| t.name.text == "Action") {
                            self.err(src, f.name.span, format!("{} returns Action, so it needs the message: (msg: Request, …)", f.name.text));
                        }
                        if is_route && params.len() > 1 {
                            self.err(src, f.name.span, "a route takes only the message; use `fn` for more parameters");
                        }
                        let ret = match &f.ret {
                            None => Ty::Void,
                            Some(t) => {
                                let t2 = self.ty_of(src, t);
                                if matches!(t2, Ty::Action | Ty::Bool | Ty::Error) {
                                    t2
                                } else {
                                    self.err(src, t.span, format!("functions return Action or Bool (or nothing), not {}", t2.name()));
                                    // Reported once: calls and returns don't complain again.
                                    Ty::Error
                                }
                            }
                        };
                        let route = if is_main {
                            "main".into()
                        } else if src.ns.is_empty() {
                            f.name.text.clone()
                        } else {
                            format!("{}__{}", src.ns, f.name.text)
                        };
                        self.fns.insert(k, UserFn { route, params, ret, ctx: 0, is_main, has_msg });
                    }
                    ast::ItemKind::On(_) | ast::ItemKind::Test(..) => {}
                    ast::ItemKind::Table { name, ty, ttl } => self.declare_table(src, name, ty, ttl.as_ref()),
                    ast::ItemKind::DialogVar { name, ty } => {
                        let t = self.ty_of(src, ty);
                        if !matches!(t, Ty::Str | Ty::Int | Ty::Bool | Ty::Error) {
                            self.err(src, ty.span, "a dialog var is Str, Int or Bool");
                        }
                        if self.dlg_vars.insert(name.text.clone(), t).is_some() {
                            self.err(src, name.span, format!("dialog var {} declared twice", name.text));
                        }
                        self.need_module("dialog");
                    }
                }
            }
        }
    }

    /// `shared table name: Map<K, V> [ttl d]` → an htable table.
    fn declare_table(&mut self, src: &Source, name: &ast::Name, ty: &ast::TypeRef, ttl: Option<&Expr>) {
        let n = &name.text;
        if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            self.err(src, name.span, "a table name is letters, digits and _");
        }
        let val = match (ty.name.text.as_str(), ty.args.as_slice()) {
            ("Map", [k, v]) => {
                if !matches!(k.name.text.as_str(), "Str" | "Int" | "IpAddr") {
                    self.err(src, k.span, "a table key is Str or Int");
                }
                match v.name.text.as_str() {
                    "Bool" => TableVal::Bool,
                    "Int" => TableVal::Int,
                    "Str" | "String" => TableVal::Str,
                    "Counter" => TableVal::Counter,
                    other => {
                        self.err(src, v.span, format!("a table value is Bool, Int, Str or Counter, not {other}"));
                        TableVal::Str
                    }
                }
            }
            _ => {
                self.err(src, ty.span, "a shared table is a Map<Key, Value>");
                TableVal::Str
            }
        };
        let secs = match ttl.map(|t| &t.kind) {
            None => 0,
            Some(ExprKind::Duration(ms, _)) if *ms >= 1000 => ms / 1000,
            Some(_) => {
                self.err(src, ttl.map_or(name.span, |t| t.span), "ttl: a duration of at least 1s");
                0
            }
        };
        if self.tables.insert(n.clone(), val).is_some() {
            self.err(src, name.span, format!("table {n} declared twice"));
        }
        self.need_module("htable");
        if self.env.toml_tables.contains(n) {
            // Its options (ttl, dbtable…) come from ferrosip.toml.
            if let Some(t) = ttl {
                self.err(src, t.span, format!("table {n} is declared in ferrosip.toml: set its expiry (autoexpire) there"));
            }
            return;
        }
        let mut spec = format!("{n}=>size=8;");
        if secs > 0 {
            spec.push_str(&format!("autoexpire={secs};"));
        }
        self.modparam("htable", "htable", spec, line_of(src, name.span));
    }

    /// Which contexts each function runs in: routes start in request
    /// processing; code after an `await` runs in the failure context.
    fn contexts(&mut self, sources: &[Source]) {
        let mut edges: Vec<(String, String, u8)> = Vec::new();
        let mut roots: Vec<(String, u8)> = Vec::new();
        for src in sources {
            for item in &src.file.items {
                if let ast::ItemKind::Route(f) | ast::ItemKind::Fn(f) = &item.kind {
                    let k = key(&src.ns, &f.name.text);
                    if matches!(item.kind, ast::ItemKind::Route(_)) {
                        roots.push((k.clone(), ctx::REQUEST));
                    }
                    let mut after = BEFORE;
                    calls_in(&f.body.stmts, &src.ns, &mut after, &mut |callee, at| edges.push((k.clone(), callee, at)));
                }
            }
        }
        for src in sources {
            for item in &src.file.items {
                if let ast::ItemKind::On(on) = &item.kind {
                    let c = match kamailio_route(&on.event.text) {
                        Some(k) => k.ctx,
                        None if on.event.text == "reply" => ctx::REPLY,
                        None => ctx::EVENT,
                    };
                    let mut after = BEFORE;
                    calls_in(&on.body.stmts, &src.ns, &mut after, &mut |callee, _| roots.push((callee, c)));
                }
            }
        }
        for (k, c) in roots {
            if let Some(f) = self.fns.get_mut(&k) {
                f.ctx |= c;
            }
        }
        loop {
            let mut changed = false;
            for (from, to, at) in &edges {
                let caller = self.fns.get(from).map_or(0, |f| f.ctx);
                // After an `await` the call runs after the final (only).
                let c = match *at {
                    _ if caller == 0 => 0,
                    AFTER => (caller & !ctx::REQUEST) | ctx::FAILURE,
                    MAYBE => caller | ctx::FAILURE,
                    _ => caller,
                };
                if let Some(t) = self.fns.get_mut(to)
                    && t.ctx | c != t.ctx
                {
                    t.ctx |= c;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn fx<'s>(src: &'s Source, k: &str, uf: &UserFn, f: &ast::Func, ctx: u8) -> Fx<'s> {
        let mut locals = HashMap::new();
        for (name, ty) in uf.params.iter().skip(usize::from(uf.has_msg)) {
            locals.insert(name.clone(), Local { avp: format!("$avp(p__{}__{})", uf.route, name), ty: ty.clone() });
        }
        let (msg_name, msg_ty) = match f.params.first() {
            Some(p) if uf.has_msg => (p.name.text.clone(), Ty::Request),
            _ => (String::new(), Ty::Void),
        };
        Fx { src, key: k.into(), ctx: if ctx == 0 { ctx::REQUEST } else { ctx }, msg_name, msg_ty, locals, after_await: false, depth: 0, event: "" }
    }

    // ------------------------------------------------------------ blocks

    fn block(&mut self, fx: &mut Fx, stmts: &[Stmt]) -> Vec<S::Stmt> {
        let mut out = Vec::new();
        fx.depth = fx.depth.saturating_add(1);
        // `let`s are visible to the end of their block.
        let outer: std::collections::HashSet<String> = fx.locals.keys().cloned().collect();
        let entry = fx.ctx;
        let mut dead = false;
        for (i, s) in stmts.iter().enumerate() {
            self.stmt(fx, s, &mut out);
            // A statement that ends the route: nothing after it can run.
            let ends = matches!(s.kind, StmtKind::Expr(_) | StmtKind::Return(_) | StmtKind::Drop | StmtKind::Exit)
                && matches!(out.last(), Some(S::Stmt::Exit | S::Stmt::Drop | S::Stmt::Return(_)));
            if ends
                && !dead
                && let Some(next) = stmts.get(i.saturating_add(1))
            {
                self.err(fx.src, next.span, "unreachable: the statement before ends the route (a reply, relay or other Action)");
                dead = true;
            }
        }
        // An `await` inside: after this block the code may or may not run
        // after the final.
        if fx.ctx != entry {
            fx.ctx |= entry;
        }
        if fx.depth > 1 {
            fx.locals.retain(|k, _| outer.contains(k));
        }
        fx.depth = fx.depth.saturating_sub(1);
        out
    }

    /// `[let name =] await txn.relay(msg, …)`: relay with `t_relay_await`;
    /// the script stops here and continues with the next statement when
    /// the transaction has its final (the failure context). The result
    /// goes in `<name>__code` / `__reason` / `__timeout`.
    fn await_stmt(&mut self, fx: &mut Fx, name: Option<&ast::Name>, e: &Expr, line: usize, out: &mut Vec<S::Stmt>) {
        let ExprKind::Await(inner) = &e.kind else { return };
        // A Bool function's caller needs its value at once: it can't wait.
        if self.fns.get(&fx.key).is_some_and(|f| f.ret == Ty::Bool) {
            self.err(fx.src, e.span, "`await` can't be in a function returning Bool (its caller needs the value now); return Action or nothing");
        }
        if fx.msg_ty != Ty::Request {
            self.err(fx.src, e.span, "`await` needs a request");
        }
        // Any call whose signature waits (`http.get`…): the record of its
        // result, read when the script resumes.
        let relay = matches!(&inner.kind, ExprKind::Call(c, _) if matches!(&c.kind, ExprKind::Ident(n) if n == "relay")
            || matches!(&c.kind, ExprKind::Field(b, m) if matches!(&b.kind, ExprKind::Ident(ns) if ns == "txn") && m.text == "relay"));
        if !relay {
            if fx.ctx & ctx::FAILURE != 0 {
                self.err(fx.src, inner.span, "after `await txn.relay` the request is relayed: nothing else can be awaited");
            }
            let ExprKind::Call(callee, args) = &inner.kind else {
                self.err(fx.src, inner.span, "`await` takes a call: await txn.relay(msg), await http.get(url)…");
                return;
            };
            self.awaiting = true;
            let v = self.call(fx, callee, args, inner.span, line, out);
            self.awaiting = false;
            let aw = match v.ty {
                Ty::Record(aw) => aw,
                Ty::Error => return,
                t => {
                    self.err(fx.src, inner.span, format!("this call doesn't wait (it gives {}): drop the `await`", t.name()));
                    return;
                }
            };
            out.push(S::Stmt::Expr(v.e));
            if let Some(n) = name {
                let base = self.local_avp(fx, &n.text);
                for (field, pv, _) in aw.fields {
                    out.push(S::Stmt::Assign(Self::set_target(&Self::sub(&base, field)), S::Expr::Pv(pv.to_string(), line), line));
                }
                fx.locals.insert(n.text.clone(), Local { avp: base, ty: Ty::Record(aw) });
            }
            return;
        }
        let args = match &inner.kind {
            ExprKind::Call(callee, args) => match &callee.kind {
                ExprKind::Ident(n) if n == "relay" => Some(args),
                ExprKind::Field(b, m) if matches!(&b.kind, ExprKind::Ident(ns) if ns == "txn") && m.text == "relay" => Some(args),
                _ => None,
            },
            _ => None,
        };
        let Some(args) = args else {
            self.err(fx.src, inner.span, "only `await txn.relay(msg, …)` can be awaited");
            return;
        };
        let v = self.call_sig(fx, "txn", inner.span, "relay_await", inner.span, args, inner.span, line, out);
        if v.ty == Ty::Error {
            return;
        }
        out.push(S::Stmt::Expr(v.e));
        fx.after_await = true;
        // What follows runs after the final (the enclosing blocks: perhaps).
        fx.ctx = (fx.ctx & !ctx::REQUEST) | ctx::FAILURE;
        if let Some(n) = name {
            let base = self.local_avp(fx, &n.text);
            let stem = base.trim_end_matches(')').to_string();
            // `$rc` first: -1 when the relay failed at once (the script went
            // on without waiting), 1 when it resumed at the final.
            for (field, pv) in [("rc", "$rc"), ("code", "$T_reply_code"), ("reason", "$T_reply_reason"), ("timeout", "$T_timeout")] {
                out.push(S::Stmt::Assign(Self::set_target(&format!("{stem}__{field})")), S::Expr::Pv(pv.into(), line), line));
            }
            fx.locals.insert(n.text.clone(), Local { avp: base, ty: Ty::Result });
        }
    }

    /// `$avp(x)` → `$avp(x__field)`.
    fn sub(avp: &str, field: &str) -> String {
        format!("{}__{field})", avp.trim_end_matches(')'))
    }

    /// `for x in [a, b, c] { … }` / `for i in lo..hi { … }` → a `while`
    /// over an index local, bumped before the body runs (so after an
    /// `await` in the body the loop goes on with the next item).
    fn for_loop(&mut self, fx: &mut Fx, name: &ast::Name, over: &Expr, body: &ast::Block, line: usize, out: &mut Vec<S::Stmt>) {
        if has_await(&body.stmts) {
            fx.ctx |= ctx::FAILURE;
        }
        if fx.locals.contains_key(&name.text) || name.text == fx.msg_name {
            self.err(fx.src, name.span, format!("{} is already defined here", name.text));
        }
        self.temps = self.temps.saturating_add(1);
        let idx = self.local_avp(fx, &format!("for{}", self.temps));
        let var = self.local_avp(fx, &name.text);
        let iv = || S::Expr::Pv(idx.clone(), line);
        let bump = S::Stmt::Assign(Self::set_target(&idx), bin(S::BinOp::Add, iv(), S::Expr::Int(1)), line);
        let (cond, pick, ty) = match &over.kind {
            ExprKind::Range(lo, hi) => {
                let (l, h) = (self.expr(fx, lo, out), self.expr(fx, hi, out));
                if !matches!(l.ty, Ty::Int | Ty::Error) || !matches!(h.ty, Ty::Int | Ty::Error) {
                    self.err(fx.src, over.span, "a range loop counts integers (1..3)");
                }
                out.push(S::Stmt::Assign(Self::set_target(&idx), l.e, line));
                (bin(S::BinOp::Le, iv(), h.e), vec![S::Stmt::Assign(Self::set_target(&var), iv(), line)], Ty::Int)
            }
            ExprKind::List(items) if !items.is_empty() => {
                let mut vals = Vec::new();
                for it in items {
                    vals.push(self.expr(fx, it, out));
                }
                let ty = vals.iter().map(|v| v.ty.clone()).find(|t| *t != Ty::Error).unwrap_or(Ty::Error);
                for (v, it) in vals.iter().zip(items) {
                    if v.ty != ty && v.ty != Ty::Error {
                        self.err(fx.src, it.span, format!("the list mixes {} and {}", ty.name(), v.ty.name()));
                    }
                }
                if !matches!(ty, Ty::Str | Ty::Int | Ty::Method | Ty::Error) {
                    self.err(fx.src, over.span, format!("a loop goes over Str or Int values, not {}", ty.name()));
                }
                // if i == 0 { x = a } else if i == 1 { x = b } …
                let mut pick: Vec<S::Stmt> = Vec::new();
                for (k, v) in vals.into_iter().enumerate().rev() {
                    let set = vec![S::Stmt::Assign(Self::set_target(&var), v.e, line)];
                    pick = vec![S::Stmt::If(bin(S::BinOp::Eq, iv(), S::Expr::Int(i64::try_from(k).unwrap_or(i64::MAX))), set, pick)];
                }
                out.push(S::Stmt::Assign(Self::set_target(&idx), S::Expr::Int(0), line));
                (bin(S::BinOp::Lt, iv(), S::Expr::Int(i64::try_from(items.len()).unwrap_or(i64::MAX))), pick, ty)
            }
            _ => {
                self.err(fx.src, over.span, "`for` goes over a list ([a, b]) or a range (1..3)");
                return;
            }
        };
        let shadow = fx.locals.insert(name.text.clone(), Local { avp: var, ty });
        let mut b = pick;
        b.push(bump);
        b.extend(self.block(fx, &body.stmts));
        // The variable belongs to the loop.
        match shadow {
            Some(l) => fx.locals.insert(name.text.clone(), l),
            None => fx.locals.remove(&name.text),
        };
        out.push(S::Stmt::While(cond, b));
    }

    fn local_avp(&self, fx: &Fx, name: &str) -> String {
        let route = self.fns.get(&fx.key).map_or("reply".into(), |f| f.route.clone());
        format!("$avp(l__{route}__{name})")
    }

    /// `$avp(x)` → `$(avp(x)[*])` (assignment replaces the value list).
    fn set_target(avp: &str) -> String {
        avp.strip_prefix("$avp(").and_then(|r| r.strip_suffix(')')).map_or_else(|| avp.to_string(), |n| format!("$(avp({n})[*])"))
    }

    /// Store `v` in variable `target` (bools as 1/-1).
    fn store(&mut self, target: &str, v: V, line: usize, out: &mut Vec<S::Stmt>) {
        let t = Self::set_target(target);
        if let Some(b) = const_bool(&v.e).filter(|_| v.ty == Ty::Bool) {
            out.push(S::Stmt::Assign(t, S::Expr::Int(if b { 1 } else { -1 }), line));
        } else if v.ty == Ty::Bool {
            out.push(S::Stmt::If(v.e, vec![S::Stmt::Assign(t.clone(), S::Expr::Int(1), line)], vec![S::Stmt::Assign(t, S::Expr::Int(-1), line)]));
        } else {
            out.push(S::Stmt::Assign(t, v.e, line));
        }
    }

    fn stmt(&mut self, fx: &mut Fx, s: &Stmt, out: &mut Vec<S::Stmt>) {
        let line = line_of(fx.src, s.span);
        match &s.kind {
            StmtKind::Let { name, ty, value, otherwise } => {
                if fx.locals.contains_key(&name.text) || name.text == fx.msg_name {
                    self.err(fx.src, name.span, format!("{} is already defined here", name.text));
                }
                if matches!(value.kind, ExprKind::Await(_)) {
                    if ty.is_some() || otherwise.is_some() {
                        self.err(fx.src, value.span, "`let x = await …` takes no type and no else (match on the result)");
                    }
                    self.await_stmt(fx, Some(name), value, line, out);
                    return;
                }
                let v = self.expr(fx, value, out);
                if let Some(t) = ty {
                    let want = self.ty_of(fx.src, t);
                    if want != v.ty && v.ty != Ty::Error && want != Ty::Error {
                        self.err(fx.src, value.span, format!("expected {}, found {}", want.name(), v.ty.name()));
                    }
                }
                if matches!(v.ty, Ty::Void | Ty::Action) {
                    self.err(fx.src, value.span, format!("{} gives no value to keep", crate::fmt::expr(value)));
                }
                let avp = self.local_avp(fx, &name.text);
                let ty = v.ty.clone();
                self.store(&avp, v, line, out);
                if let Some(o) = otherwise {
                    if ty != Ty::Bool && ty != Ty::Error {
                        self.err(fx.src, value.span, format!("`let … else` needs a true/false value, found {}", ty.name()));
                    }
                    let mut alt = Vec::new();
                    self.stmt(fx, o, &mut alt);
                    out.push(S::Stmt::If(bin(S::BinOp::Le, S::Expr::Pv(avp.clone(), line), S::Expr::Int(0)), alt, vec![]));
                }
                fx.locals.insert(name.text.clone(), Local { avp, ty });
            }
            StmtKind::Assign(target, value) => self.assign(fx, target, value, line, out),
            StmtKind::If(c, then, els) => {
                let cond = self.cond(fx, c, out);
                let t = self.block(fx, &then.stmts);
                let e = match els {
                    None => vec![],
                    Some(ast::Else::Block(b)) => self.block(fx, &b.stmts),
                    Some(ast::Else::If(s)) => {
                        let mut v = Vec::new();
                        self.stmt(fx, s, &mut v);
                        v
                    }
                };
                match const_bool(&cond) {
                    Some(true) => out.extend(t),
                    Some(false) => out.extend(e),
                    None => out.push(S::Stmt::If(cond, t, e)),
                }
            }
            StmtKind::While(c, body) => {
                if has_await(&body.stmts) {
                    fx.ctx |= ctx::FAILURE;
                }
                let mut pre = Vec::new();
                let cond = self.cond(fx, c, &mut pre);
                if !pre.is_empty() {
                    self.err(fx.src, c.span, "a loop condition must be simple (use a variable)");
                }
                let b = self.block(fx, &body.stmts);
                out.push(S::Stmt::While(cond, b));
            }
            StmtKind::For(name, over, body) => self.for_loop(fx, name, over, body, line, out),
            StmtKind::Guard(c, otherwise) => {
                const MUST_END: &str = "a guard's else must end the route (reply, drop, exit, return, or an Action call)";
                let syntax_ok = ends_route(otherwise);
                if !syntax_ok {
                    self.err(fx.src, otherwise.span, MUST_END);
                }
                let cond = self.guard_cond(fx, c, out);
                let mut alt = Vec::new();
                let errs = self.diags.len();
                self.stmt(fx, otherwise, &mut alt);
                // A call ends the route only if it is an Action (it lowers
                // to `…; exit;`); one that returns nothing falls through.
                if syntax_ok && self.diags.len() == errs && !matches!(alt.last(), Some(S::Stmt::Exit | S::Stmt::Drop | S::Stmt::Return(_))) {
                    self.err(fx.src, otherwise.span, MUST_END);
                }
                out.push(S::Stmt::If(not(cond), alt, vec![]));
            }
            StmtKind::Match(subject, arms) => self.match_stmt(fx, subject, arms, line, out),
            StmtKind::Return(None) => {
                let ret = self.fns.get(&fx.key).map_or(Ty::Void, |f| f.ret.clone());
                if ret == Ty::Bool {
                    self.err(fx.src, s.span, "this function returns Bool: return true or false");
                }
                out.push(if self.fns.get(&fx.key).is_none_or(|f| f.is_main) { S::Stmt::Exit } else { S::Stmt::Return(None) });
            }
            StmtKind::Return(Some(e)) => {
                let ret = self.fns.get(&fx.key).map_or(Ty::Void, |f| f.ret.clone());
                let v = self.expr(fx, e, out);
                match (&ret, &v.ty) {
                    (Ty::Error, _) | (_, Ty::Error) => {}
                    (Ty::Action | Ty::Void, Ty::Action) => {
                        if !matches!(out.last(), Some(S::Stmt::Exit)) {
                            out.push(S::Stmt::Exit);
                        }
                    }
                    (Ty::Bool, Ty::Bool | Ty::Any) => {
                        out.push(S::Stmt::If(v.e, vec![S::Stmt::Return(Some(S::Expr::Int(1)))], vec![S::Stmt::Return(Some(S::Expr::Int(-1)))]));
                    }
                    (r, t) => self.err(
                        fx.src,
                        e.span,
                        format!("this function returns {}, found {}", if *r == Ty::Void { "nothing".into() } else { r.name() }, t.name()),
                    ),
                }
            }
            StmtKind::Drop => out.push(S::Stmt::Drop),
            StmtKind::Exit => out.push(S::Stmt::Exit),
            StmtKind::Break => out.push(S::Stmt::Break),
            StmtKind::Expr(e) if matches!(e.kind, ExprKind::Await(_)) => self.await_stmt(fx, None, e, line, out),
            StmtKind::Expr(e) => {
                let v = self.expr(fx, e, out);
                match v.ty {
                    Ty::Action => {} // already lowered with its exit
                    Ty::Void | Ty::Bool | Ty::Error | Ty::Any => {
                        if !matches!(v.e, S::Expr::Int(_)) {
                            out.push(S::Stmt::Expr(v.e));
                        }
                    }
                    // `hits.incr(ip)` on its own: count, ignore the result.
                    Ty::Int if matches!(&v.e, S::Expr::Pv(p, _) if p.starts_with("$shtinc(") || p.starts_with("$shtdec(")) => {
                        let t = self.temp();
                        out.push(S::Stmt::Assign(Self::set_target(&t), v.e, line));
                    }
                    t => self.err(fx.src, e.span, format!("this value ({}) is not used", t.name())),
                }
            }
        }
    }

    /// `guard msg.max_forwards > 0` keeps Kamailio's meaning: check and
    /// decrement (maxfwd's `mf_process_maxfwd_header`).
    fn guard_cond(&mut self, fx: &mut Fx, c: &Expr, out: &mut Vec<S::Stmt>) -> S::Expr {
        if let ExprKind::Binary(BinOp::Gt, a, b) = &c.kind
            && is_field(a, &fx.msg_name, "max_forwards")
            && matches!(b.kind, ExprKind::Int(0))
        {
            return call("mf_process_maxfwd_header", vec![S::RawArg::Int(70)], line_of(fx.src, c.span));
        }
        self.cond(fx, c, out)
    }

    fn assign(&mut self, fx: &mut Fx, target: &Expr, value: &Expr, line: usize, out: &mut Vec<S::Stmt>) {
        // In a test: `location.lookup = false` mocks the function.
        if fx.event == "test"
            && let Some(f) = self.sig_of(target)
        {
            let rc = match &value.kind {
                ExprKind::Bool(b) => {
                    if *b {
                        1
                    } else {
                        -1
                    }
                }
                ExprKind::Int(n) if *n != 0 => *n,
                _ => {
                    self.err(fx.src, value.span, "a mock returns true, false or a non-zero number");
                    return;
                }
            };
            if let Some(t) = self.tests.last_mut() {
                t.mocks.push((f, rc));
            }
            return;
        }
        // A mock of a function the namespace doesn't have: say so.
        if fx.event == "test"
            && let ExprKind::Field(b, n) = &target.kind
            && let ExprKind::Ident(ns) = &b.kind
            && !fx.locals.contains_key(ns)
            && let Some(fns) = self.env.namespaces.get(ns)
        {
            let known: Vec<&str> = fns.keys().map(String::as_str).collect();
            let msg = format!("{ns} has no function {}(){} to mock", n.text, suggest(&n.text, known));
            self.err(fx.src, n.span, msg);
            return;
        }
        // d.caller = v (in dialog handlers) / dialog.caller = v (in routes).
        if let ExprKind::Field(base, name) = &target.kind
            && let ExprKind::Ident(b) = &base.kind
            && ((b == "dialog" && !fx.locals.contains_key(b)) || (*b == fx.msg_name && fx.msg_ty == Ty::Dialog))
            && (b == "dialog" || self.dlg_vars.contains_key(&name.text) || !EVENT_FIELDS.iter().any(|(t, f, ..)| *t == "Dialog" && *f == name.text))
        {
            let Some(want) = self.dlg_vars.get(&name.text).cloned() else {
                let known: Vec<&str> = self.dlg_vars.keys().map(String::as_str).collect();
                self.err(fx.src, name.span, format!("no `dialog var {}`{}", name.text, suggest(&name.text, known)));
                return;
            };
            let v = self.expr(fx, value, out);
            if v.ty != want && v.ty != Ty::Error && want != Ty::Error {
                self.err(fx.src, value.span, format!("dialog var {} is {}, found {}", name.text, want.name(), v.ty.name()));
            }
            let pv = format!("$dlg_var({})", name.text);
            if let Some(b) = const_bool(&v.e).filter(|_| v.ty == Ty::Bool) {
                out.push(S::Stmt::Assign(pv, S::Expr::Int(i64::from(b)), line));
            } else if v.ty == Ty::Bool {
                out.push(S::Stmt::If(v.e, vec![S::Stmt::Assign(pv.clone(), S::Expr::Int(1), line)], vec![S::Stmt::Assign(pv, S::Expr::Int(0), line)]));
            } else {
                out.push(S::Stmt::Assign(pv, v.e, line));
            }
            return;
        }
        // msg.headers["X"] = v → replace the header.
        if let ExprKind::Index(base, idx) = &target.kind
            && is_field(base, &fx.msg_name, "headers")
        {
            let name = self.header_name(fx, idx);
            let v = self.expr(fx, value, out);
            if !matches!(v.ty, Ty::Str | Ty::Int | Ty::Error | Ty::Any) {
                self.err(fx.src, value.span, format!("a header value is text, found {}", v.ty.name()));
            }
            let raw = self.raw(fx, v, line, out);
            let text = match raw {
                S::RawArg::Str(s) => s,
                S::RawArg::Int(i) => i.to_string(),
                S::RawArg::Pv(p) => p,
            };
            out.push(S::Stmt::Expr(call("remove_hf", vec![S::RawArg::Str(name.clone())], line)));
            out.push(S::Stmt::Expr(call("append_hf", vec![S::RawArg::Str(format!("{name}: {text}\r\n"))], line)));
            return;
        }
        if let ExprKind::Call(c, args) = &target.kind
            && matches!(&c.kind, ExprKind::Ident(n) if n == "pv")
        {
            let Some(p) = self.pv_name(fx, args, target.span) else { return };
            let v = self.expr(fx, value, out);
            if matches!(v.ty, Ty::Request | Ty::Reply | Ty::Action | Ty::Void | Ty::Result) {
                self.err(fx.src, value.span, format!("{} can't be stored", v.ty.name()));
            }
            // Exactly as written: `$avp(x) = v` adds a value, as in a .cfg.
            if v.ty == Ty::Bool {
                out.push(S::Stmt::If(v.e, vec![S::Stmt::Assign(p.clone(), S::Expr::Int(1), line)], vec![S::Stmt::Assign(p, S::Expr::Int(-1), line)]));
            } else {
                out.push(S::Stmt::Assign(p, v.e, line));
            }
            return;
        }
        match &target.kind {
            ExprKind::Ident(n) => {
                let Some(l) = fx.locals.get(n) else {
                    self.err(fx.src, target.span, format!("{n} is not defined (use `let {n} = …`)"));
                    return;
                };
                let (avp, ty) = (l.avp.clone(), l.ty.clone());
                let v = self.expr(fx, value, out);
                if v.ty != ty && v.ty != Ty::Error && ty != Ty::Error && v.ty != Ty::Any && ty != Ty::Any {
                    self.err(fx.src, value.span, format!("{n} is {}, found {}", ty.name(), v.ty.name()));
                }
                self.store(&avp, v, line, out);
            }
            _ => {
                let Some(path) = field_path(target, &fx.msg_name) else {
                    self.err(fx.src, target.span, "can't assign to this (a local, a msg field or msg.headers[\"X\"])");
                    return;
                };
                let Some(f) = msg::field(&path) else {
                    self.err(fx.src, target.span, format!("msg has no field {path:?}{}", suggest(&path, msg::FIELDS.iter().map(|f| f.path))));
                    return;
                };
                if !f.settable || fx.msg_ty == Ty::Reply {
                    self.err(fx.src, target.span, format!("msg.{path} can't be changed{}", if fx.msg_ty == Ty::Reply { " on a reply" } else { "" }));
                    return;
                }
                let v = self.expr(fx, value, out);
                let want = field_ty(f.ty);
                if v.ty != want && v.ty != Ty::Error && v.ty != Ty::Any && !(want == Ty::Str && v.ty == Ty::Int) {
                    self.err(fx.src, value.span, format!("msg.{path} is {}, found {}", want.name(), v.ty.name()));
                }
                out.push(S::Stmt::Assign(f.pv.to_string(), v.e, line));
            }
        }
    }

    fn header_name(&mut self, fx: &mut Fx, idx: &Expr) -> String {
        match &idx.kind {
            ExprKind::Str(parts) if parts.len() == 1 => match parts.as_slice() {
                [StrPart::Lit(s)] if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => s.clone(),
                _ => {
                    self.err(fx.src, idx.span, "a header name is a plain word (\"X-Foo\")");
                    "X".into()
                }
            },
            _ => {
                self.err(fx.src, idx.span, "a header name is a literal string (\"X-Foo\")");
                "X".into()
            }
        }
    }

    // ------------------------------------------------------------- match

    fn match_stmt(&mut self, fx: &mut Fx, subject: &Expr, arms: &[ast::Arm], line: usize, out: &mut Vec<S::Stmt>) {
        let v = self.expr(fx, subject, out);
        if v.ty == Ty::Result {
            let S::Expr::Pv(base, _) = v.e else { return };
            return self.match_result(fx, &base, subject.span, arms, out);
        }
        // Evaluate once.
        let subj = match &v.e {
            S::Expr::Pv(..) | S::Expr::Int(_) | S::Expr::Str(_) => v.e.clone(),
            _ => {
                let t = self.temp();
                out.push(S::Stmt::Assign(Self::set_target(&t), v.e.clone(), line));
                S::Expr::Pv(t, line)
            }
        };
        let mut chain: Vec<(Option<S::Expr>, Vec<S::Stmt>)> = Vec::new();
        for arm in arms {
            let mut conds = Vec::new();
            let mut wild = false;
            for p in &arm.pats {
                match self.pat_cond(fx, p, &subj, &v.ty) {
                    Some(c) => conds.push(c),
                    None => wild = true,
                }
            }
            let mut cond = if wild { None } else { conds.into_iter().reduce(|a, b| bin(S::BinOp::Or, a, b)) };
            if let Some(g) = &arm.guard {
                let mut pre = Vec::new();
                let gc = self.cond(fx, g, &mut pre);
                if !pre.is_empty() {
                    self.err(fx.src, g.span, "a match guard must be simple (compute it into a variable first)");
                }
                cond = Some(match cond {
                    Some(c) => bin(S::BinOp::And, c, gc),
                    None => gc,
                });
            }
            let body = match &arm.body {
                ast::ArmBody::Block(b) => self.block(fx, &b.stmts),
                ast::ArmBody::Stmt(s) => {
                    let mut v = Vec::new();
                    self.stmt(fx, s, &mut v);
                    v
                }
            };
            chain.push((cond, body));
        }
        // if c1 { b1 } else if c2 { b2 } … else { b_wild }
        let mut acc: Vec<S::Stmt> = Vec::new();
        for (cond, body) in chain.into_iter().rev() {
            acc = match cond {
                None => body,
                Some(c) => vec![S::Stmt::If(c, body, acc)],
            };
        }
        out.extend(acc);
    }

    /// `match res { Final(r) [if …] => …, Timeout => …, _ => … }` on an
    /// `await` result: an if-chain on its `__timeout` / `__code` values.
    /// Every outcome must be handled.
    fn match_result(&mut self, fx: &mut Fx, base: &str, span: Span, arms: &[ast::Arm], out: &mut Vec<S::Stmt>) {
        let line = line_of(fx.src, span);
        let timeout = || bin(S::BinOp::Gt, S::Expr::Pv(Self::sub(base, "timeout"), line), S::Expr::Int(0));
        let (mut final_done, mut timeout_done) = (false, false);
        let mut chain: Vec<(Option<S::Expr>, Vec<S::Stmt>)> = Vec::new();
        for arm in arms {
            let mut conds = Vec::new();
            let (mut wild, mut binds) = (false, Vec::new());
            for p in &arm.pats {
                match p {
                    Pat::Wild(_) => wild = true,
                    Pat::Variant(n, b) if n.text == "Timeout" && b.is_none() => {
                        conds.push(timeout());
                        timeout_done |= arm.guard.is_none();
                    }
                    Pat::Variant(n, b) if n.text == "Final" => {
                        conds.push(not(timeout()));
                        final_done |= arm.guard.is_none();
                        if let Some(b) = b.as_ref().filter(|b| b.text != "_") {
                            binds.push(b.text.clone());
                        }
                    }
                    Pat::Variant(n, _) => self.err(fx.src, n.span, format!("an `await` result is Final(r) or Timeout, not {}", n.text)),
                    Pat::Lit(e) => self.err(fx.src, e.span, "an `await` result is Final(r) or Timeout"),
                    Pat::Range(_, _, sp) => self.err(fx.src, *sp, "an `await` result is Final(r) or Timeout (test r.code in the guard)"),
                }
            }
            if wild && arm.guard.is_none() {
                (final_done, timeout_done) = (true, true);
            }
            if binds.len() > 1 || (!binds.is_empty() && arm.pats.len() > 1) {
                self.err(fx.src, arm.span, "bind the reply in a single Final(r) pattern");
            }
            // The bound reply is visible in the guard and the body.
            let shadowed: Vec<(String, Option<Local>)> =
                binds.iter().map(|b| (b.clone(), fx.locals.insert(b.clone(), Local { avp: base.to_string(), ty: Ty::Final }))).collect();
            let mut cond = if wild { None } else { conds.into_iter().reduce(|a, b| bin(S::BinOp::Or, a, b)) };
            if let Some(g) = &arm.guard {
                let mut pre = Vec::new();
                let gc = self.cond(fx, g, &mut pre);
                if !pre.is_empty() {
                    self.err(fx.src, g.span, "a match guard must be simple (compute it into a variable first)");
                }
                cond = Some(match cond {
                    Some(c) => bin(S::BinOp::And, c, gc),
                    None => gc,
                });
            }
            let body = match &arm.body {
                ast::ArmBody::Block(b) => self.block(fx, &b.stmts),
                ast::ArmBody::Stmt(st) => {
                    let mut v = Vec::new();
                    self.stmt(fx, st, &mut v);
                    v
                }
            };
            for (name, old) in shadowed {
                match old {
                    Some(l) => fx.locals.insert(name, l),
                    None => fx.locals.remove(&name),
                };
            }
            chain.push((cond, body));
        }
        if !final_done || !timeout_done {
            let missing = match (final_done, timeout_done) {
                (false, false) => "Final(_) and Timeout",
                (false, true) => "Final(_) (without a guard)",
                _ => "Timeout",
            };
            self.err(fx.src, span, format!("this match doesn't handle every result: add {missing} (or `_`)"));
        }
        let mut acc: Vec<S::Stmt> = Vec::new();
        for (cond, body) in chain.into_iter().rev() {
            acc = match cond {
                None => body,
                Some(c) => vec![S::Stmt::If(c, body, acc)],
            };
        }
        out.extend(acc);
    }

    /// The condition for one pattern (`None` = matches anything).
    fn pat_cond(&mut self, fx: &mut Fx, p: &Pat, subj: &S::Expr, ty: &Ty) -> Option<S::Expr> {
        let eq = |b: S::Expr| bin(S::BinOp::Eq, subj.clone(), b);
        match p {
            Pat::Wild(_) => None,
            Pat::Range(a, b, _) => {
                let (a, b) = (self.pat_int(fx, a), self.pat_int(fx, b));
                Some(bin(S::BinOp::And, bin(S::BinOp::Ge, subj.clone(), S::Expr::Int(a)), bin(S::BinOp::Le, subj.clone(), S::Expr::Int(b))))
            }
            Pat::Lit(e) => {
                let mut pre = Vec::new();
                let v = self.expr(fx, e, &mut pre);
                Some(eq(v.e))
            }
            Pat::Variant(n, bind) => {
                if bind.is_some() || matches!(n.text.as_str(), "Final" | "Timeout") {
                    self.err(fx.src, n.span, format!("{} only matches an `await` result", n.text));
                    return Some(S::Expr::Int(0));
                }
                match ty {
                    Ty::Method => {
                        if !msg::METHODS.contains(&n.text.as_str()) {
                            self.err(fx.src, n.span, format!("unknown method {}{}", n.text, suggest(&n.text, msg::METHODS.iter().copied())));
                        }
                        Some(eq(S::Expr::Str(n.text.clone())))
                    }
                    Ty::Transport => match msg::TRANSPORTS.iter().find(|(t, _)| *t == n.text) {
                        Some((_, pr)) => Some(eq(S::Expr::Str(pr.to_string()))),
                        None => {
                            self.err(fx.src, n.span, format!("unknown transport {}", n.text));
                            Some(S::Expr::Int(0))
                        }
                    },
                    Ty::Int | Ty::Any => match msg::status_code(&n.text) {
                        Some(code) => Some(eq(S::Expr::Int(code))),
                        None => {
                            let hint = suggest(&n.text, msg::STATUS_CODES.iter().map(|(s, _)| *s));
                            self.err(fx.src, n.span, format!("unknown status code {}{hint}", n.text));
                            Some(S::Expr::Int(0))
                        }
                    },
                    _ => {
                        self.err(fx.src, n.span, format!("{} is not a value of {}", n.text, ty.name()));
                        Some(S::Expr::Int(0))
                    }
                }
            }
        }
    }

    /// A range pattern's end: a number or a status code name (`Ringing`).
    fn pat_int(&mut self, fx: &Fx, e: &Expr) -> i64 {
        match &e.kind {
            ExprKind::Int(i) => *i,
            ExprKind::Ident(n) => msg::status_code(n).unwrap_or_else(|| {
                let hint = suggest(n, msg::STATUS_CODES.iter().map(|(s, _)| *s));
                self.err(fx.src, e.span, format!("unknown status code {n}{hint}"));
                0
            }),
            _ => {
                self.err(fx.src, e.span, "a range pattern's ends are numbers or status code names");
                0
            }
        }
    }

    // ------------------------------------------------------- expressions

    /// A condition: true/false.
    fn cond(&mut self, fx: &mut Fx, e: &Expr, out: &mut Vec<S::Stmt>) -> S::Expr {
        let v = self.expr(fx, e, out);
        match v.ty {
            // A Kamailio value tests as in a .cfg (a function's result > 0).
            Ty::Bool | Ty::Error | Ty::Any => v.e,
            t => {
                self.err(fx.src, e.span, format!("expected a condition (Bool), found {}", t.name()));
                S::Expr::Int(0)
            }
        }
    }

    fn expr(&mut self, fx: &mut Fx, e: &Expr, out: &mut Vec<S::Stmt>) -> V {
        let line = line_of(fx.src, e.span);
        match &e.kind {
            ExprKind::Int(n) => V { e: S::Expr::Int(*n), ty: Ty::Int },
            ExprKind::Bool(b) => V { e: truth(*b), ty: Ty::Bool },
            ExprKind::Duration(ms, _) => V { e: S::Expr::Int(clamp_i64(*ms)), ty: Ty::Duration },
            ExprKind::Str(parts) => self.string(fx, parts, line, out),
            ExprKind::Paren(x) => self.expr(fx, x, out),
            ExprKind::Ident(n) => self.ident(fx, n, e.span, line),
            ExprKind::Field(..) | ExprKind::Index(..) => self.field(fx, e, line, out),
            ExprKind::Call(callee, args) => self.call(fx, callee, args, e.span, line, out),
            ExprKind::Await(_) => {
                self.err(fx.src, e.span, "`await` arrives in the next step of phase 2; write `let res = await …`");
                V::err()
            }
            ExprKind::Unary(UnOp::Not, x) => {
                let c = self.expr(fx, x, out);
                // `!pv("$x")` is a Kamailio value too (1 or 0).
                if c.ty == Ty::Any {
                    return V { e: S::Expr::Not(Box::new(c.e)), ty: Ty::Any };
                }
                let c = match c.ty {
                    Ty::Bool | Ty::Error => c.e,
                    t => {
                        self.err(fx.src, x.span, format!("expected a condition (Bool), found {}", t.name()));
                        S::Expr::Int(0)
                    }
                };
                V { e: not(c), ty: Ty::Bool }
            }
            ExprKind::Unary(UnOp::Neg, x) => {
                let v = self.expr(fx, x, out);
                if !matches!(v.ty, Ty::Int | Ty::Error | Ty::Any) {
                    self.err(fx.src, x.span, format!("can't negate {}", v.ty.name()));
                }
                V { e: S::Expr::Neg(Box::new(v.e)), ty: Ty::Int }
            }
            ExprKind::Range(..) => {
                self.err(fx.src, e.span, "a range is only used with `in` (x in 200..299) or as a match pattern");
                V::err()
            }
            ExprKind::List(_) => {
                self.err(fx.src, e.span, "a list is only used with `in` (x in [a, b])");
                V::err()
            }
            ExprKind::Binary(op, a, b) => self.binary(fx, *op, a, b, e.span, line, out),
        }
    }

    fn binary(&mut self, fx: &mut Fx, op: BinOp, a: &Expr, b: &Expr, span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        match op {
            BinOp::And | BinOp::Or => {
                let x = self.cond(fx, a, out);
                // The right side's pre-statements would run unconditionally.
                let mut pre = Vec::new();
                let y = self.cond(fx, b, &mut pre);
                if !pre.is_empty() {
                    self.err(fx.src, b.span, "this side of && / || must be simple (compute it into a variable first)");
                }
                V { e: logic(sop(op).unwrap_or(S::BinOp::And), x, y), ty: Ty::Bool }
            }
            BinOp::In => {
                let x = self.expr(fx, a, out);
                let xe = match &x.e {
                    S::Expr::Pv(..) | S::Expr::Int(_) | S::Expr::Str(_) => x.e.clone(),
                    _ => {
                        let t = self.temp();
                        out.push(S::Stmt::Assign(Self::set_target(&t), x.e.clone(), line));
                        S::Expr::Pv(t, line)
                    }
                };
                match &b.kind {
                    ExprKind::Range(lo, hi) => {
                        let (l, h) = (self.expr(fx, lo, out), self.expr(fx, hi, out));
                        if !matches!(x.ty, Ty::Int | Ty::Error) || !matches!(l.ty, Ty::Int | Ty::Error) || !matches!(h.ty, Ty::Int | Ty::Error) {
                            self.err(fx.src, span, "a range compares integers");
                        }
                        V { e: bin(S::BinOp::And, bin(S::BinOp::Ge, xe.clone(), l.e), bin(S::BinOp::Le, xe, h.e)), ty: Ty::Bool }
                    }
                    ExprKind::List(items) if !items.is_empty() => {
                        let mut acc = None;
                        for it in items {
                            let v = self.value_like(fx, it, &x.ty, out);
                            let c = bin(S::BinOp::Eq, xe.clone(), v.e);
                            acc = Some(match acc {
                                None => c,
                                Some(p) => bin(S::BinOp::Or, p, c),
                            });
                        }
                        V { e: acc.unwrap_or(S::Expr::Int(0)), ty: Ty::Bool }
                    }
                    _ => {
                        self.err(fx.src, b.span, "`in` takes a range (200..299) or a list ([a, b])");
                        V::err()
                    }
                }
            }
            BinOp::Eq | BinOp::Ne => {
                let x = self.expr(fx, a, out);
                let y = self.value_like(fx, b, &x.ty, out);
                if !comparable(&x.ty, &y.ty) {
                    self.err(fx.src, span, format!("can't compare {} with {}", x.ty.name(), y.ty.name()));
                }
                V { e: bin(sop(op).unwrap_or(S::BinOp::Eq), x.e, y.e), ty: Ty::Bool }
            }
            BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => {
                let (x, y) = (self.expr(fx, a, out), self.expr(fx, b, out));
                for (v, s) in [(&x, a.span), (&y, b.span)] {
                    if !matches!(v.ty, Ty::Int | Ty::Duration | Ty::Error | Ty::Any) {
                        self.err(fx.src, s, format!("< and > compare numbers, found {}", v.ty.name()));
                    }
                }
                V { e: bin(sop(op).unwrap_or(S::BinOp::Lt), x.e, y.e), ty: Ty::Bool }
            }
            BinOp::Match => {
                let x = self.expr(fx, a, out);
                let y = self.expr(fx, b, out);
                if !matches!(x.ty, Ty::Str | Ty::Error | Ty::Any) || !matches!(y.ty, Ty::Str | Ty::Error | Ty::Any) {
                    self.err(fx.src, span, "=~ matches text against a regular expression string");
                }
                V { e: bin(S::BinOp::Match, x.e, y.e), ty: Ty::Bool }
            }
            BinOp::Add => {
                let (x, y) = (self.expr(fx, a, out), self.expr(fx, b, out));
                let ty = match (&x.ty, &y.ty) {
                    (Ty::Int, Ty::Int) => Ty::Int,
                    (Ty::Duration, Ty::Duration) => Ty::Duration,
                    (Ty::Str, Ty::Str | Ty::Int) | (Ty::Int, Ty::Str) => Ty::Str,
                    (Ty::Error, t) | (t, Ty::Error) => t.clone(),
                    (Ty::Any, Ty::Any | Ty::Int | Ty::Str) | (Ty::Int | Ty::Str, Ty::Any) => Ty::Any,
                    (p, q) => {
                        self.err(fx.src, span, format!("can't add {} and {}", p.name(), q.name()));
                        Ty::Error
                    }
                };
                // The script's `+` takes its type from the left operand: an
                // Int on the left would add, so start from "" to concatenate.
                let left = if (&x.ty, &y.ty) == (&Ty::Int, &Ty::Str) { bin(S::BinOp::Add, S::Expr::Str(String::new()), x.e) } else { x.e };
                V { e: bin(S::BinOp::Add, left, y.e), ty }
            }
            BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                let (x, y) = (self.expr(fx, a, out), self.expr(fx, b, out));
                if !matches!(x.ty, Ty::Int | Ty::Duration | Ty::Error | Ty::Any) || !matches!(y.ty, Ty::Int | Ty::Error | Ty::Duration | Ty::Any) {
                    self.err(fx.src, span, format!("arithmetic needs numbers, found {} and {}", x.ty.name(), y.ty.name()));
                }
                let ty = if x.ty == Ty::Duration { Ty::Duration } else { Ty::Int };
                V { e: bin(sop(op).unwrap_or(S::BinOp::Sub), x.e, y.e), ty }
            }
        }
    }

    /// A value compared with something of type `like`: bare names become
    /// methods / transports where that's what the other side is.
    fn value_like(&mut self, fx: &mut Fx, e: &Expr, like: &Ty, out: &mut Vec<S::Stmt>) -> V {
        if let ExprKind::Ident(n) = &e.kind {
            if *like == Ty::Method && msg::METHODS.contains(&n.as_str()) {
                return V { e: S::Expr::Str(n.clone()), ty: Ty::Method };
            }
            if *like == Ty::Transport
                && let Some((_, pr)) = msg::TRANSPORTS.iter().find(|(t, _)| t == n)
            {
                return V { e: S::Expr::Str(pr.to_string()), ty: Ty::Transport };
            }
        }
        self.expr(fx, e, out)
    }

    fn string(&mut self, fx: &mut Fx, parts: &[StrPart], line: usize, out: &mut Vec<S::Stmt>) -> V {
        let mut s = String::new();
        // Where a bare `$si` was just added: text right after it that
        // continues the name needs the `$(si)` form.
        let mut bare: Option<usize> = None;
        for p in parts {
            match p {
                StrPart::Lit(l) => {
                    if let Some(at) = bare.take()
                        && l.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '(' || c == '[')
                    {
                        // `at` is where the variable (`$name`) starts.
                        let name = s.get(at..).and_then(|v| v.strip_prefix('$')).unwrap_or_default().to_string();
                        s.truncate(at);
                        s.push_str(&format!("$({name})"));
                    }
                    s.push_str(&l.replace('$', "$$"));
                }
                StrPart::Expr(x) => {
                    bare = None;
                    let v = self.expr(fx, x, out);
                    match (&v.e, &v.ty) {
                        (_, Ty::Request | Ty::Reply | Ty::Action | Ty::Void | Ty::Result) => {
                            self.err(fx.src, x.span, format!("{} can't go in a string", v.ty.name()))
                        }
                        (S::Expr::Pv(p, _), _) => {
                            if !p.contains('(') {
                                bare = Some(s.len());
                            }
                            s.push_str(p)
                        }
                        (S::Expr::Int(i), _) => s.push_str(&i.to_string()),
                        (S::Expr::Str(t), _) => s.push_str(t),
                        _ => {
                            let t = self.temp();
                            self.store(&t, v, line, out);
                            s.push_str(&t);
                        }
                    }
                }
            }
        }
        V { e: S::Expr::Str(s), ty: Ty::Str }
    }

    fn ident(&mut self, fx: &mut Fx, n: &str, span: Span, line: usize) -> V {
        if let Some(l) = fx.locals.get(n) {
            let pv = S::Expr::Pv(l.avp.clone(), line);
            return match l.ty {
                Ty::Bool => V { e: bin(S::BinOp::Gt, pv, S::Expr::Int(0)), ty: Ty::Bool },
                ref t => V { e: pv, ty: t.clone() },
            };
        }
        if n == fx.msg_name {
            return V { e: S::Expr::Int(0), ty: fx.msg_ty.clone() };
        }
        if let Some(&f) = self.flags.get(n) {
            return V { e: S::Expr::Int(i64::from(f)), ty: Ty::Flag };
        }
        if let Some(&b) = self.branch_flags.get(n) {
            return V { e: S::Expr::Int(i64::from(b)), ty: Ty::BranchFlag };
        }
        if msg::METHODS.contains(&n) {
            return V { e: S::Expr::Str(n.to_string()), ty: Ty::Method };
        }
        if let Some((_, pr)) = msg::TRANSPORTS.iter().find(|(t, _)| *t == n) {
            return V { e: S::Expr::Str(pr.to_string()), ty: Ty::Transport };
        }
        if let Some(code) = msg::status_code(n) {
            return V { e: S::Expr::Int(code), ty: Ty::Int };
        }
        let mut known: Vec<String> = fx.locals.keys().cloned().collect();
        known.push(fx.msg_name.clone());
        known.extend(self.flags.keys().cloned());
        known.extend(self.branch_flags.keys().cloned());
        known.extend(msg::STATUS_CODES.iter().map(|(n, _)| n.to_string()));
        self.err(fx.src, span, format!("{n} is not defined{}", suggest(n, known.iter().map(String::as_str))));
        V::err()
    }

    /// `msg.<path>`, `msg.headers["X"]`, `features.x`.
    fn field(&mut self, fx: &mut Fx, e: &Expr, line: usize, out: &mut Vec<S::Stmt>) -> V {
        if let ExprKind::Field(base, name) = &e.kind
            && matches!(&base.kind, ExprKind::Ident(b) if b == "kamailio" && !fx.locals.contains_key(b))
        {
            if name.text == "myself" {
                return V { e: S::Expr::Myself, ty: Ty::Any };
            }
            self.err(fx.src, name.span, format!("kamailio.{} is not a value (kamailio.myself is)", name.text));
            return V::err();
        }
        if let ExprKind::Field(base, name) = &e.kind
            && let ExprKind::Ident(b) = &base.kind
            && let Some(Local { avp, ty: Ty::Record(aw) }) = fx.locals.get(b)
        {
            let (avp, aw) = (avp.clone(), *aw);
            return match aw.fields.iter().find(|(f, ..)| *f == name.text) {
                Some((f, _, t)) => {
                    let pv = S::Expr::Pv(Self::sub(&avp, f), line);
                    match t {
                        sip_core::sig::FieldTy::Bool => V { e: bin(S::BinOp::Gt, pv, S::Expr::Int(0)), ty: Ty::Bool },
                        sip_core::sig::FieldTy::Int => V { e: pv, ty: Ty::Int },
                        sip_core::sig::FieldTy::Str => V { e: pv, ty: Ty::Str },
                    }
                }
                None => {
                    let known: Vec<&str> = aw.fields.iter().map(|(f, ..)| *f).collect();
                    self.err(fx.src, name.span, format!("a {} has no {:?}{}", aw.name, name.text, suggest(&name.text, known)));
                    V::err()
                }
            };
        }
        if let ExprKind::Field(base, name) = &e.kind
            && let ExprKind::Ident(b) = &base.kind
            && let Some(l) = fx.locals.get(b)
            && matches!(l.ty, Ty::Final | Ty::Result)
        {
            if l.ty == Ty::Result {
                self.err(fx.src, e.span, format!("{b} is an `await` result: match it (Final(r) => … r.{})", name.text));
                return V::err();
            }
            let avp = l.avp.clone();
            return match name.text.as_str() {
                "code" => V { e: S::Expr::Pv(Self::sub(&avp, "code"), line), ty: Ty::Int },
                "reason" => V { e: S::Expr::Pv(Self::sub(&avp, "reason"), line), ty: Ty::Str },
                // False when the relay failed at once: nothing was sent.
                "sent" => V { e: bin(S::BinOp::Gt, S::Expr::Pv(Self::sub(&avp, "rc"), line), S::Expr::Int(0)), ty: Ty::Bool },
                other => {
                    self.err(
                        fx.src,
                        name.span,
                        format!("the final reply has code, reason and sent, not {other}{}", suggest(other, ["code", "reason", "sent"])),
                    );
                    V::err()
                }
            };
        }
        // `txn.code` / `txn.reason`: the reply `txn.status_is()` tests (the
        // winning reply in a failure handler, the current one in a reply
        // handler).
        if let ExprKind::Field(base, name) = &e.kind
            && matches!(&base.kind, ExprKind::Ident(b) if b == "txn" && !fx.locals.contains_key(b))
        {
            let (pv, ty) = match name.text.as_str() {
                "code" => ("$T_reply_code", Ty::Int),
                "reason" => ("$T_reply_reason", Ty::Str),
                other => {
                    self.err(fx.src, name.span, format!("txn has code and reason, not {other}{}", suggest(other, ["code", "reason"])));
                    return V::err();
                }
            };
            if fx.ctx & !(ctx::FAILURE | ctx::REPLY | ctx::BRANCH) != 0 {
                self.err(fx.src, e.span, format!("txn.{} is only known in a failure, reply or branch handler", name.text));
            }
            return V { e: S::Expr::Pv(pv.into(), line), ty };
        }
        if let ExprKind::Field(base, name) = &e.kind
            && let ExprKind::Ident(b) = &base.kind
            && self.config_names.contains(b)
            && !fx.locals.contains_key(b)
        {
            return match self.env.features.get(&name.text) {
                Some(Feature::Bool(v)) => V { e: truth(*v), ty: Ty::Bool },
                Some(Feature::Int(i)) => V { e: S::Expr::Int(*i), ty: Ty::Int },
                Some(Feature::Str(s)) => V { e: s_str(s), ty: Ty::Str },
                None => {
                    let known: Vec<&str> = self.env.features.keys().map(String::as_str).collect();
                    self.err(fx.src, name.span, format!("no [feature] {:?} in ferrosip.toml{}", name.text, suggest(&name.text, known)));
                    V::err()
                }
            };
        }
        if let ExprKind::Index(base, idx) = &e.kind {
            if is_field(base, &fx.msg_name, "headers") {
                let n = self.header_name(fx, idx);
                return V { e: S::Expr::Pv(format!("$hdr({n})"), line), ty: Ty::Str };
            }
            self.err(fx.src, e.span, "only msg.headers[\"Name\"] can be indexed");
            return V::err();
        }
        // `dialog.<var>` in routes: the current dialog's variable.
        if let ExprKind::Field(base, name) = &e.kind
            && matches!(&base.kind, ExprKind::Ident(b) if b == "dialog" && !fx.locals.contains_key(b))
        {
            return self.dlg_var(fx, name, line);
        }
        if let ExprKind::Field(base, _) = &e.kind
            && let ExprKind::Ident(b) = &base.kind
            && self.tables.contains_key(b)
            && !fx.locals.contains_key(b)
        {
            self.err(fx.src, e.span, format!("{b} is a shared table: use {b}.get(key), .set(key, value), .contains(key)…"));
            return V::err();
        }
        let Some(path) = field_path(e, &fx.msg_name) else {
            self.err(fx.src, e.span, format!("{} is not a msg field", crate::fmt::expr(e)));
            return V::err();
        };
        if matches!(fx.msg_ty, Ty::Dialog | Ty::Http | Ty::Dest | Ty::Source | Ty::DiamReq | Ty::DiamAns) {
            return self.event_field(fx, &path, e.span, line);
        }
        match path.as_str() {
            "has_to_tag" => return V { e: call("has_totag", vec![], line), ty: Ty::Bool },
            "has_sdp" => return V { e: call("has_body", vec![S::RawArg::Str("application/sdp".into())], line), ty: Ty::Bool },
            "max_forwards" => return V { e: S::Expr::Pv("$hdr(Max-Forwards)".into(), line), ty: Ty::Int },
            _ => {}
        }
        let _ = out;
        match msg::field(&path) {
            Some(f) => {
                let ok = if fx.msg_ty == Ty::Reply { f.reply } else { f.request };
                if !ok {
                    self.err(fx.src, e.span, format!("a {} has no {path}", fx.msg_ty.name()));
                }
                V { e: S::Expr::Pv(f.pv.into(), line), ty: field_ty(f.ty) }
            }
            None => {
                let mut known: Vec<&str> = msg::FIELDS.iter().map(|f| f.path).collect();
                known.extend(["has_to_tag", "has_sdp", "max_forwards", "headers"]);
                self.err(fx.src, e.span, format!("msg has no field {path:?}{}", suggest(&path, known)));
                V::err()
            }
        }
    }

    /// A declared dialog variable (`$dlg_var(x)`; stored as text).
    fn dlg_var(&mut self, fx: &mut Fx, name: &ast::Name, line: usize) -> V {
        match self.dlg_vars.get(&name.text).cloned() {
            Some(t) => {
                let pv = S::Expr::Pv(format!("$dlg_var({})", name.text), line);
                match t {
                    Ty::Bool => V { e: bin(S::BinOp::Gt, pv, S::Expr::Int(0)), ty: Ty::Bool },
                    t => V { e: pv, ty: t },
                }
            }
            None => {
                let known: Vec<&str> = self.dlg_vars.keys().map(String::as_str).collect();
                self.err(fx.src, name.span, format!("no `dialog var {}`{}", name.text, suggest(&name.text, known)));
                V::err()
            }
        }
    }

    /// `d.call_id`, `req.path`, `e.uri`…, and declared dialog variables.
    fn event_field(&mut self, fx: &mut Fx, path: &str, span: Span, line: usize) -> V {
        let tn = fx.msg_ty.name();
        if let Some((_, _, pv, t)) = EVENT_FIELDS.iter().find(|(ty, f, ..)| *ty == tn && *f == path) {
            if path == "code" && fx.event != "dialog.failed" {
                self.err(fx.src, span, "d.code is the failure's reply code: only in `on dialog.failed`");
            }
            return V { e: S::Expr::Pv(pv.to_string(), line), ty: field_ty(*t) };
        }
        if fx.msg_ty == Ty::Dialog && self.dlg_vars.contains_key(path) {
            return self.dlg_var(fx, &ast::Name { text: path.to_string(), span }, line);
        }
        let mut known: Vec<&str> = EVENT_FIELDS.iter().filter(|(ty, ..)| *ty == tn).map(|(_, f, ..)| *f).collect();
        known.extend(self.dlg_vars.keys().map(String::as_str).filter(|_| fx.msg_ty == Ty::Dialog));
        self.err(fx.src, span, format!("a {tn} has no {path:?}{}", suggest(path, known)));
        V::err()
    }

    /// The key of `t.get(key)`…, as text for `$sht(t=>key)`.
    fn table_key(&mut self, fx: &mut Fx, e: &Expr, line: usize, out: &mut Vec<S::Stmt>) -> String {
        let v = self.expr(fx, e, out);
        if !matches!(v.ty, Ty::Str | Ty::Int | Ty::Error) {
            self.err(fx.src, e.span, format!("a table key is Str or Int, found {}", v.ty.name()));
        }
        match self.raw(fx, v, line, out) {
            S::RawArg::Int(n) => n.to_string(),
            S::RawArg::Str(s) => {
                if s.contains(')') || s.contains("=>") {
                    self.err(fx.src, e.span, "a literal table key can't contain `)` or `=>`");
                }
                s
            }
            S::RawArg::Pv(p) => p,
        }
    }

    /// `bans.get(k)`, `.contains(k)`, `.set(k, v[, ttl: d])`, `.remove(k)`,
    /// `.incr(k)`, `.decr(k)`, `.clear()`.
    fn table_method(&mut self, fx: &mut Fx, table: &str, m: &ast::Name, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        // Callers looked the table up.
        let Some(&val) = self.tables.get(table) else { return V::err() };
        let (pos, named): (Vec<&ast::CallArg>, Vec<&ast::CallArg>) = args.iter().partition(|a| a.name.is_none());
        let want = match m.text.as_str() {
            "clear" | "count" => 0,
            "get" | "contains" | "remove" | "incr" | "decr" => 1,
            "set" => 2,
            other => {
                self.err(
                    fx.src,
                    m.span,
                    format!(
                        "a shared table has get, contains, set, remove, incr, decr, clear, count; not {other}{}",
                        suggest(other, ["get", "contains", "set", "remove", "incr", "decr", "clear", "count"])
                    ),
                );
                return V::err();
            }
        };
        if pos.len() != want || named.iter().any(|a| m.text != "set" || a.name.as_ref().is_some_and(|n| n.text != "ttl")) {
            let usage = match m.text.as_str() {
                "clear" | "count" => format!("{table}.{}()", m.text),
                "set" => format!("{table}.set(key, value[, ttl: 30s])"),
                x => format!("{table}.{x}(key)"),
            };
            self.err(fx.src, span, usage);
            return V::err();
        }
        if m.text == "clear" {
            return V { e: call("sht_reset", vec![S::RawArg::Str(table.into())], line), ty: Ty::Void };
        }
        if m.text == "count" {
            // Unexpired keys (every key matches the regex `.`).
            return V { e: S::Expr::Pv(format!("$shtcn({table}=>~~.)"), line), ty: Ty::Int };
        }
        // `pos` holds `want` arguments (checked above): one key, then for
        // `set` the value.
        let (Some(k), value) = (pos.first(), pos.get(1)) else { return V::err() };
        let key = self.table_key(fx, &k.value, line, out);
        let slot = |kind: &str| format!("${kind}({table}=>{key})");
        match m.text.as_str() {
            "get" => {
                let pv = S::Expr::Pv(slot("sht"), line);
                match val {
                    TableVal::Bool => V { e: bin(S::BinOp::Gt, pv, S::Expr::Int(0)), ty: Ty::Bool },
                    // A missing key reads 0 (docs/fsr.md), not $null.
                    TableVal::Int | TableVal::Counter => V { e: S::Expr::Pv(format!("$(sht({table}=>{key}){{s.int}})"), line), ty: Ty::Int },
                    v => V { e: pv, ty: v.ty() },
                }
            }
            "contains" => V { e: bin(S::BinOp::Ne, S::Expr::Pv(slot("sht"), line), S::Expr::Pv("$null".into(), line)), ty: Ty::Bool },
            "remove" => {
                out.push(S::Stmt::Assign(slot("sht"), S::Expr::Pv("$null".into(), line), line));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            "incr" | "decr" => {
                if !matches!(val, TableVal::Int | TableVal::Counter) {
                    self.err(fx.src, m.span, format!("{table} holds {:?} values: only Int and Counter count", val));
                }
                V { e: S::Expr::Pv(slot(if m.text == "incr" { "shtinc" } else { "shtdec" }), line), ty: Ty::Int }
            }
            _ => {
                let Some(value) = value else { return V::err() };
                let v = self.expr(fx, &value.value, out);
                if v.ty != val.ty() && v.ty != Ty::Error {
                    self.err(fx.src, value.value.span, format!("{table} holds {} values, found {}", val.ty().name(), v.ty.name()));
                }
                match named.first() {
                    None => {
                        let t = slot("sht");
                        self.store(&t, v, line, out);
                    }
                    Some(a) => {
                        let ExprKind::Duration(ms, _) = a.value.kind else {
                            self.err(fx.src, a.value.span, "ttl: a duration (30s)");
                            return V::err();
                        };
                        let f = if val == TableVal::Str { "sht_setxs" } else { "sht_setxi" };
                        let raw = self.raw(fx, v, line, out);
                        let k = if key.starts_with('$') { S::RawArg::Pv(key.clone()) } else { S::RawArg::Str(key.clone()) };
                        out.push(S::Stmt::Expr(call(f, vec![S::RawArg::Str(table.into()), k, raw, S::RawArg::Int(clamp_i64(ms / 1000).max(1))], line)));
                    }
                }
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
        }
    }

    // ------------------------------------------------------------- calls

    fn call(&mut self, fx: &mut Fx, callee: &Expr, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        match &callee.kind {
            ExprKind::Ident(name) => self.call_plain(fx, name, callee.span, args, span, line, out),
            ExprKind::Field(base, method) => {
                // A shared table's methods.
                if let ExprKind::Ident(b) = &base.kind
                    && self.tables.contains_key(b)
                    && !fx.locals.contains_key(b)
                {
                    let b = b.clone();
                    return self.table_method(fx, &b, method, args, span, line, out);
                }
                // req.reply(…), d.end(): the event parameter's methods.
                if let ExprKind::Ident(b) = &base.kind
                    && *b == fx.msg_name
                    && matches!(fx.msg_ty, Ty::Dialog | Ty::Http | Ty::Dest | Ty::Source | Ty::DiamReq | Ty::DiamAns)
                {
                    return self.event_method(fx, &method.text, method.span, args, span, line, out);
                }
                // msg.set(F) / msg.is(F) / msg.reset(F), msg.is_sane(), msg.headers.remove/has("X").
                if let ExprKind::Ident(b) = &base.kind
                    && *b == fx.msg_name
                {
                    return self.msg_method(fx, &method.text, method.span, args, line, out);
                }
                if is_field(base, &fx.msg_name, "headers") {
                    if !matches!(method.text.as_str(), "remove" | "has") {
                        self.err(fx.src, method.span, format!("msg.headers has remove() and has(), not {}()", method.text));
                        return V::err();
                    }
                    let [a] = args else {
                        self.err(fx.src, span, format!("msg.headers.{}(\"Name\")", method.text));
                        return V::err();
                    };
                    let n = self.header_name(fx, &a.value);
                    return match method.text.as_str() {
                        "remove" => {
                            out.push(S::Stmt::Expr(call("remove_hf", vec![S::RawArg::Str(n)], line)));
                            V { e: S::Expr::Int(0), ty: Ty::Void }
                        }
                        _ => V { e: call("is_present_hf", vec![S::RawArg::Str(n)], line), ty: Ty::Bool },
                    };
                }
                let ExprKind::Ident(ns) = &base.kind else {
                    self.err(fx.src, callee.span, "call a function as name(…) or module.name(…)");
                    return V::err();
                };
                if ns == "kamailio" && !fx.locals.contains_key(ns) && !self.env.namespaces.contains_key(ns) {
                    return self.kamailio_call(fx, method, args, span, line, out);
                }
                // A function of an imported .fsr file?
                let user = key(ns, &method.text);
                if self.fns.contains_key(&user) {
                    return self.call_user(fx, &user, method.span, args, span, line, out);
                }
                self.call_sig(fx, ns, base.span, &method.text, method.span, args, span, line, out)
            }
            _ => {
                self.err(fx.src, callee.span, "call a function as name(…) or module.name(…)");
                V::err()
            }
        }
    }

    /// `pv("$avp(x)")`: the pseudo-variable named by a literal.
    fn pv_name(&mut self, fx: &mut Fx, args: &[ast::CallArg], span: Span) -> Option<String> {
        let lit = match args {
            [a] if a.name.is_none() => match &a.value.kind {
                ExprKind::Str(p) => match p.as_slice() {
                    [StrPart::Lit(s)] => Some(s.clone()),
                    [] => Some(String::new()),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        match lit {
            Some(p) if p.len() > 1 && sip_core::pv::pv_len(p.as_bytes()) == p.len() => Some(p),
            Some(p) => {
                self.err(fx.src, span, format!("pv({p:?}): not one pseudo-variable ($avp(x), $var(y), $hdr(Z)…)"));
                None
            }
            None => {
                self.err(fx.src, span, "pv(\"$name\") takes one literal string");
                None
            }
        }
    }

    /// `kamailio.call("fn", args…)`: any module function, by its Kamailio
    /// name, unchecked. Strings are templates (`"{pv("$rU")}@x"`), as in
    /// a .cfg; the result tests like a .cfg call's.
    fn kamailio_call(&mut self, fx: &mut Fx, method: &ast::Name, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        // Kamailio's bitwise | and & (no .fsr operator).
        if let Some(op) = match method.text.as_str() {
            "bitor" => Some(S::BinOp::BitOr),
            "bitand" => Some(S::BinOp::BitAnd),
            _ => None,
        } {
            let [a, b] = args else {
                self.err(fx.src, span, format!("kamailio.{}(a, b)", method.text));
                return V::err();
            };
            let (x, y) = (self.expr(fx, &a.value, out), self.expr(fx, &b.value, out));
            for (v, e) in [(&x, a), (&y, b)] {
                if !matches!(v.ty, Ty::Int | Ty::Any | Ty::Error) {
                    self.err(fx.src, e.value.span, format!("kamailio.{} works on numbers, found {}", method.text, v.ty.name()));
                }
            }
            return V { e: bin(op, x.e, y.e), ty: Ty::Any };
        }
        if method.text != "call" {
            self.err(
                fx.src,
                method.span,
                format!("kamailio has call(\"fn\", args…), bitor(a, b), bitand(a, b), myself, and the kamailio.*_route handlers, not {}", method.text),
            );
            return V::err();
        }
        let name = match args.first().map(|a| &a.value.kind) {
            Some(ExprKind::Str(p)) => match p.as_slice() {
                [StrPart::Lit(s)] if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') => s.clone(),
                _ => String::new(),
            },
            _ => String::new(),
        };
        if name.is_empty() {
            self.err(fx.src, span, "kamailio.call(\"function_name\", args…): the name is a literal");
            return V::err();
        }
        let mut raw = Vec::new();
        for a in args.get(1..).unwrap_or_default() {
            if let Some(n) = &a.name {
                self.err(fx.src, n.span, "kamailio.call takes positional arguments");
            }
            let v = self.expr(fx, &a.value, out);
            if matches!(v.ty, Ty::Request | Ty::Reply | Ty::Action | Ty::Void | Ty::Result) {
                self.err(fx.src, a.value.span, format!("{} is not a function argument", v.ty.name()));
            }
            raw.push(self.raw(fx, v, line, out));
        }
        V { e: call(&name, raw, line), ty: Ty::Any }
    }

    fn call_plain(&mut self, fx: &mut Fx, name: &str, name_span: Span, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        match name {
            "pv" if !self.fns.contains_key(name) => match self.pv_name(fx, args, span) {
                Some(p) => V { e: S::Expr::Pv(p, line), ty: Ty::Any },
                None => V::err(),
            },
            "reply" => {
                let (mut code, mut reason) = (None, None);
                for (i, a) in args.iter().enumerate() {
                    match (a.name.as_ref().map(|n| n.text.as_str()), i) {
                        (Some("code") | None, 0) => code = Some(&a.value),
                        (Some("reason") | None, 1) => reason = Some(&a.value),
                        _ => self.err(fx.src, a.value.span, "reply(code[, reason])"),
                    }
                }
                let Some(code) = code else {
                    self.err(fx.src, span, "reply(code[, reason])");
                    return V::err();
                };
                if fx.ctx & ctx::REPLY != 0 {
                    self.err(fx.src, span, "reply() answers a request; not in `on reply`");
                } else if fx.ctx & ctx::EVENT != 0 {
                    let hint = if fx.msg_ty == Ty::Http { format!(" (answer the HTTP request with {}.reply(…))", fx.msg_name) } else { String::new() };
                    self.err(fx.src, span, format!("reply() answers a request; there is none in an event handler{hint}"));
                }
                let c = self.expr(fx, code, out);
                if !matches!(c.ty, Ty::Int | Ty::Error) {
                    self.err(fx.src, code.span, format!("a reply code is an Int, found {}", c.ty.name()));
                }
                let reason_raw = match reason {
                    Some(r) => {
                        let v = self.expr(fx, r, out);
                        if !matches!(v.ty, Ty::Str | Ty::Error) {
                            self.err(fx.src, r.span, "a reason phrase is text");
                        }
                        self.raw(fx, v, line, out)
                    }
                    None => match &c.e {
                        S::Expr::Int(n) => S::RawArg::Str(msg::reason(*n).into()),
                        _ => S::RawArg::Str("Reply".into()),
                    },
                };
                let code_raw = self.raw(fx, c, line, out);
                // After `await` the request belongs to a transaction:
                // answer it statefully (t_reply also works statelessly
                // where there is none, for functions called from both).
                let f = if fx.ctx & ctx::FAILURE != 0 { "t_reply" } else { "send_reply" };
                out.push(S::Stmt::Expr(call(f, vec![code_raw, reason_raw], line)));
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
            "relay" => self.call_sig(fx, "txn", name_span, "relay", name_span, args, span, line, out),
            _ if fx.event == "test"
                && let Some(v) = self.test_builtin(fx, name, args, span, line, out) =>
            {
                v
            }
            "now" => {
                if !args.is_empty() {
                    self.err(fx.src, span, "now() takes no argument");
                }
                V { e: S::Expr::Pv("$Ts".into(), line), ty: Ty::Int }
            }
            "forward" => {
                let ok = matches!(args, [a] if matches!(&a.value.kind, ExprKind::Ident(n) if fx.locals.get(n).is_some_and(|l| l.ty == Ty::Final)));
                if !fx.after_await || !ok {
                    self.err(fx.src, span, "forward(r) sends on the final reply `r` of `Final(r)`, after `await`");
                }
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
            _ => {
                let k = key(&fx_ns(fx), name);
                let k = if self.fns.contains_key(&k) { k } else { name.to_string() };
                if self.fns.contains_key(&k) {
                    return self.call_user(fx, &k, name_span, args, span, line, out);
                }
                let mut known: Vec<&str> = self.fns.keys().filter(|k| !k.contains("::")).map(String::as_str).collect();
                known.extend(["reply", "relay", "forward"]);
                self.err(fx.src, name_span, format!("unknown function {name}(){}", suggest(name, known)));
                V::err()
            }
        }
    }

    fn call_user(&mut self, fx: &mut Fx, k: &str, name_span: Span, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        // Callers looked `k` up.
        let Some(f) = self.fns.get(k) else { return V::err() };
        let (route, params, ret, is_main, has_msg) = (f.route.clone(), f.params.clone(), f.ret.clone(), f.is_main, f.has_msg);
        if is_main {
            self.err(fx.src, name_span, "main is where requests start; it can't be called");
            return V::err();
        }
        if args.len() != params.len() {
            self.err(fx.src, span, format!("{} takes {} argument(s), got {}", k, params.len(), args.len()));
            return V::err();
        }
        for (i, (a, (pname, pty))) in args.iter().zip(&params).enumerate() {
            if i == 0 && has_msg {
                let v = self.expr(fx, &a.value, out);
                if v.ty != Ty::Request && v.ty != Ty::Error {
                    self.err(fx.src, a.value.span, "pass the message first: name(msg, …)");
                }
                continue;
            }
            let v = self.expr(fx, &a.value, out);
            if v.ty != *pty && v.ty != Ty::Error {
                self.err(fx.src, a.value.span, format!("{pname} is {}, found {}", pty.name(), v.ty.name()));
            }
            let slot = format!("$avp(p__{route}__{pname})");
            self.store(&slot, v, line, out);
        }
        let r = S::Expr::Route(route, line);
        match ret {
            Ty::Action => {
                out.push(S::Stmt::Expr(r));
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
            Ty::Bool => V { e: r, ty: Ty::Bool },
            Ty::Error => V::err(),
            _ => {
                out.push(S::Stmt::Expr(r));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
        }
    }

    fn msg_method(&mut self, fx: &mut Fx, m: &str, mspan: Span, args: &[ast::CallArg], line: usize, out: &mut Vec<S::Stmt>) -> V {
        match m {
            "set" | "is" | "reset" => {
                // `msg.set(F)`; a branch flag may name the branch: `msg.set(FLB_NATB, branch: 0)`.
                let (a, branch) = match args {
                    [a] if a.name.is_none() => (a, None),
                    [a, b] if a.name.is_none() && b.name.as_ref().is_some_and(|n| n.text == "branch") => (a, Some(b)),
                    _ => {
                        self.err(fx.src, mspan, format!("msg.{m}(FLAG), or msg.{m}(BRANCH_FLAG[, branch: n])"));
                        return V::err();
                    }
                };
                let v = self.expr(fx, &a.value, out);
                if !matches!(v.ty, Ty::Flag | Ty::BranchFlag) {
                    if v.ty != Ty::Error {
                        self.err(fx.src, a.value.span, format!("expected a flag (declare it: `flag NAME` or `branch flag NAME`), found {}", v.ty.name()));
                    }
                    return V::err();
                }
                let S::Expr::Int(n) = v.e else { return V::err() };
                let mut raw = vec![S::RawArg::Int(n)];
                if let Some(b) = branch {
                    match (&b.value.kind, v.ty == Ty::BranchFlag) {
                        (ExprKind::Int(i), true) if *i >= 0 => raw.push(S::RawArg::Int(*i)),
                        (_, true) => {
                            self.err(fx.src, b.value.span, "the branch is a number (0: the R-URI branch)");
                            return V::err();
                        }
                        (_, false) => {
                            self.err(fx.src, b.value.span, "`branch:` is for a branch flag (`branch flag NAME`)");
                            return V::err();
                        }
                    }
                }
                let f = match (m, v.ty == Ty::BranchFlag) {
                    ("set", false) => "setflag",
                    ("reset", false) => "resetflag",
                    (_, false) => "isflagset",
                    ("set", true) => "setbflag",
                    ("reset", true) => "resetbflag",
                    (_, true) => "isbflagset",
                };
                let e = call(f, raw, line);
                if m == "is" { V { e, ty: Ty::Bool } } else { V { e, ty: Ty::Void } }
            }
            "is_sane" => V { e: call("sanity_check", vec![], line), ty: Ty::Bool },
            _ => {
                self.err(fx.src, mspan, format!("msg has no method {m}(){}", suggest(m, ["set", "is", "reset", "is_sane"])));
                V::err()
            }
        }
    }

    /// `req.reply(code[, body][, content_type])`, `d.end()`.
    fn event_method(&mut self, fx: &mut Fx, m: &str, mspan: Span, args: &[ast::CallArg], span: Span, line: usize, out: &mut Vec<S::Stmt>) -> V {
        match (&fx.msg_ty, m) {
            (Ty::Http, "reply") => {
                let Some(code) = args.first().filter(|_| args.len() <= 3 && args.iter().all(|a| a.name.is_none())) else {
                    self.err(fx.src, span, format!("{}.reply(code[, body][, content_type])", fx.msg_name));
                    return V::err();
                };
                let c = self.expr(fx, &code.value, out);
                if !matches!(c.ty, Ty::Int | Ty::Error) {
                    self.err(fx.src, code.value.span, format!("an HTTP status is an Int, found {}", c.ty.name()));
                }
                let reason = match &c.e {
                    S::Expr::Int(n) => http_reason(*n),
                    _ => "Reply",
                };
                let mut text = |i: usize, default: &str, this: &mut Self, out: &mut Vec<S::Stmt>| match args.get(i) {
                    None => S::RawArg::Str(default.into()),
                    Some(a) => {
                        let v = this.expr(fx, &a.value, out);
                        if !matches!(v.ty, Ty::Str | Ty::Int | Ty::Error) {
                            this.err(fx.src, a.value.span, format!("expected text, found {}", v.ty.name()));
                        }
                        this.raw(fx, v, line, out)
                    }
                };
                let body = text(1, "", self, out);
                let ctype = text(2, "text/plain", self, out);
                let code = self.raw(fx, c, line, out);
                out.push(S::Stmt::Expr(call("xhttp_reply", vec![code, S::RawArg::Str(reason.into()), ctype, body], line)));
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
            (Ty::Dialog, "end") => {
                if !args.is_empty() {
                    self.err(fx.src, span, format!("{}.end() takes no argument", fx.msg_name));
                }
                if matches!(fx.event, "dialog.ended" | "dialog.failed") {
                    self.err(fx.src, mspan, format!("the dialog already ended: no {}.end() in `on {}`", fx.msg_name, fx.event));
                }
                V { e: call("dlg_bye", vec![S::RawArg::Str("all".into())], line), ty: Ty::Bool }
            }
            // req.answer(avps): the answer's AVPs (Kamailio's JSON), sent
            // when the handlers have run ($diameter_response).
            (Ty::DiamReq, "answer") => {
                let [a] = args else {
                    self.err(fx.src, span, format!("{}.answer(avps): the answer's AVPs as JSON", fx.msg_name));
                    return V::err();
                };
                if a.name.is_some() {
                    self.err(fx.src, a.value.span, format!("{}.answer(avps)", fx.msg_name));
                }
                let v = self.expr(fx, &a.value, out);
                if !matches!(v.ty, Ty::Str | Ty::Any | Ty::Error) {
                    self.err(fx.src, a.value.span, format!("the answer's AVPs are JSON text (Str), found {}", v.ty.name()));
                }
                out.push(S::Stmt::Assign("$diameter_response".into(), v.e, line));
                V { e: S::Expr::Int(0), ty: Ty::Void }
            }
            (t, _) => {
                let have = match t {
                    Ty::Http => "reply()",
                    Ty::Dialog => "end()",
                    Ty::DiamReq => "answer()",
                    _ => "no methods",
                };
                self.err(fx.src, mspan, format!("a {} has {have}, not {m}()", t.name()));
                V::err()
            }
        }
    }

    /// `ns.name(args…)` against a signature.
    #[allow(clippy::too_many_arguments, reason = "the call site, its signature and the lowering context")]
    /// `sql.quote(v)`: `v` as an SQL string literal (Kamailio's
    /// `{sql.val.str}`), to put a message value into a query safely.
    fn sql_quote(&mut self, fx: &mut Fx, args: &[ast::CallArg], span: Span, out: &mut Vec<S::Stmt>) -> V {
        let [a] = args else {
            self.err(fx.src, span, "sql.quote(value)");
            return V::err();
        };
        let v = self.expr(fx, &a.value, out);
        let e = match v.e {
            S::Expr::Pv(p, l) => {
                // $rU → $(rU{sql.val.str}); $(x{t}) → $(x{t}{sql.val.str}).
                let inner = match p.strip_prefix("$(").and_then(|x| x.strip_suffix(')')) {
                    Some(x) => x.to_string(),
                    None => p.trim_start_matches('$').to_string(),
                };
                S::Expr::Pv(format!("$({inner}{{sql.val.str}})"), l)
            }
            S::Expr::Str(t) if !t.contains('$') => S::Expr::Str(sip_core::pv::sql_quote(&t)),
            S::Expr::Int(i) => S::Expr::Int(i),
            _ => {
                self.err(fx.src, a.value.span, "sql.quote takes one value: a field, a variable or a literal (quote each part of a longer text)");
                return V::err();
            }
        };
        V { e, ty: Ty::Str }
    }

    fn call_sig(
        &mut self,
        fx: &mut Fx,
        ns: &str,
        ns_span: Span,
        name: &str,
        name_span: Span,
        args: &[ast::CallArg],
        span: Span,
        line: usize,
        out: &mut Vec<S::Stmt>,
    ) -> V {
        if ns == "sql" && name == "quote" {
            return self.sql_quote(fx, args, span, out);
        }
        let Some(fns) = self.env.namespaces.get(ns) else {
            let known: Vec<&str> = self.env.namespaces.keys().map(String::as_str).collect();
            self.err(fx.src, ns_span, format!("unknown module {ns:?}{}", suggest(ns, known)));
            return V::err();
        };
        if let Some(m) = self.env.modules.get(&(ns.to_string(), name.to_string())) {
            let m = m.clone();
            self.need_module(&m);
        }
        let Some(sig) = fns.get(name).copied() else {
            let known: Vec<&str> = fns.keys().map(String::as_str).collect();
            self.err(fx.src, name_span, format!("{ns} has no function {name}(){}", suggest(name, known)));
            return V::err();
        };
        if !self.imported.contains(ns) && ns != "log" && ns != "txn" {
            self.err(fx.src, ns_span, format!("add `import {ns}` at the top"));
        }
        let bad = fx.ctx & !sig.allowed;
        if bad != 0 {
            let where_ = if bad & ctx::REPLY != 0 {
                "in `on reply`"
            } else if bad & ctx::EVENT != 0 {
                "in an event handler (there is no request to act on)"
            } else if bad & ctx::FAILURE != 0 {
                "after an `await`"
            } else {
                "here"
            };
            self.err(fx.src, name_span, format!("{ns}.{name}() can't be used {where_}"));
        }
        // The message itself may come first; it isn't passed.
        let mut rest: &[ast::CallArg] = args;
        if let Some((first, after)) = args.split_first()
            && first.name.is_none()
            && let ExprKind::Ident(n) = &first.value.kind
            && *n == fx.msg_name
        {
            rest = after;
        }
        let mut raws: Vec<S::RawArg> = sig.fixed.iter().map(|f| S::RawArg::Str(f.to_string())).collect();
        let mut given: Vec<Option<&ast::CallArg>> = vec![None; sig.params.len()];
        let mut pos: usize = 0;
        for a in rest {
            let idx = match &a.name {
                Some(n) => match sig.params.iter().position(|p| p.name == n.text) {
                    Some(i) => i,
                    None => {
                        self.err(fx.src, n.span, format!("{ns}.{name}() has no argument {:?}{}", n.text, suggest(&n.text, sig.params.iter().map(|p| p.name))));
                        continue;
                    }
                },
                None => {
                    let i = pos;
                    pos = pos.saturating_add(1);
                    i
                }
            };
            let Some(slot) = given.get_mut(idx) else {
                self.err(fx.src, a.value.span, format!("{ns}.{name}() takes {} argument(s)", sig.params.len()));
                continue;
            };
            *slot = Some(a);
        }
        // Omitted arguments: defaults; an optional one with no default
        // ends the list (later ones can't be passed positionally).
        let mut stop = false;
        for (p, given) in sig.params.iter().zip(given) {
            match given {
                Some(a) if stop => {
                    self.err(fx.src, a.value.span, format!("{ns}.{name}(): give the arguments before {} too", p.name));
                }
                Some(a) => {
                    let r = self.sig_arg(fx, p.ty, &a.value, line, out);
                    let dynamic = match &r {
                        S::RawArg::Pv(_) => true,
                        S::RawArg::Str(s) => s.replace("$$", "").contains('$'),
                        S::RawArg::Int(_) => false,
                    };
                    if p.literal && dynamic && p.ty != ArgTy::Var {
                        self.err(fx.src, a.value.span, format!("{ns}.{name}(): {} must be written as a constant (it is read once, at startup)", p.name));
                    }
                    raws.push(r);
                }
                None if !stop && let Some(d) = p.default => raws.push(match d.parse::<i64>() {
                    Ok(n) => S::RawArg::Int(n),
                    Err(_) => S::RawArg::Str(d.to_string()),
                }),
                None if p.optional => stop = true,
                None => self.err(fx.src, span, format!("{ns}.{name}() needs {}", p.name)),
            }
        }
        let e = call(sig.name, raws, line);
        match sig.ret {
            Ret::Await(aw) => {
                if !self.awaiting {
                    self.err(fx.src, name_span, format!("{ns}.{name}() waits for its result: `let r = await {ns}.{name}(…)`"));
                }
                V { e, ty: Ty::Record(aw) }
            }
            Ret::Bool => V { e, ty: Ty::Bool },
            Ret::Void => V { e, ty: Ty::Void },
            // A failed action answers with its error, except after `await`
            // (then the transaction's best reply goes upstream).
            Ret::Action if fx.ctx & ctx::FAILURE != 0 => {
                out.push(S::Stmt::Expr(e));
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
            Ret::Action => {
                out.push(S::Stmt::If(not(e), vec![S::Stmt::Expr(call("sl_reply_error", vec![], line))], vec![]));
                out.push(S::Stmt::Exit);
                V { e: S::Expr::Int(0), ty: Ty::Action }
            }
        }
    }

    fn sig_arg(&mut self, fx: &mut Fx, ty: ArgTy, e: &Expr, line: usize, out: &mut Vec<S::Stmt>) -> S::RawArg {
        if ty == ArgTy::Var {
            let ExprKind::Ident(n) = &e.kind else {
                self.err(fx.src, e.span, "expected a variable name (it gets the result)");
                return S::RawArg::Int(0);
            };
            let avp = match fx.locals.get(n) {
                Some(l) => l.avp.clone(),
                None => {
                    let avp = self.local_avp(fx, n);
                    fx.locals.insert(n.clone(), Local { avp: avp.clone(), ty: Ty::Str });
                    avp
                }
            };
            return S::RawArg::Str(avp);
        }
        if ty == ArgTy::Flag {
            let v = self.expr(fx, e, out);
            if v.ty != Ty::Flag && v.ty != Ty::Error {
                self.err(fx.src, e.span, format!("expected a flag, found {}", v.ty.name()));
            }
            return match v.e {
                S::Expr::Int(n) => S::RawArg::Int(n),
                _ => S::RawArg::Int(0),
            };
        }
        let v = self.expr(fx, e, out);
        let ok = v.ty == Ty::Any
            || match ty {
                ArgTy::Str | ArgTy::Uri => matches!(v.ty, Ty::Str | Ty::Error | Ty::Method),
                ArgTy::Int => matches!(v.ty, Ty::Int | Ty::Error),
                ArgTy::Bool => matches!(v.ty, Ty::Bool | Ty::Error),
                ArgTy::Duration(_) => matches!(v.ty, Ty::Duration | Ty::Error),
                ArgTy::Any => matches!(v.ty, Ty::Str | Ty::Int | Ty::Error),
                ArgTy::Enum(vals) => match &e.kind {
                    ExprKind::Str(p) if matches!(p.as_slice(), [StrPart::Lit(s)] if vals.contains(&s.as_str())) => true,
                    _ => {
                        self.err(fx.src, e.span, format!("expected one of {}", vals.iter().map(|v| format!("\"{v}\"")).collect::<Vec<_>>().join(", ")));
                        return S::RawArg::Int(0);
                    }
                },
                ArgTy::Var | ArgTy::Flag => true,
            };
        if !ok {
            let want = match ty {
                ArgTy::Str => "Str",
                ArgTy::Uri => "a URI (Str)",
                ArgTy::Int => "Int",
                ArgTy::Bool => "Bool",
                ArgTy::Duration(_) => "a Duration (30s, 500ms)",
                ArgTy::Any => "Str or Int",
                _ => "?",
            };
            self.err(fx.src, e.span, format!("expected {want}, found {}", v.ty.name()));
            return S::RawArg::Int(0);
        }
        let v = match (ty, &v.e) {
            (ArgTy::Duration(Unit::Sec), S::Expr::Int(ms)) => V { e: S::Expr::Int(ms / 1000), ty: Ty::Int },
            (ArgTy::Duration(Unit::Sec), _) => V { e: bin(S::BinOp::Div, v.e, S::Expr::Int(1000)), ty: Ty::Int },
            (ArgTy::Bool, e) if const_bool(e).is_some() => V { e: S::Expr::Int(i64::from(const_bool(e) == Some(true))), ty: Ty::Int },
            (ArgTy::Bool, _) => {
                let t = self.temp();
                self.store(&t, v, line, out);
                V { e: S::Expr::Pv(t, line), ty: Ty::Int }
            }
            _ => v,
        };
        self.raw(fx, v, line, out)
    }

    /// A value as a function argument (a temporary when it's computed).
    fn raw(&mut self, _fx: &mut Fx, v: V, line: usize, out: &mut Vec<S::Stmt>) -> S::RawArg {
        match v.e {
            S::Expr::Int(n) => S::RawArg::Int(n),
            S::Expr::Str(s) => S::RawArg::Str(s),
            S::Expr::Pv(p, _) => S::RawArg::Pv(p),
            e => {
                let t = self.temp();
                self.store(&t, V { e, ty: v.ty }, line, out);
                S::RawArg::Pv(t)
            }
        }
    }
}

/// Reason phrases for `req.reply(code)`.
fn http_reason(code: i64) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Reply",
    }
}

fn fx_ns(fx: &Fx) -> String {
    fx.key.rsplit_once("::").map_or(String::new(), |(ns, _)| ns.to_string())
}

fn field_ty(t: FieldTy) -> Ty {
    match t {
        FieldTy::Str => Ty::Str,
        FieldTy::Int => Ty::Int,
        FieldTy::Method => Ty::Method,
        FieldTy::Transport => Ty::Transport,
    }
}

fn comparable(a: &Ty, b: &Ty) -> bool {
    matches!(
        (a, b),
        (Ty::Error, _)
            | (_, Ty::Error)
            | (Ty::Any, Ty::Any | Ty::Int | Ty::Str | Ty::Bool | Ty::Method | Ty::Transport)
            | (Ty::Int | Ty::Str | Ty::Bool | Ty::Method | Ty::Transport, Ty::Any)
            | (Ty::Int, Ty::Int)
            | (Ty::Str, Ty::Str)
            | (Ty::Bool, Ty::Bool)
            | (Ty::Duration, Ty::Duration)
            | (Ty::Method, Ty::Method | Ty::Str)
            | (Ty::Str, Ty::Method)
            | (Ty::Transport, Ty::Transport)
    )
}

/// `msg.a.b` → `"a.b"` when rooted at the message.
fn field_path(e: &Expr, msg: &str) -> Option<String> {
    match &e.kind {
        ExprKind::Field(base, n) => match &base.kind {
            ExprKind::Ident(b) if b == msg => Some(n.text.clone()),
            _ => field_path(base, msg).map(|p| format!("{p}.{}", n.text)),
        },
        _ => None,
    }
}

fn is_field(e: &Expr, msg: &str, path: &str) -> bool {
    field_path(e, msg).as_deref() == Some(path)
}

/// Does this statement leave the route (for `guard … else`)?
fn ends_route(s: &Stmt) -> bool {
    match &s.kind {
        StmtKind::Return(_) | StmtKind::Drop | StmtKind::Exit => true,
        // An Action call (reply(…), a typed Action function, a user fn):
        // checked properly when lowered; accept calls here.
        StmtKind::Expr(e) => matches!(e.kind, ExprKind::Call(..)),
        _ => false,
    }
}

/// Where a call is relative to `await`s in its function.
const BEFORE: u8 = 0;
/// After an `await` in an enclosing or earlier nested block (or in a loop
/// it may come back to): perhaps after the final.
const MAYBE: u8 = 1;
/// After an `await` in the same straight-line code: after the final.
const AFTER: u8 = 2;

/// Does this code contain an `await` (anywhere inside)?
fn has_await(stmts: &[Stmt]) -> bool {
    let mut st = BEFORE;
    calls_in(stmts, "", &mut st, &mut |_, _| {});
    st != BEFORE
}

/// Every user-function call in `stmts` (`ns`: the file's namespace), and
/// where it is relative to `await` (BEFORE, MAYBE, AFTER).
fn calls_in(stmts: &[Stmt], ns: &str, after: &mut u8, f: &mut dyn FnMut(String, u8)) {
    fn expr(e: &Expr, ns: &str, after: &mut u8, f: &mut dyn FnMut(String, u8)) {
        match &e.kind {
            ExprKind::Call(callee, args) => {
                match &callee.kind {
                    ExprKind::Ident(n) => f(key(ns, n), *after),
                    ExprKind::Field(b, n) => {
                        if let ExprKind::Ident(file_ns) = &b.kind {
                            f(key(file_ns, &n.text), *after);
                        }
                    }
                    _ => {}
                }
                for a in args {
                    expr(&a.value, ns, after, f);
                }
            }
            ExprKind::Await(x) => {
                expr(x, ns, after, f);
                *after = AFTER;
            }
            ExprKind::Field(x, _) | ExprKind::Unary(_, x) | ExprKind::Paren(x) => expr(x, ns, after, f),
            ExprKind::Index(a, b) | ExprKind::Binary(_, a, b) | ExprKind::Range(a, b) => {
                expr(a, ns, after, f);
                expr(b, ns, after, f);
            }
            ExprKind::List(items) => items.iter().for_each(|x| expr(x, ns, after, f)),
            ExprKind::Str(parts) => parts.iter().for_each(|p| {
                if let StrPart::Expr(x) = p {
                    expr(x, ns, after, f)
                }
            }),
            _ => {}
        }
    }
    // A nested block: an `await` in it makes what follows only "maybe".
    fn nested(stmts: &[Stmt], start: u8, ns: &str, after: &mut u8, f: &mut dyn FnMut(String, u8)) {
        let mut inner = start;
        calls_in(stmts, ns, &mut inner, f);
        if inner > *after {
            *after = MAYBE.max(*after);
        }
    }
    for s in stmts {
        match &s.kind {
            StmtKind::Let { value, otherwise, .. } => {
                expr(value, ns, after, f);
                if let Some(o) = otherwise {
                    nested(std::slice::from_ref(o.as_ref()), *after, ns, after, f);
                }
            }
            StmtKind::Assign(a, b) => {
                expr(a, ns, after, f);
                expr(b, ns, after, f);
            }
            StmtKind::If(c, t, e) => {
                expr(c, ns, after, f);
                let at = *after;
                nested(&t.stmts, at, ns, after, f);
                match e {
                    Some(ast::Else::Block(b)) => nested(&b.stmts, at, ns, after, f),
                    Some(ast::Else::If(s)) => nested(std::slice::from_ref(s.as_ref()), at, ns, after, f),
                    None => {}
                }
            }
            StmtKind::While(c, b) | StmtKind::For(_, c, b) => {
                // A loop with an `await` comes back to its start after one.
                let start = if has_await(&b.stmts) { MAYBE.max(*after) } else { *after };
                expr(c, ns, &mut start.clone(), f);
                nested(&b.stmts, start, ns, after, f);
            }
            StmtKind::Guard(c, s) => {
                expr(c, ns, after, f);
                nested(std::slice::from_ref(s.as_ref()), *after, ns, after, f);
            }
            StmtKind::Match(subject, arms) => {
                expr(subject, ns, after, f);
                let at = *after;
                for a in arms {
                    if let Some(g) = &a.guard {
                        expr(g, ns, &mut at.clone(), f);
                    }
                    match &a.body {
                        ast::ArmBody::Block(b) => nested(&b.stmts, at, ns, after, f),
                        ast::ArmBody::Stmt(s) => nested(std::slice::from_ref(s.as_ref()), at, ns, after, f),
                    }
                }
            }
            StmtKind::Return(Some(e)) | StmtKind::Expr(e) => expr(e, ns, after, f),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::sig::{arg, opt, sig};

    const TIMEOUT: &[sip_core::sig::Param] = &[arg("timeout", ArgTy::Duration(Unit::Ms))];
    const URI: &[sip_core::sig::Param] = &[opt("uri", ArgTy::Uri)];
    const TEXT: &[sip_core::sig::Param] = &[arg("text", ArgTy::Str)];
    const TO: &[sip_core::sig::Param] = &[opt("to", ArgTy::Uri)];
    const AWAIT: &[sip_core::sig::Param] = &[sip_core::sig::opt_or("to", ArgTy::Uri, ""), opt("timeout", ArgTy::Duration(Unit::Ms))];

    fn env() -> Env {
        let mut e = Env::default();
        e.add(
            "txn",
            [
                sig("t_relay", "relay", TO, Ret::Action, "relay statefully"),
                sig("t_relay_await", "relay_await", AWAIT, Ret::Bool, ""),
                sig("t_set_fr", "set_timeout", TIMEOUT, Ret::Void, ""),
            ],
        );
        e.add("location", [sig("save", "save", &[], Ret::Action, "").fixed(&["location"]), sig("lookup", "lookup", URI, Ret::Bool, "").fixed(&["location"])]);
        e.add("nat", [sig("nat_uac_test", "is_behind", &[], Ret::Bool, "").fixed(&["19"]), sig("fix_nated_contact", "fix_contact", &[], Ret::Void, "")]);
        e.add("log", [sig("xlog", "info", TEXT, Ret::Void, "").fixed(&["L_INFO"]).allowed(ctx::ANY)]);
        e.add("registrar", [sig("save", "save", &[], Ret::Action, "").fixed(&["location"]).allowed(ctx::REQUEST)]);
        e.features.insert("nat".into(), Feature::Bool(true));
        e
    }

    fn lower(src: &str) -> String {
        match crate::compile_source("t.fsr", src, &env()) {
            Ok(o) => {
                let cfg = crate::print::to_cfg(&o.ast);
                sip_script::parse(&cfg).unwrap_or_else(|e| panic!("lowered output doesn't parse: {e}\n{cfg}"));
                cfg
            }
            Err(e) => panic!("{e}"),
        }
    }

    fn errors(src: &str) -> String {
        match crate::compile_source("t.fsr", src, &env()) {
            Ok(o) => panic!("compiled:\n{}", crate::print::to_cfg(&o.ast)),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn huge_durations_saturate() {
        // Lexing saturates at u64::MAX ms; lowering clamps that to i64::MAX, never -1.
        let cfg = lower("route main(msg: Request) {\n    let t = 999999999999999999d\n    if t > 0s { relay(msg) }\n}\n");
        assert!(cfg.contains(&i64::MAX.to_string()) && !cfg.contains("= -1") && !cfg.contains("(-1)"), "{cfg}");
    }

    #[test]
    fn lowers_a_registrar() {
        let cfg = lower(
            r#"import location, nat
import { features } from config
flag NATED

route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(483)
    guard msg.is_sane() else drop
    if features.nat && nat.is_behind(msg) {
        msg.set(NATED)
        nat.fix_contact(msg)
    }
    match msg.method {
        REGISTER => location.save(msg)
        INVITE | MESSAGE => invite(msg)
        OPTIONS => reply(200)
        _ => reply(405)
    }
}

fn invite(msg: Request) -> Action {
    let found = location.lookup(msg.ruri) else return reply(404)
    msg.headers["X-Hops"] = "{msg.src.ip}:{msg.src.port}x"
    log.info("to {msg.ruri} via $5\n")
    relay(msg)
}
"#,
        );
        for want in [
            "if (!mf_process_maxfwd_header(70)) {\n        send_reply(483, \"Too Many Hops\");\n        exit;",
            "if (!sanity_check()) {\n        drop;",
            "if (nat_uac_test(\"19\")) {\n        setflag(31);\n        fix_nated_contact();",
            "if ($rm == \"REGISTER\") {\n        if (!save(\"location\")) {\n            sl_reply_error();\n        }\n        exit;",
            "} else if (($rm == \"INVITE\") || ($rm == \"MESSAGE\")) {\n        route(invite);\n        exit;\n    } else if ($rm == \"OPTIONS\") {",
            "send_reply(405, \"Method Not Allowed\");",
            "route[invite] {\n    if (lookup(\"location\", $ru)) {\n        $(avp(l__invite__found)[*]) = 1;\n    } else {\n        $(avp(l__invite__found)[*]) = (-1);\n    }\n    if ($avp(l__invite__found) <= 0) {\n        send_reply(404, \"Not Found\");\n        exit;",
            "remove_hf(\"X-Hops\");\n    append_hf(\"X-Hops: $si:$(sp)x\\r\\n\");",
            "xlog(\"L_INFO\", \"to $ru via $$5\\n\");",
            "if (!t_relay()) {\n        sl_reply_error();\n    }\n    exit;",
        ] {
            assert!(cfg.contains(want), "missing:\n{want}\n--- in:\n{cfg}");
        }
    }

    #[test]
    fn functions_with_parameters_and_bools() {
        let cfg = lower(
            r#"route main(msg: Request) {
    if allowed(msg, 3) { reply(200) }
    reply(403, "No")
}
fn allowed(msg: Request, n: Int) -> Bool {
    let ok = n > 2 && msg.ruri.user =~ "^\\+1"
    return ok
}
"#,
        );
        assert!(cfg.contains("$(avp(p__allowed__n)[*]) = 3;\n    if (route(allowed)) {"), "{cfg}");
        assert!(cfg.contains("if (($avp(p__allowed__n) > 2) && ($rU =~ \"^\\\\+1\")) {"), "{cfg}");
        assert!(cfg.contains("if ($avp(l__allowed__ok) > 0) {\n        return 1;\n    } else {\n        return (-1);"), "{cfg}");
        assert!(cfg.contains("send_reply(403, \"No\");"), "{cfg}");
    }

    #[test]
    fn on_reply_and_ranges() {
        let cfg = lower(
            r#"route main(msg: Request) { relay(msg) }
on reply(r: Reply) where r.code in 180..183 {
    if r.has_sdp { log.info("early media") }
}
"#,
        );
        assert!(cfg.contains("reply_route {\n    if (($rs >= 180) && ($rs <= 183)) {\n        if (has_body(\"application/sdp\")) {"), "{cfg}");
    }

    #[test]
    fn type_errors_have_positions() {
        let e = errors(
            r#"import location
route main(msg: Request) {
    msg.ruri.usr = "bob"
    txn.relay(msg, timeout: "abc")
    location.lookup(msg, 5)
    let x = 1
    x = "a"
    msg.set(NOPE)
    reply("x")
    msg.method == FOO
}
on reply(r: Reply) {
    r.ruri = "sip:x"
    registrar.save(r)
    reply(200)
}
"#,
        );
        for want in [
            "t.fsr:3:5: msg has no field \"ruri.usr\" (did you mean \"ruri.user\"?)",
            "t.fsr:4:20: txn.relay() has no argument \"timeout\"",
            "t.fsr:5:26: expected a URI (Str), found Int",
            "t.fsr:7:9: x is Int, found Str",
            "t.fsr:8:13: NOPE is not defined",
            "t.fsr:9:11: a reply code is an Int, found Str",
            "t.fsr:10:19: FOO is not defined",
            "t.fsr:13:5: msg.ruri can't be changed on a reply",
            "t.fsr:14:5: add `import registrar` at the top",
            "t.fsr:14:15: registrar.save() can't be used in `on reply`",
            "t.fsr:15:5: reply() answers a request; not in `on reply`",
        ] {
            assert!(e.contains(want), "missing {want:?} in:\n{e}");
        }
    }

    #[test]
    fn await_and_match_on_the_result() {
        let cfg = lower(
            r#"import location
route main(msg: Request) {
    if msg.method == INVITE { invite(msg) }
    reply(405)
}
fn invite(msg: Request) -> Action {
    let found = location.lookup(msg.ruri) else return reply(404)
    let res = await txn.relay(msg, timeout: 30s)
    match res {
        Final(r) if r.code in 200..299 => forward(r)
        Final(r) if r.code == 486 => voicemail(msg)
        Timeout | Final(_) => reply(480)
    }
}
fn voicemail(msg: Request) -> Action {
    msg.ruri.user = "vm-" + msg.ruri.user
    relay(msg)
}
"#,
        );
        for want in [
            "t_relay_await(\"\", 30000);\n    $(avp(l__invite__res__rc)[*]) = $rc;\n    $(avp(l__invite__res__code)[*]) = $T_reply_code;\n    $(avp(l__invite__res__reason)[*]) = $T_reply_reason;\n    $(avp(l__invite__res__timeout)[*]) = $T_timeout;\n",
            "if (!($avp(l__invite__res__timeout) > 0) && (($avp(l__invite__res__code) >= 200) && ($avp(l__invite__res__code) <= 299))) {\n        exit;",
            "} else if (!($avp(l__invite__res__timeout) > 0) && ($avp(l__invite__res__code) == 486)) {\n        route(voicemail);\n        exit;",
            "} else if (($avp(l__invite__res__timeout) > 0) || !($avp(l__invite__res__timeout) > 0)) {\n        t_reply(480, \"Temporarily Unavailable\");\n        exit;",
            // voicemail runs after `await`: no sl_reply_error, the best reply goes up.
            "route[voicemail] {\n    $rU = \"vm-\" + $rU;\n    t_relay();\n    exit;\n}",
        ] {
            assert!(cfg.contains(want), "missing:\n{want}\n--- in:\n{cfg}");
        }
    }

    #[test]
    fn await_result_tells_a_relay_that_failed_at_once() {
        let cfg = lower(
            "route main(msg: Request) {\n    let res = await txn.relay(msg)\n    match res {\n        Final(r) if !r.sent => log.info(\"at once\")\n        Final(r) if r.code < 300 => {}\n        _ => log.info(\"failed\")\n    }\n    exit\n}\n",
        );
        assert!(
            cfg.contains("$(avp(l__main__res__rc)[*]) = $rc;\n")
                && cfg.contains("if (!($avp(l__main__res__timeout) > 0) && !($avp(l__main__res__rc) > 0)) {\n        xlog("),
            "{cfg}"
        );
        let e = errors(
            "route main(msg: Request) {\n    let res = await txn.relay(msg)\n    match res {\n        Final(r) if r.snt => {}\n        _ => {}\n    }\n}\n",
        );
        assert!(e.contains("the final reply has code, reason and sent, not snt"), "{e}");
    }

    #[test]
    fn await_errors() {
        let e = errors(
            r#"route main(msg: Request) {
    if msg.method == INVITE {
        let res = await txn.relay(msg)
    }
    let res = await txn.relay(msg)
    match res {
        Final(r) if r.code == 200 => forward(r)
        Final(r) => reply(r.code)
    }
    let x = res.code
}
fn check(msg: Request) -> Bool {
    await txn.relay(msg)
    return true
}
"#,
        );
        // A code from a value is fine after await (t_reply checks it at run time).
        assert!(!e.contains("reply() needs a literal code"), "{e}");
        for want in [
            "t.fsr:6:11: this match doesn't handle every result: add Timeout (or `_`)",
            "t.fsr:10:13: res is an `await` result: match it",
            "t.fsr:13:5: `await` can't be in a function returning Bool",
        ] {
            assert!(e.contains(want), "missing {want:?} in:\n{e}");
        }
    }

    #[test]
    fn needs_main_and_known_modules() {
        let e = errors("import locaton\nroute other(msg: Request) { drop }\n");
        assert!(e.contains("unknown module \"locaton\" (did you mean \"location\"?)"), "{e}");
        assert!(e.contains("no `route main(msg: Request)`"), "{e}");
    }

    #[test]
    fn flags_avoid_used_bits() {
        let mut env = env();
        env.used_flags.extend([31, 30]);
        let o = crate::compile_source("t.fsr", "flag A\nflag B\nroute main(msg: Request) { msg.set(A) drop }", &env).map_err(|e| e.to_string()).unwrap();
        assert_eq!(o.flags.get("A"), Some(&29));
        assert_eq!(o.flags.get("B"), Some(&28));
    }

    #[test]
    fn flags_with_a_fixed_bit() {
        let src = "flag A\nflag ACC = 31\nflag LOW = 0\nroute main(msg: Request) {\n    msg.set(ACC)\n    msg.set(A)\n    if msg.is(LOW) { msg.reset(LOW) }\n    drop\n}";
        let o = crate::compile_source("t.fsr", src, &env()).map_err(|e| e.to_string()).unwrap();
        assert_eq!((o.flags["ACC"], o.flags["LOW"], o.flags["A"]), (31, 0, 30));
        let out = lower(src);
        assert!(out.contains("setflag(31);") && out.contains("setflag(30);") && out.contains("if (isflagset(0)) {\n        resetflag(0);"), "{out}");
        let e = errors("flag A = 3\nflag B = 3\nflag C = 32\nroute main(msg: Request) { drop }");
        assert!(e.contains("flag bit 3 is already A") && e.contains("flag bit 32 is out of range (0..31)"), "{e}");
    }

    #[test]
    fn branch_flags() {
        // Their own bits: a message flag and a branch flag may share one.
        let src = "flag ACC = 6\nbranch flag NATB = 6\nbranch flag AUTO\nroute main(msg: Request) {\n    msg.set(ACC)\n    msg.set(NATB)\n    msg.set(NATB, branch: 0)\n    if msg.is(AUTO) { msg.reset(NATB) }\n    drop\n}";
        let o = crate::compile_source("t.fsr", src, &env()).map_err(|e| e.to_string()).unwrap();
        assert_eq!((o.flags["ACC"], o.branch_flags["NATB"], o.branch_flags["AUTO"]), (6, 6, 31));
        let out = lower(src);
        assert!(out.contains("setflag(6);\n    setbflag(6);\n    setbflag(6, 0);\n    if (isbflagset(31)) {\n        resetbflag(6);"), "{out}");
        let e = errors(
            "flag A\nbranch flag A\nbranch flag B = 1\nbranch flag C = 1\nbranch flag D = 40\nroute main(msg: Request) {\n    msg.set(B, branch: x)\n    msg.set(A, branch: 0)\n    drop\n}",
        );
        for want in [
            "flag A declared twice",
            "branch flag bit 1 is already B",
            "branch flag bit 40 is out of range (0..31)",
            "the branch is a number",
            "`branch:` is for a branch flag",
        ] {
            assert!(e.contains(want), "{want}: {e}");
        }
    }
}
