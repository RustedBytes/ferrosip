//! `ferrosip import kamailio.cfg`: a Kamailio-style `.cfg` → `ferrosip.toml`
//! (core settings, listeners, modules and their parameters) and
//! `routes/main.fsr` (the routing).
//!
//! The aim is the same behaviour, so the translation is exact first and
//! typed where that is still exact:
//! - `$ru`, `$rU`, `$fu`… → `msg.ruri`, `msg.ruri.user`, `msg.from.uri`… in
//!   request code; method tests → `msg.method == INVITE`;
//! - a module function whose `.fsr` signature takes the same arguments in
//!   that context → its typed call (`location.lookup("location")`);
//!   `if (!f(…)) { sl_reply_error(); } exit;` with an Action `f` → `f(…)`,
//!   which lowers to exactly that;
//! - `sl_send_reply(code, reason); exit;` / `send_reply(…); exit;` with a
//!   literal code, in request code → `reply(NotFound[, reason])` (for
//!   `sl_send_reply` only where no transaction can exist yet: not after
//!   `t_newtran`, `t_relay`… on any path to it, through called routes too);
//! - `setflag(FLT_ACC)` / `isflagset` / `resetflag` → `msg.set(FLT_ACC)` …
//!   with `flag FLT_ACC = 1` (the same bit), `setbflag(FLB_NATB)` …
//!   likewise with `branch flag FLB_NATB = 6`; `xlog` with a literal level →
//!   `log.error(…)` / `log.info(…)` (xlog's `xerr` / `xinfo`);
//! - `t_on_failure("F")` right before `t_relay()` + `exit` → `let res =
//!   await txn.relay(msg)` + a `match` that calls `failure_route[F]` (now a
//!   function) where Kamailio would run it (`AwaitRelay::plan`);
//! - everything else goes through the escape hatch: `pv("$avp(x)")`,
//!   `kamailio.call("fn", …)`, `kamailio.myself`, and
//!   `on kamailio.failure_route(msg: Request, name: "X")` for routes armed by
//!   name. `ferrosip lint -W raw_kamailio` lists what is left to type.
//!
//! `#!ifdef` blocks are resolved with the `--define`s given (one variant).
//! Comments are not carried over (the preprocessor drops them).

use crate::config;
use sip_core::schema::{self, ParamSpec, Ty, Unit};
use sip_core::sig::{ArgTy, FnSig, Ret, ctx};
use sip_script::{Ast, BinOp, Expr, RawArg, Stmt};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const USAGE: &str = "usage: ferrosip import KAMAILIO.cfg [-o DIR] [--define NAME[=VALUE]]… [--force]
  Writes DIR/ferrosip.toml and DIR/routes/main.fsr (DIR: ./imported), then checks them.
  --define    resolve #!ifdef blocks as `ferrosip check --define` would (repeatable)
  --force     overwrite files that exist";

// ------------------------------------------------------------- the routing ---

/// `.fsr` operator strength, loosest first (docs/fsr.md).
const P_OR: u8 = 1;
const P_AND: u8 = 2;
const P_CMP: u8 = 3;
const P_ADD: u8 = 5;
const P_MUL: u8 = 6;
const P_UNARY: u8 = 7;
const P_ATOM: u8 = 9;

/// Typed message fields (request code only): Kamailio pv → `.fsr` path.
const FIELDS: &[(&str, &str, bool)] = &[
    ("$ru", "ruri", true),
    ("$rU", "ruri.user", true),
    ("$rd", "ruri.host", true),
    ("$du", "dst_uri", true),
    ("$fu", "from.uri", false),
    ("$fU", "from.user", false),
    ("$fd", "from.host", false),
    ("$ft", "from.tag", false),
    ("$fn", "from.display", false),
    ("$tu", "to.uri", false),
    ("$tU", "to.user", false),
    ("$td", "to.host", false),
    ("$tt", "to.tag", false),
    ("$ci", "call_id", false),
    ("$ua", "user_agent", false),
    ("$rb", "body", false),
    ("$si", "src.ip", false),
];

/// Names `.fsr` code can't use for a function.
const RESERVED: &[&str] = &[
    "route", "fn", "on", "let", "if", "else", "while", "for", "in", "match", "guard", "return", "drop", "exit", "break", "true", "false", "await", "import",
    "flag", "shared", "table", "dialog", "var", "test", "reply", "relay", "forward", "pv", "now", "kamailio", "msg", "main", "features",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Main,
    Sub,
    Failure,
    Branch,
    OnReply,
    Reply,
    Event,
}

struct RouteInfo {
    fsr: String,
    /// It gets the request as `msg` (every caller has one).
    has_msg: bool,
    /// `ctx` bits it may run in.
    ctx: u8,
    /// Called for its value (`if (route(X))`).
    bool_ret: bool,
}

/// What the body being translated has.
#[derive(Clone, Copy)]
struct Scope {
    has_msg: bool,
    /// A request (not a reply): typed fields and `msg.method`.
    request: bool,
    ctx: u8,
    bool_ret: bool,
}

struct Typed {
    ns: String,
    fsr: &'static str,
    sig: FnSig,
}

struct Tr {
    routes: BTreeMap<String, RouteInfo>,
    by_name: BTreeMap<&'static str, Vec<Typed>>,
    imports: BTreeSet<String>,
    notes: Vec<String>,
    switches: usize,
    /// `sl_send_reply` line in request code → a transaction may exist
    /// there (`sl_send_reply` then differs from `reply()`); missing: not
    /// reached from the request route.
    txn_at: BTreeMap<usize, bool>,
    /// Counts for the summary: typed / escape-hatch uses.
    typed: usize,
    raw: usize,
    /// The script's `#!define`s (name, value): names for flag numbers.
    consts: Vec<(String, String)>,
    /// Message flags used, by bit: `flag NAME = bit` declarations.
    flags: BTreeMap<i64, String>,
    /// Branch flags used, by bit: `branch flag NAME = bit`.
    bflags: BTreeMap<i64, String>,
    /// The failure route imported as `await txn.relay` + `match`.
    await_relay: Option<AwaitRelay>,
}

/// `t_on_failure("F")` + `t_relay()` + `exit` imported as `let res = await
/// txn.relay(msg)` and a `match` that calls `failure_route[F]` (now a
/// function) where Kamailio would run it (`AwaitRelay::plan` says when).
struct AwaitRelay {
    /// The failure route's Kamailio name and its `.fsr` function.
    route: String,
    fsr: String,
    /// The line of the `t_on_failure` call (there is one).
    arm_line: usize,
}

/// The statements `t_on_failure` + `t_relay` + `exit` at `ss[i..]`.
struct RelaySite<'a> {
    /// `if (is_method("INVITE")) { t_on_failure("F"); }`: the condition.
    cond: Option<&'a Expr>,
    /// The failure route armed, and the `t_on_failure` line.
    route: &'a str,
    arm_line: usize,
    /// Behind `if (!t_is_set("failure_route"))`.
    guarded: bool,
    /// The `t_relay()` statement, and what runs when it fails at once
    /// (`if (!t_relay()) { send_reply_error(); }`: the `send_reply_error`).
    relay: &'a Stmt,
    on_error: &'a [Stmt],
}

/// Calls `f` for every function call in `ss` (conditions included).
fn each_call<'a>(ss: &'a [Stmt], f: &mut dyn FnMut(&'a str, &'a [RawArg])) {
    fn expr<'a>(e: &'a Expr, f: &mut dyn FnMut(&'a str, &'a [RawArg])) {
        match e {
            Expr::Call { name, args, .. } => f(name, args),
            Expr::Not(x) | Expr::Neg(x) => expr(x, f),
            Expr::Bin(_, a, b) => {
                expr(a, f);
                expr(b, f);
            }
            _ => {}
        }
    }
    for s in ss {
        match s {
            Stmt::If(c, a, b) => {
                expr(c, f);
                each_call(a, f);
                each_call(b, f);
            }
            Stmt::While(c, b) => {
                expr(c, f);
                each_call(b, f);
            }
            Stmt::Switch(e, cases) => {
                expr(e, f);
                for (v, b) in cases {
                    if let Some(v) = v {
                        expr(v, f);
                    }
                    each_call(b, f);
                }
            }
            Stmt::Assign(_, e, _) | Stmt::Expr(e) | Stmt::Return(Some(e)) => expr(e, f),
            _ => {}
        }
    }
}

impl<'a> RelaySite<'a> {
    /// `t_on_failure("F")`, or `if (!t_is_set("failure_route"))
    /// t_on_failure("F")`, possibly inside `if (C) { … }` with a C that has
    /// no effect (method and to-tag tests, variables); then `t_relay()` or
    /// `if (!t_relay()) { send_reply_error(); }` (or `sl_reply_error()`, or
    /// nothing); then `exit`.
    fn at(ss: &'a [Stmt], i: usize) -> Option<Self> {
        fn arm(s: &Stmt) -> Option<(&str, usize, bool)> {
            match s {
                Stmt::Expr(Expr::Call { name, args, line }) if name == "t_on_failure" => match args.as_slice() {
                    [RawArg::Str(f)] => Some((f.as_str(), *line, false)),
                    _ => None,
                },
                Stmt::If(Expr::Not(c), a, b) if b.is_empty() && is_set_failure(c) => match a.as_slice() {
                    [x @ Stmt::Expr(_)] => arm(x).map(|(f, l, _)| (f, l, true)),
                    _ => None,
                },
                _ => None,
            }
        }
        fn pure(e: &Expr) -> bool {
            match e {
                Expr::Call { name, .. } => matches!(name.as_str(), "is_method" | "has_totag"),
                Expr::Not(x) | Expr::Neg(x) => pure(x),
                Expr::Bin(_, a, b) => pure(a) && pure(b),
                Expr::Route(..) => false,
                Expr::Str(_) | Expr::Int(_) | Expr::Pv(..) | Expr::Myself => true,
            }
        }
        let (cond, (route, arm_line, guarded)) = match ss.get(i)? {
            Stmt::If(c, a, b) if b.is_empty() && pure(c) && !is_set_failure(c) => match a.as_slice() {
                [x] => (Some(c), arm(x)?),
                _ => return None,
            },
            s => (None, arm(s)?),
        };
        let relay = ss.get(i.saturating_add(1))?;
        let is_relay = |e: &Expr| matches!(e, Expr::Call { name, args, .. } if name == "t_relay" && args.is_empty());
        let on_error: &[Stmt] = match relay {
            Stmt::Expr(e) if is_relay(e) => &[],
            Stmt::If(Expr::Not(c), a, b) if b.is_empty() && is_relay(c) => match a.as_slice() {
                [] | [Stmt::Expr(Expr::Call { .. })] if a.iter().all(|s| matches!(s, Stmt::Expr(Expr::Call { name, args, .. }) if args.is_empty() && (name == "send_reply_error" || name == "sl_reply_error"))) => a,
                _ => return None,
            },
            _ => return None,
        };
        matches!(ss.get(i.saturating_add(2)), Some(Stmt::Exit)).then_some(RelaySite { cond, route, arm_line, guarded, relay, on_error })
    }

    /// Every such site in `ss` (inside blocks too).
    fn all(ss: &'a [Stmt], out: &mut Vec<Self>) {
        for (i, s) in ss.iter().enumerate() {
            if let Some(site) = Self::at(ss, i) {
                out.push(site);
            }
            match s {
                Stmt::If(_, a, b) => {
                    Self::all(a, out);
                    Self::all(b, out);
                }
                Stmt::While(_, b) => Self::all(b, out),
                Stmt::Switch(_, cases) => cases.iter().for_each(|(_, b)| Self::all(b, out)),
                _ => {}
            }
        }
    }
}

/// `t_is_set("failure_route")`.
fn is_set_failure(e: &Expr) -> bool {
    matches!(e, Expr::Call { name, args, .. } if name == "t_is_set" && matches!(args.as_slice(), [RawArg::Str(t)] if t == "failure_route"))
}

impl AwaitRelay {
    /// When the failure route can be the code after an `await` (the
    /// conditions that make it mean the same):
    /// - one `t_on_failure` in the whole script, at a `RelaySite` (so where
    ///   it arms the route the relay follows, then `exit`; and wherever
    ///   `t_relay` runs there, no other failure route is armed:
    ///   `t_is_set("failure_route")` is false, as in a failure route), and
    ///   `t_is_set("failure_route")` only as its guard (a branch_route would
    ///   see it set);
    /// - the route it is in (or `request_route`) has the request, runs in
    ///   request or failure code only, and neither it nor any route that
    ///   leads to it is used for its value (`await` can't be inside a
    ///   condition);
    /// - `failure_route[F]` exists, once, and no modparam names it.
    ///
    /// The `match` then runs F exactly where Kamailio does: on a negative
    /// final or a timeout (`Timeout`); a 2xx went upstream (nothing to
    /// run); a relay that fails at once (`!r.sent`) runs what followed a
    /// false `t_relay()`. F becomes a function called after `await`, in
    /// the same failure context.
    fn plan(ast: &Ast, routes: &BTreeMap<String, RouteInfo>, used: &BTreeSet<String>) -> Option<AwaitRelay> {
        let bodies = all_bodies(ast);
        let (mut arms, mut is_set): (usize, usize) = (0, 0);
        for (_, b) in &bodies {
            each_call(b, &mut |n, args| {
                arms = arms.saturating_add(usize::from(n == "t_on_failure"));
                is_set = is_set.saturating_add(usize::from(n == "t_is_set" && matches!(args, [RawArg::Str(t)] if t == "failure_route")));
            });
        }
        if arms != 1 {
            return None;
        }
        // The site: in request_route or a route[…].
        let mut found = Vec::new();
        let mut sites = Vec::new();
        RelaySite::all(&ast.request_route, &mut sites);
        found.extend(sites.drain(..).map(|s| (None, s)));
        for (n, b) in &ast.routes {
            RelaySite::all(b, &mut sites);
            found.extend(sites.drain(..).map(|s| (Some(n.as_str()), s)));
        }
        let [(at, site)] = found.as_slice() else { return None };
        if is_set != usize::from(site.guarded) {
            return None;
        }
        if let Some(r) = at {
            let info = routes.get(*r)?;
            if !info.has_msg || info.ctx & !(ctx::REQUEST | ctx::FAILURE) != 0 {
                return None;
            }
            // Neither it nor a route on the way to it is used for its value.
            let mut callers: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for (n, b) in &ast.routes {
                let mut calls = Vec::new();
                route_calls(b, &mut calls);
                for (to, _) in calls {
                    if let Some((k, _)) = ast.routes.iter().find(|(x, _)| *x == to) {
                        callers.entry(k.as_str()).or_default().push(n.as_str());
                    }
                }
            }
            let (mut seen, mut todo) = (BTreeSet::new(), vec![*r]);
            while let Some(x) = todo.pop() {
                if !seen.insert(x) {
                    continue;
                }
                if routes.get(x).is_none_or(|i| i.bool_ret) {
                    return None;
                }
                todo.extend(callers.get(x).into_iter().flatten().copied());
            }
        }
        let name = site.route;
        if ast.failure_routes.iter().filter(|(n, _)| n == name).count() != 1 {
            return None;
        }
        if ast.modparams.iter().any(|p| matches!(&p.value, RawArg::Str(v) if v.split([';', '=', ',', ' ', '|']).any(|x| x == name))) {
            return None;
        }
        let mut fsr = snake(name);
        while used.contains(&fsr) {
            fsr.push_str("_failure");
        }
        Some(AwaitRelay { route: name.to_string(), fsr, arm_line: site.arm_line })
    }
}

/// Kamailio's literal xlog levels and the `.fsr` log function (its
/// Kamailio name: `xinfo` …, the same as `xlog("L_INFO", …)`).
const LOG_LEVELS: &[(&str, &str)] = &[
    ("L_ALERT", "xalert"),
    ("L_BUG", "xbug"),
    ("L_CRIT", "xcrit"),
    ("L_ERR", "xerr"),
    ("L_WARN", "xwarn"),
    ("L_NOTICE", "xnotice"),
    ("L_INFO", "xinfo"),
    ("L_DBG", "xdbg"),
];

fn esc(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '{' => o.push_str("\\{"),
            '}' => o.push_str("\\}"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o
}

fn wrap(t: (String, u8), min: u8) -> String {
    if t.1 < min { format!("({})", t.0) } else { t.0 }
}

fn is_ident(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn snake(s: &str) -> String {
    let mut o: String = s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
    if o.starts_with(|c: char| c.is_ascii_digit()) || o.is_empty() {
        o.insert(0, 'r');
    }
    o
}

/// Every string a config holds (function arguments, modparam values): a
/// route named in one is called by name, so it keeps its exact name.
fn strings_of(ast: &Ast) -> BTreeSet<String> {
    fn expr(e: &Expr, out: &mut BTreeSet<String>) {
        match e {
            Expr::Call { args, .. } => {
                for a in args {
                    if let RawArg::Str(s) = a {
                        out.insert(s.clone());
                    }
                }
            }
            Expr::Not(x) | Expr::Neg(x) => expr(x, out),
            Expr::Bin(_, a, b) => {
                expr(a, out);
                expr(b, out);
            }
            _ => {}
        }
    }
    fn stmts(ss: &[Stmt], out: &mut BTreeSet<String>) {
        for s in ss {
            match s {
                Stmt::If(c, a, b) => {
                    expr(c, out);
                    stmts(a, out);
                    stmts(b, out);
                }
                Stmt::While(c, b) => {
                    expr(c, out);
                    stmts(b, out);
                }
                Stmt::Switch(e, cases) => {
                    expr(e, out);
                    for (v, b) in cases {
                        if let Some(v) = v {
                            expr(v, out);
                        }
                        stmts(b, out);
                    }
                }
                Stmt::Assign(_, e, _) | Stmt::Expr(e) | Stmt::Return(Some(e)) => expr(e, out),
                _ => {}
            }
        }
    }
    let mut out = BTreeSet::new();
    for (_, b) in all_bodies(ast) {
        stmts(b, &mut out);
    }
    // Modparam values name routes inside (`timer=t;route=NAME`).
    for p in &ast.modparams {
        if let RawArg::Str(s) = &p.value {
            out.extend(s.split([';', '=', ',', ' ', '|']).map(str::to_string));
        }
    }
    out
}

/// Calls that may make the request's transaction (mod-txn's functions that
/// create one, relay, or suspend, and the modules' that suspend it). Not
/// here: `t_check_trans` / `t_precheck_trans` (for a request that goes on
/// they leave none; a retransmission they match ends the script), the
/// `t_on_*` / `t_set_*` settings, the `t_is_*` / `t_branch_*` /
/// `t_check_status` tests, `t_release`, `t_load_contacts` /
/// `t_next_contacts` (contacts only), and `t_uac_send` (a new request's
/// transaction, not this one's).
const TXN_CREATING: &[&str] = &[
    "t_newtran",
    "t_relay",
    "t_relay_to_udp",
    "t_relay_to_tcp",
    "t_relay_to_tls",
    "t_relay_await",
    "t_forward_nonack",
    "t_forward_nonack_udp",
    "t_forward_nonack_tcp",
    "t_forward_nonack_tls",
    "t_forward_nonack_sctp",
    // In Kamailio it creates the transaction when there is none.
    "t_reply",
    "t_suspend",
    "t_continue",
    "ts_store",
    "evapi_async_relay",
    "http_async_query",
    "I_perform_user_authorization_request",
    "I_perform_location_information_request",
    "ims_www_challenge",
    "ims_proxy_challenge",
    "Ro_CCR",
    "Rx_AAR",
    "Rx_AAR_Register",
];

/// Same, for a name that only creates one in a given module: (module, fn).
const TXN_CREATING_IN: &[(&str, &str)] = &[("ims_registrar_scscf", "save")];

/// Where a statement list can go on from, and whether a transaction may
/// exist then (`None`: it can't get there).
#[derive(Clone, Copy, Default)]
struct Flow {
    /// Past its end.
    fall: Option<bool>,
    /// Out of the route (`return`, or a `break` with nothing to break).
    ret: Option<bool>,
    /// Out of the enclosing `switch` / `while` (`break`).
    brk: Option<bool>,
}

fn join(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(x || y),
    }
}

/// "May a transaction exist here?" over the request route and the routes
/// it calls, for each `sl_send_reply` there (by line).
struct TxnFlow<'a> {
    creating: Box<dyn Fn(&str) -> bool + 'a>,
    bodies: BTreeMap<&'a str, &'a [Stmt]>,
    /// A route's "may return with a transaction" when entered without one
    /// (`None`: it never returns).
    returns: BTreeMap<&'a str, Option<bool>>,
    /// A route's state on entry: the join over its calls.
    entry: BTreeMap<&'a str, Option<bool>>,
    /// `sl_send_reply` line → a transaction may exist there.
    sites: BTreeMap<usize, bool>,
}

impl<'a> TxnFlow<'a> {
    /// The `sl_send_reply` lines in request code, with whether a
    /// transaction may exist there.
    fn run(ast: &'a Ast) -> BTreeMap<usize, bool> {
        let modules: BTreeSet<&str> = ast.modules.iter().map(String::as_str).collect();
        let creating =
            move |n: &str| TXN_CREATING.contains(&n) || n.starts_with("async_") || TXN_CREATING_IN.iter().any(|(m, f)| *f == n && modules.contains(m));
        let mut bodies: BTreeMap<&str, &[Stmt]> = BTreeMap::new();
        for (n, b) in &ast.routes {
            bodies.entry(n.as_str()).or_insert(b.as_slice());
        }
        let mut f = TxnFlow { creating: Box::new(creating), bodies, returns: BTreeMap::new(), entry: BTreeMap::new(), sites: BTreeMap::new() };
        // What each route returns with, entered without a transaction
        // (with one, it returns with one): from "never", until stable.
        loop {
            let mut changed = false;
            for (&n, &b) in &f.bodies.clone() {
                let o = f.block(b, Some(false));
                let r = join(join(o.fall, o.ret), o.brk);
                changed |= f.returns.insert(n, r) != Some(r);
            }
            if !changed {
                break;
            }
        }
        // Entry states from the request route down, until stable.
        f.entry.clear();
        loop {
            let before = f.entry.clone();
            f.sites.clear();
            f.block(&ast.request_route, Some(false));
            for (&n, &b) in &f.bodies.clone() {
                if let Some(e) = f.entry.get(n).copied().flatten() {
                    f.block(b, Some(e));
                }
            }
            if f.entry == before {
                break;
            }
        }
        // A reply the request route can't reach (after a route that always
        // drops, say) never runs: no transaction there either. Not in a
        // route it never calls (a module may call that one).
        let reached =
            std::iter::once(ast.request_route.as_slice()).chain(f.bodies.iter().filter(|(n, _)| f.entry.get(*n).copied().flatten().is_some()).map(|(_, b)| *b));
        let mut lines = Vec::new();
        for b in reached.collect::<Vec<_>>() {
            reply_lines(b, &mut lines);
        }
        for l in lines {
            f.sites.entry(l).or_insert(false);
        }
        f.sites
    }

    /// The state after evaluating `e` from `tx`.
    fn expr(&mut self, e: &'a Expr, tx: Option<bool>) -> Option<bool> {
        let tx = tx?;
        match e {
            Expr::Call { name, .. } => Some(tx || (self.creating)(name)),
            Expr::Route(n, _) => {
                let e = self.entry.entry(n.as_str()).or_insert(None);
                *e = join(*e, Some(tx));
                // An unknown route: assume the worst.
                let r = if self.bodies.contains_key(n.as_str()) { self.returns.get(n.as_str()).copied().flatten() } else { Some(true) };
                r.map(|r| r || tx)
            }
            Expr::Not(x) | Expr::Neg(x) => self.expr(x, Some(tx)),
            // The right side may not run.
            Expr::Bin(BinOp::Or | BinOp::And, a, b) => {
                let l = self.expr(a, Some(tx));
                join(l, self.expr(b, l))
            }
            Expr::Bin(_, a, b) => {
                let l = self.expr(a, Some(tx));
                self.expr(b, l)
            }
            _ => Some(tx),
        }
    }

    fn block(&mut self, ss: &'a [Stmt], tx: Option<bool>) -> Flow {
        let mut o = Flow { fall: tx, ..Flow::default() };
        for s in ss {
            let Some(tx) = o.fall else { break };
            let r = self.stmt(s, tx);
            o.fall = r.fall;
            o.ret = join(o.ret, r.ret);
            o.brk = join(o.brk, r.brk);
        }
        o
    }

    fn stmt(&mut self, s: &'a Stmt, tx: bool) -> Flow {
        let tx = Some(tx);
        let fall = |fall| Flow { fall, ..Flow::default() };
        match s {
            Stmt::Expr(e) => {
                if let Expr::Call { name, line, .. } = e
                    && name == "sl_send_reply"
                {
                    *self.sites.entry(*line).or_insert(false) |= tx == Some(true);
                }
                fall(self.expr(e, tx))
            }
            Stmt::Assign(_, e, _) => fall(self.expr(e, tx)),
            Stmt::If(c, a, b) => {
                let c = self.expr(c, tx);
                let (x, y) = (self.block(a, c), self.block(b, c));
                Flow { fall: join(x.fall, y.fall), ret: join(x.ret, y.ret), brk: join(x.brk, y.brk) }
            }
            Stmt::While(c, body) => {
                // At the test: the entry, then after each pass, until stable.
                let mut at = self.expr(c, tx);
                let mut o = Flow::default();
                loop {
                    let r = self.block(body, at);
                    o.ret = join(o.ret, r.ret);
                    o.brk = join(o.brk, r.brk);
                    let next = join(at, self.expr(c, r.fall));
                    if next == at {
                        break;
                    }
                    at = next;
                }
                Flow { fall: join(at, o.brk), ret: o.ret, brk: None }
            }
            Stmt::Switch(e, cases) => {
                // Each case is entered from the switch or by falling through.
                let at = self.expr(e, tx);
                let (mut cur, mut o) = (None, Flow::default());
                for (_, b) in cases {
                    let r = self.block(b, join(at, cur));
                    cur = r.fall;
                    o.ret = join(o.ret, r.ret);
                    o.brk = join(o.brk, r.brk);
                }
                let nomatch = if cases.iter().any(|(v, _)| v.is_none()) { None } else { at };
                Flow { fall: join(join(cur, o.brk), nomatch), ret: o.ret, brk: None }
            }
            Stmt::Exit | Stmt::Drop | Stmt::Return(Some(Expr::Int(0))) => Flow::default(),
            Stmt::Return(v) => {
                let r = match v {
                    Some(e) => self.expr(e, tx),
                    None => tx,
                };
                Flow { ret: r, ..Flow::default() }
            }
            Stmt::Break => Flow { brk: tx, ..Flow::default() },
        }
    }
}

/// The lines of the `sl_send_reply` statements in `ss`.
fn reply_lines(ss: &[Stmt], out: &mut Vec<usize>) {
    for s in ss {
        match s {
            Stmt::Expr(Expr::Call { name, line, .. }) if name == "sl_send_reply" => out.push(*line),
            Stmt::If(_, a, b) => {
                reply_lines(a, out);
                reply_lines(b, out);
            }
            Stmt::While(_, b) => reply_lines(b, out),
            Stmt::Switch(_, cases) => cases.iter().for_each(|(_, b)| reply_lines(b, out)),
            _ => {}
        }
    }
}

fn all_bodies(ast: &Ast) -> Vec<(Kind, &Vec<Stmt>)> {
    let mut v = vec![(Kind::Main, &ast.request_route)];
    v.extend(ast.routes.iter().map(|(_, b)| (Kind::Sub, b)));
    v.extend(ast.failure_routes.iter().map(|(_, b)| (Kind::Failure, b)));
    v.extend(ast.branch_routes.iter().map(|(_, b)| (Kind::Branch, b)));
    v.extend(ast.onreply_routes.iter().map(|(_, b)| (Kind::OnReply, b)));
    v.extend(ast.event_routes.iter().map(|(_, b)| (Kind::Event, b)));
    if let Some(r) = &ast.reply_route {
        v.push((Kind::Reply, r));
    }
    v
}

/// Routes called in `stmts`: (name, for its value).
fn route_calls(stmts: &[Stmt], out: &mut Vec<(String, bool)>) {
    fn expr(e: &Expr, value: bool, out: &mut Vec<(String, bool)>) {
        match e {
            Expr::Route(n, _) => out.push((n.clone(), value)),
            Expr::Not(x) | Expr::Neg(x) => expr(x, true, out),
            Expr::Bin(_, a, b) => {
                expr(a, true, out);
                expr(b, true, out);
            }
            _ => {}
        }
    }
    for s in stmts {
        match s {
            Stmt::If(c, a, b) => {
                expr(c, true, out);
                route_calls(a, out);
                route_calls(b, out);
            }
            Stmt::While(c, b) => {
                expr(c, true, out);
                route_calls(b, out);
            }
            Stmt::Switch(e, cases) => {
                expr(e, true, out);
                for (v, b) in cases {
                    if let Some(v) = v {
                        expr(v, true, out);
                    }
                    route_calls(b, out);
                }
            }
            Stmt::Assign(_, e, _) | Stmt::Return(Some(e)) => expr(e, true, out),
            Stmt::Expr(e) => expr(e, false, out),
            _ => {}
        }
    }
}

/// A reply-code variable typed in this scope: `txn.code` / `txn.reason` in
/// failure, reply and branch code (where `.fsr` has them), `msg.code` /
/// `msg.reason` on a reply. The flag: an Int.
fn code_pv(p: &str, sc: Scope) -> Option<(&'static str, bool)> {
    let txn = sc.ctx != 0 && sc.ctx & !(ctx::FAILURE | ctx::REPLY | ctx::BRANCH) == 0;
    let reply = sc.has_msg && !sc.request;
    match p {
        "$T_reply_code" if txn => Some(("txn.code", true)),
        "$T_reply_reason" if txn => Some(("txn.reason", false)),
        "$rs" if reply => Some(("msg.code", true)),
        "$rr" if reply => Some(("msg.reason", false)),
        _ => None,
    }
}

/// A reply-code pattern (`486|408`, `3[0-9][0-9]`, `[12][0-9][0-9]`) as
/// comparisons on `var`: exact codes by name, whole hundreds as ranges
/// (consecutive ones as one); `None` for any other pattern. Every
/// alternative is three positions long, so anchored (t_check_status) or
/// not (`=~`) it matches a whole three-digit code alike.
fn code_pattern(pat: &str, var: &str) -> Option<(String, u8)> {
    let mut parts = Vec::new();
    for alt in pat.split('|') {
        if let [b'1'..=b'6', _, _] = alt.as_bytes()
            && alt.bytes().all(|b| b.is_ascii_digit())
        {
            parts.push(format!("{var} == {}", code_name(alt.parse().ok()?)));
            continue;
        }
        // The hundreds: a digit or a class of them; then any two digits.
        let (hundreds, rest) = match alt.strip_prefix('[') {
            Some(r) => {
                let (class, rest) = r.split_once(']')?;
                (class_digits(class)?, rest)
            }
            None => {
                let mut cs = alt.chars();
                (vec![cs.next()?.to_digit(10)?], cs.as_str())
            }
        };
        if !matches!(rest, "[0-9][0-9]" | "\\d\\d" | "[0-9]\\d" | "\\d[0-9]") || hundreds.iter().any(|d| !(1..=6).contains(d)) {
            return None;
        }
        // Runs of consecutive hundreds (1..=6, checked above) as one range.
        let mut runs: Vec<(u32, u32)> = Vec::new();
        for &d in &hundreds {
            match runs.last_mut() {
                Some((_, last)) if last.checked_add(1) == Some(d) => *last = d,
                _ => runs.push((d, d)),
            }
        }
        for (from, to) in runs {
            parts.push(format!("{var} in {}..{}", from.saturating_mul(100), to.saturating_mul(100).saturating_add(99)));
        }
    }
    Some(match parts.len() {
        1 => (parts.remove(0), P_CMP),
        _ => (parts.join(" || "), P_OR),
    })
}

/// The digits of a regex character class (`12`, `1-3`), sorted; `None`
/// for anything else in it.
fn class_digits(class: &str) -> Option<Vec<u32>> {
    let mut c = class.chars();
    let mut out = Vec::new();
    while let Some(first) = c.next() {
        let a = first.to_digit(10)?;
        // `a-z`: a range of digits.
        if let Some(r) = c.as_str().strip_prefix('-') {
            c = r.chars();
            let z = c.next()?.to_digit(10)?;
            if z < a {
                return None;
            }
            out.extend(a..=z);
        } else {
            out.push(a);
        }
    }
    out.sort_unstable();
    out.dedup();
    (!out.is_empty()).then_some(out)
}

/// A plain decimal number written as text (`"17895"`).
fn int_text(x: &str) -> bool {
    !x.is_empty() && x.len() <= 18 && x.bytes().all(|b| b.is_ascii_digit())
}

/// A status code by name where it has one.
fn code_name(c: i64) -> String {
    fsr::msg::status_name(c).map_or(c.to_string(), str::to_string)
}

fn cmp_sym(op: BinOp) -> Option<&'static str> {
    Some(match op {
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        _ => return None,
    })
}

fn kind_ctx(k: Kind) -> (u8, bool) {
    match k {
        Kind::Main | Kind::Sub => (ctx::REQUEST, true),
        Kind::Failure => (ctx::FAILURE, true),
        Kind::Branch => (ctx::BRANCH, true),
        Kind::OnReply | Kind::Reply => (ctx::REPLY, false),
        Kind::Event => (ctx::EVENT, false),
    }
}

impl Tr {
    fn new(ast: &Ast, consts: &[(String, String)]) -> Self {
        // Typed signatures by Kamailio name, for the modules the config loads.
        let mut by_name: BTreeMap<&'static str, Vec<Typed>> = BTreeMap::new();
        for m in crate::all_modules() {
            let loaded = ast.modules.iter().any(|x| x == m);
            for s in crate::module_by_name(m).and_then(|x| x.functions()).unwrap_or_default() {
                // A core function (`force_rport`: no module provides it) is always there.
                if s.fsr.is_empty() || !(loaded || crate::providers("fn", s.name).is_empty()) {
                    continue;
                }
                let ns = s.ns.unwrap_or(crate::fsr_namespace(m)).to_string();
                by_name.entry(s.name).or_default().push(Typed { ns, fsr: s.fsr, sig: s });
            }
        }
        // Routes: names, who calls them, in which contexts.
        let strings = strings_of(ast);
        let mut used_names: BTreeSet<String> = RESERVED.iter().map(|s| s.to_string()).collect();
        used_names.extend(by_name.values().flatten().map(|t| t.ns.clone()));
        let mut routes = BTreeMap::new();
        for (name, _) in &ast.routes {
            let keep = strings.contains(name) && is_ident(name) && !used_names.contains(name);
            let mut fsr = if keep { name.clone() } else { snake(name) };
            while used_names.contains(&fsr) {
                fsr.push_str("_route");
            }
            used_names.insert(fsr.clone());
            // Called by name (a module, a timer): any context.
            let ctx = if strings.contains(name) { ctx::ANY } else { 0 };
            routes.insert(name.clone(), RouteInfo { fsr, has_msg: true, ctx, bool_ret: false });
        }
        // Propagate contexts and the message through the call graph.
        let bodies: Vec<(Option<String>, Kind, &Vec<Stmt>)> = std::iter::once((None, Kind::Main, &ast.request_route))
            .chain(ast.routes.iter().map(|(n, b)| (Some(n.clone()), Kind::Sub, b)))
            .chain(ast.failure_routes.iter().map(|(_, b)| (None, Kind::Failure, b)))
            .chain(ast.branch_routes.iter().map(|(_, b)| (None, Kind::Branch, b)))
            .chain(ast.onreply_routes.iter().map(|(_, b)| (None, Kind::OnReply, b)))
            .chain(ast.event_routes.iter().map(|(_, b)| (None, Kind::Event, b)))
            .chain(ast.reply_route.iter().map(|b| (None, Kind::Reply, b)))
            .collect();
        let mut edges = Vec::new();
        for (from, kind, body) in &bodies {
            let mut calls = Vec::new();
            route_calls(body, &mut calls);
            for (to, value) in calls {
                if let Some(r) = routes.get_mut(&to) {
                    r.bool_ret |= value;
                }
                edges.push((from.clone(), *kind, to));
            }
        }
        loop {
            let mut changed = false;
            for (from, kind, to) in &edges {
                let (c, m) = match from {
                    Some(f) => routes.get(f).map_or((0, true), |r| (r.ctx, r.has_msg)),
                    None => kind_ctx(*kind),
                };
                if let Some(r) = routes.get_mut(to) {
                    let (nc, nm) = (r.ctx | c, r.has_msg && m);
                    if nc != r.ctx || nm != r.has_msg {
                        r.ctx = nc;
                        r.has_msg = nm;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for r in routes.values_mut() {
            if r.ctx == 0 {
                r.ctx = ctx::REQUEST;
            }
        }
        let txn_at = TxnFlow::run(ast);
        used_names.extend(routes.values().map(|r| r.fsr.clone()));
        let await_relay = AwaitRelay::plan(ast, &routes, &used_names);
        Tr {
            routes,
            by_name,
            imports: BTreeSet::new(),
            notes: Vec::new(),
            switches: 0,
            txn_at,
            typed: 0,
            raw: 0,
            consts: consts.to_vec(),
            flags: BTreeMap::new(),
            bflags: BTreeMap::new(),
            await_relay,
        }
    }

    fn pv(&mut self, p: &str) -> (String, u8) {
        self.raw = self.raw.saturating_add(1);
        (format!("pv(\"{}\")", esc(p)), P_ATOM)
    }

    /// A pseudo-variable read: typed where it means the same.
    fn read_pv(&mut self, p: &str, sc: Scope) -> (String, u8) {
        if let Some((path, _)) = code_pv(p, sc) {
            self.typed = self.typed.saturating_add(1);
            return (path.into(), P_ATOM);
        }
        // On a reply (`msg: Reply`), the fields a reply has.
        if sc.has_msg
            && let Some((_, path, _)) = FIELDS.iter().find(|(k, ..)| *k == p)
            && (sc.request || fsr::msg::field(path).is_some_and(|f| f.reply))
        {
            self.typed = self.typed.saturating_add(1);
            return (format!("msg.{path}"), P_ATOM);
        }
        // `$hdr(Event)` → `msg.headers["Event"]`, which reads `$hdr(Event)`.
        if sc.has_msg
            && let Some(h) = p.strip_prefix("$hdr(").and_then(|x| x.strip_suffix(')'))
            && !h.is_empty()
            && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            self.typed = self.typed.saturating_add(1);
            return (format!("msg.headers[\"{h}\"]"), P_ATOM);
        }
        self.pv(p)
    }

    /// A variable inside a template string: an Int field reads the same
    /// there (`{msg.src.port}` is `$sp`), where it isn't in a comparison.
    fn text_pv(&mut self, p: &str, sc: Scope) -> String {
        if sc.has_msg
            && let Some(f) = fsr::msg::FIELDS.iter().find(|f| f.pv == p)
            && f.ty == fsr::msg::FieldTy::Int
            && f.path != "code"
            && (if sc.request { f.request } else { f.reply })
        {
            self.typed = self.typed.saturating_add(1);
            return format!("msg.{}", f.path);
        }
        self.read_pv(p, sc).0
    }

    /// `t_check_status("486|408|3[0-9][0-9]")` as `txn.code` comparisons
    /// (`code_pattern`); `None` for any other pattern (it stays
    /// `txn.status_is`).
    fn status_test(&mut self, args: &[RawArg], sc: Scope) -> Option<(String, u8)> {
        let [RawArg::Str(pat)] = args else { return None };
        let (var, _) = code_pv("$T_reply_code", sc)?;
        let t = code_pattern(pat, var)?;
        self.typed = self.typed.saturating_add(1);
        Some(t)
    }

    /// A Kamailio template string (`"sip:$rU@x"`) as an `.fsr` string.
    fn string(&mut self, s: &str, sc: Scope) -> String {
        let (mut out, mut lit) = (String::from("\""), String::new());
        let mut rest = s;
        while let Some(ch) = rest.chars().next() {
            if let Some(after) = rest.strip_prefix("$$") {
                lit.push('$');
                rest = after;
                continue;
            }
            if ch == '$' {
                let n = sip_core::pv::pv_len(rest.as_bytes());
                // `pv_len` ends on an ASCII byte.
                if n > 0
                    && let Some((pv, after)) = rest.split_at_checked(n)
                {
                    out.push_str(&esc(&lit));
                    lit.clear();
                    let x = self.text_pv(pv, sc);
                    out.push('{');
                    out.push_str(&x);
                    out.push('}');
                    rest = after;
                    continue;
                }
            }
            lit.push(ch);
            rest = rest.get(ch.len_utf8()..).unwrap_or_default();
        }
        out.push_str(&esc(&lit));
        out.push('"');
        out
    }

    fn arg(&mut self, a: &RawArg, sc: Scope) -> String {
        match a {
            RawArg::Str(s) => self.string(s, sc),
            RawArg::Int(i) => i.to_string(),
            RawArg::Pv(p) => self.pv(p).0,
        }
    }

    /// A typed call `ns.fn(args)` for `name(args)`, when it means the same.
    fn typed_call(&mut self, name: &str, args: &[RawArg], sc: Scope, want: &[Ret]) -> Option<String> {
        let cands = self.by_name.get(name)?;
        let pick = cands.iter().find(|t| {
            let s = &t.sig;
            if !want.iter().any(|w| std::mem::discriminant(w) == std::mem::discriminant(&s.ret)) || s.allowed & sc.ctx != sc.ctx {
                return false;
            }
            // The constant arguments must be the ones written.
            if args.len() < s.fixed.len() || s.fixed.iter().zip(args).any(|(f, a)| !matches!(a, RawArg::Str(x) if x == f)) {
                return false;
            }
            let Some(rest) = args.get(s.fixed.len()..) else { return false };
            let required = s.params.iter().filter(|p| !p.optional).count();
            // A left-out parameter with a default would be passed: not the same call.
            let Some(left_out) = s.params.get(rest.len()..) else { return false };
            if rest.len() < required || left_out.iter().any(|p| p.default.is_some()) {
                return false;
            }
            rest.iter().zip(s.params).all(|(a, p)| match (p.ty, a) {
                (ArgTy::Str | ArgTy::Uri | ArgTy::Any, RawArg::Str(x)) => !(p.literal && x.contains('$')),
                (ArgTy::Str | ArgTy::Uri | ArgTy::Any, RawArg::Pv(_)) => !p.literal,
                (ArgTy::Int | ArgTy::Any, RawArg::Int(_)) => true,
                // `"10"` to an Int parameter: Kamailio and ferrosip read it as 10.
                (ArgTy::Int, RawArg::Str(x)) => int_text(x),
                (ArgTy::Enum(vals), RawArg::Str(x)) => vals.contains(&x.as_str()),
                _ => false,
            })
        })?;
        let (ns, fsr, nfixed, params) = (pick.ns.clone(), pick.fsr, pick.sig.fixed.len(), pick.sig.params);
        let rest: Vec<String> = args
            .get(nfixed..)
            .unwrap_or_default()
            .iter()
            .zip(params)
            .map(|(a, p)| match a {
                RawArg::Str(x) if p.ty == ArgTy::Int && int_text(x) => x.clone(),
                _ => self.arg(a, sc),
            })
            .collect();
        if ns != "log" && ns != "txn" {
            self.imports.insert(ns.clone());
        }
        self.typed = self.typed.saturating_add(1);
        Some(format!("{ns}.{fsr}({})", rest.join(", ")))
    }

    fn raw_call(&mut self, name: &str, args: &[RawArg], sc: Scope) -> String {
        self.raw = self.raw.saturating_add(1);
        let mut parts = vec![format!("\"{name}\"")];
        parts.extend(args.iter().map(|a| self.arg(a, sc)));
        format!("kamailio.call({})", parts.join(", "))
    }

    /// `is_method("INVITE|BYE")` → `msg.method == INVITE || …`.
    fn method_test(&mut self, args: &[RawArg], sc: Scope) -> Option<(String, u8)> {
        if !(sc.has_msg && sc.request) {
            return None;
        }
        let [RawArg::Str(m)] = args else { return None };
        let ms: Vec<&str> = m.split('|').collect();
        if ms.iter().any(|x| !fsr::msg::METHODS.contains(x)) {
            return None;
        }
        self.typed = self.typed.saturating_add(1);
        let parts: Vec<String> = ms.iter().map(|x| format!("msg.method == {x}")).collect();
        Some((parts.join(" || "), if parts.len() > 1 { P_OR } else { P_CMP }))
    }

    /// The `.fsr` name of message flag `bit` (`branch`: of branch flag
    /// `bit`): the script's `#!define` with that value (`FLT_ACC`; a `FLT_`
    /// one first, never a `FLB_` branch flag; for a branch flag the other
    /// way round), else `FLAG_<bit>` / `BFLAG_<bit>`. Declared as `flag
    /// NAME = bit` / `branch flag NAME = bit`.
    fn flag_name(&mut self, bit: i64, branch: bool) -> String {
        if let Some(n) = if branch { &self.bflags } else { &self.flags }.get(&bit) {
            return n.clone();
        }
        let taken = |n: &str, tr: &Tr| {
            RESERVED.contains(&n)
                || fsr::msg::METHODS.contains(&n)
                || fsr::msg::TRANSPORTS.iter().any(|(t, _)| *t == n)
                || (100..700).any(|c| fsr::msg::status_name(c) == Some(n))
                || tr.flags.values().chain(tr.bflags.values()).any(|f| f == n)
                || tr.routes.values().any(|r| r.fsr == n)
                || tr.await_relay.as_ref().is_some_and(|a| a.fsr == n)
                || tr.by_name.values().flatten().any(|t| t.ns == n)
        };
        let cands: Vec<&String> =
            self.consts.iter().filter(|(n, v)| v.trim().parse::<i64>() == Ok(bit) && is_ident(n) && !taken(n, self)).map(|(n, _)| n).collect();
        let pick = |f: &dyn Fn(&str) -> bool| {
            let c: Vec<&&String> = cands.iter().filter(|n| f(n)).collect();
            match c.as_slice() {
                [one] => Some(one.to_string()),
                _ => None,
            }
        };
        let (mine, other, fallback) = if branch { ("FLB_", "FLT_", "BFLAG") } else { ("FLT_", "FLB_", "FLAG") };
        let mut name = pick(&|n| n.starts_with(mine)).or_else(|| pick(&|n| !n.starts_with(other))).unwrap_or_else(|| format!("{fallback}_{bit}"));
        while taken(&name, self) {
            name.push('_');
        }
        if branch { &mut self.bflags } else { &mut self.flags }.insert(bit, name.clone());
        name
    }

    /// `setflag(1)` / `resetflag(1)` / `isflagset(1)` → `msg.set(FLT_ACC)`
    /// / `msg.reset(…)` / `msg.is(…)`: the same `setflag(1)` … with the
    /// flag declared at that bit; `setbflag(6[, 0])` … → `msg.set(FLB_NATB[,
    /// branch: 0])` with `branch flag FLB_NATB = 6`. Literal flags 0..31
    /// only, where the code has the message.
    fn flag_op(&mut self, name: &str, args: &[RawArg], sc: Scope, cond: bool) -> Option<(String, u8)> {
        let (m, branch) = match name {
            "setflag" if !cond => ("set", false),
            "resetflag" if !cond => ("reset", false),
            "isflagset" => ("is", false),
            "setbflag" if !cond => ("set", true),
            "resetbflag" if !cond => ("reset", true),
            "isbflagset" => ("is", true),
            _ => return None,
        };
        let (bit, idx) = match args {
            [RawArg::Int(bit)] => (bit, None),
            [RawArg::Int(bit), RawArg::Int(i)] if branch && *i >= 0 => (bit, Some(*i)),
            _ => return None,
        };
        if !sc.has_msg || !(0..=31).contains(bit) {
            return None;
        }
        let f = self.flag_name(*bit, branch);
        self.typed = self.typed.saturating_add(1);
        Some(match idx {
            Some(i) => (format!("msg.{m}({f}, branch: {i})"), P_ATOM),
            None => (format!("msg.{m}({f})"), P_ATOM),
        })
    }

    /// `xlog("text")` (level L_ERR) / `xlog("L_INFO", "text")` with a
    /// literal level → `log.error(…)` / `log.info(…)`: they lower to
    /// `xerr` / `xinfo`, xlog's own shortcuts for exactly that.
    fn log_call(&mut self, args: &[RawArg], sc: Scope, want: &[Ret]) -> Option<String> {
        let (short, text) = match args {
            [_] => ("xerr", args),
            [RawArg::Str(l), text] => (LOG_LEVELS.iter().find(|(k, _)| k == l)?.1, std::slice::from_ref(text)),
            _ => return None,
        };
        self.typed_call(short, text, sc, want)
    }

    fn call_expr(&mut self, name: &str, args: &[RawArg], sc: Scope, cond: bool) -> (String, u8) {
        if let Some(t) = self.flag_op(name, args, sc, cond) {
            return t;
        }
        if name == "is_method"
            && let Some(t) = self.method_test(args, sc)
        {
            return t;
        }
        if name == "t_check_status"
            && let Some(t) = self.status_test(args, sc)
        {
            return t;
        }
        if name == "has_totag" && args.is_empty() && sc.has_msg && sc.request {
            self.typed = self.typed.saturating_add(1);
            return ("msg.has_to_tag".into(), P_ATOM);
        }
        let want: &[Ret] = if cond { &[Ret::Bool] } else { &[Ret::Bool, Ret::Void] };
        if name == "xlog"
            && let Some(t) = self.log_call(args, sc, want)
        {
            return (t, P_ATOM);
        }
        match self.typed_call(name, args, sc, want) {
            Some(t) => (t, P_ATOM),
            None => (self.raw_call(name, args, sc), P_ATOM),
        }
    }

    fn route_call(&mut self, n: &str, sc: Scope) -> (String, u8) {
        match self.routes.get(n) {
            Some(r) => {
                let a = if r.has_msg && sc.has_msg && sc.request { "msg" } else { "" };
                (format!("{}({a})", r.fsr), P_ATOM)
            }
            None => {
                self.notes.push(format!("route({n}) has no route[{n}]"));
                (self.raw_call("route", &[RawArg::Str(n.into())], sc), P_ATOM)
            }
        }
    }

    /// An expression; `cond`: its value is tested.
    fn expr(&mut self, e: &Expr, sc: Scope, cond: bool) -> (String, u8) {
        match e {
            Expr::Str(s) => (self.string(s, sc), P_ATOM),
            Expr::Int(i) if *i < 0 => (format!("-{}", i.unsigned_abs()), P_UNARY),
            Expr::Int(i) => (i.to_string(), P_ATOM),
            // A bare variable tested for truth stays one (a typed Str isn't a condition).
            Expr::Pv(p, _) if cond => self.pv(p),
            Expr::Pv(p, _) => self.read_pv(p, sc),
            Expr::Call { name, args, .. } => self.call_expr(name, args, sc, cond),
            Expr::Route(n, _) => self.route_call(n, sc),
            Expr::Myself => {
                self.raw = self.raw.saturating_add(1);
                ("kamailio.myself".into(), P_ATOM)
            }
            Expr::Not(x) => {
                let t = self.expr(x, sc, true);
                (format!("!{}", wrap(t, P_UNARY)), P_UNARY)
            }
            Expr::Neg(x) => {
                let t = self.expr(x, sc, false);
                (format!("-{}", wrap(t, P_UNARY)), P_UNARY)
            }
            Expr::Bin(op, a, b) => self.binary(*op, a, b, sc, cond),
        }
    }

    fn binary(&mut self, op: BinOp, a: &Expr, b: &Expr, sc: Scope, _cond: bool) -> (String, u8) {
        // `(int)x` parses as `0 + x`. In .fsr, Int + Str concatenates, so a
        // numeric literal becomes the number, and a pseudo-variable stays
        // untyped (`pv()`, Any), which adds.
        if op == BinOp::Add && matches!(a, Expr::Int(0)) {
            match b {
                Expr::Str(s) if let Ok(n) = s.trim().parse::<i64>() => return (n.to_string(), if n < 0 { P_UNARY } else { P_ATOM }),
                Expr::Pv(p, _) => {
                    let (t, _) = self.pv(p);
                    return (format!("0 + {t}"), P_ADD);
                }
                _ => {}
            }
        }
        // `$rm == "INVITE"` → `msg.method == INVITE`.
        if matches!(op, BinOp::Eq | BinOp::Ne)
            && sc.has_msg
            && sc.request
            && let (Expr::Pv(p, _), Expr::Str(m)) | (Expr::Str(m), Expr::Pv(p, _)) = (a, b)
            && p == "$rm"
            && fsr::msg::METHODS.contains(&m.as_str())
        {
            self.typed = self.typed.saturating_add(1);
            return (format!("msg.method {} {m}", if op == BinOp::Eq { "==" } else { "!=" }), P_CMP);
        }
        // `$T_reply_code == 486` → `txn.code == BusyHere`; `$rs >= 300` →
        // `msg.code >= 300` (class comparisons keep the number).
        if let Some(sym) = cmp_sym(op) {
            let lit = |e: &Expr| match e {
                Expr::Int(i) => Some(*i),
                Expr::Str(s) if s.len() == 3 => s.parse().ok(),
                _ => None,
            };
            let typed = |e: &Expr| match e {
                Expr::Pv(p, _) => code_pv(p, sc).filter(|(_, int)| *int).map(|(path, _)| path),
                _ => None,
            };
            let named = |c: i64| if matches!(op, BinOp::Eq | BinOp::Ne) { code_name(c) } else { c.to_string() };
            let text = match (typed(a), lit(b), lit(a), typed(b)) {
                (Some(x), Some(c), ..) => Some(format!("{x} {sym} {}", named(c))),
                (_, _, Some(c), Some(y)) => Some(format!("{} {sym} {y}", named(c))),
                _ => None,
            };
            if let Some(t) = text {
                self.typed = self.typed.saturating_add(1);
                return (t, P_CMP);
            }
        }
        // `$rs =~ "[12][0-9][0-9]"` → `msg.code in 100..299` (`=~` in .fsr
        // matches text).
        if matches!(op, BinOp::Match | BinOp::NoMatch)
            && let (Expr::Pv(p, _), Expr::Str(pat)) = (a, b)
            && let Some((var, true)) = code_pv(p, sc)
            && let Some((t, prec)) = code_pattern(pat, var)
        {
            self.typed = self.typed.saturating_add(1);
            return match (op, t.split_once(" == ")) {
                (BinOp::Match, _) => (t, prec),
                (_, Some((x, y))) if prec == P_CMP => (format!("{x} != {y}"), P_CMP),
                _ => (format!("!({t})"), P_UNARY),
            };
        }
        let (sym, p) = match op {
            BinOp::Or => ("||", P_OR),
            BinOp::And => ("&&", P_AND),
            BinOp::Eq => ("==", P_CMP),
            BinOp::Ne => ("!=", P_CMP),
            BinOp::Lt => ("<", P_CMP),
            BinOp::Gt => (">", P_CMP),
            BinOp::Le => ("<=", P_CMP),
            BinOp::Ge => (">=", P_CMP),
            BinOp::Match | BinOp::NoMatch => ("=~", P_CMP),
            BinOp::Add => ("+", P_ADD),
            BinOp::Sub => ("-", P_ADD),
            BinOp::Mul => ("*", P_MUL),
            BinOp::Div => ("/", P_MUL),
            BinOp::Mod => ("%", P_MUL),
            BinOp::BitOr | BinOp::BitAnd => {
                // No .fsr operator: the escape hatch's bitor / bitand.
                self.raw = self.raw.saturating_add(1);
                let x = self.side_raw(a, sc);
                let y = self.side_raw(b, sc);
                return (format!("kamailio.{}({x}, {y})", if op == BinOp::BitOr { "bitor" } else { "bitand" }), P_ATOM);
            }
        };
        let logic = matches!(op, BinOp::Or | BinOp::And);
        // A typed Str field never meets an Int (Kamailio compares loosely).
        let int_side = matches!(a, Expr::Int(_)) || matches!(b, Expr::Int(_));
        let side = |tr: &mut Tr, e: &Expr| -> (String, u8) {
            match e {
                Expr::Pv(pv, _) if int_side && !logic => tr.pv(pv),
                // `=~` matches text: a typed code (Int) stays raw.
                Expr::Pv(pv, _) if matches!(op, BinOp::Match | BinOp::NoMatch) && code_pv(pv, sc).is_some_and(|(_, int)| int) => tr.pv(pv),
                _ => tr.expr(e, sc, logic),
            }
        };
        let (x, y) = (side(self, a), side(self, b));
        // `a == b` is not associative in .fsr: both sides tighter.
        let (lmin, rmin) = if p == P_CMP { (P_CMP.saturating_add(1), P_CMP.saturating_add(1)) } else { (p, p.saturating_add(1)) };
        let text = format!("{} {sym} {}", wrap(x, lmin), wrap(y, rmin));
        if op == BinOp::NoMatch { (format!("!({text})"), P_UNARY) } else { (text, p) }
    }

    /// An operand of a Kamailio-only operator: variables stay raw.
    fn side_raw(&mut self, e: &Expr, sc: Scope) -> String {
        match e {
            Expr::Pv(p, _) => self.pv(p).0,
            _ => self.expr(e, sc, false).0,
        }
    }

    /// `sl_send_reply(code, reason)` / `send_reply(…)` followed by `exit`
    /// as `reply(Name[, reason])`, where that means the same: a literal
    /// code, request code only (no `.fsr` reply in onreply/branch/event
    /// handlers or routes they call), and for the stateless one no
    /// transaction that may exist at that point (`TxnFlow`). In a failure
    /// route (or a `route[…]` only failure routes call) `t_reply` + `exit`:
    /// `reply()` lowers to `t_reply` there.
    fn native_reply(&mut self, name: &str, args: &[RawArg], line: usize, sc: Scope) -> Option<String> {
        let stateless_ok = name == "sl_send_reply" && self.txn_at.get(&line) == Some(&false);
        let request = sc.ctx == ctx::REQUEST && (name == "send_reply" || stateless_ok);
        let failure = sc.ctx == ctx::FAILURE && name == "t_reply";
        if !(sc.has_msg && sc.request) || !(request || failure) {
            return None;
        }
        let [code, reason] = args else { return None };
        let code = match code {
            RawArg::Int(i) => *i,
            RawArg::Str(s) => s.trim().parse().ok()?,
            RawArg::Pv(_) => return None,
        };
        // t_reply sends final replies only (a 1xx fails at load: kept raw).
        if !(if failure { 200..=699 } else { 100..=699 }).contains(&code) {
            return None;
        }
        let reason = match reason {
            // A reason that is exactly the standard phrase is left out (any
            // other spelling goes on the wire as written: kept).
            RawArg::Str(r) if !r.contains('$') && r == fsr::msg::reason(code) && fsr::msg::status_name(code).is_some() => None,
            RawArg::Str(r) => Some(self.string(r, sc)),
            // reply() takes text; a variable's type isn't known.
            RawArg::Int(_) | RawArg::Pv(_) => return None,
        };
        self.typed = self.typed.saturating_add(1);
        let name = fsr::msg::status_name(code).map_or(code.to_string(), str::to_string);
        Some(match reason {
            Some(r) => format!("reply({name}, {r})"),
            None => format!("reply({name})"),
        })
    }

    fn line(&self, out: &mut String, ind: usize, s: &str) {
        let _ = writeln!(out, "{}{s}", "    ".repeat(ind));
    }

    /// The planned `RelaySite` (`AwaitRelay`) as `await txn.relay` + `match`:
    ///
    /// ```text
    /// [if C {]
    ///     let res = await txn.relay(msg)
    ///     match res {
    ///         Final(r) if !r.sent => { what followed a false t_relay() }
    ///         Final(r) if r.code < 300 => {}      // a 2xx went upstream
    ///         _ => manage_failure(msg)            // negative final, Timeout
    ///     }
    ///     exit
    /// [}
    /// the relay as written (no failure route armed), exit]
    /// ```
    fn await_relay(&mut self, site: &RelaySite<'_>, sc: Scope, ind: usize, out: &mut String) {
        let f = self.await_relay.as_ref().map(|a| a.fsr.clone()).unwrap_or_default();
        let at = if site.cond.is_some() { ind.saturating_add(1) } else { ind };
        if let Some(c) = site.cond {
            let c = self.expr(c, sc, true).0;
            self.line(out, ind, &format!("if {c} {{"));
        }
        self.typed = self.typed.saturating_add(1);
        self.line(out, at, "let res = await txn.relay(msg)");
        self.line(out, at, "match res {");
        let mut err = String::new();
        self.stmts(site.on_error, sc, 0, &mut err);
        match err.lines().collect::<Vec<_>>().as_slice() {
            [] => self.line(out, at.saturating_add(1), "Final(r) if !r.sent => {}"),
            [one] => self.line(out, at.saturating_add(1), &format!("Final(r) if !r.sent => {one}")),
            _ => {
                self.line(out, at.saturating_add(1), "Final(r) if !r.sent => {");
                self.stmts(site.on_error, sc, at.saturating_add(2), out);
                self.line(out, at.saturating_add(1), "}");
            }
        }
        self.line(out, at.saturating_add(1), "Final(r) if r.code < 300 => {}");
        self.line(out, at.saturating_add(1), &format!("_ => {f}(msg)"));
        self.line(out, at, "}");
        self.line(out, at, "exit");
        if site.cond.is_some() {
            self.line(out, ind, "}");
            self.stmt(site.relay, sc, ind, out);
            self.line(out, ind, "exit");
        }
    }

    /// Statements; the ones after one that ends the route are dead (dropped).
    fn stmts(&mut self, ss: &[Stmt], sc: Scope, ind: usize, out: &mut String) {
        for (i, s) in ss.iter().enumerate() {
            // Statements after `i + n` (none if past the end).
            let more_after = |n: usize| ss.len() > i.saturating_add(n);
            // t_on_failure("F") + t_relay() + exit → await txn.relay + match.
            if let Some(site) = RelaySite::at(ss, i)
                && self.await_relay.as_ref().is_some_and(|a| a.arm_line == site.arm_line)
            {
                self.await_relay(&site, sc, ind, out);
                if more_after(3) {
                    self.notes.push("statements after an exit were dropped (they never run)".into());
                }
                return;
            }
            // `if (!f(…)) { sl_reply_error(); } exit;` with an Action f → f(…).
            if let Stmt::If(Expr::Not(c), then, els) = s
                && let Expr::Call { name, args, .. } = c.as_ref()
                && els.is_empty()
                && matches!(then.as_slice(), [Stmt::Expr(Expr::Call { name: n, args: a, .. })] if n == "sl_reply_error" && a.is_empty())
                && matches!(ss.get(i.saturating_add(1)), Some(Stmt::Exit))
                && let Some(t) = self.typed_call(name, args, sc, &[Ret::Action])
            {
                self.line(out, ind, &t);
                if more_after(2) {
                    self.notes.push("statements after an exit were dropped (they never run)".into());
                }
                return;
            }
            // `sl_send_reply(code, reason); exit;` (`t_reply` in failure code) → reply(Name[, reason]).
            if let Stmt::Expr(Expr::Call { name, args, line }) = s
                && matches!(ss.get(i.saturating_add(1)), Some(Stmt::Exit))
                && let Some(t) = self.native_reply(name, args, *line, sc)
            {
                self.line(out, ind, &t);
                if more_after(2) {
                    self.notes.push("statements after an exit were dropped (they never run)".into());
                }
                return;
            }
            self.stmt(s, sc, ind, out);
            if matches!(s, Stmt::Exit | Stmt::Drop | Stmt::Return(_)) {
                if more_after(1) {
                    self.notes.push("statements after an exit/drop/return were dropped (they never run)".into());
                }
                return;
            }
        }
    }

    fn block(&mut self, head: &str, ss: &[Stmt], sc: Scope, ind: usize, out: &mut String) {
        self.line(out, ind, &format!("{head} {{"));
        self.stmts(ss, sc, ind.saturating_add(1), out);
        self.line(out, ind, "}");
    }

    fn stmt(&mut self, s: &Stmt, sc: Scope, ind: usize, out: &mut String) {
        match s {
            Stmt::If(c, a, b) => {
                let c = self.expr(c, sc, true).0;
                self.line(out, ind, &format!("if {c} {{"));
                self.stmts(a, sc, ind.saturating_add(1), out);
                let mut b = b;
                loop {
                    match b.as_slice() {
                        [] => {
                            self.line(out, ind, "}");
                            break;
                        }
                        [Stmt::If(c2, a2, b2)] => {
                            let c2 = self.expr(c2, sc, true).0;
                            self.line(out, ind, &format!("}} else if {c2} {{"));
                            self.stmts(a2, sc, ind.saturating_add(1), out);
                            b = b2;
                        }
                        _ => {
                            self.line(out, ind, "} else {");
                            self.stmts(b, sc, ind.saturating_add(1), out);
                            self.line(out, ind, "}");
                            break;
                        }
                    }
                }
            }
            Stmt::While(c, body) => {
                let c = self.expr(c, sc, true).0;
                self.block(&format!("while {c}"), body, sc, ind, out);
            }
            Stmt::Switch(e, cases) => self.switch(e, cases, sc, ind, out),
            Stmt::Assign(target, e, _) => {
                let field = FIELDS.iter().find(|(k, _, settable)| k == target && *settable).filter(|_| sc.has_msg && sc.request);
                let lhs = match field {
                    Some((_, path, _)) => {
                        self.typed = self.typed.saturating_add(1);
                        format!("msg.{path}")
                    }
                    None => self.pv(target).0,
                };
                // `$null` into a typed field: keep both raw.
                let rhs = match (field, e) {
                    (Some(_), Expr::Pv(p, _)) => self.pv(p).0,
                    (Some(_), Expr::Int(i)) => format!("\"{i}\""),
                    _ => self.expr(e, sc, false).0,
                };
                self.line(out, ind, &format!("{lhs} = {rhs}"));
            }
            Stmt::Expr(Expr::Route(n, _)) => {
                let c = self.route_call(n, sc).0;
                self.line(out, ind, &c);
            }
            Stmt::Expr(e) => {
                let t = self.expr(e, sc, false).0;
                // A bare comparison has no effect; a call's value is ignored.
                self.line(out, ind, &t);
            }
            Stmt::Exit => self.line(out, ind, "exit"),
            Stmt::Drop => self.line(out, ind, "drop"),
            Stmt::Break => self.line(out, ind, "break"),
            Stmt::Return(v) => {
                // return(0) stops the script; in a route called for its
                // value, positive is true and negative false.
                let n = match v {
                    None => Some(1),
                    Some(Expr::Int(n)) => Some(*n),
                    Some(Expr::Neg(x)) if matches!(**x, Expr::Int(_)) => {
                        if let Expr::Int(n) = **x {
                            // Script integers wrap, as in Kamailio.
                            Some(n.wrapping_neg())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                match (n, v, sc.bool_ret) {
                    (Some(0), _, _) => self.line(out, ind, "exit"),
                    (Some(n), _, true) => self.line(out, ind, if n > 0 { "return true" } else { "return false" }),
                    (Some(_), _, false) => self.line(out, ind, "return"),
                    (None, Some(v), true) => {
                        let t = self.expr(v, sc, true).0;
                        self.line(out, ind, &format!("return {t}"));
                    }
                    (None, _, _) => {
                        self.notes.push("a computed return value outside a route used as a condition is dropped".into());
                        self.line(out, ind, "return");
                    }
                }
            }
        }
    }

    /// Kamailio's `switch`: cases fall through until a `break`.
    fn switch(&mut self, e: &Expr, cases: &[(Option<Expr>, Vec<Stmt>)], sc: Scope, ind: usize, out: &mut String) {
        self.switches = self.switches.saturating_add(1);
        let var = format!("switch_{}", self.switches);
        let subject = self.expr(e, sc, false).0;
        self.line(out, ind, &format!("let {var} = {subject}"));
        // Each case's code: its own, then the next ones' until a break.
        let ends = |b: &[Stmt]| matches!(b.last(), Some(Stmt::Break | Stmt::Exit | Stmt::Drop | Stmt::Return(_)));
        let mut first = true;
        let mut default: Option<Vec<Stmt>> = None;
        let mut rest = cases;
        while !rest.is_empty() {
            // Labels that share code: `case 1: case 2: …` (empty bodies),
            // then the one with the code (or the last).
            let shared = rest.iter().take(rest.len().saturating_sub(1)).take_while(|c| c.1.is_empty()).count();
            let (empty, from) = rest.split_at_checked(shared).unwrap_or((&[], rest));
            let labels: Vec<&Option<Expr>> = empty.iter().chain(from.first()).map(|c| &c.0).collect();
            let mut code: Vec<Stmt> = Vec::new();
            for (_, body) in from {
                code.extend(body.iter().cloned());
                if ends(body) {
                    break;
                }
            }
            if matches!(code.last(), Some(Stmt::Break)) {
                code.pop();
            }
            if code.iter().any(|s| contains_break(std::slice::from_ref(s))) {
                self.notes.push("a `break` inside a nested statement of a switch case can't be expressed; it was left as a loop break".into());
            }
            if labels.iter().any(|l| l.is_none()) {
                default = Some(code);
            } else {
                let conds: Vec<String> = labels
                    .iter()
                    .filter_map(|l| l.as_ref())
                    .map(|v| {
                        let v = self.expr(v, sc, false);
                        format!("{var} == {}", wrap(v, P_CMP.saturating_add(1)))
                    })
                    .collect();
                let head = format!("{}if {}", if first { "" } else { "} else " }, conds.join(" || "));
                self.line(out, ind, &format!("{head} {{"));
                self.stmts(&code, sc, ind.saturating_add(1), out);
                first = false;
            }
            rest = from.get(1..).unwrap_or_default();
        }
        match (default, first) {
            (Some(code), true) => self.stmts(&code, sc, ind, out),
            (Some(code), false) => {
                self.line(out, ind, "} else {");
                self.stmts(&code, sc, ind.saturating_add(1), out);
                self.line(out, ind, "}");
            }
            (None, false) => self.line(out, ind, "}"),
            (None, true) => {}
        }
    }

    fn body(&mut self, ss: &[Stmt], sc: Scope, out: &mut String) {
        self.stmts(ss, sc, 1, out);
        if sc.bool_ret && !matches!(ss.last(), Some(Stmt::Exit | Stmt::Drop | Stmt::Return(_))) {
            // A route ends with return(1).
            self.line(out, 1, "return true");
        }
    }
}

fn contains_break(ss: &[Stmt]) -> bool {
    ss.iter().any(|s| match s {
        Stmt::Break => true,
        Stmt::If(_, a, b) => contains_break(a) || contains_break(b),
        Stmt::Switch(_, cases) => cases.iter().any(|(_, b)| contains_break(b)),
        _ => false,
    })
}

/// The routing as `.fsr` text (formatted), and notes.
/// `consts`: the script's `#!define`s with their values (flag names).
fn routing(ast: &Ast, source: &str, defines: &[(String, String)], consts: &[(String, String)]) -> Result<(String, Tr), String> {
    let mut tr = Tr::new(ast, consts);
    let mut items: Vec<String> = Vec::new();
    // request_route
    let mut b = String::new();
    let sc = Scope { has_msg: true, request: true, ctx: ctx::REQUEST, bool_ret: false };
    tr.body(&ast.request_route, sc, &mut b);
    items.push(format!("route main(msg: Request) {{\n{b}}}\n"));
    for (name, body) in &ast.routes {
        // Every route was declared from `ast.routes`.
        let Some(r) = tr.routes.get(name) else { continue };
        let sc = Scope { has_msg: r.has_msg, request: true, ctx: r.ctx, bool_ret: r.bool_ret };
        let (fsr, params, ret) = (r.fsr.clone(), if r.has_msg { "msg: Request" } else { "" }, if r.bool_ret { " -> Bool" } else { "" });
        let mut b = String::new();
        tr.body(body, sc, &mut b);
        let header = if fsr != *name { format!("// route[{name}]\n") } else { String::new() };
        items.push(format!("{header}fn {fsr}({params}){ret} {{\n{b}}}\n"));
    }
    type Routes = Vec<(String, Vec<Stmt>)>;
    let handlers: [(&str, &str, &Routes, Kind); 4] = [
        ("failure_route", "msg: Request, ", &ast.failure_routes, Kind::Failure),
        ("branch_route", "msg: Request, ", &ast.branch_routes, Kind::Branch),
        ("onreply_route", "msg: Reply, ", &ast.onreply_routes, Kind::OnReply),
        ("event_route", "", &ast.event_routes, Kind::Event),
    ];
    for (kind, param, list, k) in handlers {
        for (name, body) in list {
            // The failure route `await` runs: a function, called after it.
            if let Some(a) = tr.await_relay.as_ref().filter(|a| k == Kind::Failure && a.route == *name) {
                let fsr = a.fsr.clone();
                let sc = Scope { has_msg: true, request: true, ctx: ctx::FAILURE, bool_ret: false };
                let mut b = String::new();
                tr.body(body, sc, &mut b);
                items.push(format!(
                    "// failure_route[{name}]: runs after `await txn.relay` (a negative final or a timeout)\nfn {fsr}(msg: Request) {{\n{b}}}\n"
                ));
                continue;
            }
            let (c, has_msg) = kind_ctx(k);
            // An onreply_route has the reply as `msg: Reply`.
            let request = k != Kind::OnReply;
            let sc = Scope { has_msg: has_msg || !request, request, ctx: c, bool_ret: false };
            let mut b = String::new();
            tr.body(body, sc, &mut b);
            items.push(format!("on kamailio.{kind}({param}name: \"{}\") {{\n{b}}}\n", esc(name)));
        }
    }
    if let Some(r) = &ast.reply_route {
        let sc = Scope { has_msg: true, request: false, ctx: ctx::REPLY, bool_ret: false };
        let mut b = String::new();
        tr.body(r, sc, &mut b);
        items.push(format!("on reply(msg: Reply) {{\n{b}}}\n"));
    }
    let defs = if defines.is_empty() { String::new() } else { format!(" with {}", defines.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ")) };
    let mut text = format!(
        "// Imported from {source}{defs} by `ferrosip import`.\n// What has no typed form is written with pv(\"$…\"), kamailio.call(…) and\n// kamailio.*_route handlers: `ferrosip lint -W raw_kamailio` lists them.\n\n"
    );
    if !tr.imports.is_empty() {
        let _ = writeln!(text, "import {}\n", tr.imports.iter().cloned().collect::<Vec<_>>().join(", "));
    }
    if !tr.flags.is_empty() || !tr.bflags.is_empty() {
        // The bits Kamailio uses (module parameters such as acc's log_flag
        // or usrloc's nat_bflag name them).
        for (bit, name) in &tr.flags {
            let _ = writeln!(text, "flag {name} = {bit}");
        }
        for (bit, name) in &tr.bflags {
            let _ = writeln!(text, "branch flag {name} = {bit}");
        }
        text.push('\n');
    }
    text.push_str(&items.join("\n"));
    let parsed = fsr::parse(&text).map_err(|e| {
        format!("internal error: the generated .fsr doesn't parse:\n{}\n--- generated:\n{text}", fsr::render_error("main.fsr", &text, e.span, &e.msg))
    })?;
    Ok((fsr::fmt::format(&parsed), tr))
}

// --------------------------------------------------------- ferrosip.toml ---

fn tv(v: toml::Value) -> String {
    v.to_string()
}

fn dur(n: i64, unit: Unit) -> String {
    let ms = if unit == Unit::Sec { n.saturating_mul(1000) } else { n };
    if ms <= 0 {
        return n.to_string();
    }
    for (div, suf) in [(86_400_000, "d"), (3_600_000, "h"), (60_000, "m"), (1000, "s")] {
        if ms.checked_rem(div) == Some(0)
            && let Some(n) = ms.checked_div(div)
        {
            return tv(toml::Value::String(format!("{n}{suf}")));
        }
    }
    tv(toml::Value::String(format!("{ms}ms")))
}

/// A modparam value (as Kamailio passes it) in ferrosip.toml terms, for
/// a parameter of type `ty`; `None` when it doesn't convert.
fn typed_value(ty: &Ty, raw: &RawArg) -> Option<String> {
    let text = match raw {
        RawArg::Str(s) => s.clone(),
        RawArg::Int(i) => i.to_string(),
        RawArg::Pv(_) => return None,
    };
    let int = || text.trim().parse::<i64>().ok();
    Some(match ty {
        Ty::Str => tv(toml::Value::String(text)),
        Ty::Int { min, max } => {
            let n = int()?;
            if n < *min || n > *max {
                return None;
            }
            n.to_string()
        }
        Ty::Bool => match text.trim().to_ascii_lowercase().as_str() {
            "1" | "yes" | "on" | "true" => "true".into(),
            "0" | "no" | "off" | "false" => "false".into(),
            t => (t.parse::<i64>().ok()? != 0).to_string(),
        },
        Ty::Duration(u) => match int() {
            Some(n) => dur(n, *u),
            None => tv(toml::Value::String(text)),
        },
        Ty::Enum(pairs) => {
            let t = text.trim();
            let name = pairs.iter().find(|(n, v)| *v == t || *n == t).map(|(n, _)| *n)?;
            tv(toml::Value::String(name.into()))
        }
        Ty::List(t) => return typed_value(t, raw),
    })
}

fn raw_value(raw: &RawArg) -> Option<String> {
    match raw {
        RawArg::Str(s) => Some(tv(toml::Value::String(s.clone()))),
        RawArg::Int(i) => Some(i.to_string()),
        RawArg::Pv(_) => None,
    }
}

/// Whether a `listen=` value names its protocol.
fn has_listen_proto(v: &str) -> bool {
    let v = v.trim().trim_matches('"').trim_start_matches('"');
    v.split_once(':').is_some_and(|(p, _)| matches!(p, "udp" | "tcp" | "tls" | "ws" | "wss" | "sctp"))
}

/// `listen=` → a [[listen]] entry (proto, addr, advertise).
fn listen_entry(v: &str) -> Option<(String, String, Option<String>)> {
    let v = v.trim().trim_matches('"');
    let mut words = v.split_whitespace();
    let addr = words.next()?.replace('"', "");
    let mut advertise = None;
    while let Some(w) = words.next() {
        if w.eq_ignore_ascii_case("advertise") {
            advertise = words.next().map(|a| a.trim_matches('"').to_string());
        }
    }
    let (proto, rest) = match addr.split_once(':') {
        Some((p, r)) if matches!(p, "udp" | "tcp" | "tls" | "ws" | "wss" | "sctp") => (p.to_string(), r.to_string()),
        _ => ("udp".to_string(), addr.clone()),
    };
    // Kamailio's default ports: 5061 for TLS, 5060 otherwise.
    let port = if matches!(proto.as_str(), "tls" | "wss") { 5061 } else { 5060 };
    let has_port = if rest.starts_with('[') { rest.contains("]:") } else { rest.matches(':').count() == 1 };
    let rest = if has_port { rest } else { format!("{rest}:{port}") };
    Some((proto, rest, advertise))
}

fn log_level(debug: &str) -> Option<&'static str> {
    let n: i64 = debug.trim().parse().ok()?;
    Some(match n {
        i64::MIN..=-5 => "alert",
        -4..=-2 => "crit",
        -1 => "err",
        0 => "warn",
        1 => "notice",
        2 => "info",
        _ => "debug",
    })
}

struct TomlOut {
    text: String,
    notes: Vec<String>,
}

fn toml_of(ast: &Ast, core: &[sip_script::preprocess::CoreParam], entry: &str) -> TomlOut {
    let mut t = String::new();
    let mut notes = Vec::new();
    let mut comments = Vec::new();
    // [core]
    let mut core_lines = Vec::new();
    let mut listens = Vec::new();
    let mut implicit_tcp = Vec::new();
    let mut disable_tcp = false;
    let mut aliases = Vec::new();
    let mut cfg_vars: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Core `max_branches`: ferrosip keeps it as tm's `max_branches`.
    let mut max_branches = None;
    let has_tm = ast.modules.iter().any(|m| m == "tm");
    for p in core {
        // `group.name = value desc "…"`: a custom config variable.
        if let Some((g, n)) = p.name.split_once('.') {
            match sip_core::cfgvars::parse_decl(&p.value) {
                Ok((val, desc)) => {
                    let v = match val {
                        sip_core::pv::Val::Int(i) => i.to_string(),
                        other => tv(toml::Value::String(other.to_string())),
                    };
                    let key = if is_ident(n) { n.to_string() } else { tv(toml::Value::String(n.into())) };
                    let line =
                        if desc.is_empty() { format!("{key} = {v}") } else { format!("{key} = {{ value = {v}, desc = {} }}", tv(toml::Value::String(desc))) };
                    cfg_vars.entry(g.to_string()).or_default().push(line);
                }
                Err(e) => notes.push(format!("{}: {e}", p.name)),
            }
            continue;
        }
        let name = p.name.to_ascii_lowercase();
        let v = p.value.trim().trim_matches('"').to_string();
        let num = v.parse::<i64>().ok();
        let yes = matches!(v.to_ascii_lowercase().as_str(), "yes" | "on" | "true" | "1");
        let line = match (name.as_str(), num) {
            ("listen", _) => {
                match listen_entry(&v) {
                    // Without a protocol Kamailio listens on every enabled
                    // one (socket_info.c next_proto): UDP and TCP here.
                    Some((proto, addr, adv)) if !has_listen_proto(&v) => {
                        listens.push((proto, addr.clone(), adv.clone()));
                        implicit_tcp.push(("tcp".to_string(), addr, adv));
                    }
                    Some(l) => listens.push(l),
                    None => comments.push(format!("# listen = {v}  (not understood)")),
                }
                continue;
            }
            ("alias", _) => {
                let host = v.rsplit_once(':').map_or(v.as_str(), |(h, port)| if port.chars().all(|c| c.is_ascii_digit()) { h } else { v.as_str() });
                let host = host.split_once(':').map_or(host, |(proto, h)| if matches!(proto, "udp" | "tcp" | "tls" | "ws" | "wss") { h } else { host });
                aliases.push(host.to_string());
                continue;
            }
            ("disable_tcp", _) => {
                disable_tcp = yes;
                continue;
            }
            ("children", Some(n)) => format!("workers = {}", n.max(1)),
            ("tcp_children", Some(n)) => format!("tcp_readers = {}", n.max(1)),
            ("debug", _) => match log_level(&v) {
                Some(l) => format!("log_level = \"{l}\""),
                None => continue,
            },
            ("tcp_max_connections" | "tcp_accept_iplimit" | "tcp_conn_wq_max", Some(n)) => format!("{name} = {n}"),
            ("tcp_connection_lifetime" | "tcp_connect_timeout", Some(n)) => format!("{name} = {}", dur(n, Unit::Sec)),
            ("tcp_keepidle", Some(n)) => format!("tcp_keepalive = {}", dur(n, Unit::Sec)),
            ("tcp_accept_aliases", _) => format!("tcp_accept_aliases = {yes}"),
            ("max_branches", Some(n)) if has_tm => {
                max_branches = Some(n);
                continue;
            }
            _ => {
                comments.push(format!("# {} = {}  (Kamailio core setting; no effect in ferrosip)", p.name, p.value.trim()));
                continue;
            }
        };
        core_lines.push(line);
    }
    if !aliases.is_empty() {
        core_lines.push(format!("aliases = [{}]", aliases.iter().map(|a| tv(toml::Value::String(a.clone()))).collect::<Vec<_>>().join(", ")));
    }
    if !core_lines.is_empty() || !comments.is_empty() {
        t.push_str("[core]\n");
        for l in &core_lines {
            let _ = writeln!(t, "{l}");
        }
        for c in &comments {
            let _ = writeln!(t, "{c}");
        }
        t.push('\n');
    }
    if !disable_tcp {
        listens.append(&mut implicit_tcp);
    }
    for (proto, addr, adv) in &listens {
        let _ = writeln!(t, "[[listen]]\nproto = {}\naddr = {}", tv(toml::Value::String(proto.clone())), tv(toml::Value::String(addr.clone())));
        if let Some(a) = adv {
            let _ = writeln!(t, "advertise = {}", tv(toml::Value::String(a.clone())));
        }
        t.push('\n');
    }
    for (g, lines) in &cfg_vars {
        let _ = writeln!(t, "[cfg_vars.{g}]");
        for l in lines {
            let _ = writeln!(t, "{l}");
        }
        t.push('\n');
    }
    // TLS module parameters → [tls.default].
    let tls: Vec<(&str, String)> = ast
        .modparams
        .iter()
        .filter(|p| p.module == "tls")
        .filter_map(|p| match &p.value {
            RawArg::Str(s) => Some((p.name.as_str(), s.clone())),
            RawArg::Int(i) => Some((p.name.as_str(), i.to_string())),
            RawArg::Pv(_) => None,
        })
        .collect();
    if !tls.is_empty() {
        t.push_str("[tls.default]\n");
        for (n, v) in &tls {
            let line = match *n {
                "certificate" => format!("cert = {}", tv(toml::Value::String(v.clone()))),
                "private_key" => format!("key = {}", tv(toml::Value::String(v.clone()))),
                "ca_list" => format!("ca = {}", tv(toml::Value::String(v.clone()))),
                "verify_certificate" | "require_certificate" => format!("verify_client = {}", v.trim() == "1"),
                "config" => format!("profile = {}", tv(toml::Value::String(v.clone()))),
                _ => format!("# {n} = {v}  (tls parameter; no effect in ferrosip)"),
            };
            let _ = writeln!(t, "{line}");
        }
        t.push('\n');
    }
    // Modules, in load order, with their parameters.
    for m in &ast.modules {
        let targets = |pm: &str| pm.split('|').any(|n| n == m);
        let params: Vec<&sip_script::ModParam> = ast.modparams.iter().filter(|p| targets(&p.module)).collect();
        let _ = writeln!(t, "[modules.{m}]");
        if let Some(n) = max_branches.filter(|_| m == "tm" && !params.iter().any(|p| p.name == "max_branches")) {
            let _ = writeln!(t, "max_branches = {n}   # core max_branches");
        }
        if m == "tls" {
            t.push_str("# parameters: see [tls.default]\n\n");
            continue;
        }
        let spec: Option<Vec<ParamSpec>> = crate::schema_of(m).flatten();
        // name → values, in order (repeated parameters add values).
        let mut raw_lines: Vec<String> = Vec::new();
        let mut by: Vec<(String, Vec<&RawArg>)> = Vec::new();
        for p in &params {
            match by.iter_mut().find(|(n, _)| *n == p.name) {
                Some((_, v)) => v.push(&p.value),
                None => by.push((p.name.clone(), vec![&p.value])),
            }
        }
        for (name, vals) in by {
            let key = if is_ident(&name) { name.clone() } else { tv(toml::Value::String(name.clone())) };
            let one = |v: &RawArg| -> Option<String> {
                match &spec {
                    None => raw_value(v),
                    Some(s) => {
                        let p = s.iter().find(|p| p.name == name)?;
                        let out = typed_value(&p.ty, v)?;
                        // It must convert back to what the module would get.
                        let back = format!("v = {out}").parse::<toml::Table>().ok()?.get("v").cloned()?;
                        schema::convert(p, &config::neutral(&back).ok()?).ok()?;
                        Some(out)
                    }
                }
            };
            let list = spec.as_ref().and_then(|s| s.iter().find(|p| p.name == name)).is_none_or(|p| matches!(p.ty, Ty::List(_)));
            let converted: Option<Vec<String>> = vals.iter().map(|v| one(v)).collect();
            match converted.as_deref() {
                Some([one]) => {
                    let _ = writeln!(t, "{key} = {one}");
                }
                Some(c) if list => {
                    let _ = writeln!(t, "{key} = [{}]", c.join(", "));
                }
                Some(c) => {
                    notes.push(format!("modparam {m}.{name} is set {} times; the last value is kept", c.len()));
                    let _ = writeln!(t, "{key} = {}", c.last().map_or("", String::as_str));
                }
                None if crate::compat::no_effect(m, &name) => {
                    let _ = writeln!(t, "# {name} = {}  (no effect in ferrosip)", vals.iter().filter_map(|v| raw_value(v)).collect::<Vec<_>>().join(", "));
                }
                None => {
                    // Not in the schema (or not convertible): passed to the
                    // module as the modparam did.
                    let raw: Vec<String> = vals.iter().filter_map(|v| raw_value(v)).collect();
                    let in_schema = spec.as_ref().is_some_and(|s| s.iter().any(|p| p.name == name));
                    if in_schema {
                        notes.push(format!("modparam {m}.{name}: the value doesn't fit ferrosip.toml's type; passed as written ([modules.{m}.kamailio])"));
                    }
                    raw_lines.push(match raw.as_slice() {
                        [one] => format!("{key} = {one}"),
                        _ => format!("{key} = [{}]", raw.join(", ")),
                    });
                }
            }
        }
        if !raw_lines.is_empty() {
            let _ = writeln!(t, "\n[modules.{m}.kamailio]   # as modparam passes them (not in the schema)");
            for l in &raw_lines {
                let _ = writeln!(t, "{l}");
            }
        }
        t.push('\n');
    }
    for p in ast.modparams.iter().filter(|p| !p.module.split('|').any(|n| ast.modules.contains(&n.to_string()))) {
        notes.push(format!("modparam for {} which is not loaded: dropped", p.module));
    }
    let _ = write!(t, "[routing]\nentry = {}\n", tv(toml::Value::String(entry.into())));
    TomlOut { text: t, notes }
}

// ------------------------------------------------------------------ main ---

pub fn main(args: &[String]) -> Result<i32, String> {
    let mut file = None;
    let mut out_dir = PathBuf::from("imported");
    let mut defines = Vec::new();
    let mut force = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(0);
            }
            "-o" => {
                out_dir = it.next().ok_or("-o needs a directory")?.into();
            }
            "--define" => {
                let d = it.next().ok_or("--define needs NAME[=VALUE]")?;
                let (n, v) = d.split_once('=').unwrap_or((d, ""));
                defines.push((n.to_string(), v.to_string()));
            }
            "--force" => force = true,
            a if !a.starts_with('-') && file.is_none() => file = Some(a.to_string()),
            a => return Err(format!("unknown option {a:?}\n{USAGE}")),
        }
    }
    let file = file.ok_or(USAGE)?;
    let pp = sip_script::preprocess::preprocess_file(&file, &defines)?;
    let ast = sip_script::parse(&pp.text).map_err(|e| pp.locate_error(&e))?;
    let source = Path::new(&file).file_name().map_or(file.clone(), |f| f.to_string_lossy().into_owned());
    let (fsr_text, tr) = routing(&ast, &source, &defines, &pp.values)?;
    let toml = toml_of(&ast, &pp.core, "routes/main.fsr");
    let (toml_path, fsr_path) = (out_dir.join("ferrosip.toml"), out_dir.join("routes").join("main.fsr"));
    for p in [&toml_path, &fsr_path] {
        if p.exists() && !force {
            return Err(format!("{} exists (--force to overwrite)", p.display()));
        }
    }
    std::fs::create_dir_all(out_dir.join("routes")).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let header = format!("# Imported from {source} by `ferrosip import`. Routing: routes/main.fsr.\n\n");
    std::fs::write(&toml_path, header + &toml.text).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    std::fs::write(&fsr_path, &fsr_text).map_err(|e| format!("{}: {e}", fsr_path.display()))?;
    let mut notes: Vec<String> = tr.notes.into_iter().chain(toml.notes).collect();
    notes.sort();
    notes.dedup();
    eprintln!("ferrosip import: wrote {} and {}", toml_path.display(), fsr_path.display());
    eprintln!(
        "  {} routes, {} typed forms, {} escape-hatch uses (`ferrosip lint -W raw_kamailio --config {}` lists them)",
        [1, ast.routes.len(), ast.failure_routes.len(), ast.branch_routes.len(), ast.onreply_routes.len(), ast.event_routes.len()].iter().sum::<usize>(),
        tr.typed,
        tr.raw,
        toml_path.display()
    );
    for n in &notes {
        eprintln!("  note: {n}");
    }
    // Check the result, as `ferrosip check --config` would.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out =
        std::process::Command::new(exe).args(["check", "--config"]).arg(&toml_path).env("FERROSIP_IMPORT_CHECK", "1").output().map_err(|e| e.to_string())?;
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        eprintln!("ferrosip import: {}: config OK", toml_path.display());
        Ok(0)
    } else {
        eprintln!("ferrosip import: the imported configuration does not pass `ferrosip check`:\n{}", err.trim_end());
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Import a script (modules loaded as written) and compile the result.
    fn import(cfg: &str) -> String {
        let pp = sip_script::preprocess::preprocess_str("t.cfg", cfg, &[]).unwrap();
        let ast = sip_script::parse(&pp.text).unwrap();
        let (text, _) = routing(&ast, "t.cfg", &[], &pp.values).unwrap();
        let env = crate::fsr_env(Default::default());
        if let Err(e) = fsr::compile_source("main.fsr", &text, &env) {
            panic!("the import doesn't compile:\n{e}\n--- import:\n{text}");
        }
        text
    }

    fn has(text: &str, wants: &[&str]) {
        for w in wants {
            assert!(text.contains(w), "missing:\n{w}\n--- in:\n{text}");
        }
    }

    #[test]
    fn typed_where_exact_raw_elsewhere() {
        let t = import(
            r#"loadmodule "tm"
loadmodule "sl"
loadmodule "rr"
loadmodule "usrloc"
loadmodule "registrar"
loadmodule "textops"
request_route {
    if (is_method("REGISTER")) {
        if (!save("location")) { sl_reply_error(); }
        exit;
    }
    if ($rm == "INVITE" && !has_totag()) { record_route(); }
    $ru = "sip:" + $rU + "@10.0.0.1";
    $avp(x) = $(ru{s.len});
    if ($var(n)) { $var(n) = $var(n) | 4; }
    if (!lookup("location")) { sl_send_reply("404", "Not Found"); exit; }
    if (!t_relay()) { sl_reply_error(); }
    exit;
}
"#,
        );
        has(
            &t,
            &[
                "import location, route_set\n",
                "if msg.method == REGISTER {\n        location.save()\n    }",
                "if msg.method == INVITE && !msg.has_to_tag {\n        route_set.record()\n    }",
                "msg.ruri = \"sip:\" + msg.ruri.user + \"@10.0.0.1\"",
                "pv(\"$avp(x)\") = pv(\"$(ru\\{s.len\\})\")",
                "if pv(\"$var(n)\") {\n        pv(\"$var(n)\") = kamailio.bitor(pv(\"$var(n)\"), 4)",
                "if !location.lookup() {\n        reply(NotFound)\n    }",
                "    txn.relay()\n}",
            ],
        );
    }

    #[test]
    fn routes_switches_and_handlers() {
        let t = import(
            r#"loadmodule "tm"
loadmodule "sl"
loadmodule "xlog"
request_route {
    if (!route(CHECK)) { drop; }
    switch ($rU) {
        case "a":
        case "b":
            $var(x) = 1;
            break;
        case "c":
            $var(x) = 2;
        case "d":
            $var(x) = 3;
            break;
        default:
            $var(x) = 0;
    }
    t_on_failure("MISSED");
    route(RELAY);
}
route[CHECK] {
    if ($si == "10.0.0.9") { return(-1); }
    if ($rU == "stop") { return(0); }
}
route[RELAY] {
    t_relay();
}
failure_route[MISSED] {
    if (t_is_canceled()) { exit; }
    $ru = "sip:vm@10.0.0.2";
    route(RELAY);
}
onreply_route {
    xlog("L_INFO", "reply $rs\n");
}
event_route[tm:local-request] {
    xlog("L_INFO", "local\n");
}
"#,
        );
        has(
            &t,
            &[
                "if !check(msg) {\n        drop\n    }",
                "let switch_1 = msg.ruri.user",
                "if switch_1 == \"a\" || switch_1 == \"b\" {\n        pv(\"$var(x)\") = 1\n    } else if switch_1 == \"c\" {\n        pv(\"$var(x)\") = 2\n        pv(\"$var(x)\") = 3\n    } else if switch_1 == \"d\" {",
                "    } else {\n        pv(\"$var(x)\") = 0\n    }",
                "kamailio.call(\"t_on_failure\", \"MISSED\")",
                "    relay_route(msg)\n}",
                "// route[CHECK]\nfn check(msg: Request) -> Bool {\n    if msg.src.ip == \"10.0.0.9\" {\n        return false\n    }\n    if msg.ruri.user == \"stop\" {\n        exit\n    }\n    return true\n}",
                "on kamailio.failure_route(msg: Request, name: \"MISSED\") {",
                // xlog("L_INFO", …) is xinfo(…): log.info.
                "on reply(msg: Reply) {\n    log.info(\"reply {msg.code}\\n\")\n}",
                "on kamailio.event_route(name: \"tm:local-request\") {",
            ],
        );
    }

    /// Core `max_branches` (Kamailio's sr_dst_max_branches) becomes tm's
    /// `max_branches`, where ferrosip keeps it; a tm modparam wins.
    #[test]
    fn core_max_branches_goes_to_tm() {
        let toml = |cfg: &str| {
            let pp = sip_script::preprocess::preprocess_str("t.cfg", cfg, &[]).unwrap();
            let ast = sip_script::parse(&pp.text).unwrap();
            toml_of(&ast, &pp.core, "routes/main.fsr").text
        };
        let t = toml("max_branches=4\nloadmodule \"tm\"\nrequest_route { exit; }\n");
        has(&t, &["[modules.tm]\nmax_branches = 4   # core max_branches\n"]);
        assert!(!t.contains("# max_branches"), "{t}");
        let t = toml("max_branches=4\nloadmodule \"sl\"\nrequest_route { exit; }\n");
        has(&t, &["# max_branches = 4  (Kamailio core setting; no effect in ferrosip)"]);
    }

    #[test]
    fn routes_named_in_strings_keep_their_name() {
        let t = import(
            "loadmodule \"tm\"\nloadmodule \"rtimer\"\nmodparam(\"rtimer\", \"exec\", \"timer=t;route=TICK\")\nrequest_route { exit; }\nroute[TICK] { xlog(\"L_INFO\", \"tick\\n\"); }\n",
        );
        // (and it gets the message: rtimer runs it with a faked one)
        has(&t, &["fn TICK(msg: Request) {"]);
    }

    #[test]
    fn flags_by_their_define() {
        let t = import(
            r#"#!define FLT_ACC 1
#!define FLT_NATS 5
#!define FLB_NATB 6
#!define MAX 6
#!define ONE 1
loadmodule "tm"
loadmodule "xlog"
request_route {
    if (is_method("INVITE")) { setflag(FLT_ACC); }
    if (isflagset(FLT_NATS)) { setbflag(FLB_NATB); resetflag(FLT_NATS); }
    if (isflagset(6) || isflagset(9)) { exit; }
    setflag(40);
    route(NOMSG);
    t_on_reply("R");
    t_relay();
}
route[NOMSG] { setflag(FLT_ACC); }
onreply_route[R] { if (isflagset(FLT_ACC)) { resetflag(FLT_ACC); } }
event_route[tm:local-request] { setflag(FLT_ACC); }
"#,
        );
        has(
            &t,
            &[
                // a FLT_ define first, the one define with a value, else FLAG_n
                "flag FLT_ACC = 1\nflag FLT_NATS = 5\nflag MAX = 6\nflag FLAG_9 = 9\nbranch flag FLB_NATB = 6\n",
                "if msg.method == INVITE {\n        msg.set(FLT_ACC)\n    }",
                "if msg.is(FLT_NATS) {\n        msg.set(FLB_NATB)\n        msg.reset(FLT_NATS)\n    }",
                "if msg.is(MAX) || msg.is(FLAG_9) {",
                // out of range, no message: raw
                "kamailio.call(\"setflag\", 40)",
                "on kamailio.onreply_route(msg: Reply, name: \"R\") {\n    if msg.is(FLT_ACC) {\n        msg.reset(FLT_ACC)\n    }",
                "on kamailio.event_route(name: \"tm:local-request\") {\n    kamailio.call(\"setflag\", 1)",
            ],
        );
    }

    #[test]
    fn branch_flags_by_their_define() {
        let t = import(
            r#"#!define FLT_X 6
#!define FLB_NATB 6
#!define FLB_SIPPING 7
#!define FLT_ACC 1
loadmodule "tm"
request_route {
    if (isflagset(FLT_X)) { setbflag(FLB_NATB); }
    if (isbflagset(FLB_NATB) || isbflagset(9)) { resetbflag(FLB_SIPPING, 0); }
    setbflag(FLT_ACC);
    setbflag(40);
    route(NOMSG);
    t_relay();
}
route[NOMSG] { setbflag(FLB_NATB); }
event_route[tm:local-request] { setbflag(FLB_NATB); }
"#,
        );
        has(
            &t,
            &[
                // a FLB_ define first, never a FLT_ one; else BFLAG_n
                "flag FLT_X = 6\nbranch flag BFLAG_1 = 1\nbranch flag FLB_NATB = 6\nbranch flag FLB_SIPPING = 7\nbranch flag BFLAG_9 = 9\n",
                "    msg.set(BFLAG_1)\n",
                "if msg.is(FLT_X) {\n        msg.set(FLB_NATB)\n    }",
                "if msg.is(FLB_NATB) || msg.is(BFLAG_9) {\n        msg.reset(FLB_SIPPING, branch: 0)\n    }",
                // out of range, no message: raw
                "kamailio.call(\"setbflag\", 40)",
                "on kamailio.event_route(name: \"tm:local-request\") {\n    kamailio.call(\"setbflag\", 6)",
            ],
        );
    }

    #[test]
    fn core_functions_and_reply_error_that_goes_on() {
        let t = import(
            r#"loadmodule "tm"
loadmodule "sl"
loadmodule "usrloc"
loadmodule "registrar"
request_route {
    set_reply_no_connect();
    force_rport();
    if (is_method("REGISTER")) {
        if (!save("location")) { send_reply_error(); }
        exit;
    }
    if (!t_newtran()) { send_reply_error(); exit; }
    if (!t_relay()) { send_reply_error(); }
    exit;
}
"#,
        );
        has(
            &t,
            &[
                // force_rport is the core's: typed without siputils loaded
                "import location, sip, stateless\n",
                "    sip.reply_no_connect()\n    sip.force_rport()\n",
                "if !location.save_and_continue() {\n            stateless.reply_error_and_continue()\n        }\n        exit",
                "if !txn.create() {\n        stateless.reply_error_and_continue()\n        exit\n    }",
                "if !kamailio.call(\"t_relay\") {\n        stateless.reply_error_and_continue()\n    }\n    exit\n}",
            ],
        );
    }

    /// The stock route(RELAY) shape: conditional arming behind
    /// t_is_set, `if (!t_relay()) { send_reply_error(); }`, `exit`.
    const RELAY_ROUTE: &str = r#"loadmodule "tm"
loadmodule "sl"
request_route {
    if (is_method("INVITE")) { $avp(x) = "1"; }
    route(RELAY);
    exit;
}
route[RELAY] {
    if (is_method("INVITE|BYE")) {
        if(!t_is_set("branch_route")) t_on_branch("B");
    }
    if (is_method("INVITE")) {
        if(!t_is_set("failure_route")) t_on_failure("MISSED");
    }
    if (!t_relay()) {
        send_reply_error();
    }
    exit;
}
failure_route[MISSED] {
    if (t_is_canceled()) { exit; }
    if (t_check_status("486|408")) {
        $ru = "sip:vm@10.0.0.2";
        route(RELAY);
    }
}
branch_route[B] { xlog("L_INFO", "branch\n"); }
"#;

    #[test]
    fn failure_routes_as_await() {
        let t = import(RELAY_ROUTE);
        has(
            &t,
            &[
                "if msg.method == INVITE {\n        let res = await txn.relay(msg)\n        match res {\n            Final(r) if !r.sent => stateless.reply_error_and_continue()\n            Final(r) if r.code < 300 => {}\n            _ => missed(msg)\n        }\n        exit\n    }\n    if !kamailio.call(\"t_relay\") {\n        stateless.reply_error_and_continue()\n    }\n    exit\n}",
                // branch arming stays: branch_route is its own handler
                "kamailio.call(\"t_on_branch\", \"B\")",
                "// failure_route[MISSED]: runs after `await txn.relay` (a negative final or a timeout)\nfn missed(msg: Request) {\n    if txn.is_canceled() {\n        exit\n    }\n    if txn.code == BusyHere || txn.code == RequestTimeout {\n        msg.ruri = \"sip:vm@10.0.0.2\"\n        relay_route(msg)\n    }\n}",
                "on kamailio.branch_route(msg: Request, name: \"B\")",
            ],
        );
        assert!(!t.contains("t_on_failure") && !t.contains("failure_route(") && !t.contains("\"failure_route\""), "{t}");
        // The plain shapes: unconditional, unguarded, no error handling.
        let t = import(
            "loadmodule \"tm\"\nrequest_route {\n    t_on_failure(\"F\");\n    t_relay();\n    exit;\n}\nfailure_route[F] {\n    t_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
        );
        has(
            &t,
            &[
                "route main(msg: Request) {\n    let res = await txn.relay(msg)\n    match res {\n        Final(r) if !r.sent => {}\n        Final(r) if r.code < 300 => {}\n        _ => f(msg)\n    }\n    exit\n}",
                // reply() is t_reply after await, as in the failure route
                "fn f(msg: Request) {\n    reply(NotFound)\n}",
            ],
        );
    }

    #[test]
    fn failure_routes_that_stay_handlers() {
        let base = RELAY_ROUTE;
        let cases: [(&str, &str, &str); 8] = [
            // something between the arming and the relay
            ("if (!t_relay()) {", "append_hf(\"X: 1\\r\\n\");\n    if (!t_relay()) {", "another call in between"),
            // no exit after: the code after t_relay runs before the final
            ("    exit;\n}\nfailure_route", "    return;\n}\nfailure_route", "no exit after the relay"),
            // a second t_on_failure anywhere
            ("branch_route[B] {", "onreply_route[R] { t_on_failure(\"MISSED\"); }\nbranch_route[B] {", "a second arming"),
            // t_is_set("failure_route") elsewhere (a branch_route would see it set)
            ("xlog(\"L_INFO\", \"branch\\n\");", "if (t_is_set(\"failure_route\")) { xlog(\"L_INFO\", \"armed\\n\"); }", "t_is_set elsewhere"),
            // the route is used for its value
            ("    route(RELAY);\n    exit;\n}\nroute[RELAY]", "    if (route(RELAY)) { exit; }\n    exit;\n}\nroute[RELAY]", "used as a condition"),
            // called from a branch route (no await there)
            ("branch_route[B] { ", "branch_route[B] { if ($rU == \"x\") { route(RELAY); } ", "called from a branch route"),
            // an error handler other than send_reply_error / sl_reply_error
            ("        send_reply_error();\n", "        sl_send_reply(\"500\", \"Oops\");\n", "another error reply"),
            // a condition with an effect
            (
                "if (is_method(\"INVITE\")) {\n        if(!t_is_set(\"failure_route\"))",
                "if (is_method(\"INVITE\") && $var(n) == 1 && lookup(\"location\")) {\n        if(!t_is_set(\"failure_route\"))",
                "a condition with a call",
            ),
        ];
        for (from, to, why) in cases {
            assert!(base.contains(from), "{why}: {from}");
            let cfg = base.replace(from, to);
            let cfg = if why == "a condition with a call" {
                cfg.replace("loadmodule \"sl\"", "loadmodule \"sl\"\nloadmodule \"usrloc\"\nloadmodule \"registrar\"")
            } else {
                cfg
            };
            let t = import(&cfg);
            assert!(!t.contains("await") && t.contains("on kamailio.failure_route(msg: Request, name: \"MISSED\")"), "{why}:\n{t}");
        }
    }

    #[test]
    fn xlog_levels_headers_and_numbers() {
        let t = import(
            r#"loadmodule "tm"
loadmodule "xlog"
loadmodule "sanity"
loadmodule "maxfwd"
request_route {
    if (!mf_process_maxfwd_header("10")) { exit; }
    if (!sanity_check("17895", "7")) {
        xlog("Malformed SIP request from $si:$sp\n");
        exit;
    }
    if ($hdr(Event) == "message-summary") { xlog("L_INFO", "mwi $hdr(Event) cseq $cs port $rp\n"); }
    if ($hdr(Max-Forwards) > 5 || $hdr(Via[1]) == "x") { xlog("L_DBG", "dbg\n"); }
    if (xlog("L_WARN", "w\n")) { xlog("L_NOTICE", "n\n"); }
    xlog("$var(lvl)", "dyn\n");
    xlog("L_ERR", "e\n");
    t_on_reply("R");
    t_relay();
}
onreply_route[R] { xlog("L_ALERT", "reply $rs from $si:$sp\n"); }
"#,
        );
        has(
            &t,
            &[
                "if !sip.process(10) {",
                "if !sip.check(17895, 7) {\n        log.error(\"Malformed SIP request from {msg.src.ip}:{msg.src.port}\\n\")",
                "if msg.headers[\"Event\"] == \"message-summary\" {\n        log.info(\"mwi {msg.headers[\"Event\"]} cseq {msg.cseq} port {msg.ruri.port}\\n\")",
                // compared with a number, an indexed header: raw
                "if pv(\"$hdr(Max-Forwards)\") > 5 || pv(\"$hdr(Via[1])\") == \"x\" {\n        log.debug(\"dbg\\n\")",
                // a log call tested for its value, a level in a variable: raw
                "if kamailio.call(\"xlog\", \"L_WARN\", \"w\\n\") {\n        log.notice(\"n\\n\")",
                "kamailio.call(\"xlog\", \"{pv(\"$var(lvl)\")}\", \"dyn\\n\")",
                "log.error(\"e\\n\")",
                "log.alert(\"reply {msg.code} from {msg.src.ip}:{msg.src.port}\\n\")",
            ],
        );
    }

    #[test]
    fn reply_code_tests_by_name() {
        let t = import(
            r#"loadmodule "tm"
loadmodule "sl"
loadmodule "xlog"
request_route {
    if ($T_reply_code == 486 || t_check_status("486")) { exit; }
    t_on_failure("F");
    t_on_reply("R");
    t_relay();
}
failure_route[F] {
    if (t_check_status("486|408")) { exit; }
    if (t_check_status("3[0-9][0-9]")) { exit; }
    if (t_check_status("5[0-9][0-9]|486|499")) { exit; }
    if (t_check_status("4[0-8][0-9]")) { exit; }
    if (!t_check_status("401|407")) { exit; }
    if ($T_reply_code == 486 || $T_reply_code != "408" || $T_reply_code >= 500) { exit; }
    if ($T_reply_code =~ "^6") { exit; }
    xlog("L_INFO", "failed: $T_reply_code $T_reply_reason\n");
}
onreply_route[R] {
    if ($rs == 180) { xlog("L_INFO", "ringing $rr from $fu\n"); }
    if (t_check_status("1[0-9][0-9]") && $rs < 200) { exit; }
}
"#,
        );
        has(
            &t,
            &[
                // a request route: nothing changes
                "if pv(\"$T_reply_code\") == 486 || kamailio.call(\"t_check_status\", \"486\") {",
                "if txn.code == BusyHere || txn.code == RequestTimeout {",
                "if txn.code in 300..399 {",
                "if txn.code in 500..599 || txn.code == BusyHere || txn.code == 499 {",
                "if txn.status_is(\"4[0-8][0-9]\") {",
                "if !(txn.code == Unauthorized || txn.code == ProxyAuthenticationRequired) {",
                "if txn.code == BusyHere || txn.code != RequestTimeout || txn.code >= 500 {",
                "if pv(\"$T_reply_code\") =~ \"^6\" {",
                "\"failed: {txn.code} {txn.reason}\\n\"",
                "if msg.code == Ringing {",
                "\"ringing {msg.reason} from {msg.from.uri}\\n\"",
                "if txn.code in 100..199 && msg.code < 200 {",
            ],
        );
    }

    #[test]
    fn reply_code_regexes_by_range() {
        let t = import(
            r#"loadmodule "tm"
request_route {
    if ($rs =~ "[12][0-9][0-9]") { exit; }
    t_on_failure("F");
    t_on_reply("R");
    t_relay();
}
failure_route[F] {
    if ($T_reply_code =~ "[1-3][0-9][0-9]") { exit; }
    if ($T_reply_code =~ "[15][0-9][0-9]") { exit; }
    if ($T_reply_code =~ "486") { exit; }
    if ($T_reply_code !~ "486|5[0-9][0-9]") { exit; }
    if ($T_reply_code =~ "4") { exit; }
    if ($T_reply_code =~ "4..") { exit; }
    if ($T_reply_code =~ ".*") { exit; }
    if ($T_reply_code =~ "[^1][0-9][0-9]") { exit; }
}
onreply_route[R] {
    if (status =~ "[12][0-9][0-9]") { exit; }
    if ($rs !~ "[3-6][0-9][0-9]") { exit; }
    if ($rs !~ "180") { exit; }
}
"#,
        );
        has(
            &t,
            &[
                // a request route: no reply code
                "if pv(\"$rs\") =~ \"[12][0-9][0-9]\" {",
                "if txn.code in 100..399 {",
                "if txn.code in 100..199 || txn.code in 500..599 {",
                "if txn.code == BusyHere {",
                "if !(txn.code == BusyHere || txn.code in 500..599) {",
                // unanchored `=~`: shorter patterns match inside a code
                "if pv(\"$T_reply_code\") =~ \"4\" {",
                "if pv(\"$T_reply_code\") =~ \"4..\" {",
                "if pv(\"$T_reply_code\") =~ \".*\" {",
                "if pv(\"$T_reply_code\") =~ \"[^1][0-9][0-9]\" {",
                "if msg.code in 100..299 {",
                "if !(msg.code in 300..699) {",
                "if msg.code != Ringing {",
            ],
        );
    }

    fn replies(body: &str) -> String {
        import(&format!("loadmodule \"tm\"\nloadmodule \"sl\"\n{body}"))
    }

    #[test]
    fn native_replies() {
        let t = replies(
            "request_route {\n    if ($rU == \"a\") { sl_send_reply(\"486\", \"Busy Here\"); exit; }\n    if ($rU == \"b\") { sl_send_reply(\"404\", \"Not here\"); exit; }\n    if ($rU == \"c\") { send_reply(499, \"x\"); exit; }\n    if ($rU == \"d\") { sl_send_reply(\"404\", \"$rU gone\"); exit; }\n    route(R);\n}\nroute[R] { sl_send_reply(\"483\", \"too many hops\"); exit; }\n",
        );
        has(
            &t,
            &[
                "        reply(BusyHere)\n",
                "        reply(NotFound, \"Not here\")\n",
                "        reply(499, \"x\")\n",
                "        reply(NotFound, \"{msg.ruri.user} gone\")\n",
                "fn r(msg: Request) {\n    reply(TooManyHops, \"too many hops\")\n}",
            ],
        );
        assert!(!t.contains("kamailio.call(\"") && !t.contains("exit\n"), "{t}");
    }

    #[test]
    fn replies_that_stay_raw() {
        // A transaction may exist before the stateless reply.
        let t = replies("request_route {\n    if (is_method(\"INVITE\")) { t_newtran(); }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n");
        has(&t, &["kamailio.call(\"sl_send_reply\", \"404\", \"Not Found\")\n    exit"]);
        // send_reply is stateful where there is a transaction, as reply() is.
        let t = replies("request_route {\n    t_newtran();\n    send_reply(\"404\", \"Not Found\");\n    exit;\n}\n");
        has(&t, &["    reply(NotFound)\n"]);
        // Not in a failure route, nor in a route it calls.
        let t = replies(
            "request_route {\n    t_on_failure(\"F\");\n    t_relay();\n}\nfailure_route[F] {\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
        );
        has(&t, &["kamailio.call(\"sl_send_reply\", \"404\", \"Not Found\")\n    exit"]);
        let t = replies("request_route {\n    route(R);\n}\nroute[R] { sl_send_reply(\"404\", \"Not Found\"); exit; }\nfailure_route[F] { route(R); }\n");
        has(&t, &["kamailio.call(\"sl_send_reply\", \"404\", \"Not Found\")\n    exit"]);
        // A variable code; no exit after it.
        let t = replies("request_route {\n    $var(c) = 404;\n    sl_send_reply(\"$var(c)\", \"Not Found\");\n    exit;\n}\n");
        has(&t, &["kamailio.call(\"sl_send_reply\", \"{pv(\"$var(c)\")}\", \"Not Found\")\n    exit"]);
        let t = replies("request_route {\n    sl_send_reply(\"100\", \"Trying\");\n    t_relay();\n}\n");
        has(&t, &["kamailio.call(\"sl_send_reply\", \"100\", \"Trying\")"]);
    }

    #[test]
    fn failure_t_replies() {
        // reply() lowers to t_reply in failure code: the same reply.
        let t = replies(
            "request_route {\n    t_on_failure(\"F\");\n    t_relay();\n}\nfailure_route[F] {\n    if ($rU == \"a\") { t_reply(\"404\", \"Not found\"); exit; }\n    if ($rU == \"b\") { t_reply(\"486\", \"Busy Here\"); exit; }\n    if ($rU == \"c\") { t_reply(\"404\", \"Gone away\"); exit; }\n    if ($rU == \"d\") { t_reply(\"$var(c)\", \"x\"); exit; }\n    if ($rU == \"e\") { t_reply(\"180\", \"Ringing\"); exit; }\n    route(R);\n}\nroute[R] { t_reply(\"503\", \"Service Unavailable\"); exit; }\n",
        );
        has(
            &t,
            &[
                // any other spelling of the standard phrase is sent as written
                "        reply(NotFound, \"Not found\")\n",
                "        reply(BusyHere)\n",
                "        reply(NotFound, \"Gone away\")\n",
                "fn r(msg: Request) {\n    reply(ServiceUnavailable)\n}",
                // a variable code, a provisional one: raw
                "kamailio.call(\"t_reply\", \"{pv(\"$var(c)\")}\", \"x\")\n        exit",
                "kamailio.call(\"t_reply\", \"180\", \"Ringing\")\n        exit",
            ],
        );
        // Request, branch and onreply code: t_reply stays as it is.
        for (route, call) in [
            ("request_route {\n    t_newtran();\n    t_reply(\"404\", \"Not Found\");\n    exit;\n}\n", "request_route"),
            (
                "request_route {\n    t_on_branch(\"B\");\n    t_relay();\n}\nbranch_route[B] {\n    t_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
                "branch_route",
            ),
            (
                "request_route {\n    t_on_reply(\"O\");\n    t_relay();\n}\nonreply_route[O] {\n    t_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
                "onreply_route",
            ),
            (
                "request_route {\n    route(R);\n    t_on_failure(\"F\");\n    t_relay();\n}\nfailure_route[F] { route(R); }\nroute[R] { t_reply(\"404\", \"Not Found\"); exit; }\n",
                "shared route",
            ),
        ] {
            let t = replies(route);
            assert!(!t.contains("reply(NotFound"), "{call}:\n{t}");
        }
        // The exact standard phrase is left out of a stateless reply too, a
        // different case is not.
        let t = replies(
            "request_route {\n    if ($rU == \"a\") { sl_send_reply(\"404\", \"Not Found\"); exit; }\n    sl_send_reply(\"404\", \"not found\");\n    exit;\n}\n",
        );
        has(&t, &["        reply(NotFound)\n", "    reply(NotFound, \"not found\")\n"]);
    }

    /// Whether the import names the reply in `cfg` (else it stays raw).
    fn named(body: &str, want: &str) -> bool {
        let t = replies(body);
        if t.contains(want) {
            return true;
        }
        assert!(t.contains("kamailio.call(\"sl_send_reply\""), "neither named nor raw:\n{t}");
        false
    }

    #[test]
    fn stateless_replies_where_no_transaction_can_exist() {
        let r = "reply(NotFound)";
        // Before t_newtran in the same route: named; after it: raw.
        assert!(named(
            "request_route {\n    if ($rU == \"a\") {\n        sl_send_reply(\"404\", \"Not Found\");\n        exit;\n    }\n    t_newtran();\n    t_relay();\n}\n",
            r
        ));
        assert!(!named(
            "request_route {\n    t_newtran();\n    if ($rU == \"a\") {\n        sl_send_reply(\"404\", \"Not Found\");\n        exit;\n    }\n    t_relay();\n}\n",
            r
        ));
        // In a condition the call has run in both branches.
        assert!(!named("request_route {\n    if (!t_newtran()) {\n        $var(x) = 1;\n    }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n", r));
        // A branch that makes one and always ends (stock kamailio.cfg's
        // lookup failure); a switch whose cases all exit.
        let cfg = "request_route {\n    if ($rU == \"vm\") {\n        t_newtran();\n        switch ($rc) {\n            case -1:\n                send_reply(\"404\", \"Not Found\");\n                exit;\n            default:\n                send_reply(\"500\", \"x\");\n                exit;\n        }\n    }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n";
        assert!(named(cfg, "    reply(NotFound)\n}"));
        // … but one that falls through: raw.
        assert!(!named(
            "request_route {\n    if ($rU == \"vm\") {\n        t_newtran();\n    }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
            r
        ));
        // A switch case that falls out of the switch with one.
        assert!(!named(
            "request_route {\n    switch ($rU) {\n        case \"a\":\n            t_newtran();\n            break;\n        default:\n            exit;\n    }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
            r
        ));
        // A loop makes one on a later pass.
        assert!(!named(
            "request_route {\n    while ($var(i) < 3) {\n        if ($var(i) == 1) {\n            sl_send_reply(\"404\", \"Not Found\");\n            exit;\n        }\n        t_newtran();\n        $var(i) = $var(i) + 1;\n    }\n    exit;\n}\n",
            r
        ));
        // t_check_trans doesn't make one.
        assert!(named(
            "request_route {\n    if (t_check_trans()) {\n        $var(x) = 1;\n    }\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\n",
            r
        ));
    }

    #[test]
    fn transactions_through_called_routes() {
        let r = "reply(NotFound)";
        // A route that may make one and return: raw after the call.
        assert!(!named(
            "request_route {\n    route(R);\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\nroute[R] {\n    if ($rU == \"a\") { t_newtran(); }\n}\n",
            r
        ));
        // One that always exits after making it (route[PRESENCE]): named.
        assert!(named(
            "request_route {\n    route(P);\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\nroute[P] {\n    if (!is_method(\"PUBLISH\")) { return; }\n    if (!t_newtran()) { sl_reply_error(); exit; }\n    t_reply(\"200\", \"OK\");\n    exit;\n}\n",
            r
        ));
        // A route called once with one and once without: raw inside it.
        assert!(!named(
            "request_route {\n    if ($rU == \"a\") { route(R); }\n    t_newtran();\n    route(R);\n}\nroute[R] { sl_send_reply(\"404\", \"Not Found\"); exit; }\n",
            r
        ));
        assert!(named(
            "request_route {\n    if ($rU == \"a\") { route(R); }\n    route(R);\n    t_relay();\n}\nroute[R] { if ($rU == \"b\") { sl_send_reply(\"404\", \"Not Found\"); exit; } }\n",
            r
        ));
        // Recursion ends, and a route that only recurses never returns.
        assert!(named(
            "request_route {\n    route(A);\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\nroute[A] {\n    if ($var(n) > 0) { $var(n) = $var(n) - 1; route(B); }\n}\nroute[B] { route(A); }\n",
            r
        ));
        assert!(!named(
            "request_route {\n    route(A);\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\nroute[A] {\n    if ($var(n) > 0) { $var(n) = $var(n) - 1; route(B); }\n}\nroute[B] { t_newtran(); route(A); }\n",
            r
        ));
        // Never reached (stock kamailio.cfg without ACTIVE: route[CHECKACTIVE]
        // drops): it never runs, so naming it changes nothing.
        assert!(named("request_route {\n    route(C);\n    sl_send_reply(\"404\", \"Not Found\");\n    exit;\n}\nroute[C] { t_newtran(); drop; }\n", r));
    }

    #[test]
    fn modparam_values() {
        assert_eq!(typed_value(&Ty::Bool, &RawArg::Int(1)).as_deref(), Some("true"));
        assert_eq!(typed_value(&Ty::Duration(Unit::Ms), &RawArg::Int(30000)).as_deref(), Some("\"30s\""));
        assert_eq!(typed_value(&Ty::Duration(Unit::Sec), &RawArg::Int(7200)).as_deref(), Some("\"2h\""));
        assert_eq!(typed_value(&Ty::Duration(Unit::Ms), &RawArg::Int(1500)).as_deref(), Some("\"1500ms\""));
        assert_eq!(typed_value(&Ty::Enum(&[("off", "0"), ("write-back", "2")]), &RawArg::Int(2)).as_deref(), Some("\"write-back\""));
        assert_eq!(typed_value(&Ty::Int { min: 0, max: 5 }, &RawArg::Int(9)), None);
        assert_eq!(listen_entry("udp:10.0.0.1:5060 advertise 1.2.3.4:5060"), Some(("udp".into(), "10.0.0.1:5060".into(), Some("1.2.3.4:5060".into()))));
        assert_eq!(listen_entry("10.0.0.1"), Some(("udp".into(), "10.0.0.1:5060".into(), None)));
        assert_eq!(listen_entry("tls:10.0.0.1:5061"), Some(("tls".into(), "10.0.0.1:5061".into(), None)));
        assert_eq!(log_level("3"), Some("debug"));
        assert_eq!(log_level("-1"), Some("err"));
    }
    #[test]
    fn int_casts_add_instead_of_concatenating() {
        let (fsr, _) = import_both(
            "request_route {\n    $var(n) = (int)\"41\" + 1;\n    $var(e) = (int)$hdr(Expires) + 5;\n    $var(z) = (int)\"-3\";\n    $var(s) = (str)$var(n) + \"x\";\n    exit;\n}\n",
        );
        assert!(fsr.contains("pv(\"$var(n)\") = 41 + 1"), "{fsr}");
        assert!(fsr.contains("pv(\"$var(e)\") = 0 + pv(\"$hdr(Expires)\") + 5"), "{fsr}");
        assert!(fsr.contains("pv(\"$var(z)\") = -3"), "{fsr}");
        assert!(fsr.contains("pv(\"$var(s)\") = \"\" + pv(\"$var(n)\") + \"x\""), "{fsr}");
    }

    #[test]
    fn listen_without_a_protocol_is_udp_and_tcp() {
        let listens = |cfg: &str| -> Vec<(String, String)> {
            let toml: toml::Value = toml::from_str(&import_both(&format!("{cfg}\nrequest_route {{ exit; }}\n")).1).unwrap();
            toml.get("listen")
                .and_then(|l| l.as_array())
                .map(|a| a.iter().map(|l| (l["proto"].as_str().unwrap().to_string(), l["addr"].as_str().unwrap().to_string())).collect())
                .unwrap_or_default()
        };
        let both = vec![("udp".to_string(), "10.0.0.1:5060".to_string()), ("tcp".to_string(), "10.0.0.1:5060".to_string())];
        assert_eq!(listens("listen=10.0.0.1"), both);
        assert_eq!(listens("disable_tcp=no\nlisten=10.0.0.1"), both);
        assert_eq!(listens("listen=10.0.0.1\ndisable_tcp=yes"), both[..1], "disable_tcp anywhere in the file");
        assert_eq!(listens("listen=udp:10.0.0.1"), both[..1], "a named protocol is only that one");
        assert!(!has_listen_proto("[::1]:5060") && has_listen_proto("\"tcp:[::1]:5060\""));
    }

    /// The `.fsr` text and ferrosip.toml an import writes (no file header).
    fn import_both(cfg: &str) -> (String, String) {
        let pp = sip_script::preprocess::preprocess_str("t.cfg", cfg, &[]).unwrap();
        let ast = sip_script::parse(&pp.text).unwrap();
        let (text, _) = routing(&ast, "t.cfg", &[], &pp.values).unwrap();
        (text, toml_of(&ast, &pp.core, "routes/main.fsr").text)
    }

    const HEADER: &str = "// Imported from t.cfg by `ferrosip import`.\n// What has no typed form is written with pv(\"$…\"), kamailio.call(…) and\n// kamailio.*_route handlers: `ferrosip lint -W raw_kamailio` lists them.\n\n";

    #[test]
    fn imports_loops_switch_fallthrough_and_core_settings_exactly() {
        let (fsr, toml) = import_both(
            r#"debug=2
children=4
listen=udp:127.0.0.1:5060
loadmodule "sl"
loadmodule "tm"
loadmodule "textops"
modparam("tm", "fr_timer", 5000)
request_route {
    if ($rm == "OPTIONS") {
        sl_send_reply("200", "OK");
        exit;
    }
    $var(i) = 0;
    while ($var(i) < 3) {
        $var(i) = $var(i) + 1;
    }
    switch ($rU) {
        case "a":
            append_hf("X-A: 1\r\n");
            break;
        case "b":
        case "c":
            xlog("bc\n");
        default:
            route(R);
    }
    if (!t_relay()) { sl_reply_error(); }
    exit;
}
route[R] {
    if (is_present_hf("X-B")) { return(-1); }
    return 1;
}
"#,
        );
        assert_eq!(
            fsr,
            HEADER.to_string()
                + r#"import text

route main(msg: Request) {
    if msg.method == OPTIONS {
        reply(OK)
    }
    pv("$var(i)") = 0
    while pv("$var(i)") < 3 {
        pv("$var(i)") = pv("$var(i)") + 1
    }
    let switch_1 = msg.ruri.user
    if switch_1 == "a" {
        text.append_header("X-A: 1\r\n")
    } else if switch_1 == "b" || switch_1 == "c" {
        kamailio.call("xlog", "bc\n")
        r(msg)
    } else {
        r(msg)
    }
    txn.relay()
}

// route[R]
fn r(msg: Request) {
    if text.has_header("X-B") {
        return
    }
    return
}
"#
        );
        assert_eq!(
            toml,
            "[core]\nlog_level = \"info\"\nworkers = 4\n\n[[listen]]\nproto = \"udp\"\naddr = \"127.0.0.1:5060\"\n\n[modules.sl]\n\n[modules.tm]\nfr_timer = \"5s\"\n\n[modules.textops]\n\n[routing]\nentry = \"routes/main.fsr\"\n"
        );
    }

    #[test]
    fn imports_routes_by_how_their_value_is_used() {
        let (fsr, _) = import_both(
            r#"loadmodule "sl"
loadmodule "tm"
loadmodule "textops"
request_route {
    if (route(CHECK)) {
        sl_send_reply("403", "Forbidden");
        exit;
    }
    if (!route(CHECK2)) { drop; }
    route(ZERO);
    t_relay();
}
route[CHECK] {
    if (is_present_hf("X-Bad")) { return 1; }
    return -1;
}
route[CHECK2] {
    if ($si == "10.0.0.1") { return(1); }
    return(-1);
}
route[ZERO] {
    if (is_present_hf("X-Z")) { return(0); }
}
"#,
        );
        assert_eq!(
            fsr,
            HEADER.to_string()
                + r#"import text

route main(msg: Request) {
    if check(msg) {
        reply(Forbidden)
    }
    if !check2(msg) {
        drop
    }
    zero(msg)
    kamailio.call("t_relay")
}

// route[CHECK]
fn check(msg: Request) -> Bool {
    if text.has_header("X-Bad") {
        return true
    }
    return false
}

// route[CHECK2]
fn check2(msg: Request) -> Bool {
    if msg.src.ip == "10.0.0.1" {
        return true
    }
    return false
}

// route[ZERO]
fn zero(msg: Request) {
    if text.has_header("X-Z") {
        exit
    }
}
"#
        );
        let env = crate::fsr_env(Default::default());
        fsr::compile_source("main.fsr", &fsr, &env).unwrap();
    }

    #[test]
    fn listen_values() {
        /// The value of `listen=`, and the (proto, addr, advertise) it gives.
        type Case<'a> = (&'a str, (&'a str, &'a str, Option<&'a str>));
        let cases: [Case; 9] = [
            ("10.0.0.1", ("udp", "10.0.0.1:5060", None)),
            ("udp:10.0.0.1", ("udp", "10.0.0.1:5060", None)),
            ("tcp:10.0.0.1:5080", ("tcp", "10.0.0.1:5080", None)),
            ("tls:10.0.0.1", ("tls", "10.0.0.1:5061", None)),
            ("udp:[2001:db8::1]:5070", ("udp", "[2001:db8::1]:5070", None)),
            ("udp:[2001:db8::1]", ("udp", "[2001:db8::1]:5060", None)),
            ("tls:[::1]", ("tls", "[::1]:5061", None)),
            ("udp:eth0:5060 advertise \"203.0.113.1:5060\"", ("udp", "eth0:5060", Some("203.0.113.1:5060"))),
            ("\"udp:10.0.0.1:5060\" ADVERTISE 1.2.3.4", ("udp", "10.0.0.1:5060", Some("1.2.3.4"))),
        ];
        for (v, (p, a, adv)) in cases {
            assert_eq!(listen_entry(v), Some((p.to_string(), a.to_string(), adv.map(str::to_string))), "{v}");
        }
    }

    #[test]
    fn helper_conversions() {
        for (n, want) in [("-9", "alert"), ("-5", "alert"), ("-4", "crit"), ("-2", "crit"), ("0", "warn"), ("1", "notice"), ("2", "info"), ("4", "debug")] {
            assert_eq!(log_level(n), Some(want), "debug={n}");
        }
        assert_eq!(log_level("x"), None);
        for (n, unit, want) in [
            (0, Unit::Ms, "0"),
            (-5, Unit::Sec, "-5"),
            (90, Unit::Sec, "\"90s\""),
            (120, Unit::Sec, "\"2m\""),
            (86_400, Unit::Sec, "\"1d\""),
            (1001, Unit::Ms, "\"1001ms\""),
            (i64::MAX, Unit::Sec, "\"9223372036854775807ms\""),
        ] {
            assert_eq!(dur(n, unit), want, "{n} {unit:?}");
        }
        assert_eq!(typed_value(&Ty::Bool, &RawArg::Str("Off".into())).as_deref(), Some("false"));
        assert_eq!(typed_value(&Ty::Bool, &RawArg::Int(2)).as_deref(), Some("true"));
        assert_eq!(typed_value(&Ty::Bool, &RawArg::Str("maybe".into())), None);
        assert_eq!(typed_value(&Ty::Str, &RawArg::Str("a\"b".into())).as_deref(), Some("'a\"b'"), "a TOML literal string");
        assert_eq!(typed_value(&Ty::Duration(Unit::Sec), &RawArg::Str("1h".into())).as_deref(), Some("\"1h\""));
        assert_eq!(typed_value(&Ty::Enum(&[("off", "0"), ("on", "1")]), &RawArg::Str("on".into())).as_deref(), Some("\"on\""));
        assert_eq!(typed_value(&Ty::Enum(&[("off", "0")]), &RawArg::Int(5)), None);
        assert_eq!(typed_value(&Ty::Str, &RawArg::Pv("$var(x)".into())), None);
        for (from, want) in [("ROUTE-1", "route_1"), ("1st", "r1st"), ("", "r"), ("a:b", "a_b")] {
            assert_eq!(snake(from), want);
        }
        assert_eq!(esc("a\"b\\c{d}\n\t"), "a\\\"b\\\\c\\{d\\}\\n\\t");
    }

    #[test]
    fn reply_code_patterns() {
        let cases = [
            ("486", Some("c == BusyHere")),
            ("486|408", Some("c == BusyHere || c == RequestTimeout")),
            ("3[0-9][0-9]", Some("c in 300..399")),
            ("[1-2][0-9][0-9]", Some("c in 100..299")),
            ("[135]\\d\\d", Some("c in 100..199 || c in 300..399 || c in 500..599")),
            ("499", Some("c == 499")),
            ("4[0-8][0-9]", None),
            ("[0-9][0-9][0-9]", None),
            ("7[0-9][0-9]", None),
            ("48", None),
            ("[3-1][0-9][0-9]", None),
        ];
        for (pat, want) in cases {
            assert_eq!(code_pattern(pat, "c").map(|(t, _)| t).as_deref(), want, "{pat}");
        }
        assert_eq!(class_digits("1-35"), Some(vec![1, 2, 3, 5]));
        assert_eq!(class_digits("a"), None);
    }
}
