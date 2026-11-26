//! Print a lowered route tree as Kamailio-style `.cfg` text
//! (`ferrosip check --lowered`). The output parses back to the same tree.

use sip_script::{Ast, BinOp, Expr, RawArg, Stmt};
use std::fmt::Write;

fn quote(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn op(o: BinOp) -> &'static str {
    match o {
        BinOp::Or => "||",
        BinOp::And => "&&",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::Match => "=~",
        BinOp::NoMatch => "!~",
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Mod => "mod",
        BinOp::BitOr => "|",
        BinOp::BitAnd => "&",
    }
}

fn arg(a: &RawArg) -> String {
    match a {
        RawArg::Str(s) => quote(s),
        RawArg::Int(i) => i.to_string(),
        RawArg::Pv(p) => p.clone(),
    }
}

/// An expression, fully parenthesised where it nests.
pub fn expr(e: &Expr) -> String {
    match e {
        Expr::Str(s) => quote(s),
        Expr::Int(i) if *i < 0 => format!("({i})"),
        Expr::Int(i) => i.to_string(),
        Expr::Pv(p, _) => p.clone(),
        Expr::Call { name, args, .. } => format!("{name}({})", args.iter().map(arg).collect::<Vec<_>>().join(", ")),
        Expr::Route(r, _) => format!("route({r})"),
        Expr::Not(x) => format!("!{}", atom(x)),
        Expr::Neg(x) => format!("-{}", atom(x)),
        Expr::Bin(o, a, b) => format!("{} {} {}", atom(a), op(*o), atom(b)),
        Expr::Myself => "myself".into(),
    }
}

fn atom(e: &Expr) -> String {
    match e {
        Expr::Bin(..) => format!("({})", expr(e)),
        _ => expr(e),
    }
}

fn block(out: &mut String, stmts: &[Stmt], depth: usize) {
    for s in stmts {
        stmt(out, s, depth);
    }
}

fn stmt(out: &mut String, s: &Stmt, depth: usize) {
    let ind = "    ".repeat(depth);
    match s {
        Stmt::If(c, t, e) => {
            let _ = writeln!(out, "{ind}if ({}) {{", expr(c));
            block(out, t, depth.saturating_add(1));
            let mut e = e;
            // else { if … } → else if …
            while let [Stmt::If(c2, t2, e2)] = e.as_slice() {
                let _ = writeln!(out, "{ind}}} else if ({}) {{", expr(c2));
                block(out, t2, depth.saturating_add(1));
                e = e2;
            }
            if !e.is_empty() {
                let _ = writeln!(out, "{ind}}} else {{");
                block(out, e, depth.saturating_add(1));
            }
            let _ = writeln!(out, "{ind}}}");
        }
        Stmt::While(c, b) => {
            let _ = writeln!(out, "{ind}while ({}) {{", expr(c));
            block(out, b, depth.saturating_add(1));
            let _ = writeln!(out, "{ind}}}");
        }
        Stmt::Switch(v, cases) => {
            let _ = writeln!(out, "{ind}switch ({}) {{", expr(v));
            for (c, b) in cases {
                match c {
                    Some(c) => {
                        let _ = writeln!(out, "{ind}case {}:", expr(c));
                    }
                    None => {
                        let _ = writeln!(out, "{ind}default:");
                    }
                }
                block(out, b, depth.saturating_add(1));
            }
            let _ = writeln!(out, "{ind}}}");
        }
        Stmt::Assign(t, v, _) => {
            let _ = writeln!(out, "{ind}{t} = {};", expr(v));
        }
        Stmt::Expr(e) => {
            let _ = writeln!(out, "{ind}{};", expr(e));
        }
        Stmt::Exit => {
            let _ = writeln!(out, "{ind}exit;");
        }
        Stmt::Drop => {
            let _ = writeln!(out, "{ind}drop;");
        }
        Stmt::Return(None) => {
            let _ = writeln!(out, "{ind}return;");
        }
        Stmt::Return(Some(e)) => {
            let _ = writeln!(out, "{ind}return {};", expr(e));
        }
        Stmt::Break => {
            let _ = writeln!(out, "{ind}break;");
        }
    }
}

fn section(out: &mut String, head: &str, body: &[Stmt]) {
    let _ = writeln!(out, "{head} {{");
    block(out, body, 1);
    let _ = writeln!(out, "}}\n");
}

/// The whole tree as a `.cfg` script (routes only: modules and
/// parameters come from ferrosip.toml).
pub fn to_cfg(ast: &Ast) -> String {
    let mut out = String::from("# generated from .fsr (ferrosip check --lowered)\n\n");
    for m in &ast.modules {
        let _ = writeln!(out, "loadmodule {}", quote(m));
    }
    for p in &ast.modparams {
        let _ = writeln!(out, "modparam({}, {}, {})", quote(&p.module), quote(&p.name), arg(&p.value));
    }
    if !ast.modules.is_empty() || !ast.modparams.is_empty() {
        out.push('\n');
    }
    section(&mut out, "request_route", &ast.request_route);
    for (n, b) in &ast.routes {
        section(&mut out, &format!("route[{n}]"), b);
    }
    for (n, b) in &ast.failure_routes {
        section(&mut out, &format!("failure_route[{n}]"), b);
    }
    for (n, b) in &ast.branch_routes {
        section(&mut out, &format!("branch_route[{n}]"), b);
    }
    for (n, b) in &ast.onreply_routes {
        section(&mut out, &format!("onreply_route[{n}]"), b);
    }
    if let Some(b) = &ast.reply_route {
        section(&mut out, "reply_route", b);
    }
    for (n, b) in &ast.event_routes {
        section(&mut out, &format!("event_route[{n}]"), b);
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}
