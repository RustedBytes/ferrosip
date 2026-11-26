//! The canonical `.fsr` layout (`ferrosip fmt`): 4-space indents, one
//! statement per line, one blank line between items (kept where the
//! source had them inside blocks), comments where they were.

use crate::ast::*;
use std::fmt::Write;

pub fn format(f: &File) -> String {
    let mut out = String::new();
    let mut prev: Option<&ItemKind> = None;
    for item in &f.items {
        // Imports and flags group together; everything else is spaced.
        let grouped = matches!(
            (prev, &item.kind),
            (Some(ItemKind::Modules(_) | ItemKind::FromConfig(..) | ItemKind::File(..)), ItemKind::Modules(_) | ItemKind::FromConfig(..) | ItemKind::File(..))
                | (Some(ItemKind::Flag(..)), ItemKind::Flag(..))
                | (Some(ItemKind::Table { .. } | ItemKind::DialogVar { .. }), ItemKind::Table { .. } | ItemKind::DialogVar { .. })
        );
        if prev.is_some() && (!grouped || item.trivia.blank_before) {
            out.push('\n');
        }
        comments(&mut out, &item.trivia.leading, 0);
        item_text(&mut out, item);
        trailing(&mut out, &item.trivia);
        prev = Some(&item.kind);
    }
    if !f.tail.is_empty() {
        out.push('\n');
        comments(&mut out, &f.tail, 0);
    }
    out
}

fn indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("    ");
    }
}

fn comments(out: &mut String, cs: &[String], depth: usize) {
    for c in cs {
        if !c.is_empty() {
            indent(out, depth);
            out.push_str(c);
        }
        out.push('\n');
    }
}

fn trailing(out: &mut String, t: &Trivia) {
    if let Some(c) = &t.trailing {
        if out.ends_with('\n') {
            out.pop();
        }
        out.push_str("  ");
        out.push_str(c);
        out.push('\n');
    }
}

/// A comment the parser attached to a statement printed inline (`guard …
/// else reply(403)  // why`): on the same line.
fn inner_trailing(out: &mut String, s: &Stmt) {
    if let Some(c) = &s.trivia.trailing {
        out.push_str("  ");
        out.push_str(c);
    }
}

fn names(ns: &[Name]) -> String {
    ns.iter().map(|n| n.text.as_str()).collect::<Vec<_>>().join(", ")
}

fn item_text(out: &mut String, item: &Item) {
    match &item.kind {
        ItemKind::Modules(ns) => {
            let _ = writeln!(out, "import {}", names(ns));
        }
        ItemKind::FromConfig(ns, from) => {
            let _ = writeln!(out, "import {{ {} }} from {}", names(ns), from.text);
        }
        ItemKind::File(path, ns) => {
            let _ = writeln!(out, "import {} as {}", string(&[StrPart::Lit(path.clone())]), ns.text);
        }
        ItemKind::Flag(n, bit, branch) => {
            let kw = if *branch { "branch flag" } else { "flag" };
            let _ = match bit {
                Some((b, _)) => writeln!(out, "{kw} {} = {b}", n.text),
                None => writeln!(out, "{kw} {}", n.text),
            };
        }
        ItemKind::Route(f) | ItemKind::Fn(f) => {
            let kw = if matches!(item.kind, ItemKind::Route(_)) { "route" } else { "fn" };
            let _ = write!(out, "{kw} {}({})", f.name.text, params(&f.params));
            if let Some(r) = &f.ret {
                let _ = write!(out, " -> {}", ty(r));
            }
            out.push(' ');
            block(out, &f.body, 0);
            out.push('\n');
        }
        ItemKind::Table { name, ty: t, ttl } => {
            let _ = write!(out, "shared table {}: {}", name.text, ty(t));
            if let Some(d) = ttl {
                let _ = write!(out, " ttl {}", expr(d));
            }
            out.push('\n');
        }
        ItemKind::Test(name, body) => {
            let _ = write!(out, "test {} ", string(&[StrPart::Lit(name.clone())]));
            block(out, body, 0);
            out.push('\n');
        }
        ItemKind::DialogVar { name, ty: t } => {
            let _ = writeln!(out, "dialog var {}: {}", name.text, ty(t));
        }
        ItemKind::On(on) => {
            // The parameter first, then the settings: `(msg: Request, name: "X")`.
            let mut inside: Vec<String> = if on.params.is_empty() { vec![] } else { vec![params(&on.params)] };
            inside.extend(on.args.iter().map(|a| format!("{}: {}", a.name.as_ref().map_or("", |n| n.text.as_str()), expr(&a.value))));
            let _ = write!(out, "on {}({})", on.event.text, inside.join(", "));
            if let Some(c) = &on.cond {
                let _ = write!(out, " where {}", expr(c));
            }
            out.push(' ');
            block(out, &on.body, 0);
            out.push('\n');
        }
    }
}

fn params(ps: &[Param]) -> String {
    ps.iter().map(|p| format!("{}: {}", p.name.text, ty(&p.ty))).collect::<Vec<_>>().join(", ")
}

fn ty(t: &TypeRef) -> String {
    let mut s = t.name.text.clone();
    if !t.args.is_empty() {
        s.push('<');
        s.push_str(&t.args.iter().map(ty).collect::<Vec<_>>().join(", "));
        s.push('>');
    }
    if t.optional {
        s.push('?');
    }
    s
}

/// `{ … }` at `depth` (the brace line's indent); no trailing newline.
fn block(out: &mut String, b: &Block, depth: usize) {
    if b.stmts.is_empty() && b.tail.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    for (i, s) in b.stmts.iter().enumerate() {
        if i > 0 && s.trivia.blank_before {
            out.push('\n');
        }
        stmt(out, s, depth.saturating_add(1));
    }
    comments(out, &b.tail, depth.saturating_add(1));
    indent(out, depth);
    out.push('}');
}

fn stmt(out: &mut String, s: &Stmt, depth: usize) {
    comments(out, &s.trivia.leading, depth);
    indent(out, depth);
    stmt_inline(out, s, depth);
    out.push('\n');
    trailing(out, &s.trivia);
}

/// The statement without indent or newline (for `else` and arms).
fn stmt_inline(out: &mut String, s: &Stmt, depth: usize) {
    match &s.kind {
        StmtKind::Let { name, ty: t, value, otherwise } => {
            let _ = write!(out, "let {}", name.text);
            if let Some(t) = t {
                let _ = write!(out, ": {}", ty(t));
            }
            let _ = write!(out, " = {}", expr(value));
            if let Some(o) = otherwise {
                out.push_str(" else ");
                stmt_inline(out, o, depth);
                inner_trailing(out, o);
            }
        }
        StmtKind::Assign(t, v) => {
            let _ = write!(out, "{} = {}", expr(t), expr(v));
        }
        StmtKind::If(c, then, els) => {
            let _ = write!(out, "if {} ", expr(c));
            block(out, then, depth);
            match els {
                None => {}
                Some(Else::Block(b)) => {
                    out.push_str(" else ");
                    block(out, b, depth);
                }
                Some(Else::If(s)) => {
                    out.push_str(" else ");
                    stmt_inline(out, s, depth);
                }
            }
        }
        StmtKind::While(c, b) => {
            let _ = write!(out, "while {} ", expr(c));
            block(out, b, depth);
        }
        StmtKind::For(n, over, b) => {
            let _ = write!(out, "for {} in {} ", n.text, expr(over));
            block(out, b, depth);
        }
        StmtKind::Guard(c, s) => {
            let _ = write!(out, "guard {} else ", expr(c));
            stmt_inline(out, s, depth);
            inner_trailing(out, s);
        }
        StmtKind::Match(subject, arms) => {
            let _ = writeln!(out, "match {} {{", expr(subject));
            for a in arms {
                comments(out, &a.trivia.leading, depth.saturating_add(1));
                indent(out, depth.saturating_add(1));
                out.push_str(&a.pats.iter().map(pat).collect::<Vec<_>>().join(" | "));
                if let Some(g) = &a.guard {
                    let _ = write!(out, " if {}", expr(g));
                }
                out.push_str(" => ");
                match &a.body {
                    ArmBody::Block(b) => block(out, b, depth.saturating_add(1)),
                    ArmBody::Stmt(s) => stmt_inline(out, s, depth.saturating_add(1)),
                }
                out.push('\n');
                trailing(out, &a.trivia);
            }
            indent(out, depth);
            out.push('}');
        }
        StmtKind::Return(None) => out.push_str("return"),
        StmtKind::Return(Some(e)) => {
            let _ = write!(out, "return {}", expr(e));
        }
        StmtKind::Drop => out.push_str("drop"),
        StmtKind::Exit => out.push_str("exit"),
        StmtKind::Break => out.push_str("break"),
        StmtKind::Expr(e) => out.push_str(&expr(e)),
    }
}

fn pat(p: &Pat) -> String {
    match p {
        Pat::Wild(_) => "_".into(),
        Pat::Lit(e) => expr(e),
        Pat::Range(a, b, _) => format!("{}..{}", expr(a), expr(b)),
        Pat::Variant(n, None) => n.text.clone(),
        Pat::Variant(n, Some(b)) => format!("{}({})", n.text, b.text),
    }
}

fn string(parts: &[StrPart]) -> String {
    // """…""" for text across lines; a newline only at the very end stays
    // an escape ("…\n").
    let last = parts.len().saturating_sub(1);
    let multiline = parts.iter().enumerate().any(|(i, p)| match p {
        StrPart::Lit(l) if i == last => l.trim_end_matches('\n').contains('\n'),
        StrPart::Lit(l) => l.contains('\n'),
        StrPart::Expr(_) => false,
    });
    let q = if multiline { "\"\"\"" } else { "\"" };
    let mut s = String::from(q);
    for p in parts {
        match p {
            StrPart::Lit(l) => {
                for c in l.chars() {
                    match c {
                        '"' if !multiline => s.push_str("\\\""),
                        '\\' => s.push_str("\\\\"),
                        '\t' => s.push_str("\\t"),
                        '\n' if !multiline => s.push_str("\\n"),
                        '\r' => s.push_str("\\r"),
                        '{' => s.push_str("\\{"),
                        '}' => s.push_str("\\}"),
                        c => s.push(c),
                    }
                }
            }
            StrPart::Expr(e) => {
                let _ = write!(s, "{{{}}}", expr(e));
            }
        }
    }
    s.push_str(q);
    s
}

pub fn expr(e: &Expr) -> String {
    match &e.kind {
        ExprKind::Int(n) => n.to_string(),
        ExprKind::Str(parts) => string(parts),
        ExprKind::Bool(b) => b.to_string(),
        ExprKind::Duration(_, t) => t.clone(),
        ExprKind::Ident(s) => s.clone(),
        ExprKind::Field(x, n) => format!("{}.{}", expr(x), n.text),
        ExprKind::Index(x, i) => format!("{}[{}]", expr(x), expr(i)),
        ExprKind::Call(f, args) => {
            let a: Vec<String> = args
                .iter()
                .map(|a| match &a.name {
                    Some(n) => format!("{}: {}", n.text, expr(&a.value)),
                    None => expr(&a.value),
                })
                .collect();
            format!("{}({})", expr(f), a.join(", "))
        }
        ExprKind::Unary(UnOp::Not, x) => format!("!{}", expr(x)),
        ExprKind::Unary(UnOp::Neg, x) => format!("-{}", expr(x)),
        ExprKind::Binary(op, a, b) => format!("{} {} {}", expr(a), op.text(), expr(b)),
        ExprKind::Range(a, b) => format!("{}..{}", expr(a), expr(b)),
        ExprKind::List(items) => format!("[{}]", items.iter().map(expr).collect::<Vec<_>>().join(", ")),
        ExprKind::Await(x) => format!("await {}", expr(x)),
        ExprKind::Paren(x) => format!("({})", expr(x)),
    }
}
