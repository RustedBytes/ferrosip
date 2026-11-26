//! Recursive-descent parser for `.fsr`.
//!
//! Statements need no separators: each starts with a keyword or an
//! expression, and newlines only matter where an optional part could
//! otherwise swallow the next line (`return` / `drop` without a value).

use crate::ast::*;
use crate::lexer::{self, Comment, LBRACE, RBRACE, Tok, Token};

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub msg: String,
    pub span: Span,
}

type R<T> = Result<T, ParseError>;

struct P {
    toks: Vec<Token>,
    i: usize,
    comments: Vec<Comment>,
    /// Next comment not yet attached.
    c: usize,
}

const KEYWORDS: &[&str] = &[
    "import", "from", "as", "flag", "route", "fn", "on", "where", "let", "if", "else", "while", "for", "guard", "match", "return", "drop", "exit", "break",
    "await", "in", "true", "false",
];

pub fn parse(src: &str) -> R<File> {
    let (toks, comments) = lexer::lex(src).map_err(|e| ParseError { msg: e.msg, span: e.span })?;
    let mut p = P { toks, i: 0, comments, c: 0 };
    let mut items = Vec::new();
    while !p.at_eof() {
        items.push(p.item()?);
    }
    let tail = p.take_comments_before(usize::MAX);
    Ok(File { items, tail })
}

/// Parse one expression (for string interpolation holes and tests).
pub fn parse_expr(src: &str, offset: usize) -> R<Expr> {
    let (mut toks, _) = lexer::lex(src).map_err(|e| ParseError { msg: e.msg, span: shift(e.span, offset) })?;
    for t in &mut toks {
        t.span = shift(t.span, offset);
    }
    let mut p = P { toks, i: 0, comments: Vec::new(), c: 0 };
    let e = p.expr()?;
    if !p.at_eof() {
        return Err(p.err_here("unexpected text after the expression"));
    }
    Ok(e)
}

fn shift(s: Span, by: usize) -> Span {
    Span { start: s.start.saturating_add(by), end: s.end.saturating_add(by) }
}

/// What `peek` sees past the tokens (never: they end with `Eof`, and `i`
/// stops on it).
static EOF: Token = Token { tok: Tok::Eof, span: Span { start: 0, end: 0 }, nl_before: true, blank_before: false, holes: Vec::new() };

impl P {
    fn peek(&self) -> &Token {
        self.toks.get(self.i).unwrap_or(&EOF)
    }
    /// `n` tokens ahead, or the `Eof` at the end.
    fn peek_at(&self, n: usize) -> &Token {
        self.toks.get(self.i.saturating_add(n)).or(self.toks.last()).unwrap_or(&EOF)
    }
    fn at_eof(&self) -> bool {
        self.peek().tok == Tok::Eof
    }
    /// The current token, stepping past it unless it is the last (`Eof`).
    fn bump(&mut self) -> Token {
        let t = self.peek().clone();
        let next = self.i.saturating_add(1);
        if next < self.toks.len() {
            self.i = next;
        }
        t
    }
    fn prev_end(&self) -> usize {
        self.toks.get(self.i.saturating_sub(1)).map_or(0, |t| t.span.end)
    }
    fn is_punct(&self, p: &str) -> bool {
        matches!(&self.peek().tok, Tok::Punct(x) if *x == p)
    }
    fn is_kw(&self, k: &str) -> bool {
        matches!(&self.peek().tok, Tok::Ident(x) if x == k)
    }
    fn eat_punct(&mut self, p: &str) -> bool {
        if self.is_punct(p) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn eat_kw(&mut self, k: &str) -> bool {
        if self.is_kw(k) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn err_here(&self, msg: &str) -> ParseError {
        ParseError { msg: msg.to_string(), span: self.peek().span }
    }
    fn found(&self) -> String {
        match &self.peek().tok {
            Tok::Ident(s) => format!("`{s}`"),
            Tok::Int(n) => format!("`{n}`"),
            Tok::Duration(_, t) => format!("`{t}`"),
            Tok::Str(..) => "a string".into(),
            Tok::Punct(p) => format!("`{p}`"),
            Tok::Eof => "the end of the file".into(),
        }
    }
    fn expect_punct(&mut self, p: &str) -> R<Span> {
        if self.is_punct(p) { Ok(self.bump().span) } else { Err(self.err_here(&format!("expected `{p}`, found {}", self.found()))) }
    }
    fn expect_kw(&mut self, k: &str) -> R<Span> {
        if self.is_kw(k) { Ok(self.bump().span) } else { Err(self.err_here(&format!("expected `{k}`, found {}", self.found()))) }
    }
    fn name(&mut self, what: &str) -> R<Name> {
        match &self.peek().tok {
            Tok::Ident(s) if !KEYWORDS.contains(&s.as_str()) => {
                let name = Name { text: s.clone(), span: self.peek().span };
                self.bump();
                Ok(name)
            }
            _ => Err(self.err_here(&format!("expected {what}, found {}", self.found()))),
        }
    }

    /// After `.`: any word, keywords included (`msg.from.user`).
    fn field_name(&mut self) -> R<Name> {
        match &self.peek().tok {
            Tok::Ident(text) => {
                let name = Name { text: text.clone(), span: self.peek().span };
                self.bump();
                Ok(name)
            }
            _ => Err(self.err_here(&format!("expected a field or method name, found {}", self.found()))),
        }
    }

    /// Own-line comments before byte `at` that aren't attached yet.
    fn take_comments_before(&mut self, at: usize) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(c) = self.comments.get(self.c).filter(|c| c.span.start < at) {
            out.push(c.text.clone());
            // An empty entry: a blank line (fmt keeps it).
            if c.blank_after {
                out.push(String::new());
            }
            self.c = self.c.saturating_add(1);
        }
        out
    }

    /// A comment right after `end`, on the same line: not on its own
    /// line means a token precedes it there, and nothing came between.
    fn take_trailing(&mut self, end: usize) -> Option<String> {
        let c = self.comments.get(self.c)?;
        if !c.own_line && c.span.start >= end && c.span.start <= self.peek().span.start {
            self.c = self.c.saturating_add(1);
            return Some(c.text.clone());
        }
        None
    }

    fn trivia(&mut self) -> Trivia {
        let t = self.peek();
        let (start, mut blank) = (t.span.start, t.blank_before);
        // With comments in front, the blank line that counts is the one
        // before them (one between them and the code is an empty entry).
        if let Some(c) = self.comments.get(self.c).filter(|c| c.span.start < start) {
            blank = c.blank_before;
        }
        let leading = self.take_comments_before(start);
        Trivia { leading, trailing: None, blank_before: blank }
    }

    // ------------------------------------------------------------ items

    fn item(&mut self) -> R<Item> {
        let mut trivia = self.trivia();
        let start = self.peek().span;
        let kind = match &self.peek().tok {
            Tok::Ident(k) if k == "import" => {
                self.bump();
                if self.eat_punct("{") {
                    let mut names = vec![self.name("a name")?];
                    while self.eat_punct(",") {
                        names.push(self.name("a name")?);
                    }
                    self.expect_punct("}")?;
                    self.expect_kw("from")?;
                    let from = self.name("a source (config)")?;
                    ItemKind::FromConfig(names, from)
                } else if let Tok::Str(path, _) = self.peek().tok.clone() {
                    self.bump();
                    self.expect_kw("as")?;
                    ItemKind::File(path, self.name("a namespace")?)
                } else {
                    let mut names = vec![self.name("a module name")?];
                    while self.eat_punct(",") {
                        names.push(self.name("a module name")?);
                    }
                    ItemKind::Modules(names)
                }
            }
            Tok::Ident(k) if k == "flag" || (k == "branch" && matches!(&self.peek_at(1).tok, Tok::Ident(f) if f == "flag")) => {
                // `branch flag FLB_NATB = 6`: a branch flag (setbflag…).
                let branch = k == "branch";
                if branch {
                    self.bump();
                }
                self.bump();
                let n = self.name("a flag name")?;
                // `flag FLT_ACC = 1`: a fixed bit (one a module parameter names).
                let bit = if self.eat_punct("=") {
                    let t = self.bump();
                    let Tok::Int(b) = t.tok else { return Err(ParseError { msg: "expected a flag bit (0..31)".into(), span: t.span }) };
                    Some((b, t.span))
                } else {
                    None
                };
                ItemKind::Flag(n, bit, branch)
            }
            Tok::Ident(k) if k == "route" || k == "fn" => {
                let is_route = k == "route";
                self.bump();
                let f = self.func()?;
                if is_route { ItemKind::Route(f) } else { ItemKind::Fn(f) }
            }
            Tok::Ident(k) if k == "on" => {
                self.bump();
                // `reply`, `dialog.ended`: a dotted name.
                let mut event = self.name("an event (reply, dialog.ended, timer, http…)")?;
                while self.eat_punct(".") {
                    let more = self.name("an event name")?;
                    event.text = format!("{}.{}", event.text, more.text);
                    event.span = event.span.to(more.span);
                }
                let (params, args) = self.on_params()?;
                let cond = if self.eat_kw("where") { Some(self.expr()?) } else { None };
                let body = self.block()?;
                ItemKind::On(On { event, params, args, cond, body })
            }
            // `shared table name: Map<K, V> [ttl 10m]` (contextual words).
            Tok::Ident(k) if k == "shared" && matches!(&self.peek_at(1).tok, Tok::Ident(t) if t == "table") => {
                self.bump();
                self.bump();
                let name = self.name("a table name")?;
                self.expect_punct(":")?;
                let ty = self.type_ref()?;
                let ttl = if matches!(&self.peek().tok, Tok::Ident(t) if t == "ttl") {
                    self.bump();
                    Some(self.expr()?)
                } else {
                    None
                };
                ItemKind::Table { name, ty, ttl }
            }
            // `test "name" { … }`
            Tok::Ident(k)
                if k == "test"
                    && let Tok::Str(name, _) = &self.peek_at(1).tok =>
            {
                let name = name.clone();
                self.bump();
                self.bump();
                ItemKind::Test(name, self.block()?)
            }
            // `dialog var name: Type`
            Tok::Ident(k) if k == "dialog" && matches!(&self.peek_at(1).tok, Tok::Ident(t) if t == "var") => {
                self.bump();
                self.bump();
                let name = self.name("a variable name")?;
                self.expect_punct(":")?;
                ItemKind::DialogVar { name, ty: self.type_ref()? }
            }
            _ => {
                return Err(self.err_here(&format!("expected `import`, `flag`, `route`, `fn`, `on`, `shared table` or `dialog var`, found {}", self.found())));
            }
        };
        let span = start.to(Span { start: start.start, end: self.prev_end() });
        trivia.trailing = self.take_trailing(span.end);
        Ok(Item { kind, span, trivia })
    }

    fn params(&mut self) -> R<Vec<Param>> {
        self.expect_punct("(")?;
        let mut out = Vec::new();
        while !self.is_punct(")") {
            let name = self.name("a parameter name")?;
            self.expect_punct(":")?;
            out.push(Param { name, ty: self.type_ref()? });
            if !self.eat_punct(",") {
                break;
            }
        }
        self.expect_punct(")")?;
        Ok(out)
    }

    /// A handler's parentheses: parameters (`d: Dialog`, a type after the
    /// colon) and settings (`every: 30s`, an expression).
    fn on_params(&mut self) -> R<(Vec<Param>, Vec<CallArg>)> {
        self.expect_punct("(")?;
        let (mut params, mut args) = (Vec::new(), Vec::new());
        while !self.is_punct(")") {
            let name = self.name("a parameter name")?;
            self.expect_punct(":")?;
            if matches!(&self.peek().tok, Tok::Ident(_)) {
                params.push(Param { name, ty: self.type_ref()? });
            } else {
                args.push(CallArg { name: Some(name), value: self.expr()? });
            }
            if !self.eat_punct(",") {
                break;
            }
        }
        self.expect_punct(")")?;
        Ok((params, args))
    }

    fn type_ref(&mut self) -> R<TypeRef> {
        let name = self.name("a type")?;
        let mut args = Vec::new();
        if self.eat_punct("<") {
            args.push(self.type_ref()?);
            while self.eat_punct(",") {
                args.push(self.type_ref()?);
            }
            self.expect_punct(">")?;
        }
        let optional = self.eat_punct("?");
        let span = name.span.to(Span { start: name.span.start, end: self.prev_end() });
        Ok(TypeRef { name, args, optional, span })
    }

    fn func(&mut self) -> R<Func> {
        let name = self.name("a name")?;
        let params = self.params()?;
        let ret = if self.eat_punct("->") { Some(self.type_ref()?) } else { None };
        let body = self.block()?;
        Ok(Func { name, params, ret, body })
    }

    // ------------------------------------------------------- statements

    fn block(&mut self) -> R<Block> {
        let open = self.expect_punct("{")?;
        let mut stmts = Vec::new();
        while !self.is_punct("}") {
            if self.at_eof() {
                return Err(ParseError { msg: "unclosed `{`".into(), span: open });
            }
            stmts.push(self.stmt()?);
            self.eat_punct(";");
        }
        let close = self.peek().span.start;
        let tail = self.take_comments_before(close);
        let end = self.expect_punct("}")?;
        Ok(Block { stmts, span: open.to(end), tail })
    }

    fn stmt(&mut self) -> R<Stmt> {
        let mut trivia = self.trivia();
        let start = self.peek().span;
        let same_line_value = |p: &P| !p.peek().nl_before && !p.is_punct("}") && !p.is_punct(";") && !p.at_eof();
        let kind = match &self.peek().tok {
            Tok::Ident(k) if k == "let" => {
                self.bump();
                let name = self.name("a variable name")?;
                let ty = if self.eat_punct(":") { Some(self.type_ref()?) } else { None };
                self.expect_punct("=")?;
                let value = self.expr()?;
                let otherwise = if self.eat_kw("else") { Some(Box::new(self.stmt()?)) } else { None };
                StmtKind::Let { name, ty, value, otherwise }
            }
            Tok::Ident(k) if k == "if" => self.if_stmt()?,
            Tok::Ident(k) if k == "while" => {
                self.bump();
                let c = self.expr()?;
                StmtKind::While(c, self.block()?)
            }
            Tok::Ident(k) if k == "for" => {
                self.bump();
                let name = self.name("a loop variable")?;
                self.expect_kw("in")?;
                let over = self.expr()?;
                StmtKind::For(name, over, self.block()?)
            }
            Tok::Ident(k) if k == "guard" => {
                self.bump();
                let c = self.expr()?;
                self.expect_kw("else")?;
                StmtKind::Guard(c, Box::new(self.stmt()?))
            }
            Tok::Ident(k) if k == "match" => {
                self.bump();
                let subject = self.expr()?;
                self.expect_punct("{")?;
                let mut arms = Vec::new();
                while !self.is_punct("}") {
                    if self.at_eof() {
                        return Err(self.err_here("unclosed `match`"));
                    }
                    arms.push(self.arm()?);
                    self.eat_punct(",");
                }
                self.expect_punct("}")?;
                StmtKind::Match(subject, arms)
            }
            Tok::Ident(k) if k == "return" => {
                self.bump();
                StmtKind::Return(if same_line_value(self) { Some(self.expr()?) } else { None })
            }
            Tok::Ident(k) if k == "drop" => {
                self.bump();
                StmtKind::Drop
            }
            Tok::Ident(k) if k == "exit" => {
                self.bump();
                StmtKind::Exit
            }
            Tok::Ident(k) if k == "break" => {
                self.bump();
                StmtKind::Break
            }
            _ => {
                let e = self.expr()?;
                if self.eat_punct("=") { StmtKind::Assign(e, self.expr()?) } else { StmtKind::Expr(e) }
            }
        };
        let span = start.to(Span { start: start.start, end: self.prev_end() });
        trivia.trailing = self.take_trailing(span.end);
        Ok(Stmt { kind, span, trivia })
    }

    fn if_stmt(&mut self) -> R<StmtKind> {
        self.expect_kw("if")?;
        let c = self.expr()?;
        let then = self.block()?;
        let els = if self.eat_kw("else") {
            if self.is_kw("if") {
                let t = self.trivia();
                let start = self.peek().span;
                let k = self.if_stmt()?;
                let span = start.to(Span { start: start.start, end: self.prev_end() });
                Some(Else::If(Box::new(Stmt { kind: k, span, trivia: t })))
            } else {
                Some(Else::Block(self.block()?))
            }
        } else {
            None
        };
        Ok(StmtKind::If(c, then, els))
    }

    fn arm(&mut self) -> R<Arm> {
        let mut trivia = self.trivia();
        let start = self.peek().span;
        let mut pats = vec![self.pat()?];
        while self.eat_punct("|") {
            pats.push(self.pat()?);
        }
        let guard = if self.eat_kw("if") { Some(self.expr()?) } else { None };
        self.expect_punct("=>")?;
        let body = if self.is_punct("{") { ArmBody::Block(self.block()?) } else { ArmBody::Stmt(Box::new(self.stmt()?)) };
        let span = start.to(Span { start: start.start, end: self.prev_end() });
        trivia.trailing = self.take_trailing(span.end);
        Ok(Arm { pats, guard, body, span, trivia })
    }

    fn pat(&mut self) -> R<Pat> {
        let t = self.peek().clone();
        match &t.tok {
            Tok::Ident(s) if s == "_" => {
                self.bump();
                Ok(Pat::Wild(t.span))
            }
            Tok::Int(_) | Tok::Punct("-") => {
                let a = self.pat_end()?;
                if self.eat_punct("..") {
                    let b = self.pat_end()?;
                    Ok(Pat::Range(Box::new(a), Box::new(b), t.span.to(Span { start: t.span.start, end: self.prev_end() })))
                } else {
                    Ok(Pat::Lit(a))
                }
            }
            Tok::Str(..) => Ok(Pat::Lit(self.primary()?)),
            // `Ringing..SessionProgress`: a range between status code names.
            Tok::Ident(_) if matches!(self.peek_at(1).tok, Tok::Punct("..")) => {
                let a = self.pat_end()?;
                self.expect_punct("..")?;
                let b = self.pat_end()?;
                Ok(Pat::Range(Box::new(a), Box::new(b), t.span.to(Span { start: t.span.start, end: self.prev_end() })))
            }
            Tok::Ident(_) => {
                let name = self.name("a pattern")?;
                if self.eat_punct("(") {
                    let bind = if self.eat_kw("_") { None } else { Some(self.name("a binding name")?) };
                    self.expect_punct(")")?;
                    Ok(Pat::Variant(name, bind))
                } else {
                    Ok(Pat::Variant(name, None))
                }
            }
            _ => Err(self.err_here(&format!("expected a pattern, found {}", self.found()))),
        }
    }

    /// One end of a range pattern: `-5`, `200` or a name (`Ringing`).
    fn pat_end(&mut self) -> R<Expr> {
        let t = self.peek().clone();
        match &t.tok {
            Tok::Ident(n) => {
                self.bump();
                Ok(Expr { kind: ExprKind::Ident(n.clone()), span: t.span })
            }
            _ => {
                let neg = self.eat_punct("-");
                let Tok::Int(a) = self.bump().tok else { return Err(ParseError { msg: "expected a number".into(), span: t.span }) };
                // `a` is lexed digits (≥ 0): negating it can't overflow.
                let a = if neg { a.wrapping_neg() } else { a };
                Ok(Expr { kind: ExprKind::Int(a), span: t.span.to(Span { start: t.span.start, end: self.prev_end() }) })
            }
        }
    }

    // ------------------------------------------------------ expressions

    pub fn expr(&mut self) -> R<Expr> {
        self.binary(0)
    }

    fn binop(&self) -> Option<BinOp> {
        Some(match &self.peek().tok {
            Tok::Punct("||") => BinOp::Or,
            Tok::Punct("&&") => BinOp::And,
            Tok::Punct("==") => BinOp::Eq,
            Tok::Punct("!=") => BinOp::Ne,
            Tok::Punct("<") => BinOp::Lt,
            Tok::Punct("<=") => BinOp::Le,
            Tok::Punct(">") => BinOp::Gt,
            Tok::Punct(">=") => BinOp::Ge,
            Tok::Punct("=~") => BinOp::Match,
            Tok::Punct("+") => BinOp::Add,
            Tok::Punct("-") => BinOp::Sub,
            Tok::Punct("*") => BinOp::Mul,
            Tok::Punct("/") => BinOp::Div,
            Tok::Punct("%") => BinOp::Mod,
            Tok::Ident(k) if k == "in" => BinOp::In,
            _ => return None,
        })
    }

    /// Precedence climbing; `..` sits between comparison (3) and `+` (5).
    fn binary(&mut self, min: u8) -> R<Expr> {
        let mut lhs = self.unary()?;
        loop {
            if self.is_punct("..") && 4 >= min {
                self.bump();
                let rhs = self.binary(5)?;
                let span = lhs.span.to(rhs.span);
                lhs = Expr { kind: ExprKind::Range(Box::new(lhs), Box::new(rhs)), span };
                continue;
            }
            let Some(op) = self.binop() else { break };
            // A `-` starting a new line begins a new statement.
            if op == BinOp::Sub && self.peek().nl_before {
                break;
            }
            let p = op.prec();
            if p < min {
                break;
            }
            self.bump();
            let rhs = self.binary(p.saturating_add(1))?;
            let span = lhs.span.to(rhs.span);
            lhs = Expr { kind: ExprKind::Binary(op, Box::new(lhs), Box::new(rhs)), span };
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> R<Expr> {
        let t = self.peek().span;
        if self.eat_punct("!") {
            let e = self.unary()?;
            let span = t.to(e.span);
            return Ok(Expr { kind: ExprKind::Unary(UnOp::Not, Box::new(e)), span });
        }
        if self.eat_punct("-") {
            let e = self.unary()?;
            let span = t.to(e.span);
            return Ok(Expr { kind: ExprKind::Unary(UnOp::Neg, Box::new(e)), span });
        }
        if self.eat_kw("await") {
            let e = self.unary()?;
            let span = t.to(e.span);
            return Ok(Expr { kind: ExprKind::Await(Box::new(e)), span });
        }
        self.postfix()
    }

    fn postfix(&mut self) -> R<Expr> {
        let mut e = self.primary()?;
        loop {
            if self.is_punct(".") && !matches!(self.peek_at(1).tok, Tok::Punct(_)) {
                self.bump();
                let name = self.field_name()?;
                let span = e.span.to(name.span);
                e = Expr { kind: ExprKind::Field(Box::new(e), name), span };
            } else if self.is_punct("(") && !self.peek().nl_before {
                self.bump();
                let mut args = Vec::new();
                while !self.is_punct(")") {
                    // `name: value` or a positional value.
                    let named = matches!(&self.peek().tok, Tok::Ident(_)) && matches!(self.peek_at(1).tok, Tok::Punct(":"));
                    let name = if named {
                        let n = self.field_name()?; // keywords too: `from:`
                        self.bump();
                        Some(n)
                    } else {
                        None
                    };
                    args.push(CallArg { name, value: self.expr()? });
                    if !self.eat_punct(",") {
                        break;
                    }
                }
                let end = self.expect_punct(")")?;
                let span = e.span.to(end);
                e = Expr { kind: ExprKind::Call(Box::new(e), args), span };
            } else if self.is_punct("[") && !self.peek().nl_before {
                self.bump();
                let idx = self.expr()?;
                let end = self.expect_punct("]")?;
                let span = e.span.to(end);
                e = Expr { kind: ExprKind::Index(Box::new(e), Box::new(idx)), span };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn primary(&mut self) -> R<Expr> {
        let t = self.peek().clone();
        let kind = match &t.tok {
            Tok::Int(n) => {
                self.bump();
                ExprKind::Int(*n)
            }
            Tok::Duration(ms, text) => {
                self.bump();
                ExprKind::Duration(*ms, text.clone())
            }
            Tok::Str(raw, triple) => {
                self.bump();
                // Holes are located by the lexer; the rest from the start of
                // the contents (approximate after escapes).
                ExprKind::Str(split_interpolation(raw, t.span.start.saturating_add(if *triple { 3 } else { 1 }), &t.holes)?)
            }
            Tok::Ident(k) if k == "true" || k == "false" => {
                self.bump();
                ExprKind::Bool(k == "true")
            }
            Tok::Ident(k) if !KEYWORDS.contains(&k.as_str()) => {
                self.bump();
                ExprKind::Ident(k.clone())
            }
            Tok::Punct("(") => {
                self.bump();
                let e = self.expr()?;
                self.expect_punct(")")?;
                ExprKind::Paren(Box::new(e))
            }
            Tok::Punct("[") => {
                self.bump();
                let mut items = Vec::new();
                while !self.is_punct("]") {
                    items.push(self.expr()?);
                    if !self.eat_punct(",") {
                        break;
                    }
                }
                self.expect_punct("]")?;
                ExprKind::List(items)
            }
            _ => return Err(self.err_here(&format!("expected an expression, found {}", self.found()))),
        };
        Ok(Expr { kind, span: Span { start: t.span.start, end: self.prev_end() } })
    }
}

/// `"a {x} b"` → parts; holes are parsed as expressions. `holes`: where
/// each hole's text starts in the source (from the lexer).
fn split_interpolation(raw: &str, offset: usize, holes: &[usize]) -> R<Vec<StrPart>> {
    let mut holes = holes.iter();
    let mut parts = Vec::new();
    let mut lit = String::new();
    let mut chars = raw.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '{' => {
                let start = i.saturating_add(1);
                let mut depth: usize = 1;
                let mut end = start;
                let mut quoted = false;
                for (j, d) in chars.by_ref() {
                    match d {
                        '"' => quoted = !quoted,
                        _ if quoted => {}
                        '{' => depth = depth.saturating_add(1),
                        '}' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                end = j;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if depth != 0 {
                    return Err(ParseError {
                        msg: "unclosed `{` in string (write \\{ for a brace)".into(),
                        span: Span { start: offset.saturating_add(i), end: offset.saturating_add(raw.len()) },
                    });
                }
                if !lit.is_empty() {
                    parts.push(StrPart::Lit(std::mem::take(&mut lit)));
                }
                // `start` follows a `{` and `end` is on a `}`.
                let text = raw.get(start..end).unwrap_or_default();
                let at = holes.next().copied().unwrap_or(offset.saturating_add(start));
                parts.push(StrPart::Expr(parse_expr(text, at)?));
            }
            '}' => {
                return Err(ParseError {
                    msg: "`}` without `{` in string (write \\} for a brace)".into(),
                    span: Span { start: offset.saturating_add(i), end: offset.saturating_add(i).saturating_add(1) },
                });
            }
            LBRACE => lit.push('{'),
            RBRACE => lit.push('}'),
            c => lit.push(c),
        }
    }
    if !lit.is_empty() || parts.is_empty() {
        parts.push(StrPart::Lit(lit));
    }
    Ok(parts)
}
