//! Recursive-descent parser producing an AST (no name resolution yet —
//! modules are loaded between parsing and compiling).

use crate::lexer::{Tok, lex};

#[derive(Debug, Default)]
pub struct Ast {
    pub modules: Vec<String>,
    pub modparams: Vec<ModParam>,
    pub request_route: Vec<Stmt>,
    /// `route[NAME] { … }` subroutines, called with `route(NAME)`.
    pub routes: Vec<(String, Vec<Stmt>)>,
    /// `failure_route[name] { … }`, in definition order.
    pub failure_routes: Vec<(String, Vec<Stmt>)>,
    /// `onreply_route[name] { … }`, in definition order.
    pub onreply_routes: Vec<(String, Vec<Stmt>)>,
    /// `branch_route[name] { … }` (armed with `t_on_branch`).
    pub branch_routes: Vec<(String, Vec<Stmt>)>,
    /// `event_route[module:event] { … }`.
    pub event_routes: Vec<(String, Vec<Stmt>)>,
    /// `reply_route { … }` (or unnamed `onreply_route`): every reply.
    pub reply_route: Option<Vec<Stmt>>,
}

/// `modparam("usrloc", "use_domain", 1)`
#[derive(Debug)]
pub struct ModParam {
    pub module: String,
    pub name: String,
    pub value: RawArg,
    pub line: usize,
}

/// A function argument before variables are resolved.
#[derive(Debug, Clone)]
pub enum RawArg {
    Str(String),
    Int(i64),
    Pv(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Match,
    NoMatch,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitOr,
    BitAnd,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Str(String),
    Int(i64),
    Pv(String, usize),
    Call {
        name: String,
        args: Vec<RawArg>,
        line: usize,
    },
    Route(String, usize),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    /// The `myself` keyword (our own addresses and domains).
    Myself,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    If(Expr, Vec<Stmt>, Vec<Stmt>),
    While(Expr, Vec<Stmt>),
    /// switch: (case value, body); `None` = default.
    Switch(Expr, Vec<(Option<Expr>, Vec<Stmt>)>),
    Assign(String, Expr, usize),
    Expr(Expr),
    Exit,
    /// `drop`: like exit; in a reply/branch route it also drops the message.
    Drop,
    Return(Option<Expr>),
    Break,
}

struct P {
    toks: Vec<(Tok, usize)>,
    i: usize,
}

pub fn parse(src: &str) -> Result<Ast, String> {
    let mut p = P { toks: lex(src)?, i: 0 };
    let mut ast = Ast::default();
    while let Some(t) = p.peek().cloned() {
        let line = p.line();
        match t {
            Tok::Ident(k) if k == "loadmodule" => {
                p.advance(1);
                match p.next()? {
                    // "tm", "tm.so" or "/usr/lib/kamailio/modules/tm.so"
                    Tok::Str(m) => ast.modules.push(m.rsplit('/').next().unwrap_or(&m).trim_end_matches(".so").to_string()),
                    t => return Err(p.err(&format!("expected module name, got {t:?}"))),
                }
                p.eat(&Tok::Semi);
            }
            Tok::Ident(k) if k == "modparam" => {
                p.advance(1);
                let a = p.args()?;
                match (a.first(), a.get(1), a.get(2), a.len()) {
                    (Some(RawArg::Str(m)), Some(RawArg::Str(n)), Some(v), 3) => {
                        ast.modparams.push(ModParam { module: m.clone(), name: n.clone(), value: v.clone(), line })
                    }
                    _ => return Err(format!("line {line}: modparam(\"module\", \"name\", value)")),
                }
                p.eat(&Tok::Semi);
            }
            Tok::Ident(k) if k == "request_route" => {
                p.advance(1);
                ast.request_route = p.block()?;
            }
            Tok::Ident(k) if matches!(k.as_str(), "route" | "failure_route" | "onreply_route" | "reply_route" | "branch_route" | "event_route") => {
                p.advance(1);
                let name = if k != "reply_route" && p.eat(&Tok::LBracket) { Some(p.route_name()?) } else { None };
                let body = p.block()?;
                let list = match (k.as_str(), name) {
                    ("route", None) => {
                        ast.request_route = body; // `route { }` = main route (Kamailio)
                        continue;
                    }
                    ("route", Some(n)) => (&mut ast.routes, n),
                    ("failure_route", Some(n)) => (&mut ast.failure_routes, n),
                    ("onreply_route", Some(n)) => (&mut ast.onreply_routes, n),
                    ("branch_route", Some(n)) => (&mut ast.branch_routes, n),
                    ("event_route", Some(n)) => (&mut ast.event_routes, n),
                    ("onreply_route" | "reply_route", None) => {
                        if ast.reply_route.is_some() {
                            return Err(format!("line {line}: global reply route defined twice"));
                        }
                        ast.reply_route = Some(body);
                        continue;
                    }
                    // Only `reply_route` may be nameless, handled above.
                    (k, _) => return Err(format!("line {line}: {k} needs a name: {k}[NAME]")),
                };
                if list.0.iter().any(|(m, _)| *m == list.1) {
                    return Err(format!("line {line}: {k}[{}] defined twice", list.1));
                }
                list.0.push((list.1, body));
            }
            t => return Err(p.err(&format!("unexpected {t:?} at top level"))),
        }
    }
    Ok(ast)
}

impl P {
    /// Steps over `n` tokens (a token index can't overflow).
    fn advance(&mut self, n: usize) {
        self.i = self.i.saturating_add(n);
    }
    fn line(&self) -> usize {
        self.toks.get(self.i.min(self.toks.len().saturating_sub(1))).map_or(0, |t| t.1)
    }
    fn err(&self, m: &str) -> String {
        format!("line {}: {m}", self.line())
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.0)
    }
    fn peek2(&self) -> Option<&Tok> {
        self.toks.get(self.i.saturating_add(1)).map(|t| &t.0)
    }
    fn next(&mut self) -> Result<Tok, String> {
        let t = self.toks.get(self.i).map(|t| t.0.clone()).ok_or_else(|| self.err("unexpected end of file"))?;
        self.advance(1);
        Ok(t)
    }
    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == Some(t) {
            self.advance(1);
            true
        } else {
            false
        }
    }
    fn expect(&mut self, t: Tok) -> Result<(), String> {
        if self.eat(&t) { Ok(()) } else { Err(self.err(&format!("expected {t:?}, got {:?}", self.peek()))) }
    }

    /// `[NAME]` contents: an identifier, a string, or tokens like `tm:local-request`.
    fn route_name(&mut self) -> Result<String, String> {
        let mut name = String::new();
        loop {
            match self.next()? {
                Tok::RBracket if !name.is_empty() => return Ok(name),
                Tok::Ident(s) | Tok::Str(s) => name.push_str(&s),
                Tok::Int(i) => name.push_str(&i.to_string()),
                Tok::Colon => name.push(':'),
                Tok::Minus => name.push('-'),
                t => return Err(self.err(&format!("bad route name token {t:?}"))),
            }
        }
    }

    fn block(&mut self) -> Result<Vec<Stmt>, String> {
        self.expect(Tok::LBrace)?;
        let mut v = Vec::new();
        while !self.eat(&Tok::RBrace) {
            if self.eat(&Tok::Semi) {
                continue;
            }
            v.push(self.stmt()?);
        }
        Ok(v)
    }

    /// `{ … }`, or a single statement (Kamailio allows `if (c) stmt;`).
    fn body(&mut self) -> Result<Vec<Stmt>, String> {
        if self.peek() == Some(&Tok::LBrace) { self.block() } else { Ok(vec![self.stmt()?]) }
    }

    /// A string literal, joined with any string literals right after it
    /// (`"a=1;"\n"b=2"`, as Kamailio does).
    fn more_strings(&mut self, mut s: String) -> String {
        while let Some(Tok::Str(t)) = self.peek() {
            s.push_str(t);
            self.advance(1);
        }
        s
    }

    fn stmt(&mut self) -> Result<Stmt, String> {
        let line = self.line();
        match self.peek().cloned() {
            Some(Tok::Ident(k)) if k == "if" => {
                self.advance(1);
                let c = self.expr()?;
                let then = self.body()?;
                let els = if matches!(self.peek(), Some(Tok::Ident(k)) if k == "else") {
                    self.advance(1);
                    self.body()?
                } else {
                    vec![]
                };
                Ok(Stmt::If(c, then, els))
            }
            Some(Tok::Ident(k)) if k == "while" => {
                self.advance(1);
                let c = self.expr()?;
                Ok(Stmt::While(c, self.body()?))
            }
            Some(Tok::Ident(k)) if k == "switch" => {
                self.advance(1);
                let v = self.expr()?;
                self.expect(Tok::LBrace)?;
                let mut cases: Vec<(Option<Expr>, Vec<Stmt>)> = Vec::new();
                while !self.eat(&Tok::RBrace) {
                    let label = match self.next()? {
                        Tok::Ident(k) if k == "case" => Some(self.unary()?),
                        Tok::Ident(k) if k == "default" => None,
                        t => return Err(self.err(&format!("expected case/default, got {t:?}"))),
                    };
                    self.expect(Tok::Colon)?;
                    let mut body = Vec::new();
                    while !matches!(self.peek(), Some(Tok::RBrace)) && !matches!(self.peek(), Some(Tok::Ident(k)) if k == "case" || k == "default") {
                        if self.eat(&Tok::Semi) {
                            continue;
                        }
                        body.push(self.stmt()?);
                    }
                    cases.push((label, body));
                }
                Ok(Stmt::Switch(v, cases))
            }
            Some(Tok::Ident(k)) if k == "exit" || k == "drop" || k == "break" => {
                self.advance(1);
                if self.eat(&Tok::LParen) {
                    self.expect(Tok::RParen)?;
                }
                self.expect(Tok::Semi)?;
                Ok(match k.as_str() {
                    "drop" => Stmt::Drop,
                    "break" => Stmt::Break,
                    _ => Stmt::Exit,
                })
            }
            Some(Tok::Ident(k)) if k == "return" => {
                self.advance(1);
                if self.eat(&Tok::Semi) {
                    return Ok(Stmt::Return(None));
                }
                let v = self.expr()?;
                self.expect(Tok::Semi)?;
                Ok(Stmt::Return(Some(v)))
            }
            Some(Tok::Pv(name)) if self.peek2() == Some(&Tok::Assign) => {
                self.advance(2);
                let e = self.expr()?;
                self.expect(Tok::Semi)?;
                Ok(Stmt::Assign(name, e, line))
            }
            Some(Tok::Ident(_)) => {
                let e = self.unary()?;
                if !matches!(e, Expr::Call { .. } | Expr::Route(..)) {
                    return Err(format!("line {line}: expected a statement"));
                }
                // Old configs leave out the ';' before `else` and `}`.
                if !matches!(self.peek(), Some(Tok::RBrace)) && !matches!(self.peek(), Some(Tok::Ident(k)) if k == "else") {
                    self.expect(Tok::Semi)?;
                }
                Ok(Stmt::Expr(e))
            }
            Some(t) => Err(format!("line {line}: unexpected {t:?}")),
            None => Err(format!("line {line}: unexpected end of file (missing '}}'?)")),
        }
    }

    fn args(&mut self) -> Result<Vec<RawArg>, String> {
        self.expect(Tok::LParen)?;
        let mut a = Vec::new();
        if self.eat(&Tok::RParen) {
            return Ok(a);
        }
        loop {
            let mut arg = match self.next()? {
                Tok::Str(s) => RawArg::Str(self.more_strings(s)),
                Tok::Int(i) => RawArg::Int(i),
                Tok::Minus => match self.next()? {
                    Tok::Int(i) => RawArg::Int(i.wrapping_neg()),
                    t => return Err(self.err(&format!("expected number after -, got {t:?}"))),
                },
                Tok::Pv(p) => RawArg::Pv(p),
                Tok::Ident(s) if s == "max_len" => RawArg::Int(65535),
                // Bare identifiers are accepted as strings (route names, flags…).
                Tok::Ident(s) => RawArg::Str(s),
                t => return Err(self.err(&format!("expected literal or variable, got {t:?}"))),
            };
            // `"sip:" + $hdr(Host)`: concatenation, folded into one template.
            while self.eat(&Tok::Plus) {
                let mut s = match arg {
                    RawArg::Str(s) | RawArg::Pv(s) => s,
                    RawArg::Int(i) => i.to_string(),
                };
                match self.next()? {
                    Tok::Str(t) => s.push_str(&self.more_strings(t)),
                    Tok::Int(i) => s.push_str(&i.to_string()),
                    Tok::Pv(p) => s.push_str(&p),
                    t => return Err(self.err(&format!("expected a string or variable after +, got {t:?}"))),
                }
                arg = RawArg::Str(s);
            }
            a.push(arg);
            if self.eat(&Tok::RParen) {
                return Ok(a);
            }
            self.expect(Tok::Comma)?;
        }
    }

    // Precedence: || < && < comparison < + - < * / % < unary < primary
    pub fn expr(&mut self) -> Result<Expr, String> {
        let mut e = self.and()?;
        while self.eat(&Tok::OrOr) {
            e = Expr::Bin(BinOp::Or, Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }
    fn and(&mut self) -> Result<Expr, String> {
        let mut e = self.bit_or()?;
        while self.eat(&Tok::AndAnd) {
            e = Expr::Bin(BinOp::And, Box::new(e), Box::new(self.bit_or()?));
        }
        Ok(e)
    }
    // Kamailio's binary | and & bind looser than comparisons (as in C).
    fn bit_or(&mut self) -> Result<Expr, String> {
        let mut e = self.bit_and()?;
        while self.eat(&Tok::Pipe) {
            e = Expr::Bin(BinOp::BitOr, Box::new(e), Box::new(self.bit_and()?));
        }
        Ok(e)
    }
    fn bit_and(&mut self) -> Result<Expr, String> {
        let mut e = self.cmp()?;
        while self.eat(&Tok::Amp) {
            e = Expr::Bin(BinOp::BitAnd, Box::new(e), Box::new(self.cmp()?));
        }
        Ok(e)
    }
    fn cmp(&mut self) -> Result<Expr, String> {
        let e = self.add()?;
        let op = match self.peek() {
            Some(Tok::EqEq) => BinOp::Eq,
            Some(Tok::Ne) => BinOp::Ne,
            Some(Tok::Lt) => BinOp::Lt,
            Some(Tok::Gt) => BinOp::Gt,
            Some(Tok::Le) => BinOp::Le,
            Some(Tok::Ge) => BinOp::Ge,
            Some(Tok::Match) => BinOp::Match,
            Some(Tok::NoMatch) => BinOp::NoMatch,
            _ => return Ok(e),
        };
        self.advance(1);
        Ok(Expr::Bin(op, Box::new(e), Box::new(self.add()?)))
    }
    fn add(&mut self) -> Result<Expr, String> {
        let mut e = self.mul()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => BinOp::Add,
                Some(Tok::Minus) => BinOp::Sub,
                _ => return Ok(e),
            };
            self.advance(1);
            e = Expr::Bin(op, Box::new(e), Box::new(self.mul()?));
        }
    }
    fn mul(&mut self) -> Result<Expr, String> {
        let mut e = self.unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => BinOp::Mul,
                Some(Tok::Slash) => BinOp::Div,
                Some(Tok::Percent) => BinOp::Mod,
                Some(Tok::Ident(k)) if k == "mod" => BinOp::Mod,
                _ => return Ok(e),
            };
            self.advance(1);
            e = Expr::Bin(op, Box::new(e), Box::new(self.unary()?));
        }
    }
    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::Bang) {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.eat(&Tok::Minus) {
            return Ok(match self.unary()? {
                Expr::Int(i) => Expr::Int(i.wrapping_neg()),
                e => Expr::Neg(Box::new(e)),
            });
        }
        self.primary()
    }
    /// After a `(`: `int)` or `str)` makes a cast, written as `zero + x`
    /// since `+` takes its type from the left operand.
    fn cast_zero(&self) -> Option<Expr> {
        match (self.peek()?, self.peek2()?) {
            (Tok::Ident(k), Tok::RParen) if k == "int" => Some(Expr::Int(0)),
            (Tok::Ident(k), Tok::RParen) if k == "str" => Some(Expr::Str(String::new())),
            _ => None,
        }
    }
    fn primary(&mut self) -> Result<Expr, String> {
        let line = self.line();
        match self.next()? {
            Tok::Str(s) => Ok(Expr::Str(self.more_strings(s))),
            Tok::Int(i) => Ok(Expr::Int(i)),
            Tok::Pv(p) => Ok(Expr::Pv(p, line)),
            // Casts: (int)$hdr(Expires), (str)$var(x).
            Tok::LParen if let Some(zero) = self.cast_zero() => {
                self.advance(2);
                let e = self.unary()?;
                Ok(Expr::Bin(BinOp::Add, Box::new(zero), Box::new(e)))
            }
            Tok::LParen => {
                let e = self.expr()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Tok::Ident(k) if k == "route" && self.peek() == Some(&Tok::LParen) => {
                self.advance(1);
                let n = match self.next()? {
                    Tok::Ident(n) | Tok::Str(n) => n,
                    // Old configs number their routes: route[1] / route(1).
                    Tok::Int(i) => i.to_string(),
                    t => return Err(self.err(&format!("expected route name, got {t:?}"))),
                };
                self.expect(Tok::RParen)?;
                Ok(Expr::Route(n, line))
            }
            Tok::Ident(k) if self.peek() == Some(&Tok::LParen) => Ok(Expr::Call { name: k, args: self.args()?, line }),
            // Core keywords (Kamailio): method, uri, src_ip, … map to variables.
            Tok::Ident(k) => Ok(match k.as_str() {
                "method" => Expr::Pv("$rm".into(), line),
                "uri" => Expr::Pv("$ru".into(), line),
                "src_ip" => Expr::Pv("$si".into(), line),
                "src_port" => Expr::Pv("$sp".into(), line),
                "dst_ip" => Expr::Pv("$Ri".into(), line),
                "dst_port" => Expr::Pv("$Rp".into(), line),
                "from_uri" => Expr::Pv("$fu".into(), line),
                "to_uri" => Expr::Pv("$tu".into(), line),
                "af" => Expr::Pv("$af".into(), line),
                "proto" => Expr::Pv("$pr".into(), line),
                // Protocol and address-family constants (compared with proto / af).
                "UDP" | "TCP" | "TLS" | "SCTP" | "WS" | "WSS" | "udp" | "tcp" | "tls" | "sctp" | "ws" | "wss" => Expr::Str(k.to_ascii_lowercase()),
                "INET" | "INET6" => Expr::Str(k),
                "status" => Expr::Pv("$rs".into(), line),
                "rc" | "retcode" => Expr::Pv("$rc".into(), line),
                "myself" => Expr::Myself,
                "true" => Expr::Int(1),
                // Kamailio's maximum message size (BUF_SIZE).
                "max_len" => Expr::Int(65535),
                "false" => Expr::Int(0),
                _ => return Err(format!("line {line}: unknown keyword {k:?} (missing parentheses for a function call?)")),
            }),
            t => Err(format!("line {line}: expected an expression, got {t:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let ast = parse(
            r#"loadmodule "tm.so"
            # comment
            /* block
               comment */
            request_route {
                if !mf_process(70) || method == "BYE" { reply(483, "x"); exit; }
                else if (method == "OPTIONS") { exit; }
                $var(n) = 1 + 2 * 3;
                while ($var(n) > 0) { $var(n) = $var(n) - 1; }
                switch ($rU) { case "a": break; case 2: route(X); default: drop; }
                if (route(X) && $ru =~ "^sip:") { return(2); }
                t_relay("1.2.3.4:5060");
            }
            route[X] { return; }
            event_route[tm:local-request] { exit; }
            "#,
        )
        .unwrap();
        assert_eq!(ast.modules, ["tm"]);
        assert_eq!(ast.request_route.len(), 6); // the else-if belongs to the first if
        assert_eq!(ast.routes[0].0, "X");
        assert_eq!(ast.event_routes[0].0, "tm:local-request");
        let Stmt::Assign(_, Expr::Bin(BinOp::Add, _, r), _) = &ast.request_route[1] else { panic!() };
        assert!(matches!(**r, Expr::Bin(BinOp::Mul, ..)), "precedence");
    }

    #[test]
    fn errors() {
        assert!(parse("request_route { foo; }").unwrap_err().contains("unknown keyword"));
        assert!(parse("failure_route { exit; }").unwrap_err().contains("needs a name"));
        assert!(parse("route[A] { exit; } route[A] { exit; }").unwrap_err().contains("defined twice"));
    }

    /// Syntax from older and current Kamailio configs.
    #[test]
    fn kamailio_dialect() {
        let ast = parse(
            "route[1] { exit; }\n\
             request_route {\n\
               if (msg:len > max_len) route(1)\n\
               else x(\"sip:\" + $hdr(Host) + \":\" + 5060);\n\
               $var(a) = (int)$hdr(Expires) mod 10;\n\
               if (uri =~ \"a\" | uri =~ \"b\") x(@to.tag);\n\
             }",
        )
        .unwrap();
        let rr = &ast.request_route;
        let Stmt::If(Expr::Bin(BinOp::Gt, l, r), then, els) = &rr[0] else { panic!("{:?}", rr[0]) };
        assert!(matches!(&**l, Expr::Pv(p, _) if p == "$ml"));
        assert!(matches!(**r, Expr::Int(65535)));
        assert!(matches!(&then[0], Stmt::Expr(Expr::Route(n, _)) if n == "1"), "numeric route, no ';' before else");
        let Stmt::Expr(Expr::Call { args, .. }) = &els[0] else { panic!() };
        assert!(matches!(&args[0], RawArg::Str(s) if s == "sip:$hdr(Host):5060"), "{args:?}");
        let Stmt::Assign(_, Expr::Bin(BinOp::Mod, cast, _), _) = &rr[1] else { panic!("{:?}", rr[1]) };
        assert!(matches!(&**cast, Expr::Bin(BinOp::Add, z, _) if matches!(**z, Expr::Int(0))), "(int) cast");
        let Stmt::If(Expr::Bin(BinOp::BitOr, ..), then, _) = &rr[2] else { panic!("{:?}", rr[2]) };
        let Stmt::Expr(Expr::Call { args, .. }) = &then[0] else { panic!() };
        assert!(matches!(&args[0], RawArg::Pv(p) if p == "$sel(to.tag)"));
        assert!(ast.routes.iter().any(|(n, _)| n == "1"));
    }
    #[test]
    fn statement_forms() {
        let ast = parse(
            "request_route {\n\
               ;;\n\
               if (a()) b(); else c();\n\
               if (a()) { } else if (b()) { c(); } else { d(); }\n\
               exit();\n\
               return -1;\n\
               return(-1);\n\
               x(\"one\" \"two\", -3, max_len, bare, $ru);\n\
               switch ($rU) { case -1: case \"a\": ; default: }\n\
             }",
        )
        .unwrap();
        let rr = &ast.request_route;
        assert_eq!(rr.len(), 7, "{rr:?}");
        assert!(matches!(&rr[0], Stmt::If(_, t, e) if t.len() == 1 && e.len() == 1));
        let Stmt::If(_, _, els) = &rr[1] else { panic!() };
        assert!(matches!(&els[..], [Stmt::If(_, _, e)] if e.len() == 1), "else-if nests in the else arm");
        assert!(matches!(rr[2], Stmt::Exit));
        assert!(matches!(rr[3], Stmt::Return(Some(Expr::Int(-1)))));
        assert!(matches!(rr[4], Stmt::Return(Some(Expr::Int(-1)))));
        let Stmt::Expr(Expr::Call { args, .. }) = &rr[5] else { panic!() };
        let a: Vec<String> = args.iter().map(|a| format!("{a:?}")).collect();
        assert_eq!(a, ["Str(\"onetwo\")", "Int(-3)", "Int(65535)", "Str(\"bare\")", "Pv(\"$ru\")"]);
        let Stmt::Switch(_, cases) = &rr[6] else { panic!() };
        assert_eq!(cases.len(), 3);
        assert!(matches!(&cases[0], (Some(Expr::Int(-1)), b) if b.is_empty()));
        assert!(matches!(&cases[2], (None, b) if b.is_empty()));
    }

    #[test]
    fn route_kinds_and_names() {
        let ast = parse(
            "route { exit; }\n\
             route[\"quoted\"] { exit; }\n\
             route[a-b:c] { exit; }\n\
             route[2] { exit; }\n\
             failure_route[F] { exit; }\n\
             onreply_route[R] { exit; }\n\
             onreply_route { exit; }\n\
             branch_route[B] { exit; }\n\
             event_route[xhttp:request] { exit; }\n\
             loadmodule \"/usr/lib/kamailio/modules/tm.so\"\n\
             loadmodule \"sl\";\n\
             modparam(\"tm\", \"fr_timer\", -1)\n\
             modparam(\"x\", \"y\", \"a\" + \"b\");",
        )
        .unwrap();
        assert_eq!(ast.request_route.len(), 1, "an unnamed route is the main route");
        let names: Vec<&str> = ast.routes.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["quoted", "a-b:c", "2"]);
        assert_eq!(ast.failure_routes[0].0, "F");
        assert_eq!(ast.onreply_routes[0].0, "R");
        assert!(ast.reply_route.is_some(), "an unnamed onreply_route is the reply route");
        assert_eq!(ast.branch_routes[0].0, "B");
        assert_eq!(ast.event_routes[0].0, "xhttp:request");
        assert_eq!(ast.modules, ["tm", "sl"]);
        assert!(matches!(ast.modparams[0].value, RawArg::Int(-1)));
        assert!(matches!(&ast.modparams[1].value, RawArg::Str(s) if s == "ab"));
        assert_eq!(ast.modparams[1].line, 13);
    }

    #[test]
    fn precedence_and_associativity() {
        // Rendered fully parenthesised.
        fn show(e: &Expr) -> String {
            match e {
                Expr::Int(i) => i.to_string(),
                Expr::Str(s) => format!("{s:?}"),
                Expr::Pv(p, _) => p.clone(),
                Expr::Not(x) => format!("!{}", show(x)),
                Expr::Neg(x) => format!("-{}", show(x)),
                Expr::Bin(op, a, b) => format!("({} {op:?} {})", show(a), show(b)),
                e => format!("{e:?}"),
            }
        }
        let cases = [
            ("1 - 2 - 3", "((1 Sub 2) Sub 3)"),
            ("8 / 4 / 2", "((8 Div 4) Div 2)"),
            ("1 + 2 * 3", "(1 Add (2 Mul 3))"),
            ("-$var(a) * 2", "(-$var(a) Mul 2)"),
            ("!$var(a) && $var(b)", "(!$var(a) And $var(b))"),
            ("$var(a) || $var(b) && $var(c)", "($var(a) Or ($var(b) And $var(c)))"),
            ("$var(a) == 1 | $var(b) == 2", "(($var(a) Eq 1) BitOr ($var(b) Eq 2))"),
            ("1 | 2 & 3", "(1 BitOr (2 BitAnd 3))"),
            ("$var(a) + 1 < 3 * 2", "(($var(a) Add 1) Lt (3 Mul 2))"),
            ("(int)$var(a) + 1", "((0 Add $var(a)) Add 1)"),
            ("(str)$var(a)", "(\"\" Add $var(a))"),
            ("- -1", "1"),
        ];
        for (src, want) in cases {
            let ast = parse(&format!("request_route {{ $var(r) = {src}; }}")).unwrap();
            let Some(Stmt::Assign(_, e, _)) = ast.request_route.first() else { panic!("{src}") };
            assert_eq!(show(e), want, "{src}");
        }
    }

    #[test]
    fn error_messages_carry_lines() {
        let cases = [
            ("request_route {\n  x()\n  y();\n}", "line 3: expected Semi"),
            ("request_route {\n  x();\n", "unexpected end of file"),
            ("request_route {\n  $var(a) = ;\n}", "line 2: expected an expression"),
            ("\n\nfoo", "line 3: unexpected Ident(\"foo\") at top level"),
            ("loadmodule tm", "expected module name"),
            ("modparam(\"tm\", 1, 2)", "modparam(\"module\", \"name\", value)"),
            ("onreply_route { exit; }\nreply_route { exit; }", "line 2: global reply route defined twice"),
            ("branch_route { exit; }", "branch_route needs a name"),
            ("route[] { exit; }", "bad route name token RBracket"),
            ("request_route { switch (1) { foo: exit; } }", "expected case/default"),
            ("request_route { 1; }", "unexpected Int(1)"),
            ("request_route { route(R) + 1; }", "expected Semi"),
            ("request_route { x(-\"a\"); }", "expected number after -"),
            ("request_route { x(\"a\" + {); }", "expected a string or variable after +"),
        ];
        for (src, want) in cases {
            let e = parse(src).unwrap_err();
            assert!(e.contains(want), "{src:?}: {e}");
        }
    }
}
