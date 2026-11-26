//! The `.fsr` syntax tree. Every node keeps its byte span (diagnostics)
//! and the comments around it (the formatter).

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn to(self, other: Span) -> Span {
        Span { start: self.start.min(other.start), end: self.end.max(other.end) }
    }
}

/// Comments attached to a node: own-line ones before it, and one after it
/// on its last line.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Trivia {
    pub leading: Vec<String>,
    pub trailing: Option<String>,
    /// A blank line separated it from what came before (kept by fmt).
    pub blank_before: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    pub text: String,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct File {
    pub items: Vec<Item>,
    /// Comments after the last item.
    pub tail: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub kind: ItemKind,
    pub span: Span,
    pub trivia: Trivia,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ItemKind {
    /// `import txn, location`
    Modules(Vec<Name>),
    /// `import { features } from config`
    FromConfig(Vec<Name>, Name),
    /// `import "./pstn.fsr" as pstn`
    File(String, Name),
    /// `flag NATED`, `flag FLT_ACC = 1` (a fixed bit); `branch flag
    /// FLB_NATB = 6` (true: a branch flag)
    Flag(Name, Option<(i64, Span)>, bool),
    /// `route main(msg: Request) { … }`
    Route(Func),
    /// `fn invite(msg: Request) -> Action { … }`
    Fn(Func),
    /// `on reply(r: Reply) where r.code in 180..183 { … }`
    On(On),
    /// `shared table bans: Map<Str, Bool> ttl 10m`
    Table { name: Name, ty: TypeRef, ttl: Option<Expr> },
    /// `dialog var caller: Str`
    DialogVar { name: Name, ty: TypeRef },
    /// `test "name" { … }` (`ferrosip test`)
    Test(String, Block),
}

#[derive(Clone, Debug, PartialEq)]
pub struct TypeRef {
    pub name: Name,
    pub args: Vec<TypeRef>,
    pub optional: bool,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    pub name: Name,
    pub ty: TypeRef,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Func {
    pub name: Name,
    pub params: Vec<Param>,
    pub ret: Option<TypeRef>,
    pub body: Block,
}

#[derive(Clone, Debug, PartialEq)]
pub struct On {
    /// `reply`, `dialog.ended`, `timer`…
    pub event: Name,
    pub params: Vec<Param>,
    /// Named settings in the parentheses (`on timer(every: 30s)`).
    pub args: Vec<CallArg>,
    pub cond: Option<Expr>,
    pub body: Block,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
    /// Comments before the closing brace.
    pub tail: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
    pub trivia: Trivia,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StmtKind {
    /// `let x[: T] = e [else stmt]`
    Let {
        name: Name,
        ty: Option<TypeRef>,
        value: Expr,
        otherwise: Option<Box<Stmt>>,
    },
    /// `target = e`
    Assign(Expr, Expr),
    If(Expr, Block, Option<Else>),
    While(Expr, Block),
    /// `for x in [a, b] { … }` / `for i in 1..3 { … }`
    For(Name, Expr, Block),
    /// `guard cond else stmt`
    Guard(Expr, Box<Stmt>),
    Match(Expr, Vec<Arm>),
    Return(Option<Expr>),
    Drop,
    Exit,
    Break,
    Expr(Expr),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Else {
    Block(Block),
    If(Box<Stmt>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arm {
    pub pats: Vec<Pat>,
    pub guard: Option<Expr>,
    pub body: ArmBody,
    pub span: Span,
    pub trivia: Trivia,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ArmBody {
    Block(Block),
    Stmt(Box<Stmt>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Pat {
    Wild(Span),
    /// A literal int or string, or a constant name (`INVITE`).
    Lit(Expr),
    /// `200..299`, `Ringing..SessionProgress` (inclusive): each end an
    /// int literal or a status code name.
    Range(Box<Expr>, Box<Expr>, Span),
    /// `Final(r)`, `Final(_)`, `Timeout`.
    Variant(Name, Option<Name>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Not,
    Neg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    /// `=~` regex match
    Match,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

impl BinOp {
    pub fn text(self) -> &'static str {
        match self {
            BinOp::Or => "||",
            BinOp::And => "&&",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::In => "in",
            BinOp::Match => "=~",
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
        }
    }

    /// Binding strength (higher binds tighter).
    pub fn prec(self) -> u8 {
        match self {
            BinOp::Or => 1,
            BinOp::And => 2,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge | BinOp::In | BinOp::Match => 3,
            BinOp::Add | BinOp::Sub => 5,
            BinOp::Mul | BinOp::Div | BinOp::Mod => 6,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    Int(i64),
    Str(Vec<StrPart>),
    Bool(bool),
    /// `30s`: milliseconds, and the text as written.
    Duration(u64, String),
    Ident(String),
    Field(Box<Expr>, Name),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<CallArg>),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `a..b` (inclusive)
    Range(Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Await(Box<Expr>),
    Paren(Box<Expr>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallArg {
    pub name: Option<Name>,
    pub value: Expr,
}

#[derive(Clone, Debug, PartialEq)]
pub enum StrPart {
    Lit(String),
    Expr(Expr),
}
