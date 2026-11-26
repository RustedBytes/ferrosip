//! Pseudo-variables (Kamailio `pv`): `$name`, `$name(param)`,
//! `$name(param)[index]` and `$(name(param)[index]{transformation}…)`.
//!
//! Modules register variables by name with a getter and an optional setter;
//! the script compiler resolves every `$…` once at startup into a `PvRef`
//! (function pointers + parsed parameter + transformations). Strings that
//! contain variables compile into a `Fmt` template.

use crate::module::Ctx;
use std::any::Any;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// A script value.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Val {
    #[default]
    Null,
    Int(i64),
    Str(String),
}

impl Val {
    pub fn str(s: impl AsRef<[u8]>) -> Val {
        Val::Str(String::from_utf8_lossy(s.as_ref()).into_owned())
    }
    pub fn opt(s: Option<impl AsRef<[u8]>>) -> Val {
        s.map_or(Val::Null, Val::str)
    }
    /// A length or count as an integer (saturating at `i64::MAX`).
    pub fn count(n: usize) -> Val {
        Val::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Val::Null)
    }
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Val::Null => Cow::Borrowed(""),
            Val::Int(i) => Cow::Owned(i.to_string()),
            Val::Str(s) => Cow::Borrowed(s),
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Val::Null => None,
            Val::Int(i) => Some(*i),
            Val::Str(s) => s.trim().parse().ok(),
        }
    }
    /// Kamailio truthiness: non-zero integers, non-empty strings.
    pub fn truthy(&self) -> bool {
        match self {
            Val::Null => false,
            Val::Int(i) => *i != 0,
            Val::Str(s) => !s.is_empty(),
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Val::Null => f.write_str("<null>"),
            Val::Int(i) => write!(f, "{i}"),
            Val::Str(s) => f.write_str(s),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PvIdx {
    N(i64),
    All,
}

/// The `(param)[idx]` part of a variable, plus whatever the variable's
/// `fix` hook pre-computed from it at startup.
#[derive(Clone, Default)]
pub struct PvParam {
    pub name: String,
    pub idx: Option<PvIdx>,
    pub fixed: Option<Arc<dyn Any + Send + Sync>>,
}

impl PvParam {
    pub fn fixed<T: Any>(&self) -> Option<&T> {
        self.fixed.as_ref().and_then(|f| f.downcast_ref::<T>())
    }
}

pub type PvGetter = Arc<dyn Fn(&mut Ctx<'_, '_>, &PvParam) -> Val + Send + Sync>;
pub type PvSetter = Arc<dyn Fn(&mut Ctx<'_, '_>, &PvParam, Val) -> Result<(), String> + Send + Sync>;
/// Startup hook for a variable's parameter; gets the variable table so
/// parameters may themselves contain variables (`$sht(t=>$si)`).
pub type PvFix = Arc<dyn Fn(&mut PvParam, &PvTable) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
pub struct PvSpec {
    pub get: PvGetter,
    pub set: Option<PvSetter>,
    pub fix: Option<PvFix>,
    /// `$name(param)` form required.
    pub needs_param: bool,
}

impl PvSpec {
    pub fn ro(get: impl Fn(&mut Ctx<'_, '_>, &PvParam) -> Val + Send + Sync + 'static) -> Self {
        Self { get: Arc::new(get), set: None, fix: None, needs_param: false }
    }
    pub fn rw(
        get: impl Fn(&mut Ctx<'_, '_>, &PvParam) -> Val + Send + Sync + 'static,
        set: impl Fn(&mut Ctx<'_, '_>, &PvParam, Val) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self { get: Arc::new(get), set: Some(Arc::new(set)), fix: None, needs_param: false }
    }
    pub fn with_param(mut self) -> Self {
        self.needs_param = true;
        self
    }
    pub fn with_fix(mut self, fix: impl Fn(&mut PvParam, &PvTable) -> Result<(), String> + Send + Sync + 'static) -> Self {
        self.fix = Some(Arc::new(fix));
        self
    }
}

pub type PvTable = HashMap<String, PvSpec>;

/// A transformation `{class.op,arg,…}`.
#[derive(Clone, Debug)]
pub struct Tr {
    pub op: String,
    pub args: Vec<String>,
    /// `{re.subst,/re/repl/flags}`, compiled when the variable is resolved.
    re: Option<Arc<ReSubst>>,
}

impl PartialEq for Tr {
    fn eq(&self, o: &Self) -> bool {
        self.op == o.op && self.args == o.args
    }
}

impl Eq for Tr {}

impl Tr {
    pub fn new(op: impl Into<String>, args: Vec<String>) -> Self {
        Tr { op: op.into(), args, re: None }
    }
}

/// A compiled sed-style substitution.
#[derive(Debug)]
struct ReSubst {
    re: regex::Regex,
    /// Replacement in regex syntax (`\1` → `${1}`).
    repl: String,
    global: bool,
}

impl ReSubst {
    /// `/re/repl/flags` with any delimiter; flags `g` (all) and `i`.
    fn parse(s: &str) -> Result<Self, String> {
        let mut chars = s.chars();
        let d = chars.next().ok_or("empty substitution")?;
        let (mut parts, mut cur) = (Vec::new(), String::new());
        let mut esc = false;
        for c in chars {
            if esc {
                if c != d {
                    cur.push('\\');
                }
                cur.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == d {
                parts.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        parts.push(cur);
        let [re, repl, flags] = <[String; 3]>::try_from(parts).map_err(|_| format!("expected {d}regex{d}replacement{d}flags"))?;
        let mut repl_out = String::new();
        let mut it = repl.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '\\' if it.peek().is_some_and(char::is_ascii_digit) => {
                    repl_out.push_str(&format!("${{{}}}", it.next().unwrap_or('0')));
                }
                '$' => repl_out.push_str("$$"),
                c => repl_out.push(c),
            }
        }
        let re = regex::RegexBuilder::new(&re).case_insensitive(flags.contains('i')).build().map_err(|e| e.to_string())?;
        Ok(ReSubst { re, repl: repl_out, global: flags.contains('g') })
    }
}

/// A variable resolved at startup.
#[derive(Clone)]
pub struct PvRef {
    pub name: String,
    spec: PvSpec,
    pub param: PvParam,
    trs: Vec<Tr>,
}

impl fmt::Debug for PvRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}", self.name)
    }
}

impl PvRef {
    pub fn get(&self, ctx: &mut Ctx<'_, '_>) -> Val {
        let mut v = (self.spec.get)(ctx, &self.param);
        for t in &self.trs {
            v = apply_tr(t, v);
        }
        v
    }
    pub fn settable(&self) -> bool {
        self.spec.set.is_some() && self.trs.is_empty()
    }
    pub fn set(&self, ctx: &mut Ctx<'_, '_>, v: Val) -> Result<(), String> {
        match (&self.spec.set, self.trs.is_empty()) {
            (Some(s), true) => s(ctx, &self.param, v),
            _ => Err(format!("${} is read-only", self.name)),
        }
    }
}

/// A string with embedded variables.
#[derive(Clone, Debug)]
pub enum FmtPart {
    Lit(String),
    Pv(PvRef),
}

#[derive(Clone, Debug)]
pub struct Fmt(pub Vec<FmtPart>);

impl Fmt {
    pub fn eval(&self, ctx: &mut Ctx<'_, '_>) -> String {
        let mut out = String::new();
        for p in &self.0 {
            match p {
                FmtPart::Lit(s) => out.push_str(s),
                FmtPart::Pv(r) => {
                    let v = r.get(ctx);
                    if !v.is_null() {
                        out.push_str(&v.as_str());
                    }
                }
            }
        }
        out
    }
    /// A template that is just one variable (for `f($avp(x))`).
    pub fn single_pv(&self) -> Option<&PvRef> {
        match &self.0[..] {
            [FmtPart::Pv(r)] => Some(r),
            _ => None,
        }
    }
    pub fn has_pv(&self) -> bool {
        self.0.iter().any(|p| matches!(p, FmtPart::Pv(_)))
    }
    pub fn literal(&self) -> String {
        self.0.iter().map(|p| if let FmtPart::Lit(s) = p { s.as_str() } else { "" }).collect()
    }
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Index of the `close` that balances the `open` at `s[0]`.
fn balanced(s: &[u8], open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = false;
    s.iter().position(|&c| {
        match c {
            b'"' => quote = !quote,
            c if c == open && !quote => depth = depth.saturating_add(1),
            c if c == close && !quote => {
                depth = depth.saturating_sub(1);
                return depth == 0;
            }
            _ => {}
        }
        false
    })
}

/// The bytes after the `close` that balances the `open` at `s[0]`.
fn after_balanced(s: &[u8], open: u8, close: u8) -> Option<&[u8]> {
    s.get(balanced(s, open, close)?..)?.get(1..)
}

/// The text after the (one-byte) character at `s[i]`.
fn after(s: &str, i: usize) -> Option<&str> {
    s.get(i..)?.get(1..)
}

/// Length of the variable expression at the start of `s` (which starts with
/// `$`), or 0 if it isn't one. Used by the script lexer and `parse_fmt`.
pub fn pv_len(s: &[u8]) -> usize {
    pv_rest(s).map_or(0, |rest| s.len().saturating_sub(rest.len()))
}

/// The bytes after the variable expression at the start of `s`.
fn pv_rest(s: &[u8]) -> Option<&[u8]> {
    let rest = s.strip_prefix(b"$")?;
    if rest.first() == Some(&b'(') {
        return after_balanced(rest, b'(', b')');
    }
    let name_len = rest.iter().take_while(|&&c| is_name_char(c)).count();
    if name_len == 0 {
        return None;
    }
    let mut rest = rest.get(name_len..)?;
    if rest.first() == Some(&b'(') {
        rest = after_balanced(rest, b'(', b')')?;
    }
    if rest.first() == Some(&b'[') {
        (_, rest) = sip_parser::util::split_once(rest, b']')?;
    }
    Some(rest)
}

/// Parse one variable expression (the whole of `s`).
pub fn parse_pv(s: &str, table: &PvTable) -> Result<PvRef, String> {
    let b = s.as_bytes();
    if b.len() < 2 || pv_len(b) != b.len() {
        return Err(format!("bad variable syntax {s:?}"));
    }
    // $( inner {tr}{tr} )
    let (inner, trs) = if let Some(body) = s.strip_prefix("$(") {
        let body = body.strip_suffix(')').ok_or_else(|| format!("bad variable syntax {s:?}"))?;
        let (head, mut rest) = body.split_at(body.find('{').unwrap_or(body.len()));
        let mut trs = Vec::new();
        while !rest.is_empty() {
            if !rest.starts_with('{') {
                return Err(format!("bad transformation in {s:?}"));
            }
            let end = balanced(rest.as_bytes(), b'{', b'}').ok_or_else(|| format!("unclosed transformation in {s:?}"))?;
            let t = rest.get(1..end).ok_or_else(|| format!("bad transformation in {s:?}"))?;
            let mut parts = split_args(t);
            let op = parts.remove(0);
            let mut tr = Tr::new(op.trim(), parts);
            if tr.op == "re.subst" {
                // The expression may contain commas: take it whole.
                let raw = t.split_once(',').map_or("", |(_, r)| r);
                tr.re = Some(Arc::new(ReSubst::parse(raw).map_err(|e| format!("{s}: {{re.subst}}: {e}"))?));
                tr.args = vec![raw.to_string()];
            }
            if tr.op == "s.select" && tr.args.len() == 3 && tr.args.get(1..) == Some(&[String::new(), String::new()][..]) {
                // `{s.select,1,,}`: the separator is a comma (Kamailio reads
                // it as a single raw character).
                tr.args.truncate(1);
                tr.args.push(",".into());
            }
            trs.push(tr);
            rest = after(rest, end).ok_or_else(|| format!("bad transformation in {s:?}"))?.trim_start();
        }
        (format!("${head}"), trs)
    } else {
        (s.to_string(), Vec::new())
    };
    let after_dollar = inner.get(1..).ok_or_else(|| format!("bad variable syntax {s:?}"))?;
    let name_len = after_dollar.bytes().take_while(|&c| is_name_char(c)).count();
    let (name, mut rest) = after_dollar.split_at_checked(name_len).ok_or_else(|| format!("bad variable syntax {s:?}"))?;
    let name = name.to_string();
    let mut param = PvParam::default();
    let mut has_param = false;
    if rest.starts_with('(') {
        let e = balanced(rest.as_bytes(), b'(', b')').ok_or_else(|| format!("unbalanced ( in {s:?}"))?;
        param.name = rest.get(1..e).ok_or_else(|| format!("bad variable syntax {s:?}"))?.trim().to_string();
        has_param = true;
        rest = after(rest, e).unwrap_or_default();
    }
    if let Some(bracketed) = rest.strip_prefix('[') {
        let (idx, _) = bracketed.split_once(']').ok_or_else(|| format!("unclosed [ in {s:?}"))?;
        let idx = idx.trim();
        param.idx = Some(if idx == "*" { PvIdx::All } else { PvIdx::N(idx.parse().map_err(|_| format!("bad index {idx:?} in {s:?}"))?) });
    }
    let spec = table.get(&name).ok_or_else(|| format!("unknown variable ${name}"))?.clone();
    if spec.needs_param && !has_param {
        return Err(format!("${name} needs a parameter: ${name}(…)"));
    }
    if let Some(fix) = &spec.fix {
        fix(&mut param, table).map_err(|e| format!("${name}({}): {e}", param.name))?;
    }
    for t in &trs {
        check_tr(t).map_err(|e| format!("{s}: {e}"))?;
    }
    Ok(PvRef { name, spec, param, trs })
}

/// Parse a string with embedded variables; `$$` is a literal `$`.
pub fn parse_fmt(s: &str, table: &PvTable) -> Result<Fmt, String> {
    let (mut parts, mut lit, mut rest) = (Vec::new(), String::new(), s);
    while let Some(ch) = rest.chars().next() {
        if ch == '$' {
            if let Some(after) = rest.strip_prefix("$$") {
                lit.push('$');
                rest = after;
                continue;
            }
            let n = pv_len(rest.as_bytes());
            if n > 0 {
                if !lit.is_empty() {
                    parts.push(FmtPart::Lit(std::mem::take(&mut lit)));
                }
                let (pv, after) = rest.split_at_checked(n).ok_or_else(|| format!("bad variable syntax in {s:?}"))?;
                parts.push(FmtPart::Pv(parse_pv(pv, table)?));
                rest = after;
                continue;
            }
        }
        lit.push(ch);
        rest = rest.get(ch.len_utf8()..).unwrap_or_default();
    }
    if !lit.is_empty() || parts.is_empty() {
        parts.push(FmtPart::Lit(lit));
    }
    Ok(Fmt(parts))
}

fn split_args(s: &str) -> Vec<String> {
    // Commas separate arguments; a backslash escapes the next character.
    let (mut out, mut cur, mut esc) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            _ if esc => {
                cur.push(c);
                esc = false;
            }
            '\\' => esc = true,
            ',' => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

const TRS: &[(&str, usize)] = &[
    ("s.len", 0),
    ("s.int", 0),
    ("s.tolower", 0),
    ("s.toupper", 0),
    ("s.trim", 0),
    ("s.rtrim", 0),
    ("s.ltrim", 0),
    ("s.substr", 2),
    ("s.select", 2),
    ("s.strip", 1),
    ("s.striptail", 1),
    ("s.prefixes", 0),
    ("s.replace", 2),
    ("re.subst", 1),
    ("s.unquote", 0),
    ("s.numeric", 0),
    ("uri.user", 0),
    ("uri.host", 0),
    ("uri.port", 0),
    ("uri.transport", 0),
    ("uri.scheme", 0),
    ("uri.params", 0),
    ("uri.param", 1),
    ("param.value", 1),
    ("param.exist", 1),
    ("param.count", 0),
    ("nameaddr.uri", 0),
    ("nameaddr.name", 0),
    ("tobody.uri", 0),
    ("tobody.tag", 0),
    ("json.parse", 1),
    ("sql.val", 0),
    ("sql.val.int", 0),
    ("sql.val.str", 0),
];

/// A string as an SQL literal: in single quotes, with `'` and `\`
/// doubled. Safe for SQLite, PostgreSQL and MySQL alike (MySQL reads `\\`
/// as one backslash; PostgreSQL and SQLite keep both, so only a value
/// with a backslash in it comes out differently there).
pub fn sql_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len().saturating_add(2));
    o.push('\'');
    for c in s.chars() {
        match c {
            '\'' => o.push_str("''"),
            '\\' => o.push_str("\\\\"),
            '\0' => {}
            c => o.push(c),
        }
    }
    o.push('\'');
    o
}

fn check_tr(t: &Tr) -> Result<(), String> {
    match TRS.iter().find(|(n, _)| *n == t.op) {
        // param.* take an optional separator; s.select takes 2.
        Some((_, n)) if t.args.len() == *n || (t.op.starts_with("param.") && t.args.len() == n.saturating_add(1)) => Ok(()),
        Some((_, n)) => Err(format!("{{{}}} takes {n} argument(s)", t.op)),
        None => Err(format!("unknown transformation {{{}}}", t.op)),
    }
}

/// Apply a transformation (unknown/invalid input yields `$null`, as in Kamailio).
/// A script count argument as a length: negative is 0, too large saturates.
fn non_neg(x: i64) -> usize {
    usize::try_from(x.max(0)).unwrap_or(usize::MAX)
}

pub fn apply_tr(t: &Tr, v: Val) -> Val {
    // Kamailio's {sql.val*}: a value ready to put into an SQL statement.
    match (t.op.as_str(), &v) {
        ("sql.val", Val::Null) => return Val::Str("NULL".into()),
        ("sql.val.int", Val::Null) => return Val::Int(0),
        ("sql.val.str", Val::Null) => return Val::Str("''".into()),
        ("sql.val" | "sql.val.int", Val::Int(i)) => return Val::Int(*i),
        ("sql.val.int", _) => return Val::Int(v.as_str().trim().parse().unwrap_or(0)),
        ("sql.val" | "sql.val.str", _) => return Val::Str(sql_quote(&v.as_str())),
        _ => {}
    }
    let s = v.as_str().into_owned();
    let a = |i: usize| t.args.get(i).map(String::as_str).unwrap_or("");
    let ai = |i: usize| a(i).trim().parse::<i64>().unwrap_or(0);
    let uri = || crate::pv::uri_parts(&s);
    match t.op.as_str() {
        "s.len" => Val::count(s.len()),
        "s.int" => Val::Int(s.trim().parse().unwrap_or(0)),
        "s.tolower" => Val::Str(s.to_lowercase()),
        "s.toupper" => Val::Str(s.to_uppercase()),
        "s.trim" => Val::Str(s.trim().to_string()),
        "s.rtrim" => Val::Str(s.trim_end().to_string()),
        "s.ltrim" => Val::Str(s.trim_start().to_string()),
        "s.numeric" => Val::Str(s.chars().filter(char::is_ascii_digit).collect()),
        // One matching pair of `"` or `'` (Kamailio pv_trans.c TR_S_UNQUOTE).
        "s.unquote" => Val::Str(match s.as_bytes() {
            [q @ (b'"' | b'\''), .., last] if last == q => s.get(1..s.len().saturating_sub(1)).unwrap_or_default().to_string(),
            _ => s.to_string(),
        }),
        "s.substr" => {
            let (off, len) = (ai(0), ai(1));
            let n = i64::try_from(s.len()).unwrap_or(i64::MAX);
            let start = if off < 0 { n.saturating_add(off).max(0) } else { off.min(n) };
            let start = usize::try_from(start).unwrap_or(s.len());
            let end = if len <= 0 { s.len() } else { start.saturating_add(usize::try_from(len).unwrap_or(usize::MAX)).min(s.len()) };
            Val::Str(s.get(start..end).unwrap_or("").to_string())
        }
        "s.select" => {
            let (idx, sep) = (ai(0), a(1).chars().next().unwrap_or(','));
            let parts: Vec<&str> = s.split(sep).collect();
            let i = if idx < 0 { i64::try_from(parts.len()).unwrap_or(i64::MAX).saturating_add(idx) } else { idx };
            usize::try_from(i).ok().and_then(|i| parts.get(i)).map_or(Val::Null, |p| Val::Str(p.to_string()))
        }
        "s.strip" => Val::Str(s.get(non_neg(ai(0))..).unwrap_or("").to_string()),
        "s.striptail" => Val::Str(s.get(..s.len().saturating_sub(non_neg(ai(0)))).unwrap_or("").to_string()),
        "s.prefixes" => Val::Str((1..=s.len()).filter_map(|i| s.get(..i)).collect::<Vec<_>>().join(",")),
        "s.replace" => Val::Str(s.replace(a(0), a(1))),
        "re.subst" => match &t.re {
            Some(r) if r.global => Val::Str(r.re.replace_all(&s, r.repl.as_str()).into_owned()),
            Some(r) => Val::Str(r.re.replace(&s, r.repl.as_str()).into_owned()),
            None => v,
        },
        "uri.user" => uri().map_or(Val::Null, |u| Val::opt(u.1)),
        "uri.host" => uri().map_or(Val::Null, |u| Val::Str(u.2)),
        "uri.port" => uri().and_then(|u| u.3).map_or(Val::Null, |p| Val::Int(i64::from(p))),
        "uri.scheme" => uri().map_or(Val::Null, |u| Val::Str(u.0)),
        "uri.params" => uri().map_or(Val::Null, |u| Val::Str(u.4)),
        "uri.transport" => uri().and_then(|u| param_of(&u.4, "transport", ';')).map_or(Val::Null, Val::Str),
        "uri.param" => uri().and_then(|u| param_of(&u.4, a(0), ';')).map_or(Val::Null, Val::Str),
        "param.value" => param_of(&s, a(0), a(1).chars().next().unwrap_or(';')).map_or(Val::Null, Val::Str),
        "param.exist" => Val::Int(i64::from(param_of(&s, a(0), a(1).chars().next().unwrap_or(';')).is_some())),
        "param.count" => Val::count(s.split(';').filter(|p| !p.trim().is_empty()).count()),
        "nameaddr.uri" | "tobody.uri" => Val::str(sip_parser::uri::name_addr(s.as_bytes()).0),
        "nameaddr.name" => {
            let name = s.split_once('<').map_or("", |(name, _)| name);
            Val::Str(name.trim().trim_matches('"').to_string())
        }
        "tobody.tag" => {
            let (_, params) = sip_parser::uri::name_addr(s.as_bytes());
            Val::opt(sip_parser::uri::param(params, b"tag"))
        }
        "json.parse" => {
            serde_json::from_str::<serde_json::Value>(&s).ok().and_then(|j| crate::json::get(&j, a(0)).map(crate::json::to_val)).unwrap_or(Val::Null)
        }
        _ => Val::Null,
    }
}

fn param_of(params: &str, name: &str, sep: char) -> Option<String> {
    params.split(sep).map(str::trim).find_map(|p| {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// (scheme, user, host, port, params) of a SIP URI.
pub type UriParts = (String, Option<String>, String, Option<u16>, String);

pub fn uri_parts(s: &str) -> Option<UriParts> {
    let u = sip_parser::parse_uri(s.as_bytes())?;
    let st = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    Some((st(u.scheme), u.user.map(st), st(u.host), u.port, st(u.params)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> PvTable {
        let mut t = PvTable::new();
        t.insert("ru".into(), PvSpec::ro(|_, _| Val::Str("sip:Alice@Example.com:5070;transport=tcp".into())));
        t.insert("var".into(), PvSpec::ro(|_, p| Val::Str(format!("v:{}", p.name))).with_param());
        t
    }

    #[test]
    fn lengths() {
        assert_eq!(pv_len(b"$ru@x"), 3);
        assert_eq!(pv_len(b"$var(a(b))[1] x"), 13);
        assert_eq!(pv_len(b"$(ru{uri.user}{s.len}) x"), 22);
        assert_eq!(pv_len(b"$ x"), 0);
        assert_eq!(pv_len(b"$(ru"), 0);
    }

    #[test]
    fn parse_and_transform() {
        let t = table();
        let r = parse_pv("$(ru{uri.user}{s.tolower})", &t).unwrap();
        assert_eq!(r.trs.len(), 2);
        assert_eq!(apply_tr(&r.trs[0], Val::Str("sip:Alice@x".into())), Val::Str("Alice".into()));
        let p = parse_pv("$var(x)[2]", &t).unwrap();
        assert_eq!((p.param.name.as_str(), p.param.idx.clone()), ("x", Some(PvIdx::N(2))));
        assert!(parse_pv("$var", &t).is_err(), "needs param");
        assert!(parse_pv("$nope", &t).is_err());
        assert!(parse_pv("$(ru{s.bogus})", &t).is_err());
    }

    #[test]
    fn fmt_parsing() {
        let t = table();
        let f = parse_fmt("to $var(u)@$$host", &t).unwrap();
        assert_eq!(f.0.len(), 3);
        assert_eq!(f.literal(), "to @$host");
        assert!(!parse_fmt("no vars, $ alone", &t).unwrap().has_pv());
    }

    #[test]
    fn fuzz_regressions() {
        let t = PvTable::default();
        // A transformation list cut inside a multi-byte character.
        let s =
            String::from_utf8_lossy(&[0x24, 0x28, 0x72, 0x75, 0x7b, 0x31, 0x7d, 0x72, 0x69, 0x2e, 0x75, 0x7b, 0x65, 0x32, 0x7d, 0xc3, 0xa9, 0x29]).into_owned();
        // Only not panicking matters.
        drop(parse_pv(&s, &t));
        drop(parse_fmt("T$(r$(ruu{1}ri.u{e2}uu{0n}\u{1}\u{e}{sllen}\u{11313}l)", &t));
    }

    #[test]
    fn transformations() {
        let tr = |op: &str, args: &[&str], v: &str| apply_tr(&Tr::new(op, args.iter().map(|s| s.to_string()).collect()), Val::Str(v.into()));
        assert_eq!(tr("s.substr", &["1", "3"], "abcdef"), Val::Str("bcd".into()));
        let ru = parse_pv("$(ru{re.subst,/;transport=([a-z]+)/;t=\\1/g})", &PvTable::from([("ru".into(), PvSpec::ro(|_, _| Val::Null))])).unwrap();
        assert_eq!(apply_tr(&ru.trs[0], Val::Str("sip:a@b;transport=tcp;x;transport=udp".into())), Val::Str("sip:a@b;t=tcp;x;t=udp".into()));
        assert_eq!(tr("s.select", &["-1", ","], "a,b,c"), Val::Str("c".into()));
        assert_eq!(tr("uri.port", &[], "sip:a@b:5070"), Val::Int(5070));
        assert_eq!(tr("uri.param", &["transport"], "sip:a@b;transport=tcp"), Val::Str("tcp".into()));
        assert_eq!(tr("tobody.tag", &[], "\"A\" <sip:a@b>;tag=xyz"), Val::Str("xyz".into()));
        assert_eq!(tr("param.value", &["q", ";"], "expires=60;q=0.5"), Val::Str("0.5".into()));
        assert_eq!(tr("s.prefixes", &[], "123"), Val::Str("1,12,123".into()));
    }
}

#[cfg(test)]
mod sql_tests {
    use super::sql_quote;

    #[test]
    fn sql_values_are_quoted() {
        assert_eq!(sql_quote("o'brien"), "'o''brien'");
        assert_eq!(sql_quote("x'or'1'='1"), "'x''or''1''=''1'");
        assert_eq!(sql_quote(r"\' OR 1=1 --"), r"'\\'' OR 1=1 --'");
        assert_eq!(sql_quote(""), "''");
    }
}

#[cfg(test)]
mod tr_tests {
    use super::*;

    fn s(v: &str) -> Val {
        Val::Str(v.into())
    }

    fn table() -> PvTable {
        PvTable::from([("x".to_string(), PvSpec::ro(|_, _| Val::Null)), ("p".to_string(), PvSpec::ro(|_, p| Val::Str(p.name.clone())).with_param())])
    }

    /// The transformations of `$(x{…}{…})`, applied in order to `input`.
    fn run(expr: &str, input: Val) -> Val {
        let r = parse_pv(expr, &table()).unwrap_or_else(|e| panic!("{expr}: {e}"));
        r.trs.iter().fold(input, |v, t| apply_tr(t, v))
    }

    #[test]
    fn string_transformations() {
        let cases: &[(&str, &str, Val)] = &[
            ("$(x{s.len})", "héllo", Val::Int(6)),
            ("$(x{s.len})", "", Val::Int(0)),
            ("$(x{s.int})", " 42 ", Val::Int(42)),
            ("$(x{s.int})", "-7", Val::Int(-7)),
            ("$(x{s.int})", "abc", Val::Int(0)),
            ("$(x{s.tolower})", "AbC", s("abc")),
            ("$(x{s.toupper})", "AbC", s("ABC")),
            ("$(x{s.trim})", " \t a b \r\n", s("a b")),
            ("$(x{s.rtrim})", " a ", s(" a")),
            ("$(x{s.ltrim})", " a ", s("a ")),
            ("$(x{s.numeric})", "+49 (30) 123-4", s("49301234")),
            ("$(x{s.unquote})", "\"abc\"", s("abc")),
            ("$(x{s.unquote})", "abc", s("abc")),
            ("$(x{s.unquote})", "'abc'", s("abc")),
            ("$(x{s.unquote})", "\"\"abc\"\"", s("\"abc\"")),
            ("$(x{s.unquote})", "\"abc'", s("\"abc'")),
            ("$(x{s.unquote})", "\"", s("\"")),
            ("$(x{s.substr,0,3})", "abcdef", s("abc")),
            ("$(x{s.substr,2,0})", "abcdef", s("cdef")),
            ("$(x{s.substr,-2,0})", "abcdef", s("ef")),
            ("$(x{s.substr,-2,1})", "abcdef", s("e")),
            ("$(x{s.substr,-20,2})", "abcdef", s("ab")),
            ("$(x{s.substr,4,10})", "abcdef", s("ef")),
            ("$(x{s.substr,10,2})", "abcdef", s("")),
            ("$(x{s.select,0,;})", "a;b;c", s("a")),
            ("$(x{s.select,2,;})", "a;b;c", s("c")),
            ("$(x{s.select,3,;})", "a;b;c", Val::Null),
            ("$(x{s.select,-1,;})", "a;b;c", s("c")),
            ("$(x{s.select,-3,;})", "a;b;c", s("a")),
            ("$(x{s.select,-4,;})", "a;b;c", Val::Null),
            ("$(x{s.select,1,\\,})", "a,b,c", s("b")),
            ("$(x{s.select,1,,})", "a,b,c", s("b")),
            ("$(x{s.strip,2})", "abcdef", s("cdef")),
            ("$(x{s.strip,10})", "abc", s("")),
            ("$(x{s.strip,-1})", "abc", s("abc")),
            ("$(x{s.striptail,2})", "abcdef", s("abcd")),
            ("$(x{s.striptail,10})", "abc", s("")),
            ("$(x{s.prefixes})", "", s("")),
            ("$(x{s.prefixes})", "49", s("4,49")),
            ("$(x{s.replace,a,xy})", "banana", s("bxynxynxy")),
            ("$(x{s.substr,1,3}{s.toupper}{s.len})", "abcdef", Val::Int(3)),
        ];
        for (expr, input, want) in cases {
            assert_eq!(&run(expr, s(input)), want, "{expr} on {input:?}");
        }
    }

    #[test]
    fn regex_substitution() {
        let cases: &[(&str, &str, &str)] = &[
            ("$(x{re.subst,/a/b/})", "aaa", "baa"),
            ("$(x{re.subst,/a/b/g})", "aaa", "bbb"),
            ("$(x{re.subst,/A/b/gi})", "aAa", "bbb"),
            ("$(x{re.subst,/^\\+?([0-9]+)$/00\\1/})", "+4930", "004930"),
            ("$(x{re.subst,#,#;#g})", "a,b", "a;b"),
            ("$(x{re.subst,/x/$1/})", "x", "$1"),
            ("$(x{re.subst,/q/z/})", "abc", "abc"),
        ];
        for (expr, input, want) in cases {
            assert_eq!(run(expr, s(input)), s(want), "{expr} on {input:?}");
        }
        for bad in ["$(x{re.subst,/a/b})", "$(x{re.subst,/(/b/})", "$(x{re.subst})"] {
            assert!(parse_pv(bad, &table()).is_err(), "{bad}");
        }
    }

    #[test]
    fn uri_and_param_transformations() {
        let uri = "sips:Alice@Example.com:5071;transport=TLS;lr;x=1";
        let cases: &[(&str, &str, Val)] = &[
            ("$(x{uri.user})", uri, s("Alice")),
            ("$(x{uri.host})", uri, s("Example.com")),
            ("$(x{uri.port})", uri, Val::Int(5071)),
            ("$(x{uri.scheme})", uri, s("sips")),
            ("$(x{uri.params})", uri, s("transport=TLS;lr;x=1")),
            ("$(x{uri.transport})", uri, s("TLS")),
            ("$(x{uri.param,x})", uri, s("1")),
            ("$(x{uri.param,lr})", uri, s("")),
            ("$(x{uri.param,y})", uri, Val::Null),
            ("$(x{uri.user})", "sip:host", Val::Null),
            ("$(x{uri.port})", "sip:host", Val::Null),
            ("$(x{uri.transport})", "sip:host", Val::Null),
            ("$(x{uri.host})", "not a uri", Val::Null),
            ("$(x{param.value,q})", "expires=60; q = 0.5", s("0.5")),
            ("$(x{param.value,Q})", "q=1", s("1")),
            ("$(x{param.value,z})", "q=1", Val::Null),
            ("$(x{param.value,b,&})", "a=1&b=2", s("2")),
            ("$(x{param.exist,lr})", "a=1;lr", Val::Int(1)),
            ("$(x{param.exist,rr})", "a=1;lr", Val::Int(0)),
            ("$(x{param.count})", "a=1;b;;c ", Val::Int(3)),
            ("$(x{param.count})", "", Val::Int(0)),
            ("$(x{nameaddr.uri})", "\"Al\" <sip:a@b;x=1>;tag=t", s("sip:a@b;x=1")),
            ("$(x{nameaddr.name})", "\"Al Bo\" <sip:a@b>", s("Al Bo")),
            ("$(x{nameaddr.name})", "sip:a@b", s("")),
            ("$(x{tobody.uri})", "<sip:a@b>;tag=t", s("sip:a@b")),
            ("$(x{tobody.tag})", "<sip:a@b>;tag=t", s("t")),
            ("$(x{tobody.tag})", "<sip:a@b>", Val::Null),
            ("$(x{json.parse,a.b[1]})", r#"{"a":{"b":[1,"two"]}}"#, s("two")),
            ("$(x{json.parse,a.b[0]})", r#"{"a":{"b":[1,"two"]}}"#, Val::Int(1)),
            ("$(x{json.parse,a.c})", r#"{"a":{}}"#, Val::Null),
            ("$(x{json.parse,a})", "not json", Val::Null),
        ];
        for (expr, input, want) in cases {
            assert_eq!(&run(expr, s(input)), want, "{expr} on {input:?}");
        }
    }

    #[test]
    fn sql_value_transformations() {
        let cases: &[(&str, Val, Val)] = &[
            ("$(x{sql.val})", Val::Null, s("NULL")),
            ("$(x{sql.val})", Val::Int(5), Val::Int(5)),
            ("$(x{sql.val})", s("o'k"), s("'o''k'")),
            ("$(x{sql.val.int})", Val::Null, Val::Int(0)),
            ("$(x{sql.val.int})", s(" 12 "), Val::Int(12)),
            ("$(x{sql.val.int})", s("1; DROP"), Val::Int(0)),
            ("$(x{sql.val.str})", Val::Null, s("''")),
            ("$(x{sql.val.str})", Val::Int(5), s("'5'")),
            ("$(x{sql.val.str})", s("a\0b"), s("'ab'")),
        ];
        for (expr, input, want) in cases {
            assert_eq!(&run(expr, input.clone()), want, "{expr} on {input:?}");
        }
    }

    #[test]
    fn null_input_is_an_empty_string_to_string_transformations() {
        assert_eq!(run("$(x{s.len})", Val::Null), Val::Int(0));
        assert_eq!(run("$(x{s.toupper})", Val::Null), s(""));
        assert_eq!(run("$(x{uri.user})", Val::Null), Val::Null);
        assert_eq!(run("$(x{s.len})", Val::Int(-12)), Val::Int(3), "integers are formatted first");
    }

    #[test]
    fn transformation_argument_counts_are_checked() {
        let cases: &[(&str, bool)] = &[
            ("$(x{s.len})", true),
            ("$(x{s.len,1})", false),
            ("$(x{s.substr,1})", false),
            ("$(x{s.substr,1,2})", true),
            ("$(x{param.value,a})", true),
            ("$(x{param.value,a,;})", true),
            ("$(x{param.value,a,;,x})", false),
            ("$(x{param.count,;})", true),
            ("$(x{nope})", false),
            ("$(x{s.len}", false),
            ("$(x{s.len}junk)", false),
            ("$(x{s.len} {s.int})", true),
        ];
        for (expr, ok) in cases {
            assert_eq!(parse_pv(expr, &table()).is_ok(), *ok, "{expr}");
        }
    }

    #[test]
    fn variable_syntax() {
        let t = table();
        type Case = (&'static str, Option<(&'static str, Option<PvIdx>)>);
        let cases: &[Case] = &[
            ("$p(a)", Some(("a", None))),
            ("$p( a b )", Some(("a b", None))),
            ("$p(a)[0]", Some(("a", Some(PvIdx::N(0))))),
            ("$p(a)[-2]", Some(("a", Some(PvIdx::N(-2))))),
            ("$p(a)[ * ]", Some(("a", Some(PvIdx::All)))),
            ("$p(a(b))", Some(("a(b)", None))),
            ("$p(a)[x]", None),
            ("$p(a", None),
            ("$x(a)", Some(("a", None))),
            ("$", None),
            ("$$", None),
            ("x", None),
        ];
        for (expr, want) in cases {
            let got = parse_pv(expr, &t).ok();
            assert_eq!(got.as_ref().map(|r| (r.param.name.as_str(), r.param.idx.clone())), want.clone(), "{expr}");
        }
    }

    #[test]
    fn pv_len_of_expressions() {
        let cases: &[(&str, usize)] = &[
            ("$ru", 3),
            ("$ru;x", 3),
            ("$var(x)", 7),
            ("$var(x)[1]", 10),
            ("$var(x)[1", 0),
            ("$avp(a)[*]+1", 10),
            ("$(var(x){s.len})", 16),
            ("$(var(x){s.substr,0,\")\"})", 25),
            ("$var(\")\")", 9),
            ("$_x9", 4),
            ("$-", 0),
            ("$", 0),
            ("", 0),
            ("ru", 0),
        ];
        for (s, want) in cases {
            assert_eq!(pv_len(s.as_bytes()), *want, "{s:?}");
        }
    }

    #[test]
    fn fmt_templates() {
        let t = table();
        let cases: &[(&str, usize, &str, bool)] = &[
            ("", 1, "", false),
            ("plain", 1, "plain", false),
            ("$$", 1, "$", false),
            ("a$$b", 1, "a$b", false),
            ("$p(u)", 1, "", true),
            ("<$p(u)@$p(d)>", 5, "<@>", true),
            ("cost: 5$", 1, "cost: 5$", false),
            ("ü$p(u)ß", 3, "üß", true),
        ];
        for (src, parts, lit, has) in cases {
            let f = parse_fmt(src, &t).unwrap_or_else(|e| panic!("{src}: {e}"));
            assert_eq!((f.0.len(), f.literal().as_str(), f.has_pv()), (*parts, *lit, *has), "{src:?}");
        }
        assert!(parse_fmt("$p(u)", &t).unwrap().single_pv().is_some());
        assert!(parse_fmt("x$p(u)", &t).unwrap().single_pv().is_none());
        assert!(parse_fmt("$nope", &t).is_err(), "an unknown variable is a load error");
    }

    #[test]
    fn val_conversions() {
        let cases: &[(Val, &str, Option<i64>, bool, &str)] = &[
            (Val::Null, "", None, false, "<null>"),
            (Val::Int(0), "0", Some(0), false, "0"),
            (Val::Int(-3), "-3", Some(-3), true, "-3"),
            (s(""), "", None, false, ""),
            (s("0"), "0", Some(0), true, "0"),
            (s(" 17 "), " 17 ", Some(17), true, " 17 "),
            (s("1x"), "1x", None, true, "1x"),
        ];
        for (v, st, int, truthy, disp) in cases {
            assert_eq!((v.as_str().as_ref(), v.as_int(), v.truthy(), v.to_string().as_str()), (*st, *int, *truthy, *disp), "{v:?}");
        }
        assert_eq!(Val::count(usize::MAX), Val::Int(i64::MAX));
        assert_eq!(Val::opt(None::<&str>), Val::Null);
        assert_eq!(Val::str([0xff, b'a']), s("\u{fffd}a"));
    }
}
