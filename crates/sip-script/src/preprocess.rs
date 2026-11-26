//! Kamailio's config preprocessor, run before lexing:
//!
//! - `#!define NAME [value]`, `#!trydef` (only if undefined), `#!redefine`,
//!   `#!undef`;
//! - `#!ifdef NAME`, `#!ifndef NAME`, `#!else`, `#!endif` (nestable);
//! - `#!subst "/regex/replacement/flags"`: applied to string literals
//!   (flags `g` and `i`, `\1` back references, `\/` an escaped separator);
//! - `#!substdef "/NAME/value/"`: `#!subst` plus `#!define NAME value`;
//! - `include_file "path"` (missing file is an error) and `import_file
//!   "path"` (missing file is skipped), resolved against the including
//!   file's directory, then the working directory;
//! - defined names are replaced in the config text (identifier tokens outside
//!   strings and comments) by their value, as Kamailio does;
//! - top-level core parameters (`debug=2`, `listen=udp:…`, `children=8`,
//!   …) are taken out of the text into [`CoreParam`]s for `main` to apply.
//!   Their values aren't script syntax (IP addresses, `proto:ip:port`).
//!
//! The output keeps one line per input line (directives become empty lines),
//! and [`Preprocessed::locate`] maps a line of the output back to `file:line`,
//! includes too.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::lexer::skip;

/// A top-level `name = value` (Kamailio core parameter), value as written.
#[derive(Debug, Clone, PartialEq)]
pub struct CoreParam {
    pub name: String,
    pub value: String,
    /// `file:line` of the assignment.
    pub at: String,
}

#[derive(Debug, Default)]
pub struct Preprocessed {
    /// Script text for the parser.
    pub text: String,
    pub core: Vec<CoreParam>,
    /// For each output line (index = line − 1): the file and line it came from.
    lines: Vec<(usize, usize)>,
    files: Vec<String>,
    /// Names defined at the end (for diagnostics and `-c`).
    pub defines: Vec<String>,
    /// The same names with their values (`#!define FLT_ACC 1`), sorted.
    pub values: Vec<(String, String)>,
}

impl Preprocessed {
    /// A script that wasn't preprocessed (lowered from `.fsr`): lines
    /// are `file`'s own.
    pub fn plain(file: &str) -> Self {
        Preprocessed { text: String::new(), core: Vec::new(), lines: Vec::new(), files: vec![file.to_string()], defines: Vec::new(), values: Vec::new() }
    }

    /// `file:line` for line `n` (1-based) of `text`.
    pub fn locate(&self, n: usize) -> String {
        if let Some(&(f, l)) = n.checked_sub(1).and_then(|k| self.lines.get(k))
            && let Some(file) = self.files.get(f)
        {
            return format!("{file}:{l}");
        }
        match self.files.as_slice() {
            [file] if self.lines.is_empty() => format!("{file}:{n}"),
            _ => format!("line {n}"),
        }
    }

    /// Rewrite "line N" in a parser error to `file:line`.
    pub fn locate_error(&self, err: &str) -> String {
        let Some(rest) = err.strip_prefix("line ") else { return err.to_string() };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        match digits.parse::<usize>() {
            Ok(n) => format!("{}{}", self.locate(n), rest.get(digits.len()..).unwrap_or_default()),
            Err(_) => err.to_string(),
        }
    }
}

struct Subst {
    re: regex::Regex,
    rep: String,
    global: bool,
}

struct State<'a> {
    defines: HashMap<String, String>,
    substs: Vec<Subst>,
    out: Preprocessed,
    /// Brace depth outside strings/comments: core parameters only at 0.
    depth: i32,
    in_block_comment: bool,
    /// Inside a string that started on an earlier line (strings may span
    /// lines): its quote character.
    in_string: Option<u8>,
    read: &'a dyn Fn(&Path) -> std::io::Result<String>,
    include_depth: usize,
}

/// Preprocess the config file at `path`. `defines` are pre-set (`--define`).
pub fn preprocess_file(path: &str, defines: &[(String, String)]) -> Result<Preprocessed, String> {
    let read = |p: &Path| std::fs::read_to_string(p);
    let src = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    run(path, &src, defines, &read)
}

/// Preprocess config text (`name` labels its lines; includes resolve against
/// the working directory).
pub fn preprocess_str(name: &str, src: &str, defines: &[(String, String)]) -> Result<Preprocessed, String> {
    let read = |p: &Path| std::fs::read_to_string(p);
    run(name, src, defines, &read)
}

/// Preprocess one file on its own: included files read as empty (for the
/// formatter, which checks that a file parses without touching others).
pub fn preprocess_standalone(src: &str) -> Result<Preprocessed, String> {
    run("", src, &[], &|_| Ok(String::new()))
}

fn run(name: &str, src: &str, defines: &[(String, String)], read: &dyn Fn(&Path) -> std::io::Result<String>) -> Result<Preprocessed, String> {
    let mut st = State {
        defines: defines.iter().cloned().collect(),
        substs: Vec::new(),
        out: Preprocessed::default(),
        depth: 0,
        in_block_comment: false,
        in_string: None,
        read,
        include_depth: 0,
    };
    st.file(name, src)?;
    let mut d: Vec<String> = st.defines.keys().cloned().collect();
    d.sort();
    st.out.defines = d;
    let mut v: Vec<(String, String)> = st.defines.into_iter().collect();
    v.sort();
    st.out.values = v;
    Ok(st.out)
}

/// Index of the quote `q` closing a string, scanning from `from` (escapes
/// skipped); `None` if the string goes on past the end of the line.
fn close_quote(b: &[u8], from: usize, q: u8) -> Option<usize> {
    let mut escaped = false;
    let (i, _) = b.iter().enumerate().skip(from).find(|&(_, &c)| {
        let close = !escaped && c == q;
        escaped = !escaped && c == b'\\';
        close
    })?;
    Some(i)
}

fn quoted_arg(rest: &str) -> Option<String> {
    let r = rest.trim();
    let q = r.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let (inner, _) = r.get(1..)?.split_once(q)?;
    Some(inner.to_string())
}

impl State<'_> {
    fn file(&mut self, name: &str, src: &str) -> Result<(), String> {
        let fi = self.out.files.len();
        self.out.files.push(name.to_string());
        // (active, any branch taken) per #!ifdef level.
        let mut conds: Vec<(bool, bool)> = Vec::new();
        let active = |c: &Vec<(bool, bool)>| c.iter().all(|x| x.0);
        for (n, raw) in (1..).zip(src.lines()) {
            let at = format!("{name}:{n}");
            let t = raw.trim_start();
            let directive = t.strip_prefix("#!").or_else(|| t.strip_prefix("!!"));
            let in_text = self.in_block_comment || self.in_string.is_some();
            if let Some(d) = directive.filter(|_| !in_text) {
                let (kw, rest) = d.split_once(char::is_whitespace).unwrap_or((d, ""));
                let rest = rest.trim();
                let arg = || rest.split_whitespace().next().unwrap_or("").to_string();
                match kw {
                    "ifdef" | "ifndef" => {
                        let on = self.defines.contains_key(&arg()) == (kw == "ifdef");
                        conds.push((on, on));
                    }
                    "ifexp" => {
                        let on = ifexp(rest, &self.defines).map_err(|e| format!("{at}: #!ifexp: {e}"))?;
                        conds.push((on, on));
                    }
                    "else" => {
                        let c = conds.last_mut().ok_or(format!("{at}: #!else without #!ifdef"))?;
                        c.0 = !c.1;
                        c.1 = true;
                    }
                    "endif" => {
                        conds.pop().ok_or(format!("{at}: #!endif without #!ifdef"))?;
                    }
                    _ if !active(&conds) => {}
                    "define" | "trydef" | "redefine" => {
                        let (n, v) = rest.split_once(char::is_whitespace).map_or((rest, ""), |(n, v)| (n, v.trim()));
                        if n.is_empty() {
                            return Err(format!("{at}: #!{kw} needs a name"));
                        }
                        if kw == "define" && self.defines.contains_key(n) {
                            return Err(format!("{at}: {n} already defined (use #!redefine or #!trydef)"));
                        }
                        if kw != "trydef" || !self.defines.contains_key(n) {
                            self.defines.insert(n.to_string(), v.to_string());
                        }
                    }
                    "undef" => {
                        self.defines.remove(&arg());
                    }
                    "subst" | "substdef" | "substdefs" => {
                        let spec = quoted_arg(rest).ok_or(format!("{at}: #!{kw} \"/regex/replacement/flags\""))?;
                        let mut it = spec.chars();
                        let sep = it.next().ok_or(format!("{at}: empty #!{kw}"))?;
                        let parts = split_unescaped(it.as_str(), sep);
                        let [pat, rep, flags] = parts[..] else { return Err(format!("{at}: #!{kw} needs {sep}regex{sep}replacement{sep}")) };
                        let re = regex::RegexBuilder::new(&unescape_sep(pat, sep))
                            .case_insensitive(flags.contains('i'))
                            .build()
                            .map_err(|e| format!("{at}: #!{kw}: {e}"))?;
                        self.substs.push(Subst { re, rep: replacement(rep, sep), global: flags.contains('g') });
                        if kw != "subst" {
                            let val = if kw == "substdefs" { format!("\"{rep}\"") } else { rep.to_string() };
                            self.defines.insert(pat.to_string(), val);
                        }
                    }
                    // Version markers and cfg-engine selection: nothing to do.
                    "KAMAILIO" | "SER" | "OPENSER" | "SIP-ROUTER" | "MAXCOMPAT" | "ALL" => {}
                    _ => return Err(format!("{at}: unsupported preprocessor directive #!{kw}")),
                }
                self.push_line("", fi, n);
                continue;
            }
            if !active(&conds) {
                self.push_line("", fi, n);
                continue;
            }
            // include_file / import_file (at line start, outside comments).
            let inc =
                (!in_text).then(|| t.strip_prefix("include_file").map(|r| (r, true)).or_else(|| t.strip_prefix("import_file").map(|r| (r, false)))).flatten();
            if let Some((r, required)) = inc {
                let p = quoted_arg(r).ok_or(format!("{at}: include_file \"path\""))?;
                self.include(name, &p, required, &at)?;
                continue;
            }
            let line = self.substitute(raw);
            if self.depth == 0
                && !in_text
                && let Some(cp) = core_param(line.trim_start(), &at)
            {
                self.out.core.push(cp);
                self.push_line("", fi, n);
                continue;
            }
            self.push_line(&line, fi, n);
        }
        if !conds.is_empty() {
            return Err(format!("{name}: #!ifdef without #!endif"));
        }
        Ok(())
    }

    fn include(&mut self, from: &str, p: &str, required: bool, at: &str) -> Result<(), String> {
        if self.include_depth >= 16 {
            return Err(format!("{at}: include_file nested too deeply"));
        }
        let base = Path::new(from).parent().map(Path::to_path_buf).unwrap_or_default();
        let candidates: Vec<PathBuf> = if Path::new(p).is_absolute() { vec![PathBuf::from(p)] } else { vec![base.join(p), PathBuf::from(p)] };
        for c in &candidates {
            if let Ok(src) = (self.read)(c) {
                self.include_depth = self.include_depth.saturating_add(1);
                let r = self.file(&c.display().to_string(), &src);
                self.include_depth = self.include_depth.saturating_sub(1);
                return r;
            }
        }
        if required { Err(format!("{at}: include_file {p:?}: not found")) } else { Ok(()) }
    }

    fn push_line(&mut self, line: &str, file: usize, n: usize) {
        self.track(line);
        self.out.text.push_str(line);
        self.out.text.push('\n');
        self.out.lines.push((file, n));
    }

    /// Follow braces outside strings and comments (core parameters only
    /// appear at depth 0).
    // Positions are byte offsets into `line`: the saturating adds never clamp.
    fn track(&mut self, line: &str) {
        let b = line.as_bytes();
        let mut i: usize = 0;
        if let Some(q) = self.in_string {
            match close_quote(b, 0, q) {
                Some(e) => {
                    i = e.saturating_add(1);
                    self.in_string = None;
                }
                None => return,
            }
        }
        while i < b.len() {
            if self.in_block_comment {
                match line.get(i..).and_then(|r| r.find("*/")) {
                    Some(e) => {
                        i = i.saturating_add(e).saturating_add(2);
                        self.in_block_comment = false;
                        continue;
                    }
                    None => return,
                }
            }
            match b.get(i..).unwrap_or_default() {
                [b'#', ..] | [b'/', b'/', ..] => return,
                [b'/', b'*', ..] => {
                    self.in_block_comment = true;
                    i = i.saturating_add(2);
                    continue;
                }
                &[q @ (b'"' | b'\''), ..] => match close_quote(b, i.saturating_add(1), q) {
                    Some(e) => i = e,
                    None => {
                        self.in_string = Some(q);
                        return;
                    }
                },
                [b'{', ..] => self.depth = self.depth.saturating_add(1),
                [b'}', ..] => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
            i = i.saturating_add(1);
        }
    }

    /// Replace defined identifiers (outside strings/comments) by their value,
    /// and apply `#!subst` to string literals.
    fn substitute(&self, line: &str) -> String {
        if self.defines.is_empty() && self.substs.is_empty() || self.in_block_comment {
            return line.to_string();
        }
        let b = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        // Positions are byte offsets into `line`: the saturating adds never clamp.
        let mut i: usize = 0;
        // The rest of a string from an earlier line is kept as written.
        if let Some(q) = self.in_string {
            let Some(e) = close_quote(b, 0, q) else { return line.to_string() };
            i = e.saturating_add(1);
            out.push_str(line.get(..i).unwrap_or_default());
        }
        let name_byte = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        while let Some(&c) = b.get(i) {
            if c == b'#' || (c == b'/' && matches!(b.get(i.saturating_add(1)), Some(b'/' | b'*'))) {
                out.push_str(line.get(i..).unwrap_or_default());
                break;
            }
            if c == b'"' || c == b'\'' {
                let s = i;
                i = close_quote(b, i.saturating_add(1), c).map_or(b.len(), |e| e.saturating_add(1));
                let lit = line.get(s..i).unwrap_or_default();
                out.push_str(&self.subst_string(lit));
                continue;
            }
            if c == b'$' {
                // Variables keep their names: $var(DBURL) is not a define.
                let s = i;
                i = i.saturating_add(1);
                if b.get(i) == Some(&b'(') {
                    // To the matching `)`, or the end of the line.
                    let mut depth = 0_usize;
                    let close = b.iter().enumerate().skip(i).find(|&(_, &c)| {
                        match c {
                            b'(' => depth = depth.saturating_add(1),
                            b')' => depth = depth.saturating_sub(1),
                            _ => return false,
                        }
                        depth == 0
                    });
                    i = close.map_or(b.len(), |(e, _)| e.saturating_add(1));
                } else {
                    i = skip(b, i, name_byte);
                    if b.get(i) == Some(&b'(') {
                        i = skip(b, i, |c| c != b')').saturating_add(1).min(b.len());
                    }
                }
                out.push_str(line.get(s..i).unwrap_or_default());
                continue;
            }
            if name_byte(c) && !c.is_ascii_digit() {
                let s = i;
                i = skip(b, i, name_byte);
                let id = line.get(s..i).unwrap_or_default();
                match self.defines.get(id).filter(|v| !v.is_empty()) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(id),
                }
                continue;
            }
            // Whole characters (config files may contain UTF-8).
            let ch = line.get(i..).and_then(|r| r.chars().next()).unwrap_or('\u{fffd}');
            out.push(ch);
            i = i.saturating_add(ch.len_utf8());
        }
        out
    }

    fn subst_string(&self, lit: &str) -> String {
        if self.substs.is_empty() || lit.len() < 2 {
            return lit.to_string();
        }
        // `lit` starts with its quote; it ends with it unless the string goes
        // on to the next line (then there's nothing to close here).
        // `lit` starts with an ASCII quote.
        let (q, body) = lit.split_at_checked(1).unwrap_or(("", lit));
        let (inner, close) = match body.strip_suffix(q) {
            Some(i) => (i, q),
            None => (body, ""),
        };
        let mut s = inner.to_string();
        for sb in &self.substs {
            s = if sb.global { sb.re.replace_all(&s, sb.rep.as_str()).into_owned() } else { sb.re.replace(&s, sb.rep.as_str()).into_owned() };
        }
        format!("{q}{s}{close}")
    }
}

/// `spec` cut at each `sep` not escaped with `\` (as Kamailio's
/// `subst_parser`): at most three parts, the last one taking the rest.
fn split_unescaped(spec: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut escaped) = (0, false);
    for (i, c) in spec.char_indices() {
        if parts.len() == 2 {
            break;
        }
        if c == sep && !escaped {
            parts.push(spec.get(start..i).unwrap_or_default());
            start = i.saturating_add(c.len_utf8());
        }
        escaped = !escaped && c == '\\';
    }
    parts.push(spec.get(start..).unwrap_or_default());
    parts
}

/// A regex with `\<sep>` made a plain `<sep>` (when that isn't a regex
/// escape of its own).
fn unescape_sep(pat: &str, sep: char) -> String {
    if sep.is_ascii_alphanumeric() || regex::escape(&sep.to_string()).len() > 1 {
        return pat.to_string();
    }
    pat.replace(&format!("\\{sep}"), &sep.to_string())
}

/// A Kamailio replacement (`\1` back references, `\\`, escaped
/// separator, `$` literal) as a `regex` replacement string. Other escapes
/// stay in the text: the string literal they land in decodes them.
fn replacement(rep: &str, sep: char) -> String {
    let mut out = String::with_capacity(rep.len());
    let mut it = rep.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some(d @ '0'..='9') => {
                    out.push_str("${");
                    out.push(d);
                    out.push('}');
                }
                Some('$') => out.push_str("$$"),
                Some(e) if e == '\\' || e == sep => out.push(e),
                Some(e) => {
                    out.push('\\');
                    out.push(e);
                }
                None => out.push('\\'),
            },
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out
}

/// `#!ifexp` with boolean operators over defines: a name is true when it is
/// defined (and not defined as `0`); `!`, `&&`, `||` and parentheses.
fn ifexp(e: &str, defines: &HashMap<String, String>) -> Result<bool, String> {
    let mut toks: Vec<&str> = Vec::new();
    let mut rest = e.trim_start_matches(|c: char| c.is_ascii_whitespace());
    while let Some(c) = rest.chars().next() {
        let n = match c {
            '(' | ')' | '!' => 1,
            '&' | '|' if rest.starts_with("&&") || rest.starts_with("||") => 2,
            c if c.is_ascii_alphanumeric() || c == '_' => rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len()),
            _ => return Err(format!("only names, !, &&, || and parentheses are supported: {e:?}")),
        };
        let (tok, r) = rest.split_at_checked(n).unwrap_or((rest, ""));
        toks.push(tok);
        rest = r.trim_start_matches(|c: char| c.is_ascii_whitespace());
    }
    /// Takes the next token if it is `s`.
    fn eat(t: &mut &[&str], s: &str) -> bool {
        match t.split_first() {
            Some((x, rest)) if *x == s => {
                *t = rest;
                true
            }
            _ => false,
        }
    }
    fn or(t: &mut &[&str], d: &HashMap<String, String>) -> Result<bool, String> {
        let mut v = and(t, d)?;
        while eat(t, "||") {
            v |= and(t, d)?;
        }
        Ok(v)
    }
    fn and(t: &mut &[&str], d: &HashMap<String, String>) -> Result<bool, String> {
        let mut v = not(t, d)?;
        while eat(t, "&&") {
            v &= not(t, d)?;
        }
        Ok(v)
    }
    fn not(t: &mut &[&str], d: &HashMap<String, String>) -> Result<bool, String> {
        let Some((&first, rest)) = t.split_first() else { return Err("unexpected None".into()) };
        *t = rest;
        match first {
            "!" => Ok(!not(t, d)?),
            "(" => {
                let v = or(t, d)?;
                if !eat(t, ")") {
                    return Err("missing )".into());
                }
                Ok(v)
            }
            n if n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') => Ok(d.get(n).is_some_and(|v| v.trim() != "0")),
            t => Err(format!("unexpected {:?}", Some(t))),
        }
    }
    let mut t = toks.as_slice();
    let v = or(&mut t, defines)?;
    if !t.is_empty() {
        return Err(format!("trailing tokens in {e:?}"));
    }
    Ok(v)
}

/// `name = value` at the top level (not `==`, not a route or keyword line).
fn core_param(t: &str, at: &str) -> Option<CoreParam> {
    let n_end = t.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))?;
    let (name, rest) = t.split_at_checked(n_end)?;
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return None;
    }
    let rest = rest.trim_start();
    let v = rest.strip_prefix('=').filter(|r| !r.starts_with('='))?;
    // Strip a trailing comment and semicolon.
    let mut val = String::new();
    let mut quote = None;
    for c in v.chars() {
        match (quote, c) {
            (None, '#') => break,
            (None, '"' | '\'') => {
                quote = Some(c);
                val.push(c);
            }
            (Some(q), c) if c == q => {
                quote = None;
                val.push(c);
            }
            _ => val.push(c),
        }
    }
    // A value that opens a string spanning lines is not a core parameter.
    if quote.is_some() {
        return None;
    }
    let val = val.trim().trim_end_matches(';').trim().to_string();
    Some(CoreParam { name: name.to_string(), value: val, at: at.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pp(src: &str) -> Preprocessed {
        preprocess_str("t.cfg", src, &[]).unwrap()
    }

    #[test]
    fn ifdef_else_define_and_substitution() {
        let p = pp(
            "#!define WITH_AUTH\n#!define DBURL \"text:///db\"\n#!ifdef WITH_AUTH\nloadmodule \"auth\"\n#!else\nloadmodule \"none\"\n#!endif\nmodparam(\"x\", \"db_url\", DBURL)\n#!ifndef WITH_AUTH\nbad\n#!endif\n",
        );
        let lines: Vec<&str> = p.text.lines().collect();
        assert_eq!(lines.len(), 11, "one output line per input line");
        assert_eq!(lines[3], "loadmodule \"auth\"");
        assert_eq!(lines[5], "");
        assert_eq!(lines[7], "modparam(\"x\", \"db_url\", \"text:///db\")");
        assert!(!p.text.contains("bad"));
    }

    #[test]
    fn nested_conditions_and_trydef() {
        let p = pp("#!trydef A 1\n#!trydef A 2\n#!ifdef A\n#!ifdef B\nx\n#!else\ny = A\n#!endif\n#!endif\n");
        assert!(p.core.iter().any(|c| c.name == "y" && c.value == "1"), "{:?}", p.core);
        assert!(!p.text.contains('x'));
    }

    /// Found by fuzzing: #!subst on a string running to the end of a line
    /// that ends in a multi-byte character.
    #[test]
    fn subst_on_unterminated_non_ascii_string() {
        let p = pp("#!subst \"/a/b/\"\nx(\"a\u{16a5}\n\")\n");
        assert!(p.text.contains("x(\"b\u{16a5}\n\")"), "{}", p.text);
    }

    /// Strings spanning lines: no defines replaced, braces counted or
    /// directives run inside them, and no core parameter starts one.
    #[test]
    fn multi_line_strings() {
        let p = pp("#!define X 1\nrequest_route {\n  x(\"a {\nX\n#!define Y\nb\");\n}\ndebug=2\n");
        assert!(p.text.contains("\nX\n#!define Y\nb\")"), "{}", p.text);
        assert_eq!(p.core.len(), 1, "depth back to 0 after the string");
        assert!(!p.defines.contains(&"Y".to_string()));
        let p = pp("a=$\"\nrequest_route { x(\"}\") }\n");
        assert!(p.core.is_empty(), "a value opening a string isn't lifted");
    }

    #[test]
    fn core_params_lifted_only_at_top_level() {
        let p = pp("debug=2 # comment\nlisten=udp:127.0.0.1:5060 advertise 1.2.3.4:5060\nrequest_route {\n    $var(a) = 1;\n    x = 2;\n}\n");
        let names: Vec<_> = p.core.iter().map(|c| (c.name.as_str(), c.value.as_str())).collect();
        assert_eq!(names, [("debug", "2"), ("listen", "udp:127.0.0.1:5060 advertise 1.2.3.4:5060")]);
        assert!(p.text.contains("x = 2;"), "assignments inside routes stay");
        assert_eq!(p.core[1].at, "t.cfg:2");
    }

    #[test]
    fn substdef_and_subst_on_strings() {
        let p = pp("#!substdef \"!MY_IP!10.0.0.1!g\"\n#!subst \"/USER/alice/\"\nlisten=udp:MY_IP:5060\nx(\"sip:USER@MY_IP\")\n");
        assert_eq!(p.core[0].value, "udp:10.0.0.1:5060");
        assert!(p.text.contains("x(\"sip:alice@10.0.0.1\")"), "{}", p.text);
    }

    #[test]
    fn variables_and_strings_are_not_define_targets() {
        let p = pp("#!define FOO bar\nrequest_route { $var(FOO) = \"FOO\"; FOO(); }\n");
        assert!(p.text.contains("$var(FOO) = \"FOO\"; bar();"), "{}", p.text);
    }

    #[test]
    fn includes_and_locations() {
        let dir = std::env::temp_dir().join(format!("pp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inc.cfg"), "route[X] {\n  exit;\n}\n").unwrap();
        std::fs::write(dir.join("main.cfg"), "include_file \"inc.cfg\"\nimport_file \"missing.cfg\"\nrequest_route { route(X); }\n").unwrap();
        let p = preprocess_file(dir.join("main.cfg").to_str().unwrap(), &[]).unwrap();
        assert!(p.text.contains("route[X]"));
        assert!(p.locate(2).ends_with("inc.cfg:2"), "{}", p.locate(2));
        assert!(p.locate_error("line 4: oops").ends_with("main.cfg:3: oops"), "{}", p.locate_error("line 4: oops"));
        std::fs::write(dir.join("bad.cfg"), "include_file \"nope.cfg\"\n").unwrap();
        assert!(preprocess_file(dir.join("bad.cfg").to_str().unwrap(), &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ifexp_boolean() {
        let p = pp("#!define A\n#!define Z 0\n#!ifexp B || A && !C\nyes1\n#!endif\n#!ifexp Z || (B && A)\nno1\n#!endif\n");
        assert!(p.text.contains("yes1") && !p.text.contains("no1"), "{}", p.text);
        assert!(preprocess_str("t", "#!ifexp A == 1\n#!endif\n", &[]).is_err());
    }

    #[test]
    fn errors() {
        assert!(preprocess_str("t", "#!ifdef A\n", &[]).is_err());
        assert!(preprocess_str("t", "#!endif\n", &[]).is_err());
        assert!(preprocess_str("t", "#!define A\n#!define A\n", &[]).is_err());
        assert!(preprocess_str("t", "#!bogus\n", &[]).is_err());
        let p = preprocess_str("t", "#!ifdef WITH_X\nx\n#!endif\n", &[("WITH_X".into(), String::new())]).unwrap();
        assert!(p.text.contains('x'), "--define pre-sets names");
    }
    /// Preprocess `main` with the files in `fs` (name, text) readable.
    fn with_files(main: &str, fs: &[(&str, &str)]) -> Result<Preprocessed, String> {
        let files: HashMap<PathBuf, String> = fs.iter().map(|(n, t)| (PathBuf::from(n), (*t).to_string())).collect();
        let read = move |p: &Path| files.get(p).cloned().ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound));
        run("dir/main.cfg", main, &[], &read)
    }

    /// The non-empty output lines.
    fn kept(p: &Preprocessed) -> Vec<&str> {
        p.text.lines().filter(|l| !l.trim().is_empty()).collect()
    }

    #[test]
    fn nested_conditionals_pick_the_right_branches() {
        let src = "#!ifdef A\n#!ifndef B\nA_notB\n#!else\nA_B\n#!endif\n#!ifdef C\nA_C\n#!endif\n#!else\n#!ifdef B\nnotA_B\n#!else\nnotA_notB\n#!endif\n#!endif\nalways\n";
        let cases: [(&[&str], &[&str]); 5] = [
            (&[], &["notA_notB", "always"]),
            (&["A"], &["A_notB", "always"]),
            (&["A", "B"], &["A_B", "always"]),
            (&["A", "B", "C"], &["A_B", "A_C", "always"]),
            (&["B", "C"], &["notA_B", "always"]),
        ];
        for (defs, want) in cases {
            let d: Vec<(String, String)> = defs.iter().map(|n| ((*n).to_string(), String::new())).collect();
            let p = preprocess_str("t", src, &d).unwrap();
            assert_eq!(kept(&p), want, "defined: {defs:?}");
            assert_eq!(p.text.lines().count(), src.lines().count(), "one output line per input line");
        }
    }

    #[test]
    fn else_inside_an_inactive_branch_stays_inactive() {
        let p = pp("#!ifdef NOPE\n#!ifdef ALSO_NOPE\na\n#!else\nb\n#!endif\n#!endif\nc\n");
        assert_eq!(kept(&p), ["c"]);
    }

    #[test]
    fn directives_in_inactive_branches_are_ignored() {
        let p = pp("#!ifdef NOPE\n#!define X 1\n#!undef Y\n#!subst \"/a/b/\"\n#!include_whatever\n#!endif\n#!ifdef X\nx\n#!endif\ny(\"a\")\n");
        assert_eq!(kept(&p), ["y(\"a\")"]);
        assert!(!p.defines.contains(&"X".to_string()));
    }

    #[test]
    fn define_undef_redefine_and_values() {
        let p = pp("#!define A 1\n#!redefine A 2\n#!define B\n#!undef B\n#!ifdef B\nb\n#!endif\n#!ifndef B\nnot_b\n#!endif\nx(A, AB, A_1, A)\n");
        assert_eq!(kept(&p), ["not_b", "x(2, AB, A_1, 2)"], "only whole identifiers are replaced");
        assert_eq!(p.values, [("A".to_string(), "2".to_string())]);
        let p = pp("!!define OLD 7\nx(OLD)\n");
        assert_eq!(kept(&p), ["x(7)"], "!! is an old spelling of #!");
        assert!(preprocess_str("t", "#!define\n", &[]).unwrap_err().contains("needs a name"));
    }

    #[test]
    fn a_define_without_a_value_leaves_the_name() {
        let p = pp("#!define WITH_NAT\nx(WITH_NAT)\n");
        assert_eq!(kept(&p), ["x(WITH_NAT)"]);
    }

    #[test]
    fn defines_are_not_replaced_in_comments_or_strings() {
        let p = pp("#!define X 1\nx(X) # X\ny(X) // X\nz(\"X\", 'X') /* X */\n");
        assert_eq!(kept(&p), ["x(1) # X", "y(1) // X", "z(\"X\", 'X') /* X */"]);
    }

    #[test]
    fn subst_flags_backrefs_and_escapes() {
        let cases = [
            // Without g only the first match is replaced.
            ("#!subst \"/a/b/\"\n", "x(\"aaa\")", "x(\"baa\")"),
            ("#!subst \"/a/b/g\"\n", "x(\"aaa\")", "x(\"bbb\")"),
            // i: case-insensitive.
            ("#!subst \"/user/bob/i\"\n", "x(\"sip:USER@h\")", "x(\"sip:bob@h\")"),
            // \N in the replacement is a back reference.
            ("#!subst \"/([a-z]+)@([a-z]+)/\\2@\\1/\"\n", "x(\"sip:al@ex\")", "x(\"sip:ex@al\")"),
            // A $ in the replacement is kept literally.
            ("#!subst \"/USER/$fU/\"\n", "x(\"USER\")", "x(\"$fU\")"),
            // An escaped separator belongs to the regex or the replacement.
            ("#!subst \"/a\\/b/c\\/d/\"\n", "x(\"a/b\")", "x(\"c/d\")"),
            ("#!subst \"/a/b\\\\c/\"\n", "x(\"a\")", "x(\"b\\c\")"),
        ];
        for (directive, line, want) in cases {
            let p = preprocess_str("t", &format!("{directive}{line}\n"), &[]).unwrap();
            assert_eq!(kept(&p), [want], "{directive:?}");
        }
        assert!(preprocess_str("t", "#!subst \"/a/b\"\n", &[]).is_err(), "missing closing separator");
        assert!(preprocess_str("t", "#!subst \"/(/b/\"\n", &[]).is_err(), "bad regex");
    }

    #[test]
    fn substdefs_defines_a_quoted_value() {
        let p = pp("#!substdefs \"/DOMAIN/example.com/\"\nx(DOMAIN, \"sip:DOMAIN\")\n");
        assert_eq!(kept(&p), ["x(\"example.com\", \"sip:example.com\")"]);
    }

    #[test]
    fn includes_resolve_against_the_including_file() {
        let p = with_files(
            "#!define A 1\ninclude_file \"sub/a.cfg\"\nimport_file \"none.cfg\"\nx(A, B)\n",
            &[("dir/sub/a.cfg", "#!define B 2\ninclude_file \"b.cfg\"\na(A)\n"), ("dir/sub/b.cfg", "b()\n")],
        )
        .unwrap();
        assert_eq!(kept(&p), ["b()", "a(1)", "x(1, 2)"], "defines flow both ways across includes");
        // An include line becomes the included file's lines.
        assert_eq!(p.locate(3), "dir/sub/b.cfg:1");
        assert_eq!(p.locate(4), "dir/sub/a.cfg:3");
        assert_eq!(p.locate(5), "dir/main.cfg:4");
    }

    #[test]
    fn include_errors() {
        let e = with_files("include_file \"self.cfg\"\n", &[("dir/self.cfg", "include_file \"self.cfg\"\n")]).unwrap_err();
        assert!(e.contains("nested too deeply"), "{e}");
        let e = with_files("include_file \"x.cfg\"\n", &[("dir/x.cfg", "#!ifdef A\n")]).unwrap_err();
        assert!(e.starts_with("dir/x.cfg: #!ifdef without #!endif"), "{e}");
        let e = with_files("include_file \"x.cfg\"\n", &[]).unwrap_err();
        assert_eq!(e, "dir/main.cfg:1: include_file \"x.cfg\": not found");
        assert!(with_files("#!ifdef NOPE\ninclude_file \"x.cfg\"\n#!endif\n", &[]).is_ok(), "inactive includes aren't read");
    }

    #[test]
    fn locate_without_preprocessing() {
        let p = Preprocessed::plain("a.fsr");
        assert_eq!(p.locate(3), "a.fsr:3");
        assert_eq!(p.locate_error("line 3: bad"), "a.fsr:3: bad");
        assert_eq!(p.locate_error("other"), "other");
        assert_eq!(pp("x\n").locate(9), "line 9", "past the end");
    }
}
