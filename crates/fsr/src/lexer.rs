//! Tokens with spans; comments are collected on the side for the
//! formatter. Strings keep their `{expr}` holes as raw text (the parser
//! re-lexes them).

use crate::ast::Span;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Ident(String),
    Int(i64),
    /// Milliseconds, text as written.
    Duration(u64, String),
    /// Contents (escapes resolved; `\{` / `\}` kept as markers), and
    /// whether it was triple-quoted.
    Str(String, bool),
    Punct(&'static str),
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
    /// The token starts a new line.
    pub nl_before: bool,
    /// A blank line precedes it.
    pub blank_before: bool,
    /// For a string: where the text of each `{…}` hole starts in the
    /// source (holes are kept as written, so their spans map back exactly).
    pub holes: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct Comment {
    pub text: String,
    pub span: Span,
    /// Nothing but whitespace before it on its line.
    pub own_line: bool,
    /// A blank line precedes / follows it (kept by fmt).
    pub blank_before: bool,
    pub blank_after: bool,
}

#[derive(Debug, PartialEq)]
pub struct LexError {
    pub msg: String,
    pub span: Span,
}

const PUNCT: &[&str] = &[
    "=>", "->", "==", "!=", "<=", ">=", "&&", "||", "..", "=~", "(", ")", "{", "}", "[", "]", ",", ":", ";", ".", "=", "<", ">", "!", "+", "-", "*", "/", "%",
    "|", "?",
];

/// Markers for literal braces inside strings (so `{` starts a hole only
/// when unescaped).
pub const LBRACE: char = '\u{E000}';
pub const RBRACE: char = '\u{E001}';

/// The index of the first byte at or after `from` that fails `f` (or the end).
fn skip(b: &[u8], from: usize, f: impl Fn(u8) -> bool) -> usize {
    b.iter().enumerate().skip(from).find(|&(_, &c)| !f(c)).map_or(b.len(), |(j, _)| j)
}

pub fn lex(src: &str) -> Result<(Vec<Token>, Vec<Comment>), LexError> {
    let b = src.as_bytes();
    // Spans below start and end on character boundaries. Positions are byte
    // offsets into `src`, so the saturating adds below never clamp.
    let span = |a: usize, z: usize| src.get(a..z).unwrap_or_default();
    let (mut i, mut toks, mut comments): (usize, _, _) = (0, Vec::new(), Vec::new());
    let (mut nl, mut blank, mut line_start) = (true, false, true);
    while let Some(&c) = b.get(i) {
        if c == b'\n' {
            if nl && !toks.is_empty() {
                blank = true;
            }
            nl = true;
            line_start = true;
            i = i.saturating_add(1);
            continue;
        }
        if c.is_ascii_whitespace() {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        // `i` is on a character boundary here (it only moves by whole
        // characters or over ASCII bytes), so `rest` is never empty.
        let rest = src.get(i..).unwrap_or_default();
        let mut holes = Vec::new();
        // Comments.
        if rest.starts_with("//") {
            let end = rest.find('\n').map_or(b.len(), |n| i.saturating_add(n));
            comments.push(Comment {
                text: span(i, end).trim_end().to_string(),
                span: Span { start, end },
                own_line: line_start,
                blank_before: blank,
                blank_after: blank_after(src, end),
            });
            blank = false;
            i = end;
            continue;
        }
        if rest.starts_with("/*") {
            let end = rest
                .get(2..)
                .and_then(|r| r.find("*/"))
                .map(|n| i.saturating_add(n).saturating_add(4))
                .ok_or(LexError { msg: "unclosed /* comment".into(), span: Span { start, end: start.saturating_add(2) } })?;
            let text = span(i, end);
            comments.push(Comment {
                text: text.to_string(),
                span: Span { start, end },
                own_line: line_start,
                blank_before: blank,
                blank_after: blank_after(src, end),
            });
            blank = false;
            nl |= text.contains('\n');
            i = end;
            continue;
        }
        line_start = false;
        let tok = if c.is_ascii_digit() {
            i = skip(b, i, |c| c.is_ascii_digit() || c == b'_');
            let digits: String = span(start, i).chars().filter(|c| *c != '_').collect();
            let n: i64 = digits.parse().map_err(|_| LexError { msg: format!("number too large: {digits}"), span: Span { start, end: i } })?;
            // A unit right after the number makes a duration: 30s, 500ms, 1h30m.
            if b.get(i).is_some_and(u8::is_ascii_alphabetic) {
                i = skip(b, i, |c| c.is_ascii_alphanumeric());
                let text = span(start, i);
                let ms = parse_duration(text).map_err(|e| LexError { msg: e, span: Span { start, end: i } })?;
                Tok::Duration(ms, text.to_string())
            } else {
                Tok::Int(n)
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            i = skip(b, i, |c| c.is_ascii_alphanumeric() || c == b'_');
            Tok::Ident(span(start, i).to_string())
        } else if c == b'"' {
            // Triple-quoted strings span lines.
            let triple = rest.starts_with("\"\"\"");
            i = i.saturating_add(if triple { 3 } else { 1 });
            let mut s = String::new();
            // Inside a `{…}` hole the text is an expression, kept as written
            // (it may hold strings of its own: "{t.get("k")}").
            let mut hole = 0usize;
            loop {
                if i >= b.len() {
                    return Err(LexError { msg: "unclosed string".into(), span: Span { start, end: b.len() } });
                }
                let here = src.get(i..).unwrap_or_default();
                if triple && hole == 0 && here.starts_with("\"\"\"") {
                    i = i.saturating_add(3);
                    break;
                }
                let ch = here.chars().next().unwrap_or('\0');
                if hole > 0 {
                    match ch {
                        '{' => hole = hole.saturating_add(1),
                        '}' => hole = hole.saturating_sub(1),
                        '"' => {
                            // A string inside the hole: copy it whole, to its
                            // closing quote (escapes skipped) on this line.
                            let mut escaped = false;
                            let stop = b.iter().enumerate().skip(i.saturating_add(1)).find(|&(_, &c)| {
                                let stop = !escaped && (c == b'"' || c == b'\n');
                                escaped = !escaped && c == b'\\';
                                stop
                            });
                            let Some((j, &b'"')) = stop else {
                                return Err(LexError {
                                    msg: "unclosed `{` in string (write \\{ for a brace)".into(),
                                    span: Span { start, end: stop.map_or(b.len(), |(j, _)| j) },
                                });
                            };
                            // `j` is on the closing quote; an escape may
                            // have skipped into a character, never past it.
                            let end = j.saturating_add(1);
                            s.push_str(span(i, end));
                            i = end;
                            continue;
                        }
                        '\n' if !triple => return Err(LexError { msg: "unclosed `{` in string (write \\{ for a brace)".into(), span: Span { start, end: i } }),
                        _ => {}
                    }
                    s.push(ch);
                    i = i.saturating_add(ch.len_utf8());
                    continue;
                }
                if ch == '{' {
                    hole = 1;
                    s.push(ch);
                    i = i.saturating_add(1);
                    holes.push(i);
                    continue;
                }
                match ch {
                    '"' if !triple => {
                        i = i.saturating_add(1);
                        break;
                    }
                    '\n' if !triple => return Err(LexError { msg: "unclosed string (use \"\"\" for several lines)".into(), span: Span { start, end: i } }),
                    '\\' => {
                        let e = here.get(1..).and_then(|r| r.chars().next()).unwrap_or('\0');
                        s.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '"' => '"',
                            '\\' => '\\',
                            '{' => LBRACE,
                            '}' => RBRACE,
                            other => {
                                return Err(LexError {
                                    msg: format!("unknown escape \\{other}"),
                                    span: Span { start: i, end: i.saturating_add(1).saturating_add(other.len_utf8()) },
                                });
                            }
                        });
                        i = i.saturating_add(1).saturating_add(e.len_utf8());
                    }
                    c => {
                        s.push(c);
                        i = i.saturating_add(c.len_utf8());
                    }
                }
            }
            Tok::Str(s, triple)
        } else {
            let p = PUNCT.iter().find(|p| rest.starts_with(**p)).ok_or_else(|| {
                let ch = rest.chars().next().unwrap_or('?');
                LexError { msg: format!("unexpected character {ch:?}"), span: Span { start, end: i.saturating_add(ch.len_utf8()) } }
            })?;
            i = i.saturating_add(p.len());
            Tok::Punct(p)
        };
        toks.push(Token { tok, span: Span { start, end: i }, nl_before: nl, blank_before: blank, holes });
        nl = false;
        blank = false;
    }
    toks.push(Token { tok: Tok::Eof, span: Span { start: b.len(), end: b.len() }, nl_before: true, blank_before: false, holes: Vec::new() });
    Ok((toks, comments))
}

/// `"1h30m"` → ms.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let (mut total, mut rest) = (0u64, s);
    while !rest.is_empty() {
        let d = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if d == 0 {
            return Err(format!("bad duration {s:?}"));
        }
        let (num, after) = rest.split_at_checked(d).ok_or_else(|| format!("bad duration {s:?}"))?;
        let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
        let u = after.find(|c: char| c.is_ascii_digit()).unwrap_or(after.len());
        let (unit, after) = after.split_at_checked(u).ok_or_else(|| format!("bad duration {s:?}"))?;
        let mult = match unit {
            "ms" => 1,
            "s" => 1000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            other => return Err(format!("bad duration {s:?}: unknown unit {other:?} (ms, s, m, h, d)")),
        };
        total = total.saturating_add(n.saturating_mul(mult));
        rest = after;
    }
    Ok(total)
}

/// Only whitespace with two or more line breaks after `at`, before the next
/// text.
fn blank_after(src: &str, at: usize) -> bool {
    let rest = src.get(at..).unwrap_or_default();
    let ws = rest.find(|c: char| !c.is_whitespace()).map_or(rest, |n| rest.split_at(n).0);
    ws.matches('\n').count() >= 2 && ws.len() < rest.len()
}

/// 1-based line and column of a byte offset.
///
/// An offset inside a character counts as that character's start.
pub fn line_col(src: &str, at: usize) -> (usize, usize) {
    let at = src.floor_char_boundary(at);
    let before = src.split_at(at).0;
    let line = before.matches('\n').count().saturating_add(1);
    let col = before.rsplit('\n').next().unwrap_or(before).len().saturating_add(1);
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<Tok> {
        lex(src).unwrap().0.into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn tokens() {
        assert_eq!(
            kinds("let x = 30s + 2 // hi\n\"a{b}\\{c\" => 1h30m 200..299"),
            vec![
                Tok::Ident("let".into()),
                Tok::Ident("x".into()),
                Tok::Punct("="),
                Tok::Duration(30_000, "30s".into()),
                Tok::Punct("+"),
                Tok::Int(2),
                Tok::Str(format!("a{{b}}{LBRACE}c"), false),
                Tok::Punct("=>"),
                Tok::Duration(5_400_000, "1h30m".into()),
                Tok::Int(200),
                Tok::Punct(".."),
                Tok::Int(299),
                Tok::Eof,
            ]
        );
        let (t, c) = lex("a\n\n// own\nb // tail\n").unwrap();
        assert!(t[1].nl_before && t[1].blank_before);
        assert_eq!((c[0].own_line, c[1].own_line), (true, false));
        assert!(lex("\"open").is_err());
        assert!(lex("5x").unwrap_err().msg.contains("unknown unit"));
        assert_eq!(line_col("ab\ncd", 4), (2, 2));
    }
}
