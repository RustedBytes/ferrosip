#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    /// A variable expression, verbatim (`$ru`, `$avp(x)[1]`, `$(ru{uri.user})`).
    Pv(String),
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    Comma,
    Semi,
    Colon,
    Bang,
    Assign,
    EqEq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Match,
    NoMatch,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    AndAnd,
    OrOr,
    /// Binary `|` and `&`.
    Pipe,
    Amp,
}

/// The index of the first byte at or after `from` that fails `f` (or the end).
pub(crate) fn skip(b: &[u8], from: usize, f: impl Fn(u8) -> bool) -> usize {
    b.iter().enumerate().skip(from).find(|&(_, &c)| !f(c)).map_or(b.len(), |(j, _)| j)
}

pub fn lex(src: &str) -> Result<Vec<(Tok, usize)>, String> {
    let mut out = Vec::new();
    let mut line: usize = 1;
    let b = src.as_bytes();
    let mut i = 0;
    // `i` always sits on a character boundary, and the spans taken below
    // end on ASCII bytes, so `get` never misses; it just can't panic.
    // `i` and `line` are bounded by `src.len()`: the saturating adds below
    // never actually clamp.
    let span = |a: usize, z: usize| src.get(a..z).unwrap_or_default();
    while i < b.len() {
        // The real character (not a byte): config files may contain UTF-8.
        let rest = src.get(i..).unwrap_or_default();
        let c = rest.chars().next().unwrap_or('\0');
        let two = |s: &str| rest.starts_with(s);
        let t = match c {
            '\n' => {
                line = line.saturating_add(1);
                i = i.saturating_add(1);
                continue;
            }
            c if c.is_whitespace() => {
                i = i.saturating_add(c.len_utf8());
                continue;
            }
            '#' => {
                i = skip(b, i, |c| c != b'\n');
                continue;
            }
            '/' if two("//") => {
                i = skip(b, i, |c| c != b'\n');
                continue;
            }
            '/' if two("/*") => {
                let (body, _) = rest.get(2..).and_then(|r| r.split_once("*/")).ok_or(format!("line {line}: unterminated comment"))?;
                line = line.saturating_add(body.matches('\n').count());
                i = i.saturating_add(body.len()).saturating_add(4);
                continue;
            }
            '$' => {
                let n = sip_core::pv::pv_len(rest.as_bytes());
                if n == 0 {
                    return Err(format!("line {line}: bad variable near {:?}", rest.chars().take(12).collect::<String>()));
                }
                out.push((Tok::Pv(rest.get(..n).unwrap_or_default().to_string()), line));
                i = i.saturating_add(n);
                continue;
            }
            '"' | '\'' => {
                let q = c;
                let mut s = String::new();
                i = i.saturating_add(1);
                loop {
                    let Some(ch) = src.get(i..).and_then(|r| r.chars().next()) else { return Err(format!("line {line}: unterminated string")) };
                    i = i.saturating_add(ch.len_utf8());
                    match ch {
                        // Kamailio strings may span lines (exec_msg scripts, SQL).
                        '\n' => {
                            line = line.saturating_add(1);
                            s.push('\n');
                        }
                        ch if ch == q => break,
                        '\\' => {
                            let e = src.get(i..).and_then(|r| r.chars().next()).ok_or("dangling escape")?;
                            i = i.saturating_add(e.len_utf8());
                            match e {
                                'n' => s.push('\n'),
                                'r' => s.push('\r'),
                                't' => s.push('\t'),
                                '$' => s.push_str("$$"), // literal $ in templates
                                '\\' | '"' | '\'' => s.push(e),
                                // Unknown escapes keep the backslash (regexes: "\.", "\1").
                                e => {
                                    s.push('\\');
                                    s.push(e);
                                }
                            }
                        }
                        ch => s.push(ch),
                    }
                }
                out.push((Tok::Str(s), line));
                continue;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                i = skip(b, i, |c| c.is_ascii_digit());
                // A separator followed by a digit: `.` or `/` at `i`.
                let sep_digit = |i: usize, sep: u8| matches!(b.get(i..), Some([c, d, ..]) if *c == sep && d.is_ascii_digit());
                // IPv4 literal (`src_ip == 10.0.0.1`, `10.0.0.0/8`): a string.
                if sep_digit(i, b'.') {
                    i = skip(b, i, |c| c.is_ascii_digit() || c == b'.');
                    if sep_digit(i, b'/') {
                        i = skip(b, i.saturating_add(1), |c| c.is_ascii_digit());
                    }
                    out.push((Tok::Str(span(start, i).to_string()), line));
                    continue;
                }
                let s = span(start, i);
                out.push((Tok::Int(s.parse().map_err(|_| format!("line {line}: bad number {s}"))?), line));
                continue;
            }
            // Kamailio selects: `@to.tag`, `@via[2]`, `@cfg_get.group.name`.
            '@' if rest.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic) => {
                let start = i.saturating_add(1);
                i = skip(b, start, |c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'[' | b']' | b'-'));
                out.push((Tok::Pv(format!("$sel({})", span(start, i))), line));
                continue;
            }
            // Old core keyword `msg:len` ($ml).
            'm' if two("msg:len") && !rest.as_bytes().get(7).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') => {
                i = i.saturating_add(7);
                out.push((Tok::Pv("$ml".into()), line));
                continue;
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                i = skip(b, i, |c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.');
                out.push((Tok::Ident(span(start, i).to_string()), line));
                continue;
            }
            _ => {
                let (t, n) = match c {
                    '=' if two("==") => (Tok::EqEq, 2),
                    '=' if two("=~") => (Tok::Match, 2),
                    '=' => (Tok::Assign, 1),
                    '!' if two("!=") => (Tok::Ne, 2),
                    '!' if two("!~") => (Tok::NoMatch, 2),
                    '!' => (Tok::Bang, 1),
                    '<' if two("<=") => (Tok::Le, 2),
                    '<' => (Tok::Lt, 1),
                    '>' if two(">=") => (Tok::Ge, 2),
                    '>' => (Tok::Gt, 1),
                    '&' if two("&&") => (Tok::AndAnd, 2),
                    '|' if two("||") => (Tok::OrOr, 2),
                    '&' => (Tok::Amp, 1),
                    '|' => (Tok::Pipe, 1),
                    '{' => (Tok::LBrace, 1),
                    '}' => (Tok::RBrace, 1),
                    '[' => (Tok::LBracket, 1),
                    ']' => (Tok::RBracket, 1),
                    '(' => (Tok::LParen, 1),
                    ')' => (Tok::RParen, 1),
                    ',' => (Tok::Comma, 1),
                    ';' => (Tok::Semi, 1),
                    ':' => (Tok::Colon, 1),
                    '+' => (Tok::Plus, 1),
                    '-' => (Tok::Minus, 1),
                    '*' => (Tok::Star, 1),
                    '/' => (Tok::Slash, 1),
                    '%' => (Tok::Percent, 1),
                    c => return Err(format!("line {line}: unexpected character {c:?}")),
                };
                i = i.saturating_add(n);
                t
            }
        };
        out.push((t, line));
    }
    Ok(out)
}

#[cfg(test)]
mod fuzz_regressions {
    #[test]
    fn non_ascii_input() {
        // Must not loop pushing empty identifiers (a fuzzing input).
        assert!(super::lex("reques] { \u{75a}xmt; }").is_err());
        assert!(super::lex("a\u{a0}b").is_ok(), "non-ASCII whitespace");
        assert!(super::lex("x = \"\u{e9}t\u{e9}\";").is_ok(), "UTF-8 inside strings is fine");
        assert!(super::lex("$\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}").is_err(), "error text cut on a char boundary");
        // Escapes, comments and variables next to multi-byte characters.
        let toks = super::lex("/* \u{e9} */ x = \"\\\u{e9}\\\u{20ac}\" + $avp(\u{e4}); // \u{e9}\n").unwrap();
        assert_eq!(toks[2].0, super::Tok::Str("\\\u{e9}\\\u{20ac}".into()));
        assert_eq!(toks[4].0, super::Tok::Pv("$avp(\u{e4})".into()));
    }
}

#[cfg(test)]
mod tests {
    use super::{Tok, lex};

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|(t, _)| t).collect()
    }

    #[test]
    fn literals_and_operators() {
        use Tok::*;
        let s = |x: &str| Str(x.into());
        let cases: Vec<(&str, Vec<Tok>)> = vec![
            ("10.0.0.1", vec![s("10.0.0.1")]),
            ("10.0.0.0/8", vec![s("10.0.0.0/8")]),
            ("10/8", vec![Int(10), Slash, Int(8)]),
            ("5060", vec![Int(5060)]),
            ("a.b_c", vec![Ident("a.b_c".into())]),
            ("msg:len", vec![Pv("$ml".into())]),
            ("msg:length", vec![Ident("msg".into()), Colon, Ident("length".into())]),
            ("@via[1].host", vec![Pv("$sel(via[1].host)".into())]),
            ("== != <= >= =~ !~ < > = !", vec![EqEq, Ne, Le, Ge, Match, NoMatch, Lt, Gt, Assign, Bang]),
            ("&& || & | + - * / %", vec![AndAnd, OrOr, Amp, Pipe, Plus, Minus, Star, Slash, Percent]),
            ("{ } [ ] ( ) , ; :", vec![LBrace, RBrace, LBracket, RBracket, LParen, RParen, Comma, Semi, Colon]),
            ("$avp(x)[1] $(ru{uri.user})", vec![Pv("$avp(x)[1]".into()), Pv("$(ru{uri.user})".into())]),
        ];
        for (src, want) in cases {
            assert_eq!(toks(src), want, "{src:?}");
        }
    }

    #[test]
    fn string_escapes() {
        let cases = [
            (r#""a\nb""#, "a\nb"),
            (r#""a\tb\r""#, "a\tb\r"),
            (r#""\$x""#, "$$x"),
            (r#""q\"q""#, "q\"q"),
            (r#"'it\'s'"#, "it's"),
            (r#"'say "hi"'"#, "say \"hi\""),
            (r#""a\\b""#, "a\\b"),
            (r#""\.\1""#, "\\.\\1"),
        ];
        for (src, want) in cases {
            assert_eq!(toks(src), [Tok::Str(want.into())], "{src}");
        }
    }

    #[test]
    fn comments_and_line_numbers() {
        let t = lex("a # x\n// y\n/* z\n\n*/ b \"s\n\" c\nd").unwrap();
        let lines: Vec<(String, usize)> = t
            .into_iter()
            .map(|(t, l)| match t {
                Tok::Ident(s) | Tok::Str(s) => (s, l),
                t => (format!("{t:?}"), l),
            })
            .collect();
        let want = [("a", 1), ("b", 5), ("s\n", 6), ("c", 6), ("d", 7)].map(|(s, l)| (s.to_string(), l));
        assert_eq!(lines, want, "a token gets the line it ends on");
    }

    #[test]
    fn lexer_errors_name_the_line() {
        let cases = [
            ("\n\n\"open", "line 3: unterminated string"),
            ("\n/* open", "line 2: unterminated comment"),
            ("\n99999999999999999999", "line 2: bad number 99999999999999999999"),
            ("x ` y", "line 1: unexpected character '`'"),
            ("a @ b", "line 1: unexpected character '@'"),
        ];
        for (src, want) in cases {
            assert_eq!(lex(src).unwrap_err(), want, "{src:?}");
        }
    }
}
