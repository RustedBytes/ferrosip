//! Script formatter (`ferroctl fmt`): re-indents a routing script without
//! changing what it means.
//!
//! What it does:
//! - indents 4 spaces per `{ }` level; `case`/`default` bodies one more level
//!   than their label; continuation lines inside open `( )` one more level;
//! - trims trailing whitespace, collapses runs of blank lines to one, drops
//!   blank lines at the start/end of the file and of a `{ }` block, and ends
//!   the file with one newline.
//!
//! What it keeps: everything else on a line (spacing between tokens,
//! comments, strings), and lines that continue a multi-line token (`/* */`
//! comments, a `$( … )` variable broken across lines) exactly as written.
//!
//! Safety: the input must parse, and the output must lex to exactly the same
//! token stream as the input; otherwise nothing is returned.

use crate::lexer::{Tok, lex};

const INDENT: &str = "    ";

struct Block {
    switch: bool,
    /// Inside a switch, after a `case`/`default` label.
    in_case: bool,
}

/// Format a routing script. Errors on a script that doesn't parse.
pub fn format(src: &str) -> Result<String, String> {
    // Kamailio configs need their #! directives applied before they parse.
    crate::parse(&crate::preprocess::preprocess_standalone(src)?.text)?;
    let out = reindent(src);
    if !same_tokens(src, &out) {
        // A bug in the formatter, never the user's fault: refuse rather than
        // change the script's meaning.
        return Err("formatter would change the token stream; file left unchanged (please report)".into());
    }
    Ok(out)
}

/// The formatter only moves whitespace; check that the meaning is the same.
/// - The script itself: the preprocessed token streams are equal, and so
///   are the core parameters and defines the preprocessor collected (a
///   core parameter's value is free text, not script tokens).
/// - When the raw text lexes as a whole, its token streams are equal too.
fn same_tokens(a: &str, b: &str) -> bool {
    let toks = |s: &str| lex(s).map(|v| v.into_iter().map(|(t, _)| t).collect::<Vec<Tok>>());
    let pp = |s: &str| {
        crate::preprocess::preprocess_standalone(s).map(|p| (toks(&p.text), p.core.into_iter().map(|c| (c.name, c.value)).collect::<Vec<_>>(), p.defines))
    };
    let script_same = matches!((pp(a), pp(b)), (Ok((Ok(ta), ca, da)), Ok((Ok(tb), cb, db))) if ta == tb && ca == cb && da == db);
    let raw_same = match (toks(a), toks(b)) {
        (Ok(x), Ok(y)) => x == y,
        (Err(_), Err(_)) => true,
        _ => false,
    };
    script_same && raw_same
}

fn is_label(code: &str) -> bool {
    let word = |w: &str| code.strip_prefix(w).is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t', ':', '(', '"', '\'', '$']));
    word("case") || word("default")
}

/// Structure seen so far, and how far the source has been scanned (a token
/// can run past the end of its line: `/* */` comments, `$( … )` variables).
#[derive(Default)]
struct State {
    stack: Vec<Block>,
    parens: usize,
    pending_switch: bool,
    pos: usize,
}

// Positions below are byte offsets into `src`, so the saturating adds never
// actually clamp.
fn reindent(src: &str) -> String {
    let mut out = String::with_capacity(src.len().saturating_add(src.len() / 8));
    let mut st = State::default();
    let mut blank = false;
    let mut start: usize = 0;
    for line in src.split_inclusive('\n') {
        let raw = line.strip_suffix('\n').unwrap_or(line);
        let end = start.saturating_add(raw.len());
        let line_start = start;
        start = start.saturating_add(line.len());
        if st.pos > line_start {
            // This line starts inside a token from an earlier line: keep it
            // exactly as written (trailing blanks too if the token goes on).
            scan(src, &mut st, end);
            out.push_str(if st.pos > end { raw } else { raw.trim_end() });
            out.push('\n');
            blank = false;
            continue;
        }
        let code = raw.trim();
        if code.is_empty() {
            // No blank line at the top of the file or right after a `{`.
            blank = !out.is_empty() && !out.ends_with("{\n");
            continue;
        }
        if blank && !code.starts_with('}') {
            out.push('\n');
        }
        blank = false;
        // Blocks closed by the `}`s this line starts with ("} else {").
        let closing = code.chars().take_while(|&c| c == '}' || c == ' ' || c == '\t').filter(|&c| c == '}').count();
        let open = st.stack.len().saturating_sub(closing);
        let parent = open.checked_sub(1).and_then(|k| st.stack.get(k));
        let label = is_label(code) && parent.is_some_and(|b| b.switch);
        let mut level: usize = st.stack.iter().take(open).map(|b| if b.switch && b.in_case { 2 } else { 1 }).sum();
        if label && parent.is_some_and(|b| b.in_case) {
            level = level.saturating_sub(1);
        }
        if st.parens > 0 && closing == 0 {
            level = level.saturating_add(1);
        }
        let code_from = raw.trim_start();
        st.pos = end.saturating_sub(code_from.len());
        scan(src, &mut st, end);
        for _ in 0..level {
            out.push_str(INDENT);
        }
        // Trailing blanks belong to a token that continues on the next line.
        out.push_str(if st.pos > end { code_from } else { code });
        out.push('\n');
        if label && let Some(b) = st.stack.iter_mut().rev().find(|b| b.switch) {
            b.in_case = true;
        }
    }
    out
}

/// Track braces/parens from `st.pos` to the end of the line at `end`,
/// skipping strings, variables and comments the way the lexer does. A token
/// that runs past `end` leaves `st.pos` beyond it.
fn scan(src: &str, st: &mut State, end: usize) {
    let b = src.as_bytes();
    let mut i = st.pos;
    while i < end {
        // `b[end]` is the line's '\n' (or the end): two-byte tests below
        // never match across the line.
        let tail = b.get(i..).unwrap_or_default();
        match tail {
            [b'#', ..] | [b'/', b'/', ..] => i = end,
            [b'/', b'*', body @ ..] => {
                i = body.windows(2).position(|w| w == b"*/").map_or(src.len(), |e| i.saturating_add(e).saturating_add(4));
            }
            [q @ (b'"' | b'\''), body @ ..] => {
                // Strings may span lines (as in Kamailio): a string that
                // runs past `end` leaves `pos` beyond it, so its other lines
                // are kept exactly as written.
                let mut escaped = false;
                let close = body.iter().position(|c| {
                    let quote = !escaped && c == q;
                    escaped = !escaped && *c == b'\\';
                    quote
                });
                i = close.map_or(b.len().saturating_add(1), |k| i.saturating_add(k).saturating_add(2));
            }
            [b'$', ..] => {
                // `$(ru{uri.user})`, `$avp(x)`: braces and parens inside a
                // variable are not structure.
                i = i.saturating_add(sip_core::pv::pv_len(tail).max(1));
            }
            [c, ..] if c.is_ascii_alphabetic() || *c == b'_' => {
                let n = tail.iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_' || **c == b'.').count();
                if tail.get(..n) == Some(b"switch") {
                    st.pending_switch = true;
                }
                i = i.saturating_add(n);
            }
            [c, ..] => {
                match c {
                    b'{' => st.stack.push(Block { switch: std::mem::take(&mut st.pending_switch), in_case: false }),
                    b'}' => {
                        st.stack.pop();
                    }
                    b'(' => st.parens = st.parens.saturating_add(1),
                    b')' => st.parens = st.parens.saturating_sub(1),
                    _ => {}
                }
                i = i.saturating_add(1);
            }
            [] => break,
        }
    }
    st.pos = i.max(end);
}

#[cfg(test)]
mod tests {
    use super::format;

    #[test]
    fn reindents_blocks_switch_and_continuations() {
        let src = "loadmodule \"tm\"\n\n\n\nrequest_route {\n\n  if (is_method(\"INVITE\") &&\n$rU == \"bob\") {\n\t\tt_relay();   \n  } else {\nswitch ($rU) {\ncase \"a\":\nxlog(\"a\");\nbreak;\n  default:\n      sl_send_reply(404, \"x\");\n}\n }\n\n}\n\n";
        let want = "loadmodule \"tm\"\n\nrequest_route {\n    if (is_method(\"INVITE\") &&\n        $rU == \"bob\") {\n        t_relay();\n    } else {\n        switch ($rU) {\n            case \"a\":\n                xlog(\"a\");\n                break;\n            default:\n                sl_send_reply(404, \"x\");\n        }\n    }\n}\n";
        let got = format(src).unwrap();
        assert_eq!(got, want);
        assert_eq!(format(&got).unwrap(), got, "idempotent");
    }

    #[test]
    fn keeps_comments_strings_and_variables() {
        let src = "# top { comment\nrequest_route {\n/* multi\n   line { */\nxlog(\"{ not a block\");  // }\n$var(u) = $(ru{uri.user});\n}\n";
        let want = "# top { comment\nrequest_route {\n    /* multi\n   line { */\n    xlog(\"{ not a block\");  // }\n    $var(u) = $(ru{uri.user});\n}\n";
        assert_eq!(format(src).unwrap(), want);
    }

    #[test]
    fn tokens_spanning_lines_are_kept() {
        // Found by fuzzing: a variable that continues on the next line.
        for src in ["route{$r=$(\n);}", "route{$r=$(  \n  );}\n", "route {\n/* a  \n  b */ exit;\n}\n"] {
            let once = format(src).unwrap();
            assert_eq!(format(&once).unwrap(), once);
        }
    }

    #[test]
    fn refuses_broken_scripts() {
        assert!(format("request_route {\n").is_err());
    }

    #[test]
    fn formats_the_sample_config_stably() {
        let src = include_str!("../../../etc/ferrosip.cfg");
        let once = format(src).unwrap();
        assert_eq!(format(&once).unwrap(), once);
    }

    /// Found by fuzzing: a core parameter whose value isn't script tokens.
    #[test]
    fn core_parameter_values_are_free_text() {
        assert_eq!(format("lo =$va[\n").unwrap(), "lo =$va[\n");
        let src = "listen=udp:127.0.0.1:5060 advertise 1.2.3.4:5060\n  debug=2\nrequest_route {\nexit;\n}\n";
        assert_eq!(format(src).unwrap(), "listen=udp:127.0.0.1:5060 advertise 1.2.3.4:5060\ndebug=2\nrequest_route {\n    exit;\n}\n");
    }

    /// Found by fuzzing: the continuation lines of a string spanning lines
    /// were re-indented, which changed the string.
    #[test]
    fn multi_line_strings_are_kept() {
        let src = "request_route {\nif (a()) {\n  x(\"one {\n    two\", \"b\");\n}\n}\n";
        let once = format(src).unwrap();
        assert!(once.contains("x(\"one {\n    two\""), "{once}");
        assert_eq!(format(&once).unwrap(), once);
    }

    #[test]
    fn kamailio_syntax_and_stock_config() {
        let src = "request_route {\nif (msg:len > max_len | @to.tag == \"\") route(1)\nelse $var(y) = \"a\" + (int)$var(x) mod 3;\n}\nroute[1] { exit; }\n";
        let once = format(src).unwrap();
        assert_eq!(format(&once).unwrap(), once);
        let k = include_str!("../../../tests/compat/kamailio/etc/kamailio.cfg");
        let once = format(k).unwrap();
        assert_eq!(format(&once).unwrap(), once);
    }
}
