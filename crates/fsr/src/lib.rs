//! `.fsr`, ferrosip's typed routing language (docs/fsr.md): parsing,
//! formatting, type checking, and lowering to the route tree that `.cfg`
//! scripts compile to.

pub mod ast;
pub mod compile;
pub mod fmt;
pub mod lexer;
pub mod lint;
pub mod msg;
pub mod parser;
pub mod print;

pub use compile::{Diag, Env, Feature, Output, TestDef};
pub use parser::{ParseError, parse};

use std::path::{Path, PathBuf};

/// A compile failure, rendered (`file:line:col: msg` + caret), one per entry.
#[derive(Debug)]
pub struct Errors(pub Vec<String>);

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.join("\n"))
    }
}

fn parse_source(name: &str, ns: &str, text: String) -> Result<compile::Source, Errors> {
    match parse(&text) {
        Ok(file) => Ok(compile::Source { name: name.into(), ns: ns.into(), text, file }),
        Err(e) => Err(Errors(vec![render_error(name, &text, e.span, &e.msg)])),
    }
}

fn render(sources: &[compile::Source], diags: Vec<Diag>) -> Errors {
    Errors(
        diags
            .into_iter()
            .map(|d| match sources.iter().find(|s| s.name == d.file) {
                Some(s) => render_error(&d.file, &s.text, d.span, &d.msg),
                None => format!("{}: {}", d.file, d.msg),
            })
            .collect(),
    )
}

/// Compile one self-contained source (no file imports).
pub fn compile_source(name: &str, text: &str, env: &Env) -> Result<Output, Errors> {
    let src = parse_source(name, "", text.to_string())?;
    if let Some(i) = src.file.items.iter().find(|i| matches!(i.kind, ast::ItemKind::File(..))) {
        return Err(Errors(vec![render_error(name, text, i.span, "file imports need a file on disk (compile_file)")]));
    }
    let sources = vec![src];
    compile::Compiler::new(env).compile(&sources).map_err(|d| render(&sources, d))
}

/// Compile an entry file and the files it imports (`import "./x.fsr" as x`,
/// relative to the importing file; one level of namespaces).
pub fn compile_file(path: &Path, env: &Env) -> Result<Output, Errors> {
    compile_with(path, &[], env)
}

/// `compile_file`, plus test files (`ferrosip test routes/x_test.fsr`):
/// compiled in the entry's namespace, after it.
pub fn compile_with(path: &Path, extra: &[PathBuf], env: &Env) -> Result<Output, Errors> {
    let (mut sources, files) = load(path)?;
    let same = |a: &Path, b: &Path| a.canonicalize().ok().is_some_and(|x| b.canonicalize().ok() == Some(x));
    // A test file that is the routing itself (or one it imports) is already in.
    for p in extra.iter().filter(|p| !files.iter().any(|f| same(f, p))) {
        let text = std::fs::read_to_string(p).map_err(|e| Errors(vec![format!("{}: {e}", p.display())]))?;
        sources.push(parse_source(&p.display().to_string(), "", text)?);
    }
    compile::Compiler::new(env).compile(&sources).map_err(|d| render(&sources, d))
}

/// The entry file and its imports, parsed; also every file path read
/// (for reload checks).
pub fn load(path: &Path) -> Result<(Vec<compile::Source>, Vec<PathBuf>), Errors> {
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| Errors(vec![format!("{}: {e}", p.display())]));
    let entry = parse_source(&path.display().to_string(), "", read(path)?)?;
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut files = vec![path.to_path_buf()];
    let mut sources = vec![];
    let mut errs = vec![];
    for item in &entry.file.items {
        if let ast::ItemKind::File(rel, ns) = &item.kind {
            let p = dir.join(rel);
            if sources.iter().any(|s: &compile::Source| s.ns == ns.text) {
                errs.push(render_error(&entry.name, &entry.text, ns.span, &format!("namespace {} is used twice", ns.text)));
                continue;
            }
            match read(&p).and_then(|t| parse_source(&p.display().to_string(), &ns.text, t)) {
                Ok(s) => {
                    if let Some(i) = s.file.items.iter().find(|i| matches!(i.kind, ast::ItemKind::File(..))) {
                        errs.push(render_error(&s.name, &s.text, i.span, "an imported file can't import files (one level)"));
                    }
                    files.push(p);
                    sources.push(s);
                }
                Err(e) => errs.extend(e.0),
            }
        }
    }
    if !errs.is_empty() {
        return Err(Errors(errs));
    }
    sources.insert(0, entry);
    Ok((sources, files))
}

/// `file:line:col: message` with the source line and a caret.
pub fn render_error(file: &str, src: &str, span: ast::Span, msg: &str) -> String {
    let (line, col) = lexer::line_col(src, span.start);
    let text = src.lines().nth(line.saturating_sub(1)).unwrap_or("");
    // Spans come from the lexer (character boundaries), but don't trust
    // them with a panic.
    let (start, end) = (src.floor_char_boundary(span.start), src.ceil_char_boundary(span.end.max(span.start)));
    let width = src.get(start..end).and_then(|s| s.lines().next()).map_or(1, |l| l.chars().count().max(1));
    format!("{file}:{line}:{col}: {msg}\n    {text}\n    {}{}", " ".repeat(col.saturating_sub(1)), "^".repeat(width))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The main example of the design document, almost verbatim.
    const DOC: &str = r#"import txn, location, auth, nat, media
import { features } from config

flag NATED            // named flags, the compiler assigns bits
flag FROM_TRUNK

route main(msg: Request) {
    guard msg.max_forwards > 0     else reply(483)
    guard msg.is_sane()            else drop

    if features.nat && nat.is_behind(msg) {
        msg.set(NATED)
        nat.fix_contact(msg)
    }

    if msg.has_to_tag {
        return in_dialog(msg)
    }

    match msg.method {
        CANCEL   => txn.relay_cancel(msg)
        REGISTER => register(msg)
        INVITE   => invite(msg)
        OPTIONS  => reply(200)
        _        => reply(405)
    }
}

fn register(msg: Request) -> Action {
    location.save(msg)
}

fn invite(msg: Request) -> Action {
    let contacts = location.lookup(msg.ruri) else return reply(404)

    if msg.is(NATED) { media.offer(msg) }

    // the transaction result is a value, not a separate failure block
    let res = await txn.relay(msg, timeout: 30s)

    match res {
        Final(r) if r.code in 200..299 => forward(r)
        Final(r) if r.code == 486      => voicemail(msg)
        Timeout | Final(_)             => reply(480)
    }
}

on reply(r: Reply) where r.code in 180..183 {
    if r.has_sdp { media.answer(r) }
}
"#;

    #[test]
    fn parses_the_design_example() {
        let f = parse(DOC).unwrap();
        assert_eq!(f.items.len(), 8);
        let ast::ItemKind::Fn(invite) = &f.items[6].kind else { panic!("{:?}", f.items[6].kind) };
        assert_eq!(invite.name.text, "invite");
        let ast::StmtKind::Let { otherwise, .. } = &invite.body.stmts[0].kind else { panic!() };
        assert!(matches!(otherwise.as_deref().map(|s| &s.kind), Some(ast::StmtKind::Return(Some(_)))));
        let ast::StmtKind::Let { value, .. } = &invite.body.stmts[2].kind else { panic!() };
        assert!(matches!(value.kind, ast::ExprKind::Await(_)));
        assert_eq!(invite.body.stmts[2].trivia.leading, vec!["// the transaction result is a value, not a separate failure block"]);
        let ast::StmtKind::Match(_, arms) = &invite.body.stmts[3].kind else { panic!() };
        assert_eq!(arms.len(), 3);
        assert_eq!(arms[2].pats.len(), 2);
        assert_eq!(f.items[2].trivia.trailing.as_deref(), Some("// named flags, the compiler assigns bits"));
    }

    #[test]
    fn format_is_stable_and_keeps_comments() {
        let once = fmt::format(&parse(DOC).unwrap());
        let twice = fmt::format(&parse(&once).unwrap());
        assert_eq!(once, twice, "idempotent");
        assert!(once.contains("flag NATED  // named flags, the compiler assigns bits\n"));
        assert!(once.contains("    // the transaction result is a value, not a separate failure block\n    let res = await txn.relay(msg, timeout: 30s)\n"));
        assert!(once.contains("        Final(r) if r.code in 200..299 => forward(r)\n"));
        assert!(once.contains("    guard msg.max_forwards > 0 else reply(483)\n"));
        assert!(once.contains("import txn, location, auth, nat, media\nimport { features } from config\n\nflag NATED"));
        // Same tree after a round trip (spans aside).
        assert_eq!(fmt::format(&parse(&once).unwrap()), once);
    }

    #[test]
    fn flag_with_a_fixed_bit_formats() {
        let out = fmt::format(&parse("flag A\nflag  FLT_ACC=1\nroute main(msg: Request) { drop }\n").unwrap());
        assert!(out.starts_with("flag A\nflag FLT_ACC = 1\n"), "{out}");
        assert!(parse("flag X = Y\n").is_err());
    }

    #[test]
    fn branch_flag_formats() {
        let out = fmt::format(&parse("flag A\nbranch  flag FLB_NATB=6\nbranch flag X\nroute main(msg: Request) { drop }\n").unwrap());
        assert!(out.starts_with("flag A\nbranch flag FLB_NATB = 6\nbranch flag X\n"), "{out}");
        // `branch` alone is still a name elsewhere.
        assert!(parse("route main(msg: Request) {\n    let branch = 1\n}\n").is_ok());
    }

    #[test]
    fn strings_and_interpolation() {
        let f = parse("route main(msg: Request) {\n    log.info(\"banned {msg.src.ip}: \\{literal\\} \\\"q\\\"\")\n}\n").unwrap();
        let out = fmt::format(&f);
        assert!(out.contains(r#"log.info("banned {msg.src.ip}: \{literal\} \"q\"")"#), "{out}");
        let e = parser::parse_expr("\"a {x.y} b\"", 0).unwrap();
        let ast::ExprKind::Str(parts) = e.kind else { panic!() };
        assert_eq!(parts.len(), 3);
        let multi = parse("route m(msg: Request) {\n    x = \"\"\"\n    a\n    \"\"\"\n}\n").unwrap();
        assert!(fmt::format(&multi).contains("\"\"\"\n    a\n    \"\"\""));
    }

    #[test]
    fn errors_point_at_the_problem() {
        let src = "route main(msg: Request) {\n    let = 5\n}\n";
        let e = parse(src).unwrap_err();
        let r = render_error("main.fsr", src, e.span, &e.msg);
        assert_eq!(r, "main.fsr:2:9: expected a variable name, found `=`\n        let = 5\n            ^");
        assert!(parse("route main(msg: Request) {\n    if x {\n").unwrap_err().msg.contains("unclosed"));
        assert!(parse("lol").unwrap_err().msg.starts_with("expected `import`"));
        assert!(parse("route m(msg: Request) { x = \"a {b\" }").unwrap_err().msg.contains("unclosed `{` in string"));
    }

    /// Already-canonical text comes back unchanged: blank lines around
    /// comments stay where they were, a trailing `\n` stays an escape.
    #[test]
    fn format_keeps_blank_lines_around_comments() {
        let src = "// header\n// more\n\nimport txn\n\nroute main(msg: Request) {\n    drop\n    // c\n\n    exit\n\n    // d\n    log.info(\"a\\n\")\n}\n";
        assert_eq!(fmt::format(&parse(src).unwrap()), src);
    }

    #[test]
    fn statements_without_separators() {
        let f = parse("route m(msg: Request) {\n    return\n    drop\n    x = 1; y = 2\n    match a { 1 | 2 => exit, -1 => break }\n}\n").unwrap();
        let ast::ItemKind::Route(r) = &f.items[0].kind else { panic!() };
        assert!(matches!(r.body.stmts[0].kind, ast::StmtKind::Return(None)), "return at the end of a line takes no value");
        assert_eq!(r.body.stmts.len(), 5);
    }

    /// Errors on a multi-byte character render: their spans end after the
    /// whole character, never inside it.
    #[test]
    fn errors_on_multibyte_characters_render() {
        for (src, msg) in [
            ("route main(msg: Request) {\n    let x = 1 € 2\n}\n", "unexpected character '€'"),
            ("route main(msg: Request) {\n    let x = \"a\\é\"\n}\n", "unknown escape \\é"),
            ("route main(msg: Request) {\n    let x = 1 \u{a0} 2\n}\n", "unexpected character"),
        ] {
            let e = compile_source("t.fsr", src, &Env::default()).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(e.contains(msg) && e.contains("t.fsr:2:"), "{e}");
        }
        // A span that is not on character boundaries still renders.
        let r = render_error("t.fsr", "a é b", ast::Span { start: 3, end: 4 }, "m");
        assert!(r.starts_with("t.fsr:1:3: m"), "{r}");
        assert_eq!(lexer::line_col("é\né", 4), (2, 1));
    }

    /// `{…}` holes map back to the source exactly, even after escapes and
    /// multi-byte text (not from the decoded string).
    #[test]
    fn interpolation_hole_spans_are_exact() {
        let src = "route main(msg: Request) {\n    let x = \"\\n\\{é\\} {€€}\"\n}\n";
        let e = compile_source("t.fsr", src, &Env::default()).err().map(|e| e.to_string()).unwrap_or_default();
        // The hole holds `€€`, which is not an expression: the error points at it.
        let at = src.find('€').unwrap_or_default();
        let (line, col) = lexer::line_col(src, at);
        assert!(e.starts_with(&format!("t.fsr:{line}:{col}: unexpected character '€'")), "{e}");
    }
}
