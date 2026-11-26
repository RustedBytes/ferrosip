//! The interpreter on small scripts, no sockets: `note("…")` records a
//! template evaluated at that point, `ret(n)` returns `n` like a module
//! function would. Each test checks the log a request leaves behind.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test helpers outside #[test] fns")]

use sip_core::module::DynStr;
use sip_core::{Arg, Ctx, Dest, Handler, Lumps, Outbound, Proto, Registry};
use sip_script::Engine;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

struct NoNet;

impl Outbound for NoNet {
    fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        None
    }
}

type Log = Arc<Mutex<Vec<String>>>;

fn engine(src: &str) -> Result<(Engine, Log), String> {
    let log: Log = Arc::default();
    let mut reg = Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule))?;
    let l = log.clone();
    reg.export(
        "test",
        "note",
        |a: &[Arg]| a[0].dyn_str(),
        move |ctx: &mut Ctx, s: &DynStr| {
            let v = s.eval(ctx).into_owned();
            l.lock().unwrap().push(v);
            1
        },
    );
    reg.export("test", "ret", |a: &[Arg]| a[0].int(), |_: &mut Ctx, n: &i64| i32::try_from(*n).unwrap());
    let ast = sip_script::parse(src)?;
    Ok((Engine::compile(&ast, Arc::new(reg))?, log))
}

const MSG: &[u8] = b"INVITE sip:bob@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKx\r\nFrom: <sip:alice@x>;tag=1\r\nTo: <sip:bob@x>\r\nCall-ID: c\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";

/// Run `src` on one INVITE; the log entries in order.
fn run(src: &str) -> Vec<String> {
    let (e, log) = engine(src).unwrap();
    let arena = bumpalo::Bump::new();
    let mut msg = sip_parser::Msg::parse(MSG, &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let net = NoNet;
    let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &net, None, Dest::new(Proto::Udp, "127.0.0.1:5070".parse().unwrap()), 0);
    e.handle(&mut ctx);
    log.lock().unwrap().clone()
}

/// The value of each expression, logged through `$var(r)`.
fn values(exprs: &[&str]) -> Vec<String> {
    let body: String = exprs.iter().map(|e| format!("$var(r) = {e}; note(\"$var(r)\");\n")).collect();
    run(&format!("request_route {{\n{body}}}"))
}

#[test]
fn operator_precedence() {
    let cases = [
        ("1 + 2 * 3 - 4 / 2", "5"),
        ("(1 + 2) * 3", "9"),
        ("7 mod 3 + 1", "2"),
        ("7 % 3 * 2", "2"),
        ("10 - 4 - 3", "3"),
        ("-2 * 3", "-6"),
        ("- (2 + 3)", "-5"),
        ("2 * -3", "-6"),
        // | and & bind looser than comparisons, as in C.
        ("1 | 2 == 2", "1"),
        ("6 & 3 == 3", "0"),
        ("6 & 3", "2"),
        ("4 | 1", "5"),
        ("1 == 1 && 2 == 3 || 4 == 4", "1"),
        ("1 == 2 || 2 == 2 && 0", "0"),
        ("!0 && !1 == 0", "1"),
        ("1 + 2 > 2", "1"),
    ];
    let got = values(&cases.map(|c| c.0));
    assert_eq!(got.len(), cases.len(), "{got:?}");
    for ((e, want), g) in cases.iter().zip(&got) {
        assert_eq!(g, want, "{e}");
    }
}

#[test]
fn string_and_number_coercions() {
    let cases = [
        ("\"5\" == 5", "1"),
        ("5 == \"05\"", "1"),
        ("\"abc\" == 0", "0"),
        ("\"a\" + 1", "a1"),
        ("1 + \"2\"", "3"),
        ("1 + \"x\"", "1"),
        ("\"1\" + \"2\"", "12"),
        ("$null + 4", "4"),
        ("$null == \"\"", "0"),
        ("$null == $null", "1"),
        ("\"10\" < \"9\"", "1"),
        ("\"10\" < 9", "0"),
        ("\"b\" > \"a\"", "1"),
        ("\"7\" - 2", "5"),
        ("\"x\" * 3", "0"),
        ("5 / 0", "0"),
        ("5 mod 0", "0"),
        ("(int)\"42\" + 1", "43"),
        ("(str)4 + 2", "42"),
        ("\"n=$var(none)!\"", "n=!"),
        ("true + false", "1"),
    ];
    let got = values(&cases.map(|c| c.0));
    assert_eq!(got.len(), cases.len(), "{got:?}");
    for ((e, want), g) in cases.iter().zip(&got) {
        assert_eq!(g, want, "{e}");
    }
}

#[test]
fn regex_match_static_and_dynamic() {
    let got = run(r#"request_route {
        if ($ru =~ "^sip:bob@") { note("static"); }
        if ($ru !~ "^sip:alice") { note("nomatch"); }
        $var(re) = "@127\.0\.0\.1$";
        if ($ru =~ $var(re)) { note("dynamic"); }
        if ("sip:$rU" =~ "^sip:b.b$") { note("template"); }
        if (!($fu =~ "bob")) { note("negated"); }
        if ($rm =~ "^INV" && $rm == "INVITE") { note("method"); }
    }"#);
    assert_eq!(got, ["static", "nomatch", "dynamic", "template", "negated", "method"]);
}

#[test]
fn a_bad_constant_regex_is_a_compile_error() {
    let e = engine("request_route { if ($ru =~ \"(\") { exit; } }").err().unwrap();
    assert!(e.contains("bad regex"), "{e}");
}

#[test]
fn variable_assignment() {
    let got = run(r#"request_route {
        $var(a) = 1;
        $var(a) = $var(a) + 1;
        note("var $var(a)");
        $var(a) = $null;
        note("unset [$var(a)]");
        $avp(x) = "one";
        $avp(x) = "two";
        note("avp $avp(x) $avp(x)[1] $avp(x)[*]");
        $avp(x)[0] = $null;
        note("avp after delete $avp(x)");
        $xavp(r=>a) = "1";
        $xavp(r[0]=>b) = "2";
        note("xavp $xavp(r=>a) $xavp(r=>b)");
        $xavp(r=>a) = "new";
        note("xavp front $xavp(r=>a) [$xavp(r=>b)] $xavp(r[1]=>b)");
    }"#);
    assert_eq!(got, ["var 2", "unset []", "avp two one two,one", "avp after delete one", "xavp 1 2", "xavp front new [] 2"]);
}

#[test]
fn read_only_variables_cannot_be_assigned() {
    let e = engine("request_route { $si = \"1.2.3.4\"; }").err().unwrap();
    assert!(e.contains("can't be assigned"), "{e}");
}

#[test]
fn switch_falls_through_until_break() {
    let sw = |v: &str| {
        run(&format!(
            "request_route {{ switch ({v}) {{ case 1: note(\"one\"); case 2: note(\"two\"); break; case \"x\": note(\"x\"); default: note(\"default\"); case 9: note(\"nine\"); }} note(\"after\"); }}"
        ))
    };
    assert_eq!(sw("1"), ["one", "two", "after"]);
    assert_eq!(sw("2"), ["two", "after"]);
    assert_eq!(sw("\"2\""), ["two", "after"], "a numeric string matches an integer label");
    assert_eq!(sw("\"x\""), ["x", "default", "nine", "after"]);
    assert_eq!(sw("9"), ["nine", "after"]);
    assert_eq!(sw("5"), ["default", "nine", "after"], "no match: from default on");
    let none = run("request_route { switch (5) { case 1: note(\"one\"); } note(\"after\"); }");
    assert_eq!(none, ["after"], "no match and no default: nothing runs");
}

#[test]
fn while_and_break() {
    let got = run(r#"request_route {
        $var(i) = 0;
        while ($var(i) < 3) { note("i=$var(i)"); $var(i) = $var(i) + 1; }
        while (1) {
            $var(i) = $var(i) - 1;
            if ($var(i) == 1) { break; }
        }
        note("out at $var(i)");
        $var(o) = 0;
        while ($var(o) < 2) {
            $var(o) = $var(o) + 1;
            $var(n) = 0;
            while (1) { $var(n) = $var(n) + 1; if ($var(n) == 2) break; }
            note("o=$var(o) n=$var(n)");
        }
        while ($var(o) < 5) {
            $var(o) = $var(o) + 1;
            switch ($var(o)) { case 4: break; default: note("sw $var(o)"); }
        }
        note("end $var(o)");
    }"#);
    assert_eq!(got, ["i=0", "i=1", "i=2", "out at 1", "o=1 n=2", "o=2 n=2", "sw 3", "sw 5", "end 5"]);
}

#[test]
fn while_loops_stop_at_the_guard() {
    let got = run("request_route { $var(n) = 0; while (1) { $var(n) = $var(n) + 1; } note(\"$var(n)\"); }");
    assert_eq!(got, ["10000"]);
}

#[test]
fn route_return_codes() {
    let got = run(r#"
        route[NEG] { return(-2); }
        route[POS] { return(3); }
        route[NONE] { note("in none"); }
        route[BARE] { return; }
        route[EXPR] { return(1 + 1); }
        request_route {
            if (route(NEG)) { note("neg true"); } else { note("neg false rc=$rc"); }
            if (route(POS)) { note("pos true rc=$rc"); }
            if (route(NONE)) { note("none true rc=$rc"); }
            if (route(BARE)) { note("bare true rc=$rc"); }
            $var(v) = route(EXPR);
            note("expr $var(v)");
            if (!route(NEG)) { note("not neg"); }
            route(ZERO);
            note("not reached");
        }
        route[ZERO] { note("zero"); return(0); }
    "#);
    assert_eq!(got, ["neg false rc=-2", "pos true rc=3", "in none", "none true rc=1", "bare true rc=1", "expr 2", "not neg", "zero"]);
}

#[test]
fn function_results_and_rc() {
    let got = run(r#"request_route {
        if (ret(-1)) { note("true"); } else { note("false rc=$rc"); }
        if (ret(2)) { note("true rc=$rc"); }
        ret(-5);
        note("after a failing call rc=$rc");
        if (ret(1) && ret(-1)) { note("both"); } else { note("and is false"); }
        if (ret(-1) || ret(4)) { note("or rc=$rc"); }
        ret(0);
        note("not reached");
    }"#);
    assert_eq!(got, ["false rc=-1", "true rc=2", "after a failing call rc=-5", "and is false", "or rc=4"]);
}

#[test]
fn exit_in_a_called_route_ends_the_script() {
    let got = run("route[R] { note(\"r\"); exit; } request_route { route(R); note(\"not reached\"); }");
    assert_eq!(got, ["r"]);
    let got = run("route[R] { note(\"r\"); drop; } request_route { route(R); note(\"not reached\"); }");
    assert_eq!(got, ["r"]);
}

#[test]
fn routes_nest_with_return_values() {
    let got = run(r#"
        route[INNER] { return($var(n) * 2); }
        route[OUTER] { $var(n) = 5; $var(x) = route(INNER); return($var(x) + 1); }
        request_route { $var(r) = route(OUTER); note("$var(r) $rc"); }
    "#);
    assert_eq!(got, ["11 11"]);
}

#[test]
fn recursion_is_cut_at_the_depth_limit() {
    let got = run("route[R] { $var(d) = $var(d) + 1; route(R); } request_route { route(R); note(\"after $var(d)\"); }");
    assert!(got.is_empty(), "the script ends when the depth limit hits: {got:?}");
}

#[test]
fn method_fast_path_and_keywords() {
    let got = run(r#"request_route {
        if (method == "INVITE") { note("invite"); }
        if ($rm != "BYE") { note("not bye"); }
        if (uri == "sip:bob@127.0.0.1") { note("uri"); }
        if (proto == UDP) { note("udp"); }
        if (src_port == 5070) { note("port"); }
    }"#);
    assert_eq!(got, ["invite", "not bye", "uri", "udp", "port"]);
}

#[test]
fn unknown_names_are_compile_errors() {
    let cases = [
        ("request_route { nosuch(); }", "unknown function nosuch()"),
        ("request_route { route(MISSING); }", "no route[MISSING]"),
        ("request_route { if (myself) { exit; } }", "myself can only be compared"),
        ("request_route { switch (1) { case $var(x): exit; } }", "case labels must be literals"),
    ];
    for (src, want) in cases {
        let e = engine(src).err().unwrap_or_default();
        assert!(e.contains(want), "{src}: {e}");
    }
}
