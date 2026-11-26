//! Lowering of each statement kind, `match` on status codes and ranges,
//! and `await`, compared with the exact `.cfg` text; type and check errors
//! with their positions; the formatter over the example `.fsr` files.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use fsr::{Env, compile_source, print::to_cfg};
use sip_core::schema::Unit;
use sip_core::sig::{ArgTy, Param, Ret, arg, ctx, opt, opt_or, sig};

const TEXT: &[Param] = &[arg("text", ArgTy::Str)];
const TO: &[Param] = &[opt("to", ArgTy::Uri)];
const URI: &[Param] = &[opt("uri", ArgTy::Uri)];
const AWAIT: &[Param] = &[opt_or("to", ArgTy::Uri, ""), opt("timeout", ArgTy::Duration(Unit::Ms))];

fn env() -> Env {
    let mut e = Env::default();
    e.add("txn", [sig("t_relay", "relay", TO, Ret::Action, ""), sig("t_relay_await", "relay_await", AWAIT, Ret::Bool, "")]);
    e.add("location", [sig("save", "save", &[], Ret::Action, "").fixed(&["location"]), sig("lookup", "lookup", URI, Ret::Bool, "").fixed(&["location"])]);
    e.add("log", [sig("xlog", "info", TEXT, Ret::Void, "").fixed(&["L_INFO"]).allowed(ctx::ANY)]);
    e
}

fn lower(src: &str) -> String {
    match compile_source("t.fsr", src, &env()) {
        Ok(o) => {
            let cfg = to_cfg(&o.ast);
            sip_script::parse(&cfg).unwrap_or_else(|e| panic!("lowered output doesn't parse: {e}\n{cfg}"));
            cfg
        }
        Err(e) => panic!("{e}"),
    }
}

/// The lowered `request_route` body of `route main` holding `body`,
/// dedented by one level.
fn main_body(body: &str) -> String {
    let cfg = lower(&format!("import location\nroute main(msg: Request) {{\n{body}\n}}\n"));
    let (_, rest) = cfg.split_once("request_route {\n").unwrap();
    let (route, _) = rest.split_once("\n}\n").unwrap();
    route.lines().map(|l| l.strip_prefix("    ").unwrap_or(l)).collect::<Vec<_>>().join("\n")
}

#[test]
fn lowers_let_and_assign() {
    let got = main_body(
        r#"let a = 1
let b: Str = "x"
a = a + 2
b = b + "y{a}"
log.info(b)"#,
    );
    assert_eq!(
        got,
        r#"$(avp(l__main__a)[*]) = 1;
$(avp(l__main__b)[*]) = "x";
$(avp(l__main__a)[*]) = $avp(l__main__a) + 2;
$(avp(l__main__b)[*]) = $avp(l__main__b) + "y$avp(l__main__a)";
xlog("L_INFO", $avp(l__main__b));"#
    );
}

#[test]
fn lowers_if_else_chain() {
    let got = main_body(
        r#"if msg.ruri.user == "a" {
    log.info("a")
} else if msg.ruri.user == "b" {
    log.info("b")
} else {
    drop
}
exit"#,
    );
    assert_eq!(
        got,
        r#"if ($rU == "a") {
    xlog("L_INFO", "a");
} else if ($rU == "b") {
    xlog("L_INFO", "b");
} else {
    drop;
}
exit;"#
    );
}

#[test]
fn lowers_while_and_break() {
    let got = main_body(
        r#"let n = 0
while n < 3 {
    n = n + 1
    if n == 2 { break }
}
log.info("{n}")"#,
    );
    assert_eq!(
        got,
        r#"$(avp(l__main__n)[*]) = 0;
while ($avp(l__main__n) < 3) {
    $(avp(l__main__n)[*]) = $avp(l__main__n) + 1;
    if ($avp(l__main__n) == 2) {
        break;
    }
}
xlog("L_INFO", "$avp(l__main__n)");"#
    );
}

#[test]
fn lowers_for_over_a_list_and_a_range() {
    let got = main_body(
        r#"for u in ["a", "b"] {
    log.info(u)
}
for i in 1..2 {
    log.info("{i}")
}"#,
    );
    assert_eq!(
        got,
        r#"$(avp(l__main__for1)[*]) = 0;
while ($avp(l__main__for1) < 2) {
    if ($avp(l__main__for1) == 0) {
        $(avp(l__main__u)[*]) = "a";
    } else if ($avp(l__main__for1) == 1) {
        $(avp(l__main__u)[*]) = "b";
    }
    $(avp(l__main__for1)[*]) = $avp(l__main__for1) + 1;
    xlog("L_INFO", $avp(l__main__u));
}
$(avp(l__main__for2)[*]) = 1;
while ($avp(l__main__for2) <= 2) {
    $(avp(l__main__i)[*]) = $avp(l__main__for2);
    $(avp(l__main__for2)[*]) = $avp(l__main__for2) + 1;
    xlog("L_INFO", "$avp(l__main__i)");
}"#
    );
}

#[test]
fn lowers_guard_else() {
    let got = main_body(
        r#"guard msg.src.port != 5060 else drop
guard msg.ruri.user != "" else reply(BadRequest)
log.info("ok")"#,
    );
    assert_eq!(
        got,
        r#"if (!($sp != 5060)) {
    drop;
}
if (!($rU != "")) {
    send_reply(400, "Bad Request");
    exit;
}
xlog("L_INFO", "ok");"#
    );
}

#[test]
fn lowers_let_else_with_a_bool_call() {
    let got = main_body(
        r#"let found = location.lookup() else return reply(NotFound)
log.info("{found}")"#,
    );
    assert_eq!(
        got,
        r#"if (lookup("location")) {
    $(avp(l__main__found)[*]) = 1;
} else {
    $(avp(l__main__found)[*]) = (-1);
}
if ($avp(l__main__found) <= 0) {
    send_reply(404, "Not Found");
    exit;
}
if ($avp(l__main__found) > 0) {
    $(avp(t__1)[*]) = 1;
} else {
    $(avp(t__1)[*]) = (-1);
}
xlog("L_INFO", "$avp(t__1)");"#
    );
}

#[test]
fn lowers_message_fields_and_headers() {
    let got = main_body(
        r#"msg.ruri.user = "bob"
msg.ruri.host = "example.com"
msg.dst_uri = "sip:10.0.0.1"
msg.headers["X-A"] = "1"
msg.headers.remove("X-B")
if msg.headers.has("X-C") { log.info(msg.headers["X-C"]) }
relay(msg)"#,
    );
    assert_eq!(
        got,
        r#"$rU = "bob";
$rd = "example.com";
$du = "sip:10.0.0.1";
remove_hf("X-A");
append_hf("X-A: 1\r\n");
remove_hf("X-B");
if (is_present_hf("X-C")) {
    xlog("L_INFO", $hdr(X-C));
}
if (!t_relay()) {
    sl_reply_error();
}
exit;"#
    );
}

#[test]
fn lowers_match_on_methods_with_an_action_arm() {
    let got = main_body(
        r#"match msg.method {
    INVITE | BYE => log.info("ib")
    REGISTER => location.save(msg)
    _ => {}
}
drop"#,
    );
    assert_eq!(
        got,
        r#"if (($rm == "INVITE") || ($rm == "BYE")) {
    xlog("L_INFO", "ib");
} else if ($rm == "REGISTER") {
    if (!save("location")) {
        sl_reply_error();
    }
    exit;
}
drop;"#
    );
}

#[test]
fn lowers_match_on_status_codes_and_ranges() {
    let got = main_body(
        r#"let c = 404
match c {
    NotFound | 410 => log.info("gone")
    Ringing..SessionProgress => log.info("early")
    500..599 => log.info("5xx")
    _ => log.info("other")
}"#,
    );
    assert_eq!(
        got,
        r#"$(avp(l__main__c)[*]) = 404;
if (($avp(l__main__c) == 404) || ($avp(l__main__c) == 410)) {
    xlog("L_INFO", "gone");
} else if (($avp(l__main__c) >= 180) && ($avp(l__main__c) <= 183)) {
    xlog("L_INFO", "early");
} else if (($avp(l__main__c) >= 500) && ($avp(l__main__c) <= 599)) {
    xlog("L_INFO", "5xx");
} else {
    xlog("L_INFO", "other");
}"#
    );
}

#[test]
fn lowers_match_on_strings_with_a_guard() {
    let got = main_body(
        r#"let s = "x"
match s {
    "a" => drop
    "b" if msg.src.port == 5060 => exit
}
log.info("after")"#,
    );
    assert_eq!(
        got,
        r#"$(avp(l__main__s)[*]) = "x";
if ($avp(l__main__s) == "a") {
    drop;
} else if (($avp(l__main__s) == "b") && ($sp == 5060)) {
    exit;
}
xlog("L_INFO", "after");"#
    );
}

#[test]
fn lowers_conditions_in_ranges_and_lists() {
    let got = main_body(
        r#"if !(msg.src.port > 1 && msg.src.port < 3) || msg.ruri.user =~ "^\\+1" { exit }
if msg.src.port in 1..3 { exit }
if msg.ruri.user in ["a", "b"] { exit }
if msg.method != INVITE { drop }"#,
    );
    assert_eq!(
        got,
        r#"if (!(($sp > 1) && ($sp < 3)) || ($rU =~ "^\\+1")) {
    exit;
}
if (($sp >= 1) && ($sp <= 3)) {
    exit;
}
if (($rU == "a") || ($rU == "b")) {
    exit;
}
if ($rm != "INVITE") {
    drop;
}"#
    );
}

#[test]
fn lowers_await_relay_and_match_the_result() {
    let got = main_body(
        r#"let res = await txn.relay(msg, timeout: 5s)
match res {
    Final(r) if r.code in 200..299 => exit
    Final(r) if r.code == BusyHere => reply(TemporarilyUnavailable, "Busy {r.code}")
    Timeout => drop
    Final(r) => forward(r)
}"#,
    );
    assert_eq!(
        got,
        r#"t_relay_await("", 5000);
$(avp(l__main__res__rc)[*]) = $rc;
$(avp(l__main__res__code)[*]) = $T_reply_code;
$(avp(l__main__res__reason)[*]) = $T_reply_reason;
$(avp(l__main__res__timeout)[*]) = $T_timeout;
if (!($avp(l__main__res__timeout) > 0) && (($avp(l__main__res__code) >= 200) && ($avp(l__main__res__code) <= 299))) {
    exit;
} else if (!($avp(l__main__res__timeout) > 0) && ($avp(l__main__res__code) == 486)) {
    t_reply(480, "Busy $avp(l__main__res__code)");
    exit;
} else if ($avp(l__main__res__timeout) > 0) {
    drop;
} else if (!($avp(l__main__res__timeout) > 0)) {
    exit;
}"#
    );
}

#[test]
fn lowers_await_without_a_result() {
    let got = main_body(
        r#"msg.dst_uri = "sip:a"
await txn.relay(msg)
log.info("after {msg.ruri}")"#,
    );
    assert_eq!(
        got,
        r#"$du = "sip:a";
t_relay_await("");
xlog("L_INFO", "after $ru");"#
    );
}

#[test]
fn lowers_await_inside_an_if() {
    let got = main_body(
        r#"if msg.src.port == 1 {
    let res = await txn.relay(msg, to: "sip:10.0.0.9")
    match res {
        _ => {}
    }
}
log.info("x")"#,
    );
    assert_eq!(
        got,
        r#"if ($sp == 1) {
    t_relay_await("sip:10.0.0.9");
    $(avp(l__main__res__rc)[*]) = $rc;
    $(avp(l__main__res__code)[*]) = $T_reply_code;
    $(avp(l__main__res__reason)[*]) = $T_reply_reason;
    $(avp(l__main__res__timeout)[*]) = $T_timeout;
}
xlog("L_INFO", "x");"#
    );
}

fn errors(src: &str) -> String {
    match compile_source("t.fsr", src, &env()) {
        Ok(o) => panic!("compiled:\n{}", to_cfg(&o.ast)),
        Err(e) => e.to_string(),
    }
}

#[test]
fn check_errors_point_at_their_source() {
    let cases: &[(&str, &str)] = &[
        ("route main(msg: Request) { let x: Foo = 1 }", "t.fsr:1:35: unknown type \"Foo\" (did you mean \"Bool\"?)"),
        ("route main(msg: Request) { let x = 1\n let x = 2 }", "t.fsr:2:6: x is already defined here"),
        ("route main(msg: Request) { y = 1 }", "t.fsr:1:28: y is not defined (use `let y = …`)"),
        ("route main(msg: Request) { let x = 1\n x = \"s\" }", "t.fsr:2:6: x is Int, found Str"),
        ("route main(msg: Request) { if 1 { drop } }", "t.fsr:1:31: expected a condition (Bool), found Int"),
        ("route main(msg: Request) { if \"a\" == 1 { drop } }", "t.fsr:1:31: can't compare Str with Int"),
        ("route main(msg: Request) { if msg.src.port < \"a\" { drop } }", "t.fsr:1:46: < and > compare numbers, found Str"),
        ("route main(msg: Request) { let x = \"a\" - 1 }", "t.fsr:1:36: arithmetic needs numbers, found Str and Int"),
        (
            "route main(msg: Request) { guard msg.src.port > 1 else log.info(\"x\") }",
            "t.fsr:1:56: a guard's else must end the route (reply, drop, exit, return, or an Action call)",
        ),
        ("route main(msg: Request) { guard msg.src.port > 1 else { drop } }", "t.fsr:1:56: expected an expression, found `{`"),
        (
            "route main(msg: Request) { guard msg.src.port > 1 else msg.ruri.user = \"x\" }",
            "t.fsr:1:56: a guard's else must end the route (reply, drop, exit, return, or an Action call)",
        ),
        ("route main(msg: Request) { msg.headers.clear() }", "t.fsr:1:40: msg.headers has remove() and has(), not clear()"),
        ("route main(msg: Request) { msg.headers.has() }", "t.fsr:1:28: msg.headers.has(\"Name\")"),
        (
            "route main(msg: Request) { drop }\nfn f(msg: Request) -> Int { return 1 }\nfn g(msg: Request) { if f(msg) { drop } }",
            "t.fsr:2:23: functions return Action or Bool (or nothing), not Int",
        ),
        ("route main(msg: Request) { if msg.ruri =~ 5 { drop } }", "t.fsr:1:31: =~ matches text against a regular expression string"),
        ("route main(msg: Request) { let x = -\"a\" }", "t.fsr:1:37: can't negate Str"),
        ("route main(msg: Request) { let x = 1..3 }", "t.fsr:1:36: a range is only used with `in` (x in 200..299) or as a match pattern"),
        ("route main(msg: Request) { let x = [1, 2] }", "t.fsr:1:36: a list is only used with `in` (x in [a, b])"),
        ("route main(msg: Request) { if 1 in 5 { drop } }", "t.fsr:1:36: `in` takes a range (200..299) or a list ([a, b])"),
        ("route main(msg: Request) { for x in [1, \"a\"] { drop } }", "t.fsr:1:41: the list mixes Int and Str"),
        ("route main(msg: Request) { for x in 5 { drop } }", "t.fsr:1:37: `for` goes over a list ([a, b]) or a range (1..3)"),
        (
            "route main(msg: Request) { guard msg.src.port > 1 else log.info(\"x\") }",
            "t.fsr:1:56: a guard's else must end the route (reply, drop, exit, return, or an Action call)",
        ),
        ("route main(msg: Request) { reply(200)\n drop }", "t.fsr:2:2: unreachable: the statement before ends the route (a reply, relay or other Action)"),
        ("route main(msg: Request) { match msg.method { FOO => drop } }", "t.fsr:1:47: unknown method FOO"),
        ("route main(msg: Request) { match 1 { Ringin => drop } }", "t.fsr:1:38: unknown status code Ringin (did you mean \"Ringing\"?)"),
        ("route main(msg: Request) { match 1 { \"a\"..\"b\" => drop } }", "t.fsr:1:41: expected `=>`, found `..`"),
        ("route main(msg: Request) { match 1 { Final(r) => drop } }", "t.fsr:1:38: Final only matches an `await` result"),
        ("route main(msg: Request) { nope() }", "t.fsr:1:28: unknown function nope()"),
        ("route main(msg: Request) { main(msg) }", "t.fsr:1:28: main is where requests start; it can't be called"),
        ("route main(msg: Request) { f(msg, 1) }\nfn f(msg: Request) { drop }", "t.fsr:1:28: f takes 1 argument(s), got 2"),
        ("route main(msg: Request) { f(1) }\nfn f(msg: Request) { drop }", "t.fsr:1:30: pass the message first: name(msg, …)"),
        ("route main(msg: Request) { f(msg, \"a\") }\nfn f(msg: Request, n: Int) { drop }", "t.fsr:1:35: n is Int, found Str"),
        ("route main(msg: Request) { drop }\nfn f(msg: Request) -> Bool { return }", "t.fsr:2:30: this function returns Bool: return true or false"),
        ("route main(msg: Request) { drop }\nfn f(msg: Request) -> Bool { return 1 }", "t.fsr:2:37: this function returns Bool, found Int"),
        ("route main(msg: Request) { drop }\nfn f(x: Int) -> Action { drop }", "t.fsr:2:4: f returns Action, so it needs the message: (msg: Request, …)"),
        (
            "route main(msg: Request) { drop }\nroute other(msg: Request, x: Int) { drop }",
            "t.fsr:2:7: a route takes only the message; use `fn` for more parameters",
        ),
        ("route main(msg: Request) { drop }\nfn f(msg: Request) -> Int { return 1 }", "t.fsr:2:23: functions return Action or Bool (or nothing), not Int"),
        ("route main(msg: Request) { drop }\nroute main(msg: Request) { drop }", "t.fsr:2:7: main is defined twice"),
        ("route main(msg: Request) { msg.headers.clear() }", "t.fsr:1:40: msg.headers has remove() and has(), not clear()"),
        ("route main(msg: Request) { reply(200, 5) }", "t.fsr:1:39: a reason phrase is text"),
        ("route main(msg: Request) { reply() }", "t.fsr:1:28: reply(code[, reason])"),
        ("route main(msg: Request) { 1 + 2 }", "t.fsr:1:28: this value (Int) is not used"),
        ("route main(msg: Request) { let x = location.lookup() else drop\n let y = await location.lookup() }", "t.fsr:1:36: add `import location` at the top"),
        ("route main(msg: Request) { if features.nope { drop } }", "t.fsr:1:31: features.nope is not a msg field"),
        ("route main(msg: Request) { let t = now(1) }", "t.fsr:1:36: now() takes no argument"),
        ("import { x } from elsewhere\nroute main(msg: Request) { drop }", "t.fsr:1:19: only `from config` is supported"),
        ("import { flags } from config\nroute main(msg: Request) { drop }", "t.fsr:1:10: config has `features` ([feature] in ferrosip.toml), not \"flags\""),
        ("on reply(r: Reply, x: Int) { }\nroute main(msg: Request) { drop }", "t.fsr:1:4: `on reply` takes one parameter: (x: Reply)"),
        ("on timer(every: \"x\") { }\nroute main(msg: Request) { drop }", "t.fsr:1:17: every: a duration (30s, 500ms)"),
        ("on nothing() { }\nroute main(msg: Request) { drop }", "t.fsr:1:4: unknown event \"nothing\""),
        ("shared table t: Map<Bool, Int>\nroute main(msg: Request) { drop }", "t.fsr:1:21: a table key is Str or Int"),
        ("shared table t: Map<Str, Float>\nroute main(msg: Request) { drop }", "t.fsr:1:26: a table value is Bool, Int, Str or Counter, not Float"),
        ("shared table t: Map<Str, Int> ttl 10ms\nroute main(msg: Request) { drop }", "t.fsr:1:35: ttl: a duration of at least 1s"),
        ("dialog var d: Float\nroute main(msg: Request) { drop }", "t.fsr:1:15: unknown type \"Float\""),
        ("dialog var d: Str\ndialog var d: Int\nroute main(msg: Request) { drop }", "t.fsr:2:12: dialog var d declared twice"),
        ("route main(msg: Request) { msg.set(1) }", "t.fsr:1:36: expected a flag (declare it: `flag NAME` or `branch flag NAME`), found Int"),
        ("route main(msg: Request) { msg.method = INVITE }", "t.fsr:1:28: msg.method can't be changed"),
        ("route main(msg: Request) { msg.src.port = 1 }", "t.fsr:1:28: msg.src.port can't be changed"),
        ("route main(msg: Request) { let x = 1 + true }", "t.fsr:1:36: can't add Int and Bool"),
    ];
    for (src, want) in cases {
        let e = errors(src);
        let first = e.lines().next().unwrap_or_default();
        assert_eq!(first, *want, "{src}");
        // Each error is followed by its line and a caret under the span.
        let caret = e.lines().nth(2).unwrap_or_default();
        assert!(caret.trim_start().starts_with('^'), "{src}: no caret in\n{e}");
    }
}

#[test]
fn int_plus_str_lowers_to_a_concatenation() {
    // The script's `+` follows its left operand: an Int there would add.
    let got = main_body("let a = msg.src.port + \":\" + msg.src.ip\nlet b = 1 + \"x\"\nlog.info(a + b)");
    assert_eq!(
        got,
        r#"$(avp(l__main__a)[*]) = (("" + $sp) + ":") + $si;
$(avp(l__main__b)[*]) = ("" + 1) + "x";
$(avp(t__1)[*]) = $avp(l__main__a) + $avp(l__main__b);
xlog("L_INFO", $avp(t__1));"#
    );
}

#[test]
fn a_bad_return_type_is_reported_once() {
    let e = errors("route main(msg: Request) { if f(msg) { drop } }\nfn f(msg: Request) -> Int { return 1 }\n");
    let lines: Vec<&str> = e.lines().filter(|l| l.starts_with("t.fsr:")).collect();
    assert_eq!(lines, ["t.fsr:2:23: functions return Action or Bool (or nothing), not Int"]);
}

fn fsr_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            fsr_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "fsr") {
            out.push(p);
        }
    }
}

#[test]
fn formatting_the_examples_is_idempotent() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut files = Vec::new();
    fsr_files(&root, &mut files);
    assert!(files.len() >= 20, "{files:?}");
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        let ast = fsr::parse(&src).unwrap_or_else(|e| panic!("{}: {}", f.display(), e.msg));
        let once = fsr::fmt::format(&ast);
        let again = fsr::parse(&once).unwrap_or_else(|e| panic!("{}: formatted text doesn't parse: {}\n{once}", f.display(), e.msg));
        assert_eq!(fsr::fmt::format(&again), once, "{}: format(format(x)) != format(x)", f.display());
    }
}
