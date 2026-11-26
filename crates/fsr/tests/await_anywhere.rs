//! `await` inside `if`, loops and called functions; `for` loops; helper
//! functions without a message.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use fsr::{Env, compile_source, print::to_cfg};
use sip_core::schema::Unit;
use sip_core::sig::{ArgTy, Param, Ret, arg, ctx, opt, opt_or, sig};

const TEXT: &[Param] = &[arg("text", ArgTy::Str)];
const TO: &[Param] = &[opt("to", ArgTy::Uri)];
const AWAIT: &[Param] = &[opt_or("to", ArgTy::Uri, ""), opt("timeout", ArgTy::Duration(Unit::Ms))];
const STATUS: &[Param] = &[arg("pattern", ArgTy::Str)];
const URL: &[Param] = &[arg("url", ArgTy::Str), opt("timeout", ArgTy::Duration(Unit::Ms))];
static RESP: sip_core::sig::AwaitTy = sip_core::sig::AwaitTy {
    name: "HttpResponse",
    fields: &[
        ("ok", "$http_ok", sip_core::sig::FieldTy::Bool),
        ("status", "$http_rs", sip_core::sig::FieldTy::Int),
        ("body", "$http_rb", sip_core::sig::FieldTy::Str),
    ],
};

fn env() -> Env {
    let mut e = Env::default();
    e.add(
        "txn",
        [
            sig("t_relay", "relay", TO, Ret::Action, ""),
            sig("t_relay_await", "relay_await", AWAIT, Ret::Bool, ""),
            sig("t_check_status", "status_is", STATUS, Ret::Bool, "").allowed(ctx::FAILURE),
        ],
    );
    e.add("http", [sig("http_async_get", "get", URL, Ret::Await(&RESP), "")]);
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

fn errors(src: &str) -> String {
    match compile_source("t.fsr", src, &env()) {
        Ok(o) => panic!("compiled:\n{}", to_cfg(&o.ast)),
        Err(e) => e.to_string(),
    }
}

fn has(cfg: &str, wants: &[&str]) {
    for want in wants {
        assert!(cfg.contains(want), "missing:\n{want}\n--- in:\n{cfg}");
    }
}

#[test]
fn failover_loop_over_gateways() {
    let cfg = lower(
        r#"route main(msg: Request) {
    for gw in ["sip:10.0.0.1", "sip:10.0.0.2"] {
        msg.dst_uri = gw
        let res = await txn.relay(msg, timeout: 5s)
        match res {
            Final(r) if r.code < 500 => forward(r)
            _ => {}
        }
    }
    reply(503, "All gateways failed")
}
"#,
    );
    has(
        &cfg,
        &[
            "$(avp(l__main__for1)[*]) = 0;\n    while ($avp(l__main__for1) < 2) {\n        if ($avp(l__main__for1) == 0) {\n            $(avp(l__main__gw)[*]) = \"sip:10.0.0.1\";\n        } else if ($avp(l__main__for1) == 1) {\n            $(avp(l__main__gw)[*]) = \"sip:10.0.0.2\";\n        }\n        $(avp(l__main__for1)[*]) = $avp(l__main__for1) + 1;\n        $du = $avp(l__main__gw);\n        t_relay_await(\"\", 5000);",
            "        if (!($avp(l__main__res__timeout) > 0) && ($avp(l__main__res__code) < 500)) {\n            exit;\n        }\n    }",
            // After the loop: possibly after a final, so stateful.
            "    }\n    t_reply(503, \"All gateways failed\");\n    exit;",
        ],
    );
}

#[test]
fn await_in_an_if_and_in_a_called_function() {
    let cfg = lower(
        r#"route main(msg: Request) {
    if msg.ruri.user == "vm" {
        let res = await txn.relay(msg)
        match res {
            Final(r) => forward(r)
            Timeout => reply(408)
        }
    }
    deliver(msg)
}
fn deliver(msg: Request) {
    log.info("trying\n")
    let res = await txn.relay(msg, to: "udp:10.0.0.9:5060")
    log.info("done\n")
}
"#,
    );
    has(
        &cfg,
        &[
            "if ($rU == \"vm\") {\n        t_relay_await(\"\");",
            "    route(deliver);\n}",
            "route[deliver] {\n    xlog(\"L_INFO\", \"trying\\n\");\n    t_relay_await(\"udp:10.0.0.9:5060\");",
        ],
    );
}

#[test]
fn ranges_and_helpers_without_a_message() {
    let cfg = lower(
        r#"route main(msg: Request) {
    for i in 1..3 {
        note("try {i}")
    }
    drop
}
fn note(text: Str) {
    log.info("{text}\n")
}
on timer(every: 10s) {
    note("tick")
}
"#,
    );
    has(
        &cfg,
        &[
            "$(avp(l__main__for1)[*]) = 1;\n    while ($avp(l__main__for1) <= 3) {\n        $(avp(l__main__i)[*]) = $avp(l__main__for1);",
            "$(avp(p__note__text)[*]) = \"try $avp(l__main__i)\";\n        route(note);",
            "route[note] {\n    xlog(\"L_INFO\", \"$avp(p__note__text)\\n\");",
            "route[timer__1] {\n    $(avp(p__note__text)[*]) = \"tick\";\n    route(note);",
        ],
    );
}

#[test]
fn rules_that_remain() {
    let e = errors(
        r#"route main(msg: Request) {
    if check(msg) { drop }
    for x in [1, "a"] { drop }
    for y in msg.ruri { drop }
    drop
}
fn check(msg: Request) -> Bool {
    let res = await txn.relay(msg)
    return true
}
fn helper() -> Action {
    drop
}
on timer(every: 1s) {
    check(msg)
}
"#,
    );
    for want in [
        "t.fsr:8:15: `await` can't be in a function returning Bool",
        "t.fsr:3:18: the list mixes Int and Str",
        "t.fsr:4:14: `for` goes over a list ([a, b]) or a range (1..3)",
        "t.fsr:11:4: helper returns Action, so it needs the message",
        "t.fsr:15:11: msg is not defined",
    ] {
        assert!(e.contains(want), "missing {want:?} in:\n{e}");
    }
}

#[test]
fn locals_are_scoped_to_their_block() {
    lower(
        r#"route main(msg: Request) {
    if msg.ruri.user == "a" {
        let x = 1
    }
    let x = "two"
    drop
}
"#,
    );
}

#[test]
fn for_loops_format() {
    let src = "route main(msg: Request) {\n    for gw in [\"a\", \"b\"] {\n        drop\n    }\n}\n";
    assert_eq!(fsr::fmt::format(&fsr::parse(src).unwrap()), src);
}

#[test]
fn tests_lower_to_routes_only_when_asked() {
    let src = r#"route main(msg: Request) { reply(200) }
test "options" {
    log.info = true
    send("OPTIONS sip:x@127.0.0.1", from: "10.0.0.1:5060")
    answer(486)
    assert(reply_code() == 200)
    assert(calls(log.info) == 0)
}
"#;
    let plain = compile_source("t.fsr", src, &env()).unwrap();
    assert!(plain.tests.is_empty() && !to_cfg(&plain.ast).contains("test__"));
    let mut e = env();
    e.tests = true;
    let o = compile_source("t.fsr", src, &e).unwrap();
    assert_eq!(o.tests.len(), 1);
    assert_eq!((o.tests[0].name.as_str(), o.tests[0].route.as_str(), o.tests[0].at.as_str()), ("options", "test__1", "t.fsr:2"));
    assert_eq!(o.tests[0].mocks, vec![("xlog".to_string(), 1)]);
    has(
        &to_cfg(&o.ast),
        &[
            "route[test__1] {\n    fsr_test_send(\"OPTIONS sip:x@127.0.0.1\", \"10.0.0.1:5060\");\n    fsr_test_answer(486, \"Busy Here\");",
            "fsr_test_assert($avp(t__1), \"t.fsr:6: assert(reply_code() == 200): reply_code() is \\\"$fsrtest(code)\\\"\");",
            "($fsrtest(calls.xlog) == 0)",
        ],
    );
}

/// Functions that only make sense after the final (failure context) are
/// fine after `await`: in the same block, in match arms and guards, and in
/// functions called only from there; not before it, nor where the code
/// may or may not have waited.
#[test]
fn after_await_only_functions() {
    lower(
        r#"route main(msg: Request) {
    let res = await txn.relay(msg)
    if txn.status_is("486") {
        busy(msg)
    }
    match res {
        Final(r) if txn.status_is("5[0-9][0-9]") => busy(msg)
        _ => {}
    }
    reply(500)
}
fn busy(msg: Request) -> Action {
    if txn.status_is("486|600") {
        reply(486)
    }
    relay(msg)
}
"#,
    );
    let e = errors(
        r#"route main(msg: Request) {
    if txn.status_is("486") {
        drop
    }
    if msg.ruri.user == "x" {
        let res = await txn.relay(msg)
    }
    if txn.status_is("486") {
        drop
    }
    both(msg)
    let res = await txn.relay(msg)
    both(msg)
    drop
}
fn both(msg: Request) {
    if txn.status_is("486") {
        drop
    }
}
"#,
    );
    for want in
        ["t.fsr:2:12: txn.status_is() can't be used here", "t.fsr:8:12: txn.status_is() can't be used here", "t.fsr:17:12: txn.status_is() can't be used here"]
    {
        assert!(e.contains(want), "missing {want:?} in:\n{e}");
    }
}

#[test]
fn code_after_the_route_ends_is_an_error() {
    let e = errors(
        r#"route main(msg: Request) {
    relay(msg)
    log.info("never\n")
}
"#,
    );
    assert!(e.contains("t.fsr:3:5: unreachable: the statement before ends the route"), "{e}");
}

#[test]
fn awaiting_other_calls() {
    let cfg = lower(
        r#"import http
route main(msg: Request) {
    let r = await http.get("http://svc/route?u={msg.ruri.user}", timeout: 300ms)
    if r.ok && r.status == 200 {
        msg.dst_uri = "sip:{r.body}"
        relay(msg)
    }
    reply(503)
}
"#,
    );
    has(
        &cfg,
        &[
            "http_async_get(\"http://svc/route?u=$rU\", 300);\n    $(avp(l__main__r__ok)[*]) = $http_ok;\n    $(avp(l__main__r__status)[*]) = $http_rs;\n    $(avp(l__main__r__body)[*]) = $http_rb;",
            "if (($avp(l__main__r__ok) > 0) && ($avp(l__main__r__status) == 200)) {\n        $du = \"sip:$avp(l__main__r__body)\";",
        ],
    );
    let e = errors(
        r#"import http
route main(msg: Request) {
    http.get("http://svc")
    let x = await log.info("no")
    let r = await http.get("http://svc")
    let s = r.stauts
    let res = await txn.relay(msg)
    let q = await http.get("http://svc")
    drop
}
"#,
    );
    for want in [
        "t.fsr:3:10: http.get() waits for its result: `let r = await http.get(…)`",
        "t.fsr:4:19: this call doesn't wait (it gives nothing): drop the `await`",
        "t.fsr:6:15: a HttpResponse has no \"stauts\" (did you mean \"status\"?)",
        "t.fsr:8:19: after `await txn.relay` the request is relayed: nothing else can be awaited",
    ] {
        assert!(e.contains(want), "missing {want:?} in:\n{e}");
    }
}
