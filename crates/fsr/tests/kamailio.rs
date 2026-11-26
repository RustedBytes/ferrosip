//! The escape hatch to Kamailio (what `ferrosip import` writes for what has
//! no typed form): `pv("$x")`, `kamailio.call("fn", …)`, `kamailio.myself`,
//! and `on kamailio.<kind>_route(…, name: "X")`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use fsr::{Env, compile_source, print::to_cfg};
use sip_core::sig::{ArgTy, Param, Ret, arg, sig};

const TEXT: &[Param] = &[arg("text", ArgTy::Str)];

fn env() -> Env {
    let mut e = Env::default();
    e.add("log", [sig("xlog", "info", TEXT, Ret::Void, "").fixed(&["L_INFO"]).allowed(sip_core::sig::ctx::ANY)]);
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
fn pseudo_variables_read_and_written_as_written() {
    let cfg = lower(
        r#"route main(msg: Request) {
    pv("$avp(dst)") = "sip:{pv("$rU")}@10.0.0.1"
    pv("$var(n)") = pv("$var(n)") + 1
    if pv("$var(n)") > 3 && pv("$avp(dst)") != pv("$null") {
        msg.ruri = pv("$avp(dst)")
    }
    let x = pv("$hdr(X-Id)")
    log.info("id {x} {pv("$ci")}")
    exit
}
"#,
    );
    has(
        &cfg,
        &[
            "$avp(dst) = \"sip:$rU@10.0.0.1\";",
            "$var(n) = $var(n) + 1;",
            "if (($var(n) > 3) && ($avp(dst) != $null)) {",
            "$ru = $avp(dst);",
            "xlog(\"L_INFO\", \"id $avp(l__main__x) $ci\");",
        ],
    );
    let e = errors("route main(msg: Request) {\n    pv(\"avp(x)\") = 1\n    pv(\"$a $b\") = 2\n    exit\n}\n");
    assert!(e.contains("not one pseudo-variable") && e.matches("pv(").count() >= 2, "{e}");
}

#[test]
fn kamailio_calls_and_myself() {
    let cfg = lower(
        r#"route main(msg: Request) {
    if kamailio.call("is_method", "INVITE|BYE") && !kamailio.call("has_totag") {
        kamailio.call("t_on_failure", "MISSED")
        kamailio.call("sl_send_reply", 404, "Not {pv("$rU")}")
    }
    if pv("$ru") == kamailio.myself {
        kamailio.call("append_hf", "X-Count: {pv("$var(n)") + 1}\r\n")
    }
    exit
}
"#,
    );
    has(
        &cfg,
        &[
            "if (is_method(\"INVITE|BYE\") && !has_totag()) {",
            "t_on_failure(\"MISSED\");",
            "sl_send_reply(404, \"Not $rU\");",
            "if ($ru == myself) {",
            "append_hf(\"X-Count: $avp(t__",
        ],
    );
    let e = errors("route main(msg: Request) {\n    kamailio.call(\"bad name\")\n    kamailio.run(\"x\")\n    exit\n}\n");
    assert!(e.contains("the name is a literal") && e.contains("not run"), "{e}");
}

#[test]
fn kamailio_route_kinds() {
    let cfg = lower(
        r#"route main(msg: Request) {
    kamailio.call("t_on_failure", "MISSED")
    kamailio.call("t_on_branch", "BR")
    kamailio.call("t_on_reply", "RPL")
    kamailio.call("t_relay")
    exit
}

on kamailio.failure_route(msg: Request, name: "MISSED") {
    if kamailio.call("t_is_canceled") {
        exit
    }
    msg.ruri = "sip:vm@10.0.0.2"
    kamailio.call("t_relay")
}

on kamailio.branch_route(msg: Request, name: "BR") {
    log.info("branch {msg.ruri}")
}

on kamailio.onreply_route(msg: Reply, name: "RPL") {
    log.info("reply {msg.code}")
}

on kamailio.event_route(name: "tm:local-request") {
    log.info("local {pv("$rm")}")
}
"#,
    );
    has(
        &cfg,
        &[
            "failure_route[MISSED] {\n    if (t_is_canceled()) {\n        exit;\n    }\n    $ru = \"sip:vm@10.0.0.2\";\n    t_relay();\n}",
            "branch_route[BR] {",
            "onreply_route[RPL] {\n    xlog(\"L_INFO\", \"reply $rs\");",
            "event_route[tm:local-request] {",
        ],
    );
    let e = errors(
        "route main(msg: Request) { exit }\non kamailio.failure_route(msg: Request) { exit }\non kamailio.event_route(msg: Request, name: \"x:y\") { exit }\n",
    );
    assert!(e.contains("the route's name") && e.contains("takes no message parameter"), "{e}");
}
