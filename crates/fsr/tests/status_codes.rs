//! SIP status codes by name: `reply(NotFound)`, `r.code == BusyHere`,
//! ranges, match arms and `req.reply(OK)`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use fsr::{Env, compile_source, print::to_cfg};
use sip_core::schema::Unit;
use sip_core::sig::{ArgTy, Param, Ret, arg, ctx, opt, opt_or, sig};

const TEXT: &[Param] = &[arg("text", ArgTy::Str)];
const AWAIT: &[Param] = &[opt_or("to", ArgTy::Uri, ""), opt("timeout", ArgTy::Duration(Unit::Ms))];

fn env() -> Env {
    let mut e = Env::default();
    e.add("txn", [sig("t_relay_await", "relay_await", AWAIT, Ret::Bool, "")]);
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

const SCRIPT: &str = r#"route main(msg: Request) {
    if msg.ruri.user == "gone" {
        reply(NotFound)
    }
    if msg.ruri.user == "busy" {
        reply(BusyHere, "Line busy")
    }
    let res = await txn.relay(msg, timeout: 5s)
    match res {
        Final(r) if r.code == RequestTimeout => reply(ServiceUnavailable)
        _ => drop
    }
}

on reply(r: Reply) where r.code in Ringing..SessionProgress {
    match r.code {
        Ringing | 181 => log.info("ringing")
        Queued..SessionProgress => log.info("progress")
        _ => {}
    }
}

on http(req: HttpRequest) where req.path == "/ping" {
    req.reply(OK)
}
"#;

#[test]
fn names_lower_to_their_codes() {
    has(
        &lower(SCRIPT),
        &[
            "send_reply(404, \"Not Found\");",
            "send_reply(486, \"Line busy\");",
            "($avp(l__main__res__code) == 408)",
            "t_reply(503, \"Service Unavailable\");",
            "if (($rs >= 180) && ($rs <= 183)) {",
            "if (($rs == 180) || ($rs == 181)) {",
            "} else if (($rs >= 182) && ($rs <= 183)) {",
            "xhttp_reply(200, \"OK\", \"text/plain\", \"\");",
        ],
    );
}

#[test]
fn format_keeps_the_names() {
    assert_eq!(fsr::fmt::format(&fsr::parse(SCRIPT).unwrap()), SCRIPT);
}

#[test]
fn a_local_shadows_a_name() {
    let cfg = lower("route main(msg: Request) {\n    let OK = 1\n    if OK == 1 {\n        reply(OK)\n    }\n}\n");
    has(&cfg, &["send_reply($avp(l__main__OK), \"Reply\");"]);
    assert!(!cfg.contains("send_reply(200"), "{cfg}");
}

#[test]
fn typos_suggest_the_name() {
    let e = errors("route main(msg: Request) {\n    reply(NotFund)\n}\n");
    assert!(e.contains("t.fsr:2:11: NotFund is not defined (did you mean \"NotFound\"?)"), "{e}");
    let e = errors("on reply(r: Reply) {\n    match r.code {\n        Ringin => drop\n        Queued..SesionProgress => drop\n        _ => {}\n    }\n}\n");
    assert!(e.contains("unknown status code Ringin (did you mean \"Ringing\"?)"), "{e}");
    assert!(e.contains("unknown status code SesionProgress (did you mean \"SessionProgress\"?)"), "{e}");
}

#[test]
fn every_name_has_its_reason() {
    for (name, code) in fsr::msg::STATUS_CODES {
        assert_ne!(fsr::msg::reason(*code), "Unknown", "{name}");
    }
    let codes: std::collections::HashSet<_> = fsr::msg::STATUS_CODES.iter().map(|(_, c)| c).collect();
    assert_eq!(codes.len(), fsr::msg::STATUS_CODES.len(), "a code named twice");
}

#[test]
fn txn_code_in_failure_reply_and_branch_handlers() {
    let cfg = lower(
        r#"on kamailio.failure_route(msg: Request, name: "F") {
    if txn.code == BusyHere || txn.code == RequestTimeout {
        log.info("busy: " + txn.reason)
    }
    if txn.code in 300..399 {
        drop
    }
}

on kamailio.onreply_route(msg: Reply, name: "R") {
    if txn.code == Ringing {
        log.info("ringing")
    }
}

on kamailio.branch_route(msg: Request, name: "B") {
    if txn.code >= 500 {
        drop
    }
}

route main(msg: Request) {
    let res = await txn.relay(msg)
    if txn.code == NotFound {
        reply(ServiceUnavailable)
    }
}
"#,
    );
    has(
        &cfg,
        &[
            "if (($T_reply_code == 486) || ($T_reply_code == 408)) {",
            "$(avp(t__1)[*]) = \"busy: \" + $T_reply_reason;",
            "if (($T_reply_code >= 300) && ($T_reply_code <= 399)) {",
            "if ($T_reply_code == 180) {",
            "if ($T_reply_code >= 500) {",
            "if ($T_reply_code == 404) {",
        ],
    );
}

#[test]
fn txn_code_is_unknown_in_a_request_route() {
    let e = errors("route main(msg: Request) {\n    if txn.code == BusyHere {\n        drop\n    }\n    log.info(txn.reason)\n}\n");
    assert!(e.contains("t.fsr:2:8: txn.code is only known in a failure, reply or branch handler"), "{e}");
    assert!(e.contains("t.fsr:5:14: txn.reason is only known in a failure, reply or branch handler"), "{e}");
    let e = errors("on reply(r: Reply) {\n    if txn.cod == 1 {\n        drop\n    }\n}\n");
    assert!(e.contains("txn has code and reason, not cod (did you mean \"code\"?)"), "{e}");
}
