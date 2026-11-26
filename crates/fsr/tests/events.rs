//! Event handlers, shared tables and dialog variables: lowering and errors.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers outside #[test] fns")]

use fsr::{Env, compile_source, print::to_cfg};
use sip_core::sig::{ArgTy, Param, Ret, arg, ctx, sig};

const TEXT: &[Param] = &[arg("text", ArgTy::Str)];

fn env() -> Env {
    let mut e = Env::default();
    e.add("txn", [sig("t_relay", "relay", &[], Ret::Action, "")]);
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

const SCRIPT: &str = r#"shared table hits: Map<Str, Counter> ttl 10s
shared table bans: Map<Str, Bool>
dialog var caller: Str
dialog var paid: Bool

route main(msg: Request) {
    if bans.contains(msg.src.ip) { drop }
    if hits.incr(msg.src.ip) > 20 {
        bans.set(msg.src.ip, true, ttl: 10m)
        drop
    }
    hits.incr("total")
    dialog.caller = msg.from.user
    reply(200)
}

on dialog.started(d: Dialog) {
    d.paid = true
}

on dialog.ended(d: Dialog) where d.paid {
    log.info("cdr {d.call_id} {d.caller} {d.duration} {d.end_reason} at {now()}\n")
}

on dialog.ended(d: Dialog) {
    hits.remove(d.caller)
}

on http(req: HttpRequest) where req.path == "/api/bans" && req.method == "DELETE" {
    bans.clear()
    req.reply(204)
}

on http(req: HttpRequest) where req.path == "/api/hits" {
    req.reply(200, "{hits.get("total")}", "text/plain")
}

on timer(every: 1500ms) {
    hits.incr("ticks")
}
"#;

#[test]
fn declarations_become_modules_and_parameters() {
    has(
        &lower(SCRIPT),
        &[
            "loadmodule \"htable\"\nloadmodule \"dialog\"\nloadmodule \"xhttp\"\nloadmodule \"rtimer\"\n",
            "modparam(\"htable\", \"htable\", \"hits=>size=8;autoexpire=10;\")\nmodparam(\"htable\", \"htable\", \"bans=>size=8;\")\n",
            "modparam(\"rtimer\", \"timer\", \"name=fsr_timer_1;interval=1500ms\")\nmodparam(\"rtimer\", \"exec\", \"timer=fsr_timer_1;route=timer__1\")",
        ],
    );
}

#[test]
fn shared_tables() {
    has(
        &lower(SCRIPT),
        &[
            "if ($sht(bans=>$si) != $null) {\n        drop;",
            "if ($shtinc(hits=>$si) > 20) {\n",
            "sht_setxi(\"bans\", $si, $avp(t__1), 600);",
            "= $shtinc(hits=>total);",
            "$sht(hits=>$dlg_var(caller)) = $null;",
            "sht_reset(\"bans\");",
        ],
    );
}

#[test]
fn dialog_handlers_and_variables() {
    has(
        &lower(SCRIPT),
        &[
            "$dlg_var(caller) = $fU;",
            "event_route[dialog:start] {\n    $dlg_var(paid) = 1;",
            "event_route[dialog:end] {\n    if ($dlg_var(paid) > 0) {\n        xlog(\"L_INFO\", \"cdr $dlg(callid) $dlg_var(caller) $dlg(duration) $dlg(end_reason) at $Ts\\n\");\n    }\n    $sht(hits=>$dlg_var(caller)) = $null;\n}",
        ],
    );
}

#[test]
fn http_handlers_answer_in_order() {
    has(
        &lower(SCRIPT),
        &[
            "event_route[xhttp:request] {\n    if (($hp == \"/api/bans\") && ($hm == \"DELETE\")) {\n        sht_reset(\"bans\");\n        xhttp_reply(204, \"No Content\", \"text/plain\", \"\");\n        exit;",
            "xhttp_reply(200, \"OK\", \"text/plain\", \"$(sht(hits=>total){s.int})\");",
            "    xhttp_reply(404, \"Not Found\", \"text/plain\", \"\");\n}",
        ],
    );
}

#[test]
fn timers_are_routes() {
    has(&lower(SCRIPT), &["route[timer__1] {\n    $(avp(t__", "= $shtinc(hits=>ticks);\n}"]);
}

#[test]
fn errors_in_handlers() {
    let e = errors(
        r#"shared table t: Map<Str, Int>
route main(msg: Request) {
    t.set("a", "x")
    drop
}
on dialog.ended(d: Dialog) {
    d.end()
    relay(msg)
    log.info(d.calid)
}
on dialog.endd(d: Dialog) {}
on http(req: HttpRequest) {
    reply(200)
}
on timer(cron: "0 3 * * *") {}
"#,
    );
    for want in [
        "t.fsr:3:16: t holds Int values, found Str",
        "t.fsr:7:7: the dialog already ended: no d.end() in `on dialog.ended`",
        "t.fsr:9:14: a Dialog has no \"calid\" (did you mean \"call_id\"?)",
        "t.fsr:11:4: unknown event \"dialog.endd\" (did you mean \"dialog.ended\"?)",
        "t.fsr:13:5: reply() answers a request; there is none in an event handler (answer the HTTP request with req.reply(…))",
        "t.fsr:15:16: cron schedules are not supported yet",
    ] {
        assert!(e.contains(want), "missing {want:?} in:\n{e}");
    }
}

#[test]
fn format_keeps_the_new_items() {
    let src = "shared table bans: Map<Str, Bool> ttl 10m\ndialog var caller: Str\n\non timer(every: 30s) {\n    bans.clear()\n}\n\non dialog.ended(d: Dialog) where d.duration > 3600 {\n    drop\n}\n";
    assert_eq!(fsr::fmt::format(&fsr::parse(src).unwrap()), src);
}

#[test]
fn diameter_handlers() {
    let cfg = lower(
        r#"route main(msg: Request) {
    reply(200)
}
on diameter.request(req: DiameterRequest) where req.command == 306 && req.application == 16777217 {
    log.info("udr {req.avps}\n")
    req.answer("[\{\"avpCode\":268,\"int32\":2001\}]")
}
on diameter.request(req: DiameterRequest) where req.answer_avps == "" {
    req.answer("[\{\"avpCode\":268,\"int32\":3001\}]")
}
on diameter.response(ans: DiameterAnswer) {
    log.info("answer {ans.avps}\n")
}
"#,
    );
    has(
        &cfg,
        &[
            "loadmodule \"ims_diameter_server\"",
            "event_route[diameter:request] {\n    if (($diameter_command == 306) && ($diameter_application == 16777217)) {\n        xlog(\"L_INFO\", \"udr $diameter_request\\n\");\n        $diameter_response = \"[{\\\"avpCode\\\":268,\\\"int32\\\":2001}]\";\n    }\n    if ($diameter_response == \"\") {",
            "event_route[diameter:response] {\n    xlog(\"L_INFO\", \"answer $diameter_response\\n\");\n}",
        ],
    );
    let e = errors(
        r#"route main(msg: Request) {
    reply(200)
}
on diameter.request(req: DiameterRequest) {
    req.answer(5)
    req.reply(200)
    log.info("{req.cmd}")
}
on diameter.response(ans: DiameterRequest) {}
on diameter.response(ans: DiameterAnswer) {
    ans.answer("[]")
}
"#,
    );
    for want in [
        "t.fsr:5:16: the answer's AVPs are JSON text (Str), found Int",
        "t.fsr:6:9: a DiameterRequest has answer(), not reply()",
        "t.fsr:7:16: a DiameterRequest has no \"cmd\"",
        "t.fsr:9:4: `on diameter.response` takes one parameter: (x: DiameterAnswer)",
        "t.fsr:11:9: a DiameterAnswer has no methods, not answer()",
    ] {
        assert!(e.contains(want), "missing {want:?} in:\n{e}");
    }
}
