//! Unit tests of the message utilities through their exported functions
//! (textops, textopsx, siputils, sanity, sl, ipops) and of the shared
//! helpers (sed-style substitution, header matching, dates).

use super::*;
use bumpalo::Bump;
use sip_core::pv::{PvTable, Val};
use sip_core::{Dest, Lumps, Outbound, Proto, Registry};
use std::net::SocketAddr;
use std::sync::Mutex;

/// An Outbound that keeps what is sent.
#[derive(Default)]
struct Capture(Mutex<Vec<String>>);

impl Outbound for Capture {
    fn send(&self, _: &Dest, data: &[u8]) -> std::io::Result<()> {
        self.0.lock().unwrap().push(String::from_utf8_lossy(data).into_owned());
        Ok(())
    }
    fn advertise(&self, _: Proto) -> Option<SocketAddr> {
        None
    }
}

const MODULES: &[&str] = &["sl", "siputils", "sanity", "textops", "textopsx", "ipops"];

fn registry() -> Registry {
    let mut reg = Registry::default();
    for n in MODULES {
        reg.load(module(n).unwrap()).unwrap();
    }
    reg
}

/// The core variables (`$var`, `$rU`, …), to build variable arguments.
fn core_pvs() -> Registry {
    let mut reg = Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
    reg
}

fn s(x: &str) -> Arg {
    Arg::Str(x.into())
}

/// A string argument with variables.
fn fmt(x: &str, pvs: &PvTable) -> Arg {
    Arg::Fmt(Arc::new(sip_core::pv::parse_fmt(x, pvs).unwrap()))
}

/// A request with these header lines (each ending in CRLF) and body;
/// Content-Length is computed.
fn req(first: &str, hdrs: &str, body: &str) -> String {
    format!(
        "{first}\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\nFrom: \"Alice\" <sip:alice@example.com>;tag=a1\r\n\
To: <sip:bob@example.com>\r\nCall-ID: c1@192.0.2.1\r\n{hdrs}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

const SDP: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\nc=IN IP4 192.0.2.1\r\n";

fn invite() -> String {
    req(
        "INVITE sip:+4930123@example.com;user=phone SIP/2.0",
        "CSeq: 10 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:alice@192.0.2.1:5060>\r\nX-Custom: one\r\nx-custom: two\r\nSupported: replaces, Timer\r\nContent-Type: application/sdp\r\n",
        SDP,
    )
}

fn options(ruri: &str) -> String {
    req(&format!("OPTIONS {ruri} SIP/2.0"), "CSeq: 1 OPTIONS\r\n", "")
}

fn ok_reply(cseq: &str) -> String {
    format!(
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bKp\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=a1\r\nTo: <sip:bob@example.com>;tag=b1\r\nCall-ID: c1\r\nCSeq: {cseq}\r\nContent-Length: 0\r\n\r\n"
    )
}

/// Run `f` on a Ctx for `msg` (received over UDP); also returns what was
/// sent (replies).
fn with<R>(msg: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> (R, Vec<String>) {
    let net = Capture::default();
    let arena = Bump::new();
    let mut m = sip_parser::Msg::parse(msg.as_bytes(), &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let r = {
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &net, None, Dest::new(Proto::Udp, SocketAddr::from(([192, 0, 2, 1], 5060))), 0);
        f(&mut ctx)
    };
    (r, net.0.into_inner().unwrap())
}

/// Call exported function `name`.
fn call(reg: &Registry, ctx: &mut Ctx<'_, '_>, name: &str, a: &[Arg]) -> i32 {
    let e = reg.get(name).unwrap_or_else(|| panic!("no function {name}"));
    let fixed = (e.fixup)(a).unwrap_or_else(|err| panic!("{name}: {err}"));
    (e.func)(ctx, &*fixed)
}

fn fixup_fails(reg: &Registry, name: &str, a: &[Arg]) -> bool {
    (reg.get(name).unwrap().fixup)(a).is_err()
}

/// One call on `msg`: its return code and the message as it would be sent.
fn apply(reg: &Registry, msg: &str, name: &str, a: &[Arg]) -> (i32, String) {
    with(msg, |ctx| {
        let rc = call(reg, ctx, name, a);
        (rc, String::from_utf8_lossy(ctx.render()).into_owned())
    })
    .0
}

/// Just the return code.
fn rc_of(reg: &Registry, msg: &str, name: &str, a: &[Arg]) -> i32 {
    apply(reg, msg, name, a).0
}

/// The header lines of a rendered message.
fn header_lines(m: &str) -> Vec<&str> {
    let head = m.split_once("\r\n\r\n").map_or(m, |(h, _)| h);
    head.split("\r\n").skip(1).collect()
}

fn body_of(m: &str) -> &str {
    m.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

fn content_length(m: &str) -> Option<usize> {
    header_lines(m).iter().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|v| v.trim().parse().ok())
}

// ------------------------------------------------------------- helpers

#[test]
fn sed_repl_converts_kamailio_replacements() {
    let cases: &[(&str, &str)] = &[
        ("plain", "plain"),
        (r"\1", "${1}"),
        (r"a\1b\2c", "a${1}b${2}c"),
        (r"\0", "${0}"),
        ("$", "$$"),
        ("$1", "$$1"),
        (r"\n\r\t", "\n\r\t"),
        (r"\\", "\\"),
        (r"\/", "/"),
        ("trailing\\", "trailing\\"),
        ("", ""),
    ];
    for &(input, want) in cases {
        assert_eq!(sed_repl(input), want, "{input:?}");
    }
}

#[test]
fn subst_parse_accepts_any_delimiter_and_flags() {
    let t = PvTable::new();
    // (expression, matches, global, case-insensitive probe)
    let ok: &[(&str, &str, bool)] = &[
        ("/a/b/", "a", false),
        ("/a/b/g", "a", true),
        ("/A/b/i", "a", false),
        ("/A/b/gi", "xa", true),
        ("|x|y|", "x", false),
        (r"#a\#b#c#", "a#b", false),
        (r"/a\/b/c/", "a/b", false),
        (r"/a\.b/c/", "a.b", false),
    ];
    for &(expr, probe, global) in ok {
        let sb = Subst::parse(expr, &t).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert_eq!(sb.global, global, "{expr}");
        assert!(sb.re.is_match(probe.as_bytes()), "{expr} on {probe}");
    }
    assert!(!Subst::parse(r"/a\.b/c/", &t).unwrap().re.is_match(b"axb"), "an escaped dot stays a literal dot");
    assert!(!Subst::parse("/A/b/", &t).unwrap().re.is_match(b"a"), "case-sensitive without i");
    for bad in ["", "/a/b", "/a", "/a/b/c/d", "/(/b/"] {
        assert!(Subst::parse(bad, &t).is_err(), "{bad:?}");
    }
}

#[test]
fn subst_apply_replaces_first_or_all_with_groups() {
    let t = PvTable::new();
    let cases: &[(&str, &str, Option<&str>)] = &[
        (r"/o/0/", "foo boo", Some("f0o boo")),
        (r"/o/0/g", "foo boo", Some("f00 b00")),
        (r"/^sip:(.*)@old\.com/sip:\1@new.com/", "sip:bob@old.com", Some("sip:bob@new.com")),
        (r"/(\w+)@(\w+)/\2@\1/", "bob@host", Some("host@bob")),
        (r"/x/y/", "abc", None),
        ("/a/$$/", "a", Some("$")),
    ];
    for &(expr, input, want) in cases {
        let sb = Subst::parse(expr, &t).unwrap();
        let got = with(&options("sip:x@y"), |ctx| sb.apply(ctx, input.as_bytes())).0;
        assert_eq!(got.as_deref().map(String::from_utf8_lossy).as_deref(), want, "{expr} on {input}");
    }
}

#[test]
fn subst_replacement_may_use_variables() {
    let pvs = core_pvs();
    let sb = Subst::from_arg(&fmt("/^(.*)$/$rU-\\1/", pvs.pvs())).unwrap();
    let got = with(&options("sip:alice@x"), |ctx| sb.apply(ctx, b"tail")).0;
    assert_eq!(got.as_deref(), Some(&b"alice-tail"[..]));
    assert!(Subst::from_arg(&fmt("/$rU/x/", pvs.pvs())).is_err(), "variables only in the replacement");
    assert!(Subst::from_arg(&Arg::Int(3)).is_err());
}

#[test]
fn http_date_formats_rfc7231_dates() {
    let cases: &[(u64, &str)] = &[
        (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
        (86_399, "Thu, 01 Jan 1970 23:59:59 GMT"),
        (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
        (978_220_800, "Sun, 31 Dec 2000 00:00:00 GMT"),
        (2_147_483_647, "Tue, 19 Jan 2038 03:14:07 GMT"),
        (4_102_444_800, "Fri, 01 Jan 2100 00:00:00 GMT"),
        (1_709_210_096, "Thu, 29 Feb 2024 12:34:56 GMT"),
    ];
    for &(secs, want) in cases {
        assert_eq!(http_date(secs), want, "{secs}");
    }
    // No panic at the end of u64.
    assert!(http_date(u64::MAX).ends_with(" GMT"));
}

#[test]
fn header_names_match_full_and_compact_forms() {
    let m = "OPTIONS sip:a@b SIP/2.0\r\nv: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\nf: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\n\
i: abc\r\nCSeq: 1 OPTIONS\r\nm: <sip:a@h>\r\nx-custom: 1\r\nX-Customer: 2\r\nk: timer\r\nl: 0\r\n\r\n";
    // (pattern, a header name in the message, matches)
    let cases: &[(&str, &str, bool)] = &[
        ("From", "f", true),
        ("f", "f", true),
        ("FROM", "f", true),
        ("t", "To", true),
        ("Via", "v", true),
        ("Call-ID", "i", true),
        ("Contact", "m", true),
        ("Content-Length", "l", true),
        ("X-Custom", "x-custom", true),
        ("X-Custom", "X-Customer", false),
        ("To", "f", false),
        // Compact forms the parser doesn't classify match by name only.
        ("Supported", "k", false),
        ("k", "k", true),
    ];
    for &(pattern, name, want) in cases {
        let hit = with(m, |ctx| {
            ctx.msg.parse_headers(HdrFlags::EOH).unwrap();
            let h = HdrMatch::new(pattern);
            let named: Vec<_> = ctx.msg.headers.iter().filter(|x| x.name == name.as_bytes()).collect();
            assert_eq!(named.len(), 1, "{name}");
            named.iter().any(|x| h.matches(x))
        })
        .0;
        assert_eq!(hit, want, "{pattern} vs {name}");
    }
}

// ----------------------------------------------------- textops: headers

#[test]
fn is_present_hf_finds_headers_by_name_or_compact_form() {
    let reg = registry();
    let m = invite();
    let cases: &[(&str, i32)] =
        &[("Via", 1), ("v", 1), ("from", 1), ("X-Custom", 1), ("X-CUSTOM", 1), ("Contact", 1), ("m", 1), ("X-Missing", -1), ("Route", -1)];
    for &(name, want) in cases {
        assert_eq!(rc_of(&reg, &m, "is_present_hf", &[s(name)]), want, "{name}");
    }
    let cases: &[(&str, i32)] = &[("^X-", 1), ("^x-cust", 1), ("^Supp", 1), ("^Y-", -1), ("^Custom", -1)];
    for &(re, want) in cases {
        assert_eq!(rc_of(&reg, &m, "is_present_hf_re", &[s(re)]), want, "{re}");
    }
}

#[test]
fn append_and_insert_hf_place_lines_and_add_crlf() {
    let reg = registry();
    let m = options("sip:a@b");
    // (function, args, rc, header lines after)
    let base = [
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1",
        "From: \"Alice\" <sip:alice@example.com>;tag=a1",
        "To: <sip:bob@example.com>",
        "Call-ID: c1@192.0.2.1",
        "CSeq: 1 OPTIONS",
        "Content-Length: 0",
    ];
    let with_at = |i: usize, l: &'static str| {
        let mut v: Vec<&str> = base.to_vec();
        v.insert(i, l);
        v
    };
    let cases: Vec<(&str, Vec<Arg>, i32, Vec<&str>)> = vec![
        ("append_hf", vec![s("X-A: 1")], 1, with_at(6, "X-A: 1")),
        ("append_hf", vec![s("X-A: 1\r\n")], 1, with_at(6, "X-A: 1")),
        ("append_hf", vec![s("X-A: 1\n")], 1, with_at(6, "X-A: 1")),
        ("append_hf", vec![s("X-A: 1"), s("From")], 1, with_at(2, "X-A: 1")),
        ("append_hf", vec![s("X-A: 1"), s("f")], 1, with_at(2, "X-A: 1")),
        ("append_hf", vec![s("X-A: 1"), s("X-None")], -1, base.to_vec()),
        ("insert_hf", vec![s("X-A: 1")], 1, with_at(0, "X-A: 1")),
        ("insert_hf", vec![s("X-A: 1"), s("Call-ID")], 1, with_at(3, "X-A: 1")),
        ("insert_hf", vec![s("X-A: 1"), s("X-None")], -1, base.to_vec()),
    ];
    for (f, a, want_rc, want) in cases {
        let (rc, out) = apply(&reg, &m, f, &a);
        assert_eq!((rc, header_lines(&out)), (want_rc, want), "{f}({a:?})");
    }
}

#[test]
fn append_urihf_wraps_the_ruri() {
    let reg = registry();
    let (rc, out) = apply(&reg, &options("sip:bob@example.com"), "append_urihf", &[s("CC-Diversion: <"), s(">")]);
    assert_eq!(rc, 1);
    assert_eq!(header_lines(&out).last(), Some(&"CC-Diversion: <sip:bob@example.com>"));
}

#[test]
fn remove_hf_family_returns_the_number_removed() {
    let reg = registry();
    let m = invite();
    // (function, args, rc, removed header names)
    let cases: &[(&str, &[&str], i32, &[&str])] = &[
        ("remove_hf", &["X-Custom"], 2, &["X-Custom", "x-custom"]),
        ("remove_hf", &["f"], 1, &["From"]),
        ("remove_hf", &["Supported"], 1, &["Supported"]),
        ("remove_hf", &["Route"], -1, &[]),
        ("remove_hf_re", &["^x-"], 2, &["X-Custom", "x-custom"]),
        ("remove_hf_re", &["^(Supported|Contact)$"], 2, &["Contact", "Supported"]),
        ("remove_hf_re", &["^Q"], -1, &[]),
        ("remove_hf_exp", &["^(X-|Supported)", "^Supp"], 2, &["X-Custom", "x-custom"]),
        ("remove_hf_exp", &["^X-", "^X-"], -1, &[]),
    ];
    let names = |m: &str| -> Vec<String> { header_lines(m).iter().map(|l| l.split(':').next().unwrap_or_default().to_string()).collect() };
    let before = names(&m);
    for &(f, a, want_rc, gone) in cases {
        let args: Vec<Arg> = a.iter().map(|x| s(x)).collect();
        let (rc, out) = apply(&reg, &m, f, &args);
        let want: Vec<String> = before.iter().filter(|n| !gone.contains(&n.as_str())).cloned().collect();
        assert_eq!((rc, names(&out)), (want_rc, want), "{f}{a:?}");
    }
}

#[test]
fn search_functions_match_message_body_and_headers() {
    let reg = registry();
    let m = invite();
    let cases: &[(&str, &[&str], i32)] = &[
        ("search", &["^INVITE "], 1),
        ("search", &["c=IN IP4"], 1),
        ("search", &["^BYE"], -1),
        ("search_body", &["^v=0"], 1),
        ("search_body", &["Call-ID"], -1),
        ("search_hf", &["X-Custom", "^one$"], 1),
        ("search_hf", &["X-Custom", "^two$"], 1),
        ("search_hf", &["X-Custom", "^two$", "a"], 1),
        ("search_hf", &["X-Custom", "^one$", "f"], 1),
        ("search_hf", &["X-Custom", "^two$", "f"], -1),
        ("search_hf", &["X-Custom", "^two$", "l"], 1),
        ("search_hf", &["X-Custom", "^one$", "l"], -1),
        ("search_hf", &["f", "tag=a1"], 1),
        ("search_hf", &["X-None", "."], -1),
    ];
    for &(f, a, want) in cases {
        let args: Vec<Arg> = a.iter().map(|x| s(x)).collect();
        assert_eq!(rc_of(&reg, &m, f, &args), want, "{f}{a:?}");
    }
    assert_eq!(rc_of(&reg, &options("sip:a@b"), "search_body", &[s(".")]), -1, "no body");
    assert!(fixup_fails(&reg, "search", &[s("(")]));
    assert!(fixup_fails(&reg, "search_hf", &[s("X"), s("a"), s("f"), s("x")]));
}

#[test]
fn search_append_inserts_after_the_first_match() {
    let reg = registry();
    let (rc, out) = apply(&reg, &options("sip:a@b"), "search_append", &[s("tag=a1"), s(";x=1")]);
    assert_eq!(rc, 1);
    assert!(out.contains("From: \"Alice\" <sip:alice@example.com>;tag=a1;x=1\r\n"), "{out}");
    assert_eq!(rc_of(&reg, &options("sip:a@b"), "search_append", &[s("nomatch"), s("x")]), -1);
}

#[test]
fn replace_and_replace_all_rewrite_the_message_with_groups() {
    let reg = registry();
    let m = options("sip:a@b");
    let (rc, out) = apply(&reg, &m, "replace", &[s("example\\.com"), s("example.net")]);
    assert_eq!(rc, 1);
    assert_eq!(out.matches("example.net").count(), 1);
    let (rc, out) = apply(&reg, &m, "replace_all", &[s("example\\.com"), s("example.net")]);
    assert_eq!(rc, 2, "one per match");
    assert!(!out.contains("example.com"));
    let (rc, out) = apply(&reg, &m, "replace", &[s("<sip:(\\w+)@"), s("<sip:\\1-x@")]);
    assert_eq!(rc, 1);
    assert!(out.contains("<sip:alice-x@example.com>"), "{out}");
    assert_eq!(rc_of(&reg, &m, "replace_all", &[s("nomatch"), s("x")]), -1);
}

#[test]
fn subst_family_edits_headers_ruri_user_body_and_one_header() {
    let reg = registry();
    let m = invite();
    // subst: header part only, first match unless g.
    let (rc, out) = apply(&reg, &m, "subst", &[s("/192\\.0\\.2\\.1/203.0.113.9/")]);
    assert_eq!(rc, 1);
    assert_eq!(out.matches("203.0.113.9").count(), 1);
    let (rc, out) = apply(&reg, &m, "subst", &[s("/192\\.0\\.2\\.1/203.0.113.9/g")]);
    assert_eq!(rc, 3, "Via, Call-ID and Contact; the SDP body is left alone");
    assert_eq!(body_of(&out), SDP);
    assert_eq!(rc_of(&reg, &m, "subst", &[s("/nomatch/x/")]), -1);
    // subst_uri / subst_user: the R-URI.
    let (rc, out) = apply(&reg, &m, "subst_uri", &[s("/^sip:\\+49(.*)@example\\.com/sip:0\\1@gw.example.com/")]);
    assert_eq!(rc, 1);
    assert!(out.starts_with("INVITE sip:030123@gw.example.com;user=phone SIP/2.0\r\n"), "{out}");
    let (rc, out) = apply(&reg, &m, "subst_user", &[s("/^\\+49/0/")]);
    assert_eq!(rc, 1);
    assert!(out.starts_with("INVITE sip:030123@example.com;user=phone SIP/2.0\r\n"), "{out}");
    assert_eq!(rc_of(&reg, &m, "subst_user", &[s("/^\\+1/0/")]), -1);
    // subst_body: Content-Length follows.
    let (rc, out) = apply(&reg, &m, "subst_body", &[s("/IP4 192\\.0\\.2\\.1/IP4 203.0.113.99/g")]);
    assert_eq!(rc, 1);
    let body = body_of(&out);
    assert_eq!(body, "v=0\r\no=- 1 1 IN IP4 203.0.113.99\r\nc=IN IP4 203.0.113.99\r\n");
    assert_eq!(content_length(&out), Some(body.len()));
    // subst_hf: the first header of that name only.
    let (rc, out) = apply(&reg, &m, "subst_hf", &[s("X-Custom"), s("/^.*$/changed/")]);
    assert_eq!(rc, 1);
    assert!(out.contains("X-Custom: changed\r\nx-custom: two\r\n"), "{out}");
    assert_eq!(rc_of(&reg, &m, "subst_hf", &[s("X-None"), s("/a/b/")]), -1);
    // Kamailio's ignored third argument is accepted; too many is not.
    assert!(!fixup_fails(&reg, "subst", &[s("/a/b/"), s("x")]));
    assert!(fixup_fails(&reg, "subst", &[s("/a/b/"), s("x"), s("y")]));
    assert!(fixup_fails(&reg, "subst_hf", &[s("/a/b/")]));
    assert!(fixup_fails(&reg, "subst", &[s("/a/b")]));
}

// -------------------------------------------------------- textops: body

#[test]
fn body_replacements_fix_content_length() {
    let reg = registry();
    let m = invite();
    let cases: &[(&str, &str, &str, i32, &str)] = &[
        ("replace_body", "192\\.0\\.2\\.1", "10.0.0.1", 1, "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\nc=IN IP4 192.0.2.1\r\n"),
        ("replace_body_all", "192\\.0\\.2\\.1", "10.0.0.1", 1, "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\nc=IN IP4 10.0.0.1\r\n"),
        ("replace_body_atonce", "IP4 (\\S+)", "IP4 [\\1]", 1, "v=0\r\no=- 1 1 IN IP4 [192.0.2.1]\r\nc=IN IP4 [192.0.2.1]\r\n"),
        ("replace_body", "nomatch", "x", -1, SDP),
    ];
    for &(f, re, txt, want_rc, want_body) in cases {
        let (rc, out) = apply(&reg, &m, f, &[s(re), s(txt)]);
        assert_eq!((rc, body_of(&out)), (want_rc, want_body), "{f}");
        assert_eq!(content_length(&out), Some(want_body.len()), "{f}");
    }
}

#[test]
fn set_body_and_remove_body_update_content_type_and_length() {
    let reg = registry();
    let (rc, out) = apply(&reg, &options("sip:a@b"), "set_body", &[s("hello"), s("text/plain")]);
    assert_eq!(rc, 1);
    assert_eq!(body_of(&out), "hello");
    assert_eq!(content_length(&out), Some(5));
    assert!(header_lines(&out).contains(&"Content-Type: text/plain"), "{out}");
    let (rc, out) = apply(&reg, &invite(), "remove_body", &[]);
    assert_eq!(rc, 1);
    assert_eq!(body_of(&out), "");
    assert_eq!(content_length(&out), Some(0));
    assert!(!out.contains("Content-Type"), "{out}");
    assert_eq!(rc_of(&reg, &options("sip:a@b"), "remove_body", &[]), -1, "no body to remove");
}

#[test]
fn has_body_checks_presence_and_content_type() {
    let reg = registry();
    let cases: &[(&[&str], i32)] = &[(&[], 1), (&["application/sdp"], 1), (&["APPLICATION/SDP"], 1), (&["text/plain"], -1)];
    for &(a, want) in cases {
        let args: Vec<Arg> = a.iter().map(|x| s(x)).collect();
        assert_eq!(rc_of(&reg, &invite(), "has_body", &args), want, "{a:?}");
    }
    let with_params = req("MESSAGE sip:a@b SIP/2.0", "CSeq: 1 MESSAGE\r\nContent-Type: text/plain; charset=utf-8\r\n", "hi");
    assert_eq!(rc_of(&reg, &with_params, "has_body", &[s("text/plain")]), 1);
    let compact = req("MESSAGE sip:a@b SIP/2.0", "CSeq: 1 MESSAGE\r\nc: text/plain\r\n", "hi");
    assert_eq!(rc_of(&reg, &compact, "has_body", &[s("text/plain")]), 1, "compact Content-Type");
    assert_eq!(rc_of(&reg, &options("sip:a@b"), "has_body", &[]), -1);
    assert_eq!(rc_of(&reg, &options("sip:a@b"), "has_body", &[s("application/sdp")]), -1);
    // After remove_body() in the same route: no body.
    let rc = with(&invite(), |ctx| {
        assert_eq!(call(&reg, ctx, "remove_body", &[]), 1);
        call(&reg, ctx, "has_body", &[])
    })
    .0;
    assert_eq!(rc, -1);
    assert!(fixup_fails(&reg, "has_body", &[s("a"), s("b")]));
}

#[test]
fn is_method_on_requests_and_replies() {
    let reg = registry();
    let cases: Vec<(String, &str, i32)> = vec![
        (invite(), "INVITE", 1),
        (invite(), "invite", 1),
        (invite(), "BYE|INVITE", 1),
        (invite(), "BYE | invite", 1),
        (invite(), "BYE|CANCEL", -1),
        (invite(), "INV", -1),
        (options("sip:a@b"), "OPTIONS", 1),
        (req("FOO sip:a@b SIP/2.0", "CSeq: 1 FOO\r\n", ""), "FOO", 1),
        // A reply: its CSeq method.
        (ok_reply("5 INVITE"), "INVITE", 1),
        (ok_reply("5 BYE"), "INVITE|BYE", 1),
        (ok_reply("5 BYE"), "INVITE", -1),
    ];
    for (m, methods, want) in cases {
        assert_eq!(rc_of(&reg, &m, "is_method", &[s(methods)]), want, "{methods} on {}", m.lines().next().unwrap_or_default());
    }
}

#[test]
fn string_helpers() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, &str, i32)] = &[
        ("starts_with", "+4930123", "+49", 1),
        ("starts_with", "+4930123", "49", -1),
        ("starts_with", "abc", "", 1),
        ("cmp_str", "abc", "abc", 1),
        ("cmp_str", "abc", "ABC", -1),
        ("cmp_istr", "abc", "ABC", 1),
        ("cmp_istr", "abc", "abd", -1),
        ("str_find", "hello world", "world", 7),
        ("str_find", "hello", "h", 1),
        ("str_find", "hello", "x", -1),
    ];
    for &(f, a, b, want) in cases {
        assert_eq!(rc_of(&reg, &m, f, &[s(a), s(b)]), want, "{f}({a:?}, {b:?})");
    }
}

#[test]
fn fnmatch_globs() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, i32)] = &[
        ("+4930123", "+49*", 1),
        ("+4430123", "+49*", -1),
        ("abc", "a?c", 1),
        ("abc", "a[b-d]c", 1),
        ("aec", "a[!b-d]c", 1),
        ("acc", "a[!b-d]c", -1),
        ("abc", "a[bc", -1),
        ("", "*", 1),
        ("x", "", -1),
    ];
    for &(v, p, want) in cases {
        assert_eq!(rc_of(&reg, &m, "fnmatch", &[s(v), s(p)]), want, "{v:?} ~ {p:?}");
    }
    assert!(fixup_fails(&reg, "fnmatch", &[s("a")]));
    assert!(!fixup_fails(&reg, "fnmatch", &[s("a"), s("b"), s("i")]));
}

// --------------------------------------------------------------- textopsx

#[test]
fn change_reply_status_rewrites_only_replies() {
    let reg = registry();
    let (rc, out) = apply(&reg, &ok_reply("1 INVITE"), "change_reply_status", &[Arg::Int(486), s("Busy Here")]);
    assert_eq!(rc, 1);
    assert!(out.starts_with("SIP/2.0 486 Busy Here\r\nVia: "), "{out}");
    assert_eq!(rc_of(&reg, &ok_reply("1 INVITE"), "change_reply_status", &[Arg::Int(99), s("x")]), -1);
    assert_eq!(rc_of(&reg, &ok_reply("1 INVITE"), "change_reply_status", &[Arg::Int(700), s("x")]), -1);
    assert_eq!(rc_of(&reg, &invite(), "change_reply_status", &[Arg::Int(486), s("x")]), -1);
}

#[test]
fn keep_hf_keeps_mandatory_and_matching_headers() {
    let reg = registry();
    let (rc, out) = apply(&reg, &invite(), "keep_hf", &[s("^x-")]);
    assert_eq!(rc, 1);
    let names: Vec<&str> = header_lines(&out).iter().map(|l| l.split(':').next().unwrap_or_default()).collect();
    assert_eq!(
        names,
        ["Via", "From", "To", "Call-ID", "CSeq", "Max-Forwards", "Contact", "X-Custom", "x-custom", "Content-Type", "Content-Length"],
        "Supported is the only one removed"
    );
}

// -------------------------------------------------------------- siputils

#[test]
fn has_totag_and_is_first_hop() {
    let reg = registry();
    assert_eq!(rc_of(&reg, &invite(), "has_totag", &[]), -1);
    assert_eq!(rc_of(&reg, &ok_reply("1 INVITE"), "has_totag", &[]), 1);
    let empty_tag = invite().replace("To: <sip:bob@example.com>", "To: <sip:bob@example.com>;tag=");
    assert_eq!(rc_of(&reg, &empty_tag, "has_totag", &[]), -1, "an empty tag is no tag");
    let cases: Vec<(String, i32)> = vec![
        (invite(), 1),
        (
            invite().replace(
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
                "Via: SIP/2.0/UDP p;branch=z9hG4bKp\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
            ),
            -1,
        ),
        (invite().replace("branch=z9hG4bK1\r\n", "branch=z9hG4bK1, SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK2\r\n"), -1),
        // A reply to our own first-hop request has two Via values.
        (ok_reply("1 INVITE"), 1),
    ];
    for (m, want) in cases {
        assert_eq!(rc_of(&reg, &m, "is_first_hop", &[]), want, "{m}");
    }
}

#[test]
fn number_helpers() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, i32)] = &[
        ("is_e164", "+4930123456", 1),
        ("is_e164", "+12", 1),
        ("is_e164", "+1", -1),
        ("is_e164", "+123456789012345", 1),
        ("is_e164", "+1234567890123456", -1),
        ("is_e164", "4930123456", -1),
        ("is_e164", "+49 30", -1),
        ("is_e164", "+", -1),
        ("is_e164", "", -1),
        ("is_numeric", "0123", 1),
        ("is_numeric", "", -1),
        ("is_numeric", "+1", -1),
        ("is_numeric", "١٢", -1),
        ("is_alphanum", "abc123", 1),
        ("is_alphanum", "abc-123", -1),
        ("is_alphanum", "", -1),
        ("is_alphanum", "ä", -1),
        ("is_uri_user_e164", "sip:+4930123@example.com", 1),
        ("is_uri_user_e164", "sip:4930123@example.com", -1),
        ("is_uri_user_e164", "sip:example.com", -1),
        ("is_uri_user_e164", "not a uri", -1),
    ];
    for &(f, v, want) in cases {
        assert_eq!(rc_of(&reg, &m, f, &[s(v)]), want, "{f}({v:?})");
    }
}

#[test]
fn ruri_helpers() {
    let reg = registry();
    let m = invite();
    assert_eq!(rc_of(&reg, &m, "is_user", &[s("+4930123")]), 1);
    assert_eq!(rc_of(&reg, &m, "is_user", &[s("4930123")]), -1);
    assert_eq!(rc_of(&reg, &options("sip:example.com"), "is_user", &[s("")]), -1, "no user part");
    let cases: &[(&[&str], i32)] = &[(&["user"], 1), (&["user", "phone"], 1), (&["user", "ip"], -1), (&["transport"], -1)];
    for &(a, want) in cases {
        let args: Vec<Arg> = a.iter().map(|x| s(x)).collect();
        assert_eq!(rc_of(&reg, &m, "uri_param", &args), want, "{a:?}");
    }
    assert!(fixup_fails(&reg, "uri_param", &[]));
    let (rc, out) = apply(&reg, &options("sip:bob@example.com"), "add_uri_param", &[s("transport=tcp")]);
    assert_eq!(rc, 1);
    assert!(out.starts_with("OPTIONS sip:bob@example.com;transport=tcp SIP/2.0\r\n"), "{out}");
}

#[test]
fn cmp_uri_and_cmp_aor() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, &str, i32)] = &[
        ("cmp_uri", "sip:bob@example.com", "sip:bob@EXAMPLE.COM", 1),
        ("cmp_uri", "SIP:bob@example.com", "sip:bob@example.com", 1),
        ("cmp_uri", "sip:bob@example.com", "sip:Bob@example.com", -1),
        ("cmp_uri", "sip:bob@example.com", "sip:bob@example.com:5060", -1),
        ("cmp_uri", "sip:bob@example.com;transport=TCP", "sip:bob@example.com;transport=tcp", 1),
        ("cmp_uri", "sip:bob@example.com;transport=tcp", "sip:bob@example.com", -1),
        ("cmp_uri", "sip:bob@example.com;foo=1", "sip:bob@example.com;foo=2", 1),
        ("cmp_uri", "sip:bob@example.com;user=phone", "sip:bob@example.com", -1),
        ("cmp_uri", "garbage", "garbage", -1),
        ("cmp_aor", "sip:bob@example.com;transport=tcp", "sip:bob@EXAMPLE.com:5070", 1),
        ("cmp_aor", "sip:bob@example.com", "sip:alice@example.com", -1),
        ("cmp_aor", "garbage", "garbage", -1),
    ];
    for &(f, a, b, want) in cases {
        assert_eq!(rc_of(&reg, &m, f, &[s(a), s(b)]), want, "{f}({a}, {b})");
    }
}

#[test]
fn request_reply_and_supported_predicates() {
    let reg = registry();
    assert_eq!(rc_of(&reg, &invite(), "is_request", &[]), 1);
    assert_eq!(rc_of(&reg, &invite(), "is_reply", &[]), -1);
    assert_eq!(rc_of(&reg, &ok_reply("1 INVITE"), "is_request", &[]), -1);
    assert_eq!(rc_of(&reg, &ok_reply("1 INVITE"), "is_reply", &[]), 1);
    let cases: &[(&str, i32)] = &[("replaces", 1), ("timer", 1), ("TIMER", 1), ("100rel", -1), ("time", -1)];
    for &(opt, want) in cases {
        assert_eq!(rc_of(&reg, &invite(), "is_supported", &[s(opt)]), want, "{opt}");
    }
    let compact = options("sip:a@b").replace("CSeq:", "k: 100rel\r\nCSeq:");
    assert_eq!(rc_of(&reg, &compact, "is_supported", &[s("100rel")]), 1, "compact Supported (k)");
}

#[test]
fn options_reply_answers_options_to_the_proxy_only() {
    let reg = registry();
    let (rc, sent) = with(&options("sip:proxy.example.com"), |ctx| call(&reg, ctx, "options_reply", &[]));
    assert_eq!(rc, 1);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].starts_with("SIP/2.0 200 OK\r\n"), "{}", sent[0]);
    assert!(sent[0].contains("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE"), "{}", sent[0]);
    for m in [options("sip:bob@proxy.example.com"), invite()] {
        let (rc, sent) = with(&m, |ctx| call(&reg, ctx, "options_reply", &[]));
        assert_eq!((rc, sent.len()), (-1, 0));
    }
}

#[test]
fn tel2sip_converts_tel_uris() {
    let reg = registry();
    let pvs = core_pvs();
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("tel:+49-30-123", "example.com", Some("sip:+4930123@example.com;user=phone")),
        ("tel:+1(555)123.4567;ext=9", "sip:gw.example.com", Some("sip:+15551234567;ext=9@gw.example.com;user=phone")),
        ("TEL:123", "h", Some("sip:123@h;user=phone")),
        ("sip:+49@x", "h", None),
    ];
    for &(uri, host, want) in cases {
        let out = fmt("$var(out)", pvs.pvs());
        let (rc, val) = with(&options("sip:a@b"), |ctx| {
            let rc = call(&reg, ctx, "tel2sip", &[s(uri), s(host), out.clone()]);
            let v = sip_core::pv::parse_pv("$var(out)", pvs.pvs()).unwrap().get(ctx);
            (rc, v)
        })
        .0;
        match want {
            Some(w) => assert_eq!((rc, val), (1, Val::Str(w.into())), "{uri}"),
            None => assert_eq!(rc, -1, "{uri}"),
        }
    }
    assert!(fixup_fails(&reg, "tel2sip", &[s("tel:1"), s("h"), s("not a variable")]));
}

// ---------------------------------------------------------------- sanity

/// `sanity_check(checks, uri_checks)` on `msg`: the return code and the
/// status line of the reply sent, if any.
fn sanity(reg: &Registry, msg: &str, checks: i64, uri_checks: i64) -> (i32, Option<String>) {
    let (rc, sent) = with(msg, |ctx| call(reg, ctx, "sanity_check", &[Arg::Int(checks), Arg::Int(uri_checks)]));
    (rc, sent.first().map(|r| r.lines().next().unwrap_or_default().to_string()))
}

#[test]
fn a_well_formed_request_passes_every_check() {
    let reg = registry();
    for m in [invite(), options("sip:a@b"), options("tel:+4930123"), options("sips:a@b"), options("urn:service:sos")] {
        assert_eq!(sanity(&reg, &m, 0x1FFF, 15), (1, None), "{m}");
    }
    assert_eq!(sanity(&reg, &ok_reply("1 INVITE"), 0x1FFF, 15), (1, None));
}

#[test]
fn each_sanity_check_rejects_what_it_should() {
    let reg = registry();
    let inv = invite();
    let opt = options("sip:a@b");
    // (check bit, uri_checks, message, expected status line)
    let cases: Vec<(i64, i64, String, &str)> = vec![
        (2, 0, options("http://a/b"), "SIP/2.0 416 Unsupported URI Scheme in Request URI"),
        (4, 0, opt.replace("Call-ID: c1@192.0.2.1\r\n", ""), "SIP/2.0 400 Missing Required Header in Request"),
        (4, 0, opt.replace("CSeq: 1 OPTIONS\r\n", ""), "SIP/2.0 400 Missing Required Header in Request"),
        (16, 0, opt.replace("SIP/2.0/UDP 192.0.2.1", "SIP/2.0/FOO 192.0.2.1"), "SIP/2.0 400 Transport Mismatch (Via)"),
        (64, 0, opt.replace("CSeq: 1 OPTIONS", "CSeq: x OPTIONS"), "SIP/2.0 400 CSeq number is illegal"),
        (64, 0, opt.replace("CSeq: 1 OPTIONS", "CSeq: 4294967296 OPTIONS"), "SIP/2.0 400 CSeq number is illegal"),
        (32, 0, opt.replace("CSeq: 1 OPTIONS", "CSeq: 1 INVITE"), "SIP/2.0 400 CSeq method does not match request method"),
        (128, 0, inv.replace(&format!("Content-Length: {}", SDP.len()), "Content-Length: 5"), "SIP/2.0 400 Content-Length mis-match"),
        (256, 0, opt.replace("CSeq:", "Expires: soon\r\nCSeq:"), "SIP/2.0 400 Expires value is illegal"),
        (256, 0, opt.replace("CSeq:", "Expires: -1\r\nCSeq:"), "SIP/2.0 400 Expires value is illegal"),
        (512, 0, opt.replace("CSeq:", "Proxy-Require: foo\r\nCSeq:"), "SIP/2.0 420 Bad Extension"),
        (1024, 2, opt.replace("<sip:alice@example.com>", "<bogus>"), "SIP/2.0 400 Bad From URI"),
        (1024, 4, opt.replace("<sip:bob@example.com>", "<bogus>"), "SIP/2.0 400 Bad To URI"),
        (1024, 8, opt.replace("CSeq:", "Contact: <bogus>\r\nCSeq:"), "SIP/2.0 400 Bad Contact URI"),
        (2048, 0, opt.replace("CSeq:", "Authorization: Digest realm=\"x\"\r\nCSeq:"), "SIP/2.0 400 Bad Credentials"),
        (2048, 0, opt.replace("CSeq:", "Proxy-Authorization: Digest username=\"a\"\r\nCSeq:"), "SIP/2.0 400 Bad Credentials"),
        (4096, 0, opt.replace(";tag=a1", ";tag=a1;tag=a2"), "SIP/2.0 400 Multiple tags"),
    ];
    for (bit, uri_checks, m, want) in cases {
        assert_eq!(sanity(&reg, &m, bit, uri_checks), (0, Some(want.to_string())), "check {bit}: {m}");
        // The other checks don't look at it.
        assert_eq!(sanity(&reg, &m, 0x1FFF & !bit, 0).0, 1, "only check {bit} fails: {m}");
    }
}

#[test]
fn sanity_accepts_the_valid_variants() {
    let reg = registry();
    let opt = options("sip:a@b");
    let cases: Vec<(i64, i64, String)> = vec![
        (16, 0, opt.replace("SIP/2.0/UDP", "SIP/2.0/tcp")),
        (16, 0, opt.replace("SIP/2.0/UDP", "SIP/2.0/WSS")),
        (256, 0, opt.replace("CSeq:", "Expires: 3600\r\nCSeq:")),
        (512, 0, opt.replace("CSeq:", "Proxy-Require: \r\nCSeq:")),
        (1024, 8, opt.replace("CSeq:", "Contact: *\r\nCSeq:")),
        (1024, 8, opt.replace("CSeq:", "Contact: <sip:a@h>, \"B\" <sip:b@h>;q=0.5\r\nCSeq:")),
        (2048, 0, opt.replace("CSeq:", "Authorization: Digest username=\"a\", realm=\"x\", response=\"y\"\r\nCSeq:")),
        (2048, 0, opt.replace("CSeq:", "Authorization: Basic YTpi\r\nCSeq:")),
        // A reply's CSeq method is not compared with anything.
        (32, 0, ok_reply("1 BYE")),
    ];
    for (bit, uri_checks, m) in cases {
        assert_eq!(sanity(&reg, &m, bit, uri_checks), (1, None), "check {bit}: {m}");
    }
}

#[test]
fn sanity_proxy_require_reply_lists_the_unsupported_extensions() {
    let reg = registry();
    let m = options("sip:a@b").replace("CSeq:", "Proxy-Require: foo, bar\r\nCSeq:");
    let (_, sent) = with(&m, |ctx| call(&reg, ctx, "sanity_check", &[Arg::Int(512)]));
    assert!(sent[0].contains("\r\nUnsupported: foo, bar\r\n"), "{}", sent[0]);
}

#[test]
fn sanity_never_answers_acks_or_replies() {
    let reg = registry();
    let ack = req("ACK sip:a@b SIP/2.0", "CSeq: 1 INVITE\r\n", "");
    assert_eq!(sanity(&reg, &ack, 32, 0), (0, None), "the ACK fails, silently");
    let bad = ok_reply("x INVITE");
    assert_eq!(sanity(&reg, &bad, 64, 0), (0, None));
}

#[test]
fn sanity_params_select_default_checks_autodrop_and_noreply() {
    let bad = options("sip:a@b").replace("CSeq: 1 OPTIONS", "CSeq: x OPTIONS");
    let run = |params: &[(&str, i64)]| {
        let m = module("sanity").unwrap();
        for &(n, v) in params {
            m.set_param(n, &Arg::Int(v)).unwrap();
        }
        let mut reg = Registry::default();
        reg.load(m).unwrap();
        let (rc, sent) = with(&bad, |ctx| call(&reg, ctx, "sanity_check", &[]));
        (rc, sent.len())
    };
    // Default 3047 includes the CSeq value check (64).
    assert_eq!(run(&[]), (0, 1));
    assert_eq!(run(&[("default_checks", 3047 & !64)]), (1, 0));
    assert_eq!(run(&[("autodrop", 0)]), (-1, 1));
    assert_eq!(run(&[("noreply", 1)]), (0, 0));
    let m = module("sanity").unwrap();
    assert!(m.set_param("default_checks", &Arg::Int(-1)).is_err());
    assert!(m.set_param("nope", &Arg::Int(1)).is_err());
    let reg = registry();
    assert!(fixup_fails(&reg, "sanity_check", &[Arg::Int(1), Arg::Int(1), Arg::Int(1)]));
    assert!(fixup_fails(&reg, "sanity_check", &[Arg::Int(-1)]));
}

// -------------------------------------------------------------------- sl

#[test]
fn sl_send_reply_sends_with_reply_extras() {
    let reg = registry();
    let (rc, sent) = with(&invite(), |ctx| {
        assert_eq!(call(&reg, ctx, "append_to_reply", &[s("X-Why: test")]), 1);
        assert_eq!(call(&reg, ctx, "set_reply_body", &[s("busy"), s("text/plain")]), 1);
        call(&reg, ctx, "sl_send_reply", &[Arg::Int(486), s("Busy Here")])
    });
    assert_eq!(rc, 1);
    let r = &sent[0];
    assert!(r.starts_with("SIP/2.0 486 Busy Here\r\n"), "{r}");
    assert!(r.contains("\r\nX-Why: test\r\n") && r.contains("\r\nContent-Type: text/plain\r\n"), "{r}");
    assert!(r.ends_with("\r\n\r\nbusy"), "{r}");
    assert!(fixup_fails(&reg, "sl_send_reply", &[Arg::Int(99), s("x")]));
    assert!(fixup_fails(&reg, "sl_send_reply", &[Arg::Int(700), s("x")]));
    assert!(!fixup_fails(&reg, "sl_send_reply", &[Arg::Int(100), s("Trying")]));
}

#[test]
fn send_reply_error_uses_sl_reason_phrases() {
    let reg = registry();
    let (rcs, sent) = with(&invite(), |ctx| {
        let first = call(&reg, ctx, "send_reply_error", &[]);
        // After sl's own final: nothing more (-2).
        (first, call(&reg, ctx, "send_reply_error", &[]))
    });
    assert_eq!(rcs, (1, -2));
    assert_eq!(sent.len(), 1);
    assert!(sent[0].starts_with("SIP/2.0 500 I'm terribly sorry, server error occurred (1/SL)\r\n"), "{}", sent[0]);
    let (_, sent) = with(&invite(), |ctx| {
        ctx.last_error = Some(sip_core::error::TM_E_SEND);
        call(&reg, ctx, "send_reply_error", &[])
    });
    assert!(sent[0].starts_with("SIP/2.0 477 Unfortunately error on sending to next hop occurred (477/SL)\r\n"), "{}", sent[0]);
    assert_eq!(rc_of(&reg, &invite(), "sl_forward_reply", &[]), -1);
}

#[test]
fn acks_are_never_answered() {
    let reg = registry();
    let ack = req("ACK sip:a@b SIP/2.0", "CSeq: 1 ACK\r\n", "");
    let (rc, sent) = with(&ack, |ctx| call(&reg, ctx, "sl_send_reply", &[Arg::Int(404), s("Not Found")]));
    assert_eq!((rc, sent.len()), (1, 0));
}

// ----------------------------------------------------------------- ipops

#[test]
fn ip_predicates() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, i32)] = &[
        ("is_ip", "10.0.0.1", 1),
        ("is_ip", "::1", 1),
        ("is_ip", "[::1]", 1),
        ("is_ip", " 10.0.0.1 ", 1),
        ("is_ip", "10.0.0.256", -1),
        ("is_ip", "example.com", -1),
        ("is_ipv4", "10.0.0.1", 1),
        ("is_ipv4", "::1", -1),
        ("is_ipv6", "[2001:db8::1]", 1),
        ("is_ipv6", "10.0.0.1", -1),
        ("is_pure_ip", "2001:db8::1", 1),
        ("is_pure_ip", "[2001:db8::1]", -1),
        ("is_ipv6_reference", "[2001:db8::1]", 1),
        ("is_ipv6_reference", "2001:db8::1", -1),
        ("is_ipv6_reference", "[10.0.0.1]", -1),
        ("ip_type", "10.0.0.1", 1),
        ("ip_type", "::1", 2),
        ("ip_type", "[::1]", 3),
        ("ip_type", "x", -1),
        ("is_ip_rfc1918", "10.255.255.255", 1),
        ("is_ip_rfc1918", "172.15.255.255", -1),
        ("is_ip_rfc1918", "172.16.0.0", 1),
        ("is_ip_rfc1918", "172.31.255.255", 1),
        ("is_ip_rfc1918", "172.32.0.0", -1),
        ("is_ip_rfc1918", "192.168.1.1", 1),
        ("is_ip_rfc1918", "192.169.0.1", -1),
        ("is_ip_rfc1918", "fd00::1", -1),
        ("is_ip_rfc1918", "x", -1),
    ];
    for &(f, v, want) in cases {
        assert_eq!(rc_of(&reg, &m, f, &[s(v)]), want, "{f}({v:?})");
    }
}

#[test]
fn compare_ips_and_subnets() {
    let reg = registry();
    let m = options("sip:a@b");
    let cases: &[(&str, &str, &str, i32)] = &[
        ("compare_ips", "::1", "[0:0::1]", 1),
        ("compare_ips", "10.0.0.1", "10.0.0.01", -1),
        ("compare_ips", "10.0.0.1", "10.0.0.2", -1),
        ("compare_ips", "x", "x", -1),
        ("ip_is_in_subnet", "10.1.2.3", "10.0.0.0/8", 1),
        ("ip_is_in_subnet", "11.1.2.3", "10.0.0.0/8", -1),
        ("ip_is_in_subnet", "192.168.1.5", "10.0.0.0/8, 192.168.0.0/16", 1),
        ("ip_is_in_subnet", "192.168.1.5", "192.168.1.5", 1),
        ("ip_is_in_subnet", "192.168.1.5", "192.168.1.4/32", -1),
        ("ip_is_in_subnet", "192.168.1.5", "192.168.1.4/31", 1),
        ("ip_is_in_subnet", "8.8.8.8", "0.0.0.0/0", 1),
        // A prefix past the address size is the full address.
        ("ip_is_in_subnet", "10.0.0.1", "10.0.0.1/99", 1),
        ("ip_is_in_subnet", "10.0.0.1", "10.0.0.0/x", -1),
        ("ip_is_in_subnet", "2001:db8::5", "2001:db8::/32", 1),
        ("ip_is_in_subnet", "2001:db9::5", "2001:db8::/32", -1),
        ("ip_is_in_subnet", "2001:db8::5", "10.0.0.0/8", -1),
        ("ip_is_in_subnet", "::ffff:10.0.0.1", "10.0.0.0/8", -1),
        ("ip_is_in_subnet", "bogus", "10.0.0.0/8", -1),
        ("is_in_subnet", "10.1.2.3", "10.0.0.0/8", 1),
    ];
    for &(f, a, b, want) in cases {
        assert_eq!(rc_of(&reg, &m, f, &[s(a), s(b)]), want, "{f}({a}, {b})");
    }
}

// ------------------------------------------------------------ variables

#[test]
fn arguments_may_contain_variables() {
    let reg = registry();
    let pvs = core_pvs();
    let m = options("sip:alice@example.com");
    let (rc, out) = apply(&reg, &m, "append_hf", &[fmt("X-User: $rU", pvs.pvs())]);
    assert_eq!(rc, 1);
    assert!(header_lines(&out).contains(&"X-User: alice"), "{out}");
    assert_eq!(rc_of(&reg, &m, "is_user", &[fmt("$fU", pvs.pvs())]), 1, "From user is alice too");
    assert_eq!(rc_of(&reg, &m, "cmp_str", &[fmt("$rU", pvs.pvs()), s("alice")]), 1);
    // Literal-only arguments refuse variables at startup.
    assert!(fixup_fails(&reg, "is_present_hf", &[fmt("$rU", pvs.pvs())]));
    assert!(fixup_fails(&reg, "remove_hf_re", &[fmt("$rU", pvs.pvs())]));
}

#[test]
fn every_module_name_loads() {
    for n in NAMES {
        let m = module(n).unwrap_or_else(|| panic!("{n}"));
        assert_eq!(m.name(), *n);
        let mut reg = Registry::default();
        reg.load(m).unwrap_or_else(|e| panic!("{n}: {e}"));
    }
    assert!(module("tm").is_none());
}
