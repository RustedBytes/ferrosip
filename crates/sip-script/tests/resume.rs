//! Resuming a suspended script: after the block it stopped in, the script
//! goes on as if it never stopped — past an `if`, around a `while`, back
//! into the route that called the suspended one. No sockets: `susp()`
//! suspends (keeping the continuation), `mark("x")` records progress.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test helpers outside #[test] fns")]

use sip_core::{Arg, AsyncPending, Continuation, Ctx, Dest, Handler, Lumps, Outbound, Proto, Registry, RouteRunner};
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

type Marks = Arc<Mutex<Vec<String>>>;
type Slot = Arc<Mutex<Option<Continuation>>>;

fn engine(src: &str) -> (Engine, Marks, Slot) {
    let marks: Marks = Arc::default();
    let slot: Slot = Arc::default();
    let mut reg = Registry::default();
    reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap(); // $var
    let m = marks.clone();
    reg.export(
        "test",
        "mark",
        |a: &[Arg]| Ok(a[0].str()?.to_string()),
        move |_: &mut Ctx, s: &String| {
            m.lock().unwrap().push(s.clone());
            1
        },
    );
    let sl = slot.clone();
    reg.export(
        "test",
        "susp",
        |_: &[Arg]| Ok(()),
        move |ctx: &mut Ctx, _: &()| {
            let sl = sl.clone();
            ctx.ext.push(Box::new(AsyncPending(Box::new(move |c| *sl.lock().unwrap() = Some(c)))));
            0
        },
    );
    let ast = sip_script::parse(src).unwrap();
    (Engine::compile(&ast, Arc::new(reg)).unwrap(), marks, slot)
}

const MSG: &[u8] = b"OPTIONS sip:x@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bKx\r\nFrom: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";

/// Run the script, then resume each time it suspends (on one Ctx, so
/// `$var` values carry over), at most `max` times. The marks, in order;
/// `|` where it resumed.
fn run(src: &str, max: usize) -> Vec<String> {
    let (e, marks, slot) = engine(src);
    let arena = bumpalo::Bump::new();
    let mut msg = sip_parser::Msg::parse(MSG, &arena).unwrap();
    let (mut lumps, mut out) = (Lumps::default(), Vec::new());
    let net = NoNet;
    let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &net, None, Dest::new(Proto::Udp, "127.0.0.1:5070".parse().unwrap()), 0);
    e.handle(&mut ctx);
    for _ in 0..max {
        let Some(c) = slot.lock().unwrap().take() else { break };
        marks.lock().unwrap().push("|".into());
        RouteRunner::resume(&e, &c, &mut ctx);
    }
    marks.lock().unwrap().clone()
}

fn marks(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

#[test]
fn after_an_if() {
    let m = run(r#"request_route { mark("a"); if (1 == 1) { susp(); mark("b"); } mark("c"); }"#, 5);
    assert_eq!(m, marks("a | b c"));
}

#[test]
fn into_the_caller() {
    let src = r#"
route[inner] { mark("i1"); if (1 == 1) { susp(); mark("i2"); } mark("i3"); }
route[mid] { mark("m1"); route(inner); mark("m2"); }
request_route { mark("a"); route(mid); mark("b"); }
"#;
    assert_eq!(run(src, 5), marks("a m1 i1 | i2 i3 m2 b"));
}

#[test]
fn a_return_goes_to_the_caller_and_exit_ends() {
    let src = r#"
route[inner] { susp(); mark("i"); return 1; mark("never"); }
request_route { route(inner); mark("after"); route(inner); exit; mark("never"); }
"#;
    assert_eq!(run(src, 5), marks("| i after | i"));
}

#[test]
fn around_a_while() {
    let src = r#"request_route {
        $var(i) = 0;
        while ($var(i) < 3) { $var(i) = $var(i) + 1; susp(); mark("w"); }
        mark("end");
    }"#;
    assert_eq!(run(src, 10), marks("| w | w | w end"));
}

#[test]
fn break_in_an_if_leaves_the_loop() {
    let src = r#"request_route {
        $var(stop) = 0;
        while (1 == 1) { susp(); if ($var(stop) == 1) { mark("brk"); break; } $var(stop) = 1; }
        mark("after");
    }"#;
    assert_eq!(run(src, 10), marks("| | brk after"));
}

#[test]
fn suspending_again_in_a_called_route() {
    let src = r#"
route[twice] { susp(); mark("t1"); susp(); mark("t2"); }
request_route { if (1 == 1) { route(twice); mark("x"); } mark("y"); }
"#;
    assert_eq!(run(src, 5), marks("| t1 | t2 x y"));
}

#[test]
fn a_route_called_for_its_value_resumes_alone() {
    let src = r#"
route[inner] { susp(); mark("i"); return 1; }
request_route { if (route(inner)) { mark("never"); } mark("never"); }
"#;
    assert_eq!(run(src, 5), marks("| i"));
}

/// Script integers are C ints in Kamailio: + - * and negation wrap, and
/// division or remainder by zero gives 0 (none of these stop the script).
#[test]
fn arithmetic_wraps_and_division_by_zero_is_zero() {
    let src = r#"request_route {
        $var(max) = 9223372036854775807;
        $var(min) = 0 - $var(max) - 1;
        if ($var(max) + 1 == $var(min)) { mark("add"); }
        if ($var(min) - 1 == $var(max)) { mark("sub"); }
        if ($var(max) * 2 == -2) { mark("mul"); }
        if (-$var(min) == $var(min)) { mark("neg"); }
        if ($var(min) / -1 == $var(min)) { mark("div"); }
        if ($var(min) % -1 == 0) { mark("rem"); }
        $var(zero) = 0;
        if (7 / $var(zero) == 0) { mark("div0"); }
        if (7 % $var(zero) == 0) { mark("rem0"); }
        if (7 mod $var(zero) == 0) { mark("mod0"); }
        mark("end");
    }"#;
    assert_eq!(run(src, 0), marks("add sub mul neg div rem div0 rem0 mod0 end"));
}
