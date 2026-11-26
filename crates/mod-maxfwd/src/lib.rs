//! maxfwd module: `mf_process(max)` — decrements Max-Forwards (or adds it).
//! Returns -1 (false) when the counter is exhausted so the script can 483,
//! -2 when the header is malformed. `is_maxfwd_lt(n)` tests the value.

use sip_core::module::args;
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::{Arg, Ctx, Module, Registry};
use sip_parser::{HdrFlags, HdrKind, util::parse_u32};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct MaxFwd {
    /// `max_limit`: no request leaves with a higher Max-Forwards.
    max_limit: AtomicU32,
}

impl Default for MaxFwd {
    fn default() -> Self {
        MaxFwd { max_limit: AtomicU32::new(70) }
    }
}

/// The request's Max-Forwards: `Ok(None)` when there is none,
/// `Err(())` when it (or the header block) can't be parsed.
fn value(ctx: &mut Ctx<'_, '_>) -> Result<Option<(u32, usize, usize)>, ()> {
    ctx.msg.parse_headers(HdrFlags::MAXFWD).map_err(|_| ())?;
    match ctx.msg.get(HdrKind::MaxForwards).map(|h| h.body) {
        // Kamailio reads it with str2s (mf_funcs.c): an unsigned 16-bit
        // number, so anything past 65535 is malformed.
        Some(body) => parse_u32(body).filter(|&v| v <= u32::from(u16::MAX)).map(|v| Some((v, ctx.msg.offset_of(body), body.len()))).ok_or(()),
        None => Ok(None),
    }
}

/// `mf_process_maxfwd_header(max)` (Kamailio's process_maxfwd_header()):
/// 1 = decremented (a value above `max_limit` becomes `max_limit`), 2 =
/// added with `max`, -1 = the value is 0, -2 = malformed.
fn process(ctx: &mut Ctx<'_, '_>, max: u32, limit: u32) -> i32 {
    match value(ctx) {
        Err(()) => -2,
        Ok(Some((0, _, _))) => -1,
        Ok(Some((v, at, len))) => {
            ctx.lumps.replace(at, len, v.saturating_sub(1).min(limit).to_string());
            1
        }
        Ok(None) => {
            let at = ctx.msg.first_line_end;
            ctx.lumps.insert(at, format!("Max-Forwards: {max}\r\n"));
            2
        }
    }
}

/// `is_maxfwd_lt(n)`: 1 = the value is below `n`, -1 = it isn't,
/// -2 = no header, -3 = malformed (Kamailio's codes).
fn lt(ctx: &mut Ctx<'_, '_>, n: u32) -> i32 {
    match value(ctx) {
        Err(()) => -3,
        Ok(None) => -2,
        Ok(Some((v, _, _))) if v < n => 1,
        Ok(Some(_)) => -1,
    }
}

fn limit_arg(a: &[Arg], name: &str) -> Result<u32, String> {
    let [max] = args(a)?;
    let max = max.int()?;
    u32::try_from(max).ok().filter(|m| *m <= 255).ok_or_else(|| format!("{name}: bad value {max} (0..255)"))
}

impl Module for MaxFwd {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![p("max_limit", Ty::Int { min: 0, max: 255 }, "70", "Highest Max-Forwards a processed request leaves with (a higher value is lowered to it)")])
    }

    fn name(&self) -> &'static str {
        "maxfwd"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "max_limit" => {
                let n = v.int()?;
                let n = u32::try_from(n).ok().filter(|n| *n <= 255).ok_or_else(|| format!("maxfwd: bad max_limit {n} (0..255)"))?;
                self.max_limit.store(n, Ordering::Relaxed);
                Ok(())
            }
            _ => Err(format!("maxfwd: unknown parameter {name:?}")),
        }
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, hidden, opt_or, sig};
        const MAX: &[Param] = &[opt_or("max", Int, "70").lit()];
        const LT: &[Param] = &[arg("limit", Int).lit().eg("10")];
        Some(vec![
            sig(
                "mf_process_maxfwd_header",
                "process",
                MAX,
                Ret::Bool,
                "Decrement Max-Forwards (capped at max_limit; added with `max` when missing); false when it is exhausted or malformed",
            )
            .allowed(ctx::REQUEST),
            sig("is_maxfwd_lt", "max_forwards_below", LT, Ret::Bool, "The request's Max-Forwards is lower than limit (false when it has none)")
                .allowed(ctx::REQUEST),
            hidden("mf_process", "the same as `maxfwd.process()` (and the `guard msg.max_forwards > 0` builtin)"),
            hidden("maxfwd_process", "the same as `maxfwd.process()` (and the `guard msg.max_forwards > 0` builtin)"),
            hidden("process_maxfwd", "the same as `maxfwd.process()` (and the `guard msg.max_forwards > 0` builtin)"),
            hidden("mf_lowlimit", "the same as `maxfwd.max_forwards_below()`"),
            hidden("maxfwd_at_least", "the same as `maxfwd.max_forwards_below()`"),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        // Kamailio's names for the same function.
        for name in ["mf_process", "mf_process_maxfwd_header", "maxfwd_process", "process_maxfwd"] {
            let me = self.clone();
            reg.export(
                "maxfwd",
                name,
                move |a: &[Arg]| limit_arg(a, name),
                move |ctx: &mut Ctx, &max: &u32| process(ctx, max, me.max_limit.load(Ordering::Relaxed)),
            );
        }
        // is_maxfwd_lt() and its other Kamailio names (maxfwd.c cmds).
        for name in ["is_maxfwd_lt", "mf_lowlimit", "maxfwd_at_least"] {
            reg.export("maxfwd", name, move |a: &[Arg]| limit_arg(a, name), |ctx: &mut Ctx, &n: &u32| lt(ctx, n));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::{Dest, Lumps, Outbound, Proto};
    use std::net::SocketAddr;

    struct NoNet;

    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// Run `f` on a request with this Max-Forwards header line ("" = none);
    /// returns its result and the request as it would be forwarded.
    fn run(mf: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> i32) -> (i32, String) {
        let req = format!(
            "OPTIONS sip:b@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\n{mf}From: <sip:a@x>;tag=1\r\nTo: <sip:b@x>\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        );
        let arena = bumpalo::Bump::new();
        let mut msg = sip_parser::Msg::parse(req.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        let rc = f(&mut ctx);
        (rc, String::from_utf8_lossy(ctx.render()).into_owned())
    }

    fn mf_line(out: &str) -> Option<&str> {
        out.lines().find(|l| l.starts_with("Max-Forwards:"))
    }

    #[test]
    fn process_codes_and_limits() {
        let (rc, out) = run("Max-Forwards: 10\r\n", |c| process(c, 70, 70));
        assert_eq!((rc, mf_line(&out)), (1, Some("Max-Forwards: 9")));
        // Capped by max_limit only; `max` is for a missing header (Kamailio).
        assert_eq!(mf_line(&run("Max-Forwards: 50\r\n", |c| process(c, 10, 70)).1), Some("Max-Forwards: 49"));
        assert_eq!(mf_line(&run("Max-Forwards: 71\r\n", |c| process(c, 10, 70)).1), Some("Max-Forwards: 70"));
        assert_eq!(mf_line(&run("Max-Forwards: 200\r\n", |c| process(c, 255, 70)).1), Some("Max-Forwards: 70"));
        assert_eq!(mf_line(&run("Max-Forwards: 200\r\n", |c| process(c, 255, 255)).1), Some("Max-Forwards: 199"));
        let (rc, out) = run("", |c| process(c, 16, 70));
        assert_eq!((rc, mf_line(&out)), (2, Some("Max-Forwards: 16")));
        assert_eq!(run("Max-Forwards: 0\r\n", |c| process(c, 70, 70)).0, -1);
        assert_eq!(run("Max-Forwards: ten\r\n", |c| process(c, 70, 70)).0, -2);
    }

    #[test]
    fn lt_codes() {
        assert_eq!(run("Max-Forwards: 5\r\n", |c| lt(c, 10)).0, 1);
        assert_eq!(run("Max-Forwards: 10\r\n", |c| lt(c, 10)).0, -1);
        assert_eq!(run("", |c| lt(c, 10)).0, -2);
        assert_eq!(run("Max-Forwards: x\r\n", |c| lt(c, 10)).0, -3);
    }

    #[test]
    fn process_handles_every_max_forwards_value_form() {
        // (header line, max, max_limit, expected rc, expected Max-Forwards line after)
        let cases: &[(&str, u32, u32, i32, Option<&str>)] = &[
            ("", 70, 70, 2, Some("Max-Forwards: 70")),
            ("", 0, 70, 2, Some("Max-Forwards: 0")),
            ("Max-Forwards: 0\r\n", 70, 70, -1, Some("Max-Forwards: 0")),
            ("Max-Forwards: 00\r\n", 70, 70, -1, Some("Max-Forwards: 00")),
            ("Max-Forwards: 1\r\n", 70, 70, 1, Some("Max-Forwards: 0")),
            ("Max-Forwards: 007\r\n", 70, 70, 1, Some("Max-Forwards: 6")),
            ("Max-Forwards: 70\r\n", 70, 70, 1, Some("Max-Forwards: 69")),
            ("Max-Forwards: 255\r\n", 70, 255, 1, Some("Max-Forwards: 254")),
            ("Max-Forwards: 256\r\n", 70, 255, 1, Some("Max-Forwards: 255")),
            // Kamailio's str2s: up to 65535 is a number (capped), past it malformed.
            ("Max-Forwards: 65535\r\n", 70, 70, 1, Some("Max-Forwards: 70")),
            ("Max-Forwards: 65536\r\n", 70, 70, -2, None),
            ("Max-Forwards: 4294967295\r\n", 70, 70, -2, None),
            ("Max-Forwards: 5\r\n", 70, 0, 1, Some("Max-Forwards: 0")),
            ("Max-Forwards:   12  \r\n", 70, 70, 1, Some("Max-Forwards:   11  ")),
            ("Max-Forwards:\t3\r\n", 70, 70, 1, Some("Max-Forwards:\t2")),
            ("max-forwards: 9\r\n", 70, 70, 1, Some("Max-Forwards: 8")),
            ("Max-Forwards: \r\n", 70, 70, -2, None),
            ("Max-Forwards: ten\r\n", 70, 70, -2, None),
            ("Max-Forwards: -1\r\n", 70, 70, -2, None),
            ("Max-Forwards: +5\r\n", 70, 70, -2, None),
            ("Max-Forwards: 5 6\r\n", 70, 70, -2, None),
            ("Max-Forwards: 5x\r\n", 70, 70, -2, None),
            ("Max-Forwards: 4294967296\r\n", 70, 70, -2, None),
            ("Max-Forwards: 99999999999\r\n", 70, 70, -2, None),
        ];
        for &(line, max, limit, rc, after) in cases {
            let (got, out) = run(line, |c| process(c, max, limit));
            assert_eq!(got, rc, "rc for {line:?} max={max} limit={limit}");
            let got_line = out.lines().find(|l| l.to_ascii_lowercase().starts_with("max-forwards:")).map(|l| {
                // The header name keeps its original case; compare the value part only.
                l.split_once(':').map_or(String::new(), |(_, v)| format!("Max-Forwards:{v}"))
            });
            if let Some(after) = after {
                assert_eq!(got_line.as_deref(), Some(after), "forwarded header for {line:?}");
            }
        }
    }

    #[test]
    fn process_inserts_a_missing_header_right_after_the_request_line() {
        let (_, out) = run("", |c| process(c, 16, 70));
        let mut lines = out.lines();
        assert_eq!(lines.next(), Some("OPTIONS sip:b@x SIP/2.0"));
        assert_eq!(lines.next(), Some("Max-Forwards: 16"));
        assert_eq!(out.matches("Max-Forwards").count(), 1);
    }

    #[test]
    fn process_leaves_the_request_unchanged_when_it_fails() {
        for line in ["Max-Forwards: 0\r\n", "Max-Forwards: bad\r\n"] {
            let (_, out) = run(line, |c| process(c, 70, 70));
            let (_, untouched) = run(line, |_| 0);
            assert_eq!(out, untouched, "request with {line:?}");
        }
    }

    #[test]
    fn process_uses_the_first_of_two_max_forwards_headers() {
        let (rc, out) = run("Max-Forwards: 3\r\nMax-Forwards: 50\r\n", |c| process(c, 70, 70));
        assert_eq!(rc, 1);
        let values: Vec<&str> = out.lines().filter(|l| l.starts_with("Max-Forwards:")).collect();
        assert_eq!(values, ["Max-Forwards: 2", "Max-Forwards: 50"]);
    }

    #[test]
    fn is_maxfwd_lt_returns_kamailio_codes_for_every_case() {
        // (header line, n, expected rc)
        let cases: &[(&str, u32, i32)] = &[
            ("", 10, -2),
            ("", 0, -2),
            ("Max-Forwards: 0\r\n", 0, -1),
            ("Max-Forwards: 0\r\n", 1, 1),
            ("Max-Forwards: 9\r\n", 10, 1),
            ("Max-Forwards: 10\r\n", 10, -1),
            ("Max-Forwards: 11\r\n", 10, -1),
            ("Max-Forwards: 255\r\n", 255, -1),
            ("Max-Forwards: 300\r\n", 255, -1),
            ("Max-Forwards:  4 \r\n", 5, 1),
            ("Max-Forwards: \r\n", 10, -3),
            ("Max-Forwards: x\r\n", 10, -3),
            ("Max-Forwards: -1\r\n", 10, -3),
            ("Max-Forwards: 1 2\r\n", 10, -3),
        ];
        for &(line, n, rc) in cases {
            let (got, out) = run(line, |c| lt(c, n));
            assert_eq!(got, rc, "is_maxfwd_lt({n}) with {line:?}");
            let (_, untouched) = run(line, |_| 0);
            assert_eq!(out, untouched, "is_maxfwd_lt changes nothing ({line:?})");
        }
    }

    #[test]
    fn arguments_and_max_limit_are_checked_to_0_255() {
        let mf = MaxFwd::default();
        assert_eq!(mf.max_limit.load(Ordering::Relaxed), 70, "documented default");
        for (v, ok) in [(0, true), (255, true), (256, false), (-1, false)] {
            assert_eq!(mf.set_param("max_limit", &Arg::Int(v)).is_ok(), ok, "max_limit={v}");
            assert_eq!(limit_arg(&[Arg::Int(v)], "mf_process").is_ok(), ok, "mf_process({v})");
        }
        assert_eq!(mf.max_limit.load(Ordering::Relaxed), 255, "a refused value keeps the last good one");
        assert!(mf.set_param("nope", &Arg::Int(1)).is_err());
        assert_eq!(limit_arg(&[Arg::Int(16)], "x"), Ok(16));
    }
}
