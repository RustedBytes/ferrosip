//! Built-in script functions, exported through the same mechanism as modules.

use crate::module::{Arg, Ctx, Module, Registry, args, want_args};
use sip_parser::{HdrFlags, HdrKind, kind_of};
use std::sync::Arc;

pub struct CoreModule;

enum HdrMatch {
    Kind(HdrKind),
    Name(Vec<u8>),
}

impl Module for CoreModule {
    fn name(&self) -> &'static str {
        "core"
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        crate::pvcore::register(reg);
        // Core management commands.
        let started = std::time::SystemTime::now();
        reg.rpc.add("core.uptime", "Seconds since start", move |_| {
            let up = started.elapsed().map_or(0, |d| d.as_secs());
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            Ok(serde_json::json!({"now": now, "up_since": now.saturating_sub(up), "uptime": up}))
        });
        reg.rpc.add("core.version", "Version string", |_| Ok(serde_json::json!(concat!("ferrosip ", env!("CARGO_PKG_VERSION")))));
        reg.rpc.add("stats.get_statistics", "Statistics: all | group: | group:name …", |p| {
            let specs: Vec<String> =
                if p.is_empty() { vec!["all".into()] } else { p.iter().map(|v| v.as_str().map_or(v.to_string(), str::to_string)).collect() };
            let mut out = serde_json::Map::new();
            for s in specs {
                for (g, n, v) in crate::stats::get(&s) {
                    out.insert(format!("{g}:{n}"), v.into());
                }
            }
            Ok(serde_json::Value::Object(out))
        });
        reg.rpc.add("core.log_tail", "core.log_tail [after_seq [max]]: recent log lines (when the log ring is on)", |p| {
            let since = p.first().and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok())).unwrap_or(0);
            let max = p.get(1).and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok())).unwrap_or(500).min(5000) as usize;
            let (lines, newest) = crate::log::tail(since, max).ok_or("the log ring is off (loadmodule \"webui\" turns it on)")?;
            let lines: Vec<serde_json::Value> =
                lines.into_iter().map(|l| serde_json::json!({"seq": l.seq, "ts_ms": l.ts_ms, "level": crate::log::name(l.level), "text": l.text})).collect();
            Ok(serde_json::json!({"newest": newest, "lines": lines}))
        });
        reg.rpc.add("cfg.list", "Custom config variables", |_| {
            let vars: Vec<_> =
                crate::cfgvars::list().into_iter().map(|(n, v, d)| serde_json::json!({"name": n, "value": v.to_string(), "description": d})).collect();
            Ok(serde_json::Value::Array(vars))
        });
        reg.rpc.add("cfg.get", "cfg.get group name", |p| {
            let name = format!("{}.{}", crate::rpc::str_param(p, 0)?, crate::rpc::str_param(p, 1)?);
            match crate::cfgvars::get(&name) {
                Some(crate::pv::Val::Int(i)) => Ok(i.into()),
                Some(v) => Ok(v.to_string().into()),
                None => Err(format!("no config variable {name}")),
            }
        });
        reg.rpc.add("cfg.set_now_int", "cfg.set_now_int group name value", |p| {
            let name = format!("{}.{}", crate::rpc::str_param(p, 0)?, crate::rpc::str_param(p, 1)?);
            let v = p.get(2).and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok())).ok_or("value must be an integer")?;
            crate::cfgvars::set(&name, crate::pv::Val::Int(v)).map(|()| serde_json::json!("ok"))
        });
        reg.rpc.add("cfg.set_now_string", "cfg.set_now_string group name value", |p| {
            let name = format!("{}.{}", crate::rpc::str_param(p, 0)?, crate::rpc::str_param(p, 1)?);
            crate::cfgvars::set(&name, crate::pv::Val::Str(crate::rpc::str_param(p, 2)?)).map(|()| serde_json::json!("ok"))
        });
        reg.rpc.add("stats.reset_statistics", "Reset counters: all | group: | group:name", |p| {
            let spec = crate::rpc::str_param(p, 0).unwrap_or_else(|_| "all".into());
            Ok(serde_json::json!(crate::stats::reset(&spec)))
        });
        // setflag(n) / resetflag(n) / isflagset(n): message flags (0..63),
        // carried into the transaction like AVPs.
        let flag_fix = |a: &[Arg]| -> Result<u64, String> {
            let [n] = args(a)?;
            let n = n.int()?;
            if !(0..64).contains(&n) {
                return Err(format!("flag {n} out of range 0..63"));
            }
            Ok(1u64 << n)
        };
        reg.export("core", "setflag", flag_fix, |ctx: &mut Ctx, &m: &u64| {
            ctx.ext_mut::<crate::pvcore::TxnVars>().flags |= m;
            1
        });
        reg.export("core", "resetflag", flag_fix, |ctx: &mut Ctx, &m: &u64| {
            ctx.ext_mut::<crate::pvcore::TxnVars>().flags &= !m;
            1
        });
        reg.export(
            "core",
            "isflagset",
            flag_fix,
            |ctx: &mut Ctx, &m: &u64| {
                if ctx.ext::<crate::pvcore::TxnVars>().is_some_and(|t| t.flags & m != 0) { 1 } else { -1 }
            },
        );
        // setbflag(n) / resetbflag(n) / isbflagset(n): branch flags (0..31)
        // of the R-URI branch.
        let bflag_fix = |a: &[Arg]| -> Result<u32, String> {
            let (n, branch) = match a {
                [n] => (n, None),
                [n, branch] => (n, Some(branch)),
                _ => return Err("expected flag[, branch]".into()),
            };
            if let Some(b) = branch
                && b.int()? != 0
            {
                return Err("only branch 0 (the R-URI branch) is supported".into());
            }
            let n = n.int()?;
            if !(0..32).contains(&n) {
                return Err(format!("branch flag {n} out of range 0..31"));
            }
            Ok(1u32 << n)
        };
        reg.export("core", "setbflag", bflag_fix, |ctx: &mut Ctx, &m: &u32| {
            ctx.ext_mut::<crate::pvcore::TxnVars>().bflags |= m;
            1
        });
        reg.export("core", "resetbflag", bflag_fix, |ctx: &mut Ctx, &m: &u32| {
            ctx.ext_mut::<crate::pvcore::TxnVars>().bflags &= !m;
            1
        });
        reg.export(
            "core",
            "isbflagset",
            bflag_fix,
            |ctx: &mut Ctx, &m: &u32| {
                if ctx.ext::<crate::pvcore::TxnVars>().is_some_and(|t| t.bflags & m != 0) { 1 } else { -1 }
            },
        );
        // force_rport(): this request's replies go to its source port even
        // without ;rport (all requests' do while core force_rport is on, the
        // default). add_rport(): our Via always gets rport from the next hop.
        reg.export(
            "core",
            "force_rport",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if ctx.ext::<crate::module::ForceRport>().is_none() {
                    ctx.ext.push(Box::new(crate::module::ForceRport));
                }
                1
            },
        );
        reg.export("core", "add_rport", |a: &[Arg]| want_args(a, 0), |_: &mut Ctx, _: &()| 1);
        // set_reply_no_connect(): replies to this request (stateless and
        // through tm) use the connection it came on, or are dropped — never
        // a new outbound connection to a client behind NAT.
        reg.export(
            "core",
            "set_reply_no_connect",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                ctx.src.no_connect = true;
                1
            },
        );
        // strempty(s) / strnotempty(s)
        for (name, want_empty) in [("strempty", true), ("strnotempty", false)] {
            reg.export(
                "core",
                name,
                |a: &[Arg]| {
                    let [s] = args(a)?;
                    s.dyn_str()
                },
                move |ctx: &mut Ctx, s: &crate::module::DynStr| if s.eval(ctx).is_empty() == want_empty { 1 } else { -1 },
            );
        }
        // set_forward_no_connect(): forward over open connections only.
        reg.export(
            "core",
            "set_forward_no_connect",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if ctx.ext::<crate::module::ForwardNoConnect>().is_none() {
                    ctx.ext.push(Box::new(crate::module::ForwardNoConnect));
                }
                1
            },
        );
        // len_gt(n): the message is longer than n bytes (old core function).
        reg.export(
            "core",
            "len_gt",
            |a: &[Arg]| {
                let [n] = args(a)?;
                usize::try_from(n.int()?).map_err(|_| "len_gt: expected a size".to_string())
            },
            |ctx: &mut Ctx, &n: &usize| if ctx.msg.buf.len() > n { 1 } else { -1 },
        );
        // set_reply_close() / set_forward_close(): Kamailio closes the TCP
        // connection after sending. Connections here are closed by their
        // lifetime and the peer, so these only log once.
        for name in ["set_reply_close", "set_forward_close"] {
            reg.export(
                "core",
                name,
                move |a: &[Arg]| {
                    want_args(a, 0)?;
                    crate::elog!("ferrosip: note: {name}() has no effect (connections close on tcp_connection_lifetime or by the peer)");
                    Ok(())
                },
                |_: &mut Ctx, _: &()| 1,
            );
        }
        // reply(code, reason)
        reg.export(
            "core",
            "reply",
            |a: &[Arg]| {
                let [code, reason] = args(a)?;
                let code = code.dyn_int()?;
                if let crate::module::DynInt::Static(c) = code
                    && !(100..700).contains(&c)
                {
                    return Err(format!("bad status code {c}"));
                }
                Ok((code, reason.dyn_str()?))
            },
            |ctx: &mut Ctx, (code, reason): &(crate::module::DynInt, crate::module::DynStr)| {
                let Some(c) = code.eval(ctx).and_then(|c| u16::try_from(c).ok()).filter(|c| (100..700).contains(c)) else {
                    return -1;
                };
                let reason = reason.eval(ctx).into_owned();
                match ctx.reply(c, &reason) {
                    Ok(()) => 1,
                    Err(_) => -1,
                }
            },
        );

        // sl_reply_error() — reply with the code of the last failure.
        reg.export(
            "core",
            "sl_reply_error",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                // The failed function already answered (save's 423…): not twice.
                if ctx.answered() {
                    return 1;
                }
                // tm answers a failed relay itself when the script ends
                // (Kamailio sl_funcs.c:432-435: FL_DELAYED_REPLY → -3).
                if ctx.ext::<crate::module::DelayedReply>().is_some() {
                    return -3;
                }
                // err2reason_phrase(prev_ser_error, …, "SL") (sl_funcs.c:437).
                let (code, reason) = crate::error::reply_error(ctx.last_error, "SL");
                if ctx.reply(code, &reason).is_ok() { 1 } else { -1 }
            },
        );

        // append_hdr("X-Foo: bar") — CRLF added at fixup time, not per message.
        reg.export(
            "core",
            "append_hdr",
            |a: &[Arg]| {
                let [h] = args(a)?;
                let h = h.dyn_str()?;
                if let crate::module::DynStr::Static(s) = &h
                    && !s.contains(':')
                {
                    return Err("header must contain ':'".into());
                }
                Ok(h)
            },
            |ctx: &mut Ctx, h: &crate::module::DynStr| {
                let mut line = h.eval(ctx).trim_end().as_bytes().to_vec();
                if !line.contains(&b':') || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                line.extend_from_slice(b"\r\n");
                let at = ctx.msg.eoh_offset().unwrap_or(ctx.msg.buf.len());
                ctx.lumps.insert(at, line);
                1
            },
        );

        // remove_hdr("User-Agent") — name resolved to a HdrKind at fixup time.
        reg.export(
            "core",
            "remove_hdr",
            |a: &[Arg]| {
                let [name] = args(a)?;
                let name = name.str()?.as_bytes();
                Ok(match kind_of(name) {
                    HdrKind::Other => HdrMatch::Name(name.to_ascii_lowercase()),
                    k => HdrMatch::Kind(k),
                })
            },
            |ctx: &mut Ctx, m: &HdrMatch| {
                if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                let mut n = 0u32;
                for h in ctx.msg.headers.iter() {
                    let hit = match m {
                        HdrMatch::Kind(k) => h.kind == *k,
                        HdrMatch::Name(name) => h.name.eq_ignore_ascii_case(name),
                    };
                    if hit {
                        ctx.lumps.delete(h.start, h.end.saturating_sub(h.start));
                        n = n.saturating_add(1);
                    }
                }
                if n > 0 { 1 } else { -1 }
            },
        );

        // ruri_user_prefix("+49")
        reg.export(
            "core",
            "ruri_user_prefix",
            |a: &[Arg]| {
                let [prefix] = args(a)?;
                Ok(prefix.str()?.as_bytes().to_vec())
            },
            |ctx: &mut Ctx, p: &Vec<u8>| match sip_parser::parse_uri(ctx.ruri()).and_then(|u| u.user) {
                Some(u) if u.starts_with(p) => 1,
                _ => -1,
            },
        );

        // append_branch("sip:alice@10.0.0.1"[, "0.5"]) — add a fork target.
        reg.export(
            "core",
            "append_branch",
            |a: &[Arg]| {
                let (uri_arg, q) = match a {
                    [uri] => (uri, None),
                    [uri, q] => (uri, Some(q)),
                    _ => return Err("append_branch(uri[, q])".into()),
                };
                let uri = uri_arg.str()?.as_bytes().to_vec();
                if sip_parser::parse_uri(&uri).is_none() {
                    return Err(format!("append_branch: bad URI {:?}", uri_arg.str()?));
                }
                let q = match q {
                    Some(q) => Some(sip_parser::uri::parse_q(q.str()?.as_bytes()).ok_or("append_branch: bad q")?),
                    None => None,
                };
                Ok(crate::module::Branch { uri, dst: None, q, path: None, ..Default::default() })
            },
            // -1 when the destination set is full (core dset.c append_branch()).
            |ctx: &mut Ctx, b: &crate::module::Branch| if ctx.append_branch(b.clone()) { 1 } else { -1 },
        );

        // rewriteuri("sip:voicemail@10.0.0.9") — set $ru (and forget $du).
        // rewriteuri (and its legacy name seturi)
        for name in ["rewriteuri", "seturi"] {
            reg.export(
                "core",
                name,
                |a: &[Arg]| {
                    let [uri] = args(a)?;
                    let uri = uri.dyn_str()?;
                    if let crate::module::DynStr::Static(s) = &uri {
                        sip_parser::parse_uri(s.as_bytes()).ok_or_else(|| format!("rewriteuri: bad URI {s:?}"))?;
                    }
                    Ok(uri)
                },
                |ctx: &mut Ctx, uri: &crate::module::DynStr| {
                    let u = uri.eval(ctx).into_owned();
                    if sip_parser::parse_uri(u.as_bytes()).is_none() {
                        return -1;
                    }
                    ctx.new_ruri = Some(u.into_bytes());
                    ctx.dst = None;
                    1
                },
            );
        }

        // log("text")
        reg.export(
            "core",
            "log",
            // log(msg) or log(level, msg) (Kamailio's level comes first).
            |a: &[Arg]| match a {
                [msg] | [_, msg] => msg.dyn_str(),
                _ => Err(format!("log() expects 1 or 2 arguments, got {}", a.len())),
            },
            |ctx: &mut Ctx, s: &crate::module::DynStr| {
                let msg = s.eval(ctx).into_owned();
                crate::elog!("[w{}] {} from {}", ctx.worker, msg, ctx.src);
                1
            },
        );
        Ok(())
    }
}
