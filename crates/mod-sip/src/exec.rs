//! exec module: run external commands from the script.
//!
//! - `exec_msg(cmd)`: the message on the command's stdin; true if it exits 0.
//! - `exec_dset(cmd)`: the R-URI as the command's argument; its output lines
//!   become the new R-URI and extra branches.
//! - `exec_avp(cmd[, "a;b"])`: output lines into `$avp(a)`, `$avp(b)`, …
//!   (`$avp(1)`, `$avp(2)`, … without a list).
//! - `exec_cmd(cmd)`: start the command and don't wait.
//!
//! Commands run with `/bin/sh -c` and block the worker until they finish,
//! as in Kamailio; `time_to_kill` (ms, 0 = never) bounds that. With
//! `setvars` (default 1) the environment carries `SIP_SRCIP`, `SIP_RURI`,
//! `SIP_USER`, `SIP_ORURI`, `SIP_OUSER`, `SIP_TID` and `SIP_HF_<NAME>`
//! for each header.

use crate::args;
use sip_core::module::{Branch, DynStr, rc};
use sip_core::pv::Val;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::{Arg, Ctx, Module, Registry};
use sip_parser::HdrFlags;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct Exec {
    setvars: AtomicBool,
    time_to_kill: AtomicU64,
}

impl Default for Exec {
    fn default() -> Self {
        Exec { setvars: AtomicBool::new(true), time_to_kill: AtomicU64::new(0) }
    }
}

impl Exec {
    fn command(&self, ctx: &mut Ctx<'_, '_>, script: &str, arg: Option<&str>) -> Command {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(script);
        if let Some(a) = arg {
            c.arg("sh").arg(a);
        }
        if self.setvars.load(Ordering::Relaxed) {
            c.env("SIP_SRCIP", ctx.src.addr.ip().to_string());
            c.env("SIP_RURI", String::from_utf8_lossy(ctx.ruri()).into_owned());
            if let Some(u) = sip_parser::parse_uri(ctx.ruri()).and_then(|u| u.user) {
                c.env("SIP_USER", String::from_utf8_lossy(u).into_owned());
            }
            if let Some(o) = ctx.msg.ruri() {
                c.env("SIP_ORURI", String::from_utf8_lossy(o).into_owned());
                if let Some(u) = sip_parser::parse_uri(o).and_then(|u| u.user) {
                    c.env("SIP_OUSER", String::from_utf8_lossy(u).into_owned());
                }
            }
            if let Some(b) = ctx.msg.via1.and_then(|v| v.branch) {
                c.env("SIP_TID", String::from_utf8_lossy(b).into_owned());
            }
            if ctx.msg.parse_headers(HdrFlags::EOH).is_ok() {
                for h in ctx.msg.headers.iter() {
                    let name: String =
                        String::from_utf8_lossy(h.name).chars().map(|ch| if ch.is_ascii_alphanumeric() { ch.to_ascii_uppercase() } else { '_' }).collect();
                    c.env(format!("SIP_HF_{name}"), String::from_utf8_lossy(h.body).into_owned());
                }
            }
        }
        c
    }

    /// Wait for `child`, killing it after `time_to_kill`. Some(exit code).
    fn wait(&self, mut child: Child) -> Option<i32> {
        let ttk = self.time_to_kill.load(Ordering::Relaxed);
        if ttk == 0 {
            return child.wait().ok()?.code();
        }
        // A deadline past what Instant holds: wait for the child.
        let Some(end) = Instant::now().checked_add(Duration::from_millis(ttk)) else { return child.wait().ok()?.code() };
        loop {
            match child.try_wait() {
                Ok(Some(s)) => return s.code(),
                Ok(None) if Instant::now() >= end => {
                    sip_core::elog!("exec: command still running after time_to_kill ({ttk} ms), killed");
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => return None,
            }
        }
    }

    /// Run and collect stdout (`None` if it could not run or failed).
    fn output(&self, mut c: Command) -> Option<String> {
        let mut child = c.stdin(Stdio::null()).stdout(Stdio::piped()).spawn().map_err(|e| sip_core::elog!("exec: {e}")).ok()?;
        let mut out = String::new();
        // Read before waiting: a full pipe would block the child.
        let mut so = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let _ = so.read_to_string(&mut out);
            out
        });
        let code = self.wait(child);
        let out = reader.join().ok()?;
        (code == Some(0)).then_some(out)
    }
}

impl Module for Exec {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("setvars", Ty::Bool, "true", "Pass SIP_* environment variables (source IP, R-URI, headers) to commands"),
            p("time_to_kill", Ty::Duration(Unit::Ms), "0s", "Kill a command still running after this long (0 = never)"),
        ])
    }

    fn name(&self) -> &'static str {
        "exec"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const CMD: &[Param] = &[arg("command", Str).eg("\"true\"")];
        const AVP: &[Param] = &[arg("command", Str).eg("\"true\""), opt("avps", Str).lit().eg("\"a;b\"")];
        Some(vec![
            sig("exec_msg", "pipe_msg", CMD, Ret::Bool, "Run a shell command with the message on its stdin; true on exit status 0").allowed(ctx::ANY),
            sig("exec_dset", "set_targets", CMD, Ret::Bool, "Run a shell command (R-URI as $1); its output lines become the R-URI and branches"),
            sig("exec_avp", "capture", AVP, Ret::Bool, "Run a shell command; its output lines go to these AVPs (`;`-separated; default $avp(1), $avp(2)…)")
                .allowed(ctx::ANY),
            sig("exec_cmd", "run", CMD, Ret::Bool, "Start a shell command in the background").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "setvars" => self.setvars.store(v.int()? != 0, Ordering::Relaxed),
            "time_to_kill" => self.time_to_kill.store(u64::try_from(v.int()?).map_err(|_| "time_to_kill must be >= 0")?, Ordering::Relaxed),
            _ => return Err(format!("exec: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let cmd = |a: &[Arg]| {
            let [c] = args(a)?;
            c.dyn_str()
        };
        let me = self.clone();
        reg.export("exec", "exec_msg", cmd, move |ctx: &mut Ctx, c: &DynStr| {
            let script = c.eval(ctx).into_owned();
            let mut command = me.command(ctx, &script, None);
            let Ok(mut child) = command.stdin(Stdio::piped()).stdout(Stdio::null()).spawn().map_err(|e| sip_core::elog!("exec_msg: {e}")) else { return -1 };
            let msg = ctx.msg.buf.to_vec();
            if let Some(mut stdin) = child.stdin.take() {
                // A writer thread: the command may not read all of it.
                std::thread::spawn(move || drop(stdin.write_all(&msg)));
            }
            rc(me.wait(child) == Some(0))
        });
        let me = self.clone();
        reg.export("exec", "exec_dset", cmd, move |ctx: &mut Ctx, c: &DynStr| {
            let script = format!("{} \"$1\"", c.eval(ctx));
            let ruri = String::from_utf8_lossy(ctx.ruri()).into_owned();
            let Some(out) = me.output(me.command(ctx, &script, Some(&ruri))) else { return -1 };
            let mut uris = out.lines().map(str::trim).filter(|l| !l.is_empty());
            let Some(first) = uris.next() else { return -1 };
            if sip_parser::parse_uri(first.as_bytes()).is_none() {
                return -1;
            }
            ctx.new_ruri = Some(first.as_bytes().to_vec());
            for u in uris.filter(|u| sip_parser::parse_uri(u.as_bytes()).is_some()) {
                ctx.branches.push(Branch { uri: u.as_bytes().to_vec(), ..Default::default() });
            }
            1
        });
        let me = self.clone();
        reg.export(
            "exec",
            "exec_avp",
            |a: &[Arg]| {
                let (cmd, names) = match a {
                    [cmd] => (cmd, None),
                    [cmd, names] => (cmd, Some(names)),
                    _ => return Err("exec_avp(cmd[, \"avp1;avp2…\"])".into()),
                };
                let names: Vec<String> = match names {
                    Some(l) => l.str()?.split(';').map(|n| n.trim().trim_start_matches("$avp(").trim_end_matches(')').to_string()).collect(),
                    None => Vec::new(),
                };
                Ok((cmd.dyn_str()?, names))
            },
            move |ctx: &mut Ctx, (c, names): &(DynStr, Vec<String>)| {
                let script = c.eval(ctx).into_owned();
                let Some(out) = me.output(me.command(ctx, &script, None)) else { return -1 };
                let vars = ctx.ext_mut::<sip_core::TxnVars>();
                for (i, line) in out.lines().enumerate() {
                    let name = match names.get(i) {
                        Some(n) => n.clone(),
                        None if names.is_empty() => i.saturating_add(1).to_string(),
                        None => break,
                    };
                    let v = line.parse::<i64>().map_or_else(|_| Val::Str(line.to_string()), Val::Int);
                    vars.avps.entry(name).or_default().push(v);
                }
                1
            },
        );
        let me = self.clone();
        reg.export("exec", "exec_cmd", cmd, move |ctx: &mut Ctx, c: &DynStr| {
            let script = c.eval(ctx).into_owned();
            match me.command(ctx, &script, None).stdin(Stdio::null()).spawn() {
                Ok(mut child) => {
                    // Reap it so it doesn't linger as a zombie.
                    std::thread::spawn(move || drop(child.wait()));
                    1
                }
                Err(e) => {
                    sip_core::elog!("exec_cmd: {e}");
                    -1
                }
            }
        });
        Ok(())
    }
}
