//! Script routes that modules trigger: tm runs `failure_route[name]`,
//! `onreply_route[name]` and `branch_route[name]`; modules raise
//! `event_route[module:event]`.
//!
//! Modules can't depend on the script engine (it depends on them), so the
//! engine registers itself here: route *names* before compiling — so fixups
//! like `t_on_failure("name")` resolve to an index at startup — and the
//! *runner* once compiled.

use crate::lumps::Lumps;
use crate::module::Ctx;
use crate::net::{Dest, Outbound, Proto};
use crate::sync::{read, write};
use bumpalo::Bump;
use sip_parser::Msg;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

/// Where an asynchronously suspended script continues (Kamailio
/// `async_sleep` / `t_continue`): the rest of one block of a route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteRoot {
    /// `request_route`.
    Request,
    /// `route[idx]`.
    Route(usize),
}

///
/// After that block the script goes on as if it had never stopped: past
/// the enclosing `if`, around an enclosing `while` again, and back into
/// the routes that called this one (`callers`) after their `route(x);`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    pub root: RouteRoot,
    /// Nested blocks from the root: (action index, arm: if = 0 / else = 1,
    /// while = 0, switch = case index).
    pub path: Vec<(usize, usize)>,
    /// First action to run in that block.
    pub at: usize,
    /// The calling routes, nearest first: where each continues once the
    /// route below it returns.
    pub callers: Vec<Frame>,
    /// The script version that suspended (its positions mean something
    /// only there): a request suspended across `cfg.reload` finishes in the
    /// routing it started in. None: the current one.
    pub script: ScriptRef,
}

/// An opaque handle on a script version (sip-script's engine).
#[derive(Clone, Default)]
pub struct ScriptRef(pub Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>);

impl std::fmt::Debug for ScriptRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "ScriptRef(..)" } else { "ScriptRef(current)" })
    }
}

impl PartialEq for ScriptRef {
    fn eq(&self, o: &Self) -> bool {
        match (&self.0, &o.0) {
            (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Eq for ScriptRef {}

/// A position in a route: a block (`path`) and an action in it (`at`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub root: RouteRoot,
    pub path: Vec<(usize, usize)>,
    pub at: usize,
}

impl Continuation {
    /// All of `route[idx]` (async_route, t_continue).
    pub fn route(idx: usize) -> Self {
        Self { root: RouteRoot::Route(idx), path: Vec::new(), at: 0, callers: Vec::new(), script: ScriptRef::default() }
    }
}

/// Pushed into the Ctx by a function that suspends the message (and then
/// returns 0): once the script has unwound, the engine calls it with the
/// point where processing continues — the action after the call, in the
/// same block, like Kamailio's `async_sleep`.
pub struct AsyncPending(pub Box<dyn FnOnce(Continuation) + Send>);

/// Executes compiled routes (implemented by the script engine).
pub trait RouteRunner: Send + Sync {
    /// Run `failure_route[idx]` on a context built from the original request.
    fn run_failure(&self, idx: usize, ctx: &mut Ctx<'_, '_>);
    /// Run `onreply_route[idx]` on a reply; false = the script said `drop`.
    fn run_onreply(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool;
    /// Run `branch_route[idx]` for one outgoing branch; false = `drop` it.
    fn run_branch(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool;
    /// Run `event_route[idx]`; false = the route said `drop`.
    fn run_event(&self, idx: usize, ctx: &mut Ctx<'_, '_>) -> bool;
    /// Index of `route[name]` (prefix_route, rtimer, KEMI).
    fn route_index(&self, _name: &str) -> Option<usize> {
        None
    }
    /// Run `route[idx]` like `route(name)` does: its return code; 0 if it
    /// exited (or dropped).
    fn run_route(&self, _idx: usize, _ctx: &mut Ctx<'_, '_>) -> i32 {
        -1
    }
    /// Continue a suspended script (see `AsyncPending`); its return code.
    fn resume(&self, _c: &Continuation, _ctx: &mut Ctx<'_, '_>) -> i32 {
        -1
    }
    /// An exported script function by name (KEMI).
    fn export(&self, _name: &str) -> Option<crate::module::Export> {
        None
    }
    /// All pseudo-variables (KEMI `KSR.pv`).
    fn pv_table(&self) -> Option<&crate::pv::PvTable> {
        None
    }
}

#[derive(Default, Debug, Clone)]
pub struct RouteNames {
    pub failure: Vec<String>,
    pub onreply: Vec<String>,
    pub branch: Vec<String>,
    pub event: Vec<String>,
}

#[derive(Default)]
pub struct RouteHub {
    /// Replaced when the script is reloaded (`cfg.reload`).
    names: std::sync::RwLock<Arc<RouteNames>>,
    runner: OnceLock<Arc<dyn RouteRunner>>,
}

fn find(list: Option<&Vec<String>>, name: &str, kind: &str) -> Result<usize, String> {
    list.and_then(|l| l.iter().position(|n| n == name)).ok_or_else(|| format!("no {kind}[{name}] in the script"))
}

impl RouteHub {
    pub fn set_names(&self, names: RouteNames) {
        *write(&self.names) = Arc::new(names);
    }

    fn names(&self) -> Arc<RouteNames> {
        read(&self.names).clone()
    }
    pub fn set_runner(&self, r: Arc<dyn RouteRunner>) {
        #[allow(clippy::let_underscore_must_use, reason = "set once: a later call keeps the first value")]
        let _ = self.runner.set(r);
    }
    pub fn runner(&self) -> Option<&Arc<dyn RouteRunner>> {
        self.runner.get()
    }
    pub fn failure_index(&self, name: &str) -> Result<usize, String> {
        find(Some(&self.names().failure), name, "failure_route")
    }
    pub fn onreply_index(&self, name: &str) -> Result<usize, String> {
        find(Some(&self.names().onreply), name, "onreply_route")
    }
    pub fn branch_index(&self, name: &str) -> Result<usize, String> {
        find(Some(&self.names().branch), name, "branch_route")
    }
    /// Event routes are optional: `None` when the script doesn't define it.
    pub fn event_index(&self, name: &str) -> Option<usize> {
        self.names().event.iter().position(|n| n == name)
    }
    pub fn has_event(&self, name: &str) -> bool {
        self.event_index(name).is_some()
    }

    /// Run `route[name]` on a context built from `msg` (or a faked
    /// request) — rtimer. `None` if there is no such route.
    pub fn run_route_with(&self, name: &str, net: &dyn Outbound, msg: Option<&[u8]>, prepare: impl FnOnce(&mut Ctx<'_, '_>)) -> Option<i32> {
        let runner = self.runner()?;
        let idx = runner.route_index(name)?;
        let fake = b"OPTIONS sip:you@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKroute\r\n\
From: <sip:route@127.0.0.1>;tag=r\r\nTo: <sip:you@127.0.0.1>\r\nCall-ID: route\r\nCSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let mut m = Msg::parse(msg.unwrap_or(fake), &arena).ok()?;
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        ctx.ext.push(Box::new(crate::module::FakedMsg));
        prepare(&mut ctx);
        Some(runner.run_route(idx, &mut ctx))
    }

    /// Run `event_route[name]` (if defined) on a context built from `msg`
    /// — a "faked" request when the event has no SIP message of its own.
    /// `prepare` can seed variables (e.g. `$avp`) before the route runs.
    /// Returns false if the route dropped.
    pub fn run_event_with(&self, name: &str, net: &dyn Outbound, msg: Option<&[u8]>, prepare: impl FnOnce(&mut Ctx<'_, '_>)) -> bool {
        let (Some(idx), Some(runner)) = (self.event_index(name), self.runner()) else { return true };
        let fake = b"OPTIONS sip:you@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKevent\r\n\
From: <sip:event@127.0.0.1>;tag=e\r\nTo: <sip:you@127.0.0.1>\r\nCall-ID: event\r\nCSeq: 1 OPTIONS\r\n\
Content-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let Ok(mut m) = Msg::parse(msg.unwrap_or(fake), &arena) else { return true };
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, net, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        ctx.ext.push(Box::new(crate::module::FakedMsg));
        prepare(&mut ctx);
        runner.run_event(idx, &mut ctx)
    }
}
