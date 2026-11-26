//! Typed signatures of script functions, for `.fsr` (docs/fsr.md):
//! declared next to each module (`Module::functions`), like parameter
//! schemas. The `.fsr` compiler type-checks calls against them and lowers
//! a call to the Kamailio-style function it names.

use crate::schema::Unit;

/// The type of one argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgTy {
    Str,
    Int,
    Bool,
    /// A duration; the function gets an integer in this unit.
    Duration(Unit),
    /// A SIP URI (a string the function parses).
    Uri,
    /// A named message flag (`flag NATED`), passed as its number.
    Flag,
    /// A variable the function writes its result to (an `.fsr` local).
    Var,
    /// One of these strings.
    Enum(&'static [&'static str]),
    /// A string or an integer, as the function takes either.
    Any,
}

/// One argument after the constant ones.
#[derive(Clone, Copy, Debug)]
pub struct Param {
    pub name: &'static str,
    pub ty: ArgTy,
    /// May be left out (only at the end).
    pub optional: bool,
    /// Passed when left out (`None`: nothing is passed, and no later
    /// argument either).
    pub default: Option<&'static str>,
    /// Must be written as a constant (the function reads it once, at
    /// startup): no variables, no `{…}` in a string.
    pub literal: bool,
    /// A sample value in `.fsr` syntax, for the signature test (when the
    /// type's own sample isn't accepted, e.g. a regex or an `ip:port`).
    pub eg: &'static str,
}

pub const fn arg(name: &'static str, ty: ArgTy) -> Param {
    Param { name, ty, optional: false, default: None, literal: false, eg: "" }
}

pub const fn opt(name: &'static str, ty: ArgTy) -> Param {
    Param { name, ty, optional: true, default: None, literal: false, eg: "" }
}

pub const fn opt_or(name: &'static str, ty: ArgTy, default: &'static str) -> Param {
    Param { name, ty, optional: true, default: Some(default), literal: false, eg: "" }
}

impl Param {
    /// Only a constant is accepted.
    pub const fn lit(mut self) -> Self {
        self.literal = true;
        self
    }
    /// A sample value (`.fsr` syntax) for the signature test.
    pub const fn eg(mut self, eg: &'static str) -> Self {
        self.eg = eg;
        self
    }
}

/// The result of an awaited call (`let r = await http.get(url)`): a record
/// whose fields are read from these pseudo-variables when the script
/// resumes, and kept with the transaction.
#[derive(Debug, PartialEq, Eq)]
pub struct AwaitTy {
    /// The type's name in `.fsr` (`HttpResponse`).
    pub name: &'static str,
    /// (field, pseudo-variable, type).
    pub fields: &'static [(&'static str, &'static str, FieldTy)],
}

/// A field of an `AwaitTy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldTy {
    Str,
    Int,
    Bool,
}

/// What a call gives back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ret {
    /// It suspends the request: only `await f(…)`, which gives the record
    /// once the result is in.
    Await(&'static AwaitTy),
    /// True/false (the function returns > 0 / < 0).
    Bool,
    /// The message is handled (replied, relayed): the route ends after it.
    Action,
    /// Nothing worth testing.
    Void,
}

/// Where a function may be called (bits).
pub mod ctx {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    /// `failure_route`, and the code after an `await`.
    pub const FAILURE: u8 = 4;
    pub const BRANCH: u8 = 8;
    pub const EVENT: u8 = 16;
    pub const ANY: u8 = REQUEST | REPLY | FAILURE | BRANCH | EVENT;
    /// Request processing, including after an `await`.
    pub const ROUTE: u8 = REQUEST | FAILURE | BRANCH;
}

#[derive(Clone, Copy, Debug)]
pub struct FnSig {
    /// The function the call lowers to (Kamailio name).
    pub name: &'static str,
    /// The `.fsr` name, in the module's namespace (`save` → `location.save`).
    pub fsr: &'static str,
    /// Put it in another namespace (`xlog` → `log.info`).
    pub ns: Option<&'static str>,
    /// Arguments passed first, before the typed ones (`"location"`).
    pub fixed: &'static [&'static str],
    pub params: &'static [Param],
    pub ret: Ret,
    /// `ctx` bits.
    pub allowed: u8,
    pub doc: &'static str,
}

/// A function `.fsr` doesn't offer, and why (`why` is shown when a
/// script asks for it): route arming (`t_on_failure`; `.fsr` has `await`
/// and `on reply`), or what a builtin covers (`setflag` → `msg.set`).
pub const fn hidden(name: &'static str, why: &'static str) -> FnSig {
    FnSig { name, fsr: "", ns: None, fixed: &[], params: &[], ret: Ret::Void, allowed: 0, doc: why }
}

/// `FnSig` with the common defaults: no constant arguments, the module's
/// namespace, allowed in request processing.
pub const fn sig(name: &'static str, fsr: &'static str, params: &'static [Param], ret: Ret, doc: &'static str) -> FnSig {
    FnSig { name, fsr, ns: None, fixed: &[], params, ret, allowed: ctx::ROUTE, doc }
}

impl FnSig {
    pub const fn fixed(mut self, f: &'static [&'static str]) -> Self {
        self.fixed = f;
        self
    }
    pub const fn ns(mut self, ns: &'static str) -> Self {
        self.ns = Some(ns);
        self
    }
    pub const fn allowed(mut self, a: u8) -> Self {
        self.allowed = a;
        self
    }
}
