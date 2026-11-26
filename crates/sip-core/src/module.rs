//! Module API: the per-message context, exported functions with fixups, and
//! the registry the script compiler resolves names against.
//!
//! Kamailio equivalent: `struct sip_msg` + `cmd_export_t` (name, function,
//! fixup) + `mod_init`/`child_init` (src/core/sr_module.h).

use crate::lumps::Lumps;
use crate::net::{Dest, Outbound, Proto, TransportEvent};
use crate::reply::build_reply_body;
use crate::sync::{lock, read, write};
use sip_parser::{HdrFlags, Msg};
use std::any::Any;
use std::any::TypeId;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

/// Script return code: success (true).
pub const RC_OK: i32 = 1;
/// Script return code: failure (false).
pub const RC_ERR: i32 = -1;
/// Script return code: stop the script (`drop`/`exit`).
pub const RC_DROP: i32 = 0;

/// [`RC_OK`] when `ok`, else [`RC_ERR`].
#[inline]
pub fn rc(ok: bool) -> i32 {
    if ok { RC_OK } else { RC_ERR }
}

/// A rewritten message body (textops `set_body`/`replace_body`, rtpengine
/// SDP…). Applied at render time as one body replacement plus a corrected
/// Content-Length (and Content-Type when given), so body edits compose.
#[derive(Clone, Debug, Default)]
pub struct BodyOverride {
    pub body: Vec<u8>,
    pub ctype: Option<String>,
}

/// Extra headers and body for the next stateless reply (`append_to_reply`,
/// `set_reply_body`).
#[derive(Clone, Debug, Default)]
pub struct ReplyExtra {
    pub headers: Vec<u8>,
    pub body: Option<(String, Vec<u8>)>,
}

/// sl statistics (Kamailio names).
fn sl_stats() -> &'static [&'static std::sync::atomic::AtomicI64; 7] {
    static S: std::sync::OnceLock<[&'static std::sync::atomic::AtomicI64; 7]> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        use crate::stats::counter;
        [
            counter("sl", "sent_replies"),
            counter("sl", "1xx_replies"),
            counter("sl", "2xx_replies"),
            counter("sl", "3xx_replies"),
            counter("sl", "4xx_replies"),
            counter("sl", "5xx_replies"),
            counter("sl", "6xx_replies"),
        ]
    })
}

/// Marks a context built around a synthetic or stored message (event
/// routes, failure routes) — corex `is_faked_msg()`.
pub struct FakedMsg;

/// The winning reply while a failure_route runs (uac_auth reads the
/// challenge from it).
#[derive(Clone, Debug, Default)]
pub struct FailureReply(pub Vec<u8>);

/// One additional fork target.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Branch {
    pub uri: Vec<u8>,
    /// Next hop (e.g. a registered client's connection); else from `uri`.
    pub dst: Option<Dest>,
    /// q-value in thousandths.
    pub q: Option<u16>,
    /// Route set for this branch (RFC 3327 Path of a registered contact),
    /// e.g. `<sip:edge1;lr>,<sip:edge2;lr>`; tm inserts it as a Route header.
    pub path: Option<Vec<u8>>,
    /// RFC 5626 `+sip.instance` / `reg-id` of a registered contact (flows).
    pub instance: Option<Vec<u8>>,
    pub reg_id: Option<u32>,
}

/// RFC 5626 instance / reg-id of the R-URI target (set by `lookup()`).
#[derive(Clone, Debug, Default)]
pub struct RuriFlow {
    pub instance: Option<Vec<u8>>,
    pub reg_id: Option<u32>,
}

/// Route set for the R-URI branch (set by `lookup()` from a contact's Path).
#[derive(Clone, Debug, Default)]
pub struct RuriPath(pub Vec<u8>);

/// While present, every stateless reply sent through this Ctx is copied
/// here (tm: a resumed request answered with `sl_send_reply` becomes the
/// transaction's reply).
#[derive(Clone, Debug, Default)]
pub struct ReplyCapture(pub Option<Vec<u8>>);

/// Present when the request already has a transaction (tm's `t_newtran`):
/// a reply sent with `reply` / `reply_with` is also recorded there (as its
/// last reply, and its final), so retransmissions get it again.
#[derive(Clone)]
pub struct ReplyHook(pub ReplyHookFn);

/// Called with each reply's code and bytes.
pub type ReplyHookFn = std::sync::Arc<dyn Fn(u16, &[u8]) + Send + Sync>;

/// Present while the request has a transaction that tm answers for it (a
/// failure route; a request route whose relay failed): sl's
/// `send_reply()` / `send_reply_error()` then reply through tm, as
/// Kamailio's do (sl.c:296-303 and 360-364 call tm's `t_reply` /
/// `t_reply_error` when `t_gett()` finds a transaction). Called with each
/// reply [`Ctx::send_reply`] built, before it is sent: false when the
/// transaction already has its final (t_reply.c `_reply_light()`: "can't
/// generate %d reply when a final %d was sent out"), and nothing is sent.
#[derive(Clone)]
pub struct TxnReply(pub TxnReplyFn);

/// See [`TxnReply`].
pub type TxnReplyFn = std::sync::Arc<dyn Fn(u16, &[u8]) -> bool + Send + Sync>;

/// Kamailio's `FL_DELAYED_REPLY` (tm.c:1916-1921): a request-route relay
/// failed and tm answers it once the script ends (tm's `delayed_reply`,
/// t_funcs.c:357-361), unless the script answers through tm first.
/// `sl_reply_error()` and `send_reply_error()` send nothing meanwhile
/// (sl_funcs.c:432-435, sl.c:355-358).
pub struct DelayedReply;

/// Run once `request_route` has ended (exit, drop or the end of the route;
/// not when it suspended): Kamailio's `POST_SCRIPT_CB`, where tm's
/// `t_unref()` sends a delayed error reply (t_lookup.c:2093-2125).
#[derive(Default)]
pub struct ScriptEnd(pub Vec<ScriptEndFn>);

/// See [`ScriptEnd`].
pub type ScriptEndFn = Box<dyn for<'x, 'y> FnOnce(&mut Ctx<'x, 'y>) + Send>;

/// `force_rport()` was called for this request: its replies go to the
/// source port even without `;rport` in its Via.
pub struct ForceRport;

/// Replies always go to the source address and port (core `force_rport`,
/// ferrosip's default); off: a UDP reply goes to the Via sent-by port
/// unless the Via has `;rport` (RFC 3261 §18.2.2, Kamailio's default).
static FORCE_RPORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

pub fn set_force_rport(on: bool) {
    FORCE_RPORT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Kamailio's core `max_branches` (`sr_dst_max_branches`, default 12): the
/// most branches of a transaction, the R-URI's included. The destination
/// set holds one less (`Ctx::append_branch`). Set by the core parameter
/// and by tm's `max_branches`; 1..30 (tm.c mod_init() refuses more).
static MAX_BRANCHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(12);

pub fn max_branches() -> usize {
    MAX_BRANCHES.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_max_branches(n: usize) {
    MAX_BRANCHES.store(n.clamp(1, 30), std::sync::atomic::Ordering::Relaxed);
}

/// Everything a route/module function can see while handling one message.
pub struct Ctx<'a, 'm> {
    pub msg: &'m mut Msg<'a>,
    pub lumps: &'m mut Lumps,
    /// Reusable per-worker output buffer.
    pub out: &'m mut Vec<u8>,
    /// Send side of all transports.
    pub net: &'m dyn Outbound,
    /// The receiving UDP worker's own socket: UDP sends from that worker go
    /// out on it directly (no shared fd, no lookup).
    pub udp: Option<&'m UdpSocket>,
    /// Where the message came from, including the TCP/TLS connection id.
    pub src: Dest,
    pub worker: usize,
    /// Why the last function failed, for `sl_reply_error()` (Kamailio's
    /// `ser_error` → reply code mapping).
    pub last_error: Option<(u16, &'static str)>,
    /// Rewritten Request-URI (Kamailio `$ru`), applied when rendering.
    pub new_ruri: Option<Vec<u8>>,
    /// Next-hop override (Kamailio `$du`), used by `t_relay()` without args.
    pub dst: Option<Dest>,
    /// Return code of the last script function (Kamailio `$rc`).
    pub rc: i32,
    /// q-value of the R-URI target (set by `lookup`); used for serial forking.
    pub ruri_q: Option<u16>,
    /// Additional targets (Kamailio's destination set / `append_branch`):
    /// `t_relay()` forks to the R-URI plus every branch here.
    pub branches: Vec<Branch>,
    /// Per-message state that modules attach (one value per type); empty
    /// unless used, so it costs nothing on the fast path.
    pub ext: Vec<Box<dyn Any + Send>>,
    /// A final reply went out statelessly (Kamailio's FL_FINAL_REPLY, set
    /// by sl's own finals only). A field, not an `ext` entry: every
    /// stateless reply sets it, and `ext` would allocate.
    pub answered: bool,
    /// The top Via was stamped on arrival (most requests): a field for the
    /// same reason.
    pub via_stamp: Option<ViaStamp<'a>>,
}

/// Called with the message context before anything is sent on its behalf
/// (relayed copies, replies), while its flags and variables are still at
/// hand. siptrace uses it for `trace_flag`. Hooks must not send through
/// the context themselves.
pub type CtxSendHook = Arc<dyn Fn(&Ctx<'_, '_>) + Send + Sync>;

static HAS_CTX_SEND_HOOKS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn ctx_send_hooks() -> &'static std::sync::RwLock<Vec<CtxSendHook>> {
    static H: std::sync::OnceLock<std::sync::RwLock<Vec<CtxSendHook>>> = std::sync::OnceLock::new();
    H.get_or_init(Default::default)
}

pub fn add_ctx_send_hook(h: CtxSendHook) {
    write(ctx_send_hooks()).push(h);
    HAS_CTX_SEND_HOOKS.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Set by `set_forward_no_connect()`: forwarded requests go only over
/// connections that are already open.
pub struct ForwardNoConnect;

/// The top Via was stamped with `received`/`rport` on arrival (the
/// message buffer holds the stamped copy): what it was, to give back the
/// bytes as received (`$ml`, `$mb`, `$msg(...)`, traces).
pub struct ViaStamp<'a> {
    pub start: usize,
    pub stamped_len: usize,
    /// The Via as received (in the message's arena).
    pub orig: &'a [u8],
}

impl<'a, 'm> Ctx<'a, 'm> {
    /// The message exactly as it arrived (before the Via stamp).
    pub fn received(&self) -> std::borrow::Cow<'_, [u8]> {
        let buf = self.msg.buf;
        match &self.via_stamp {
            Some(v)
                if let Some((before, stamped)) = buf.split_at_checked(v.start)
                    && let Some(after) = stamped.get(v.stamped_len..) =>
            {
                let mut out = Vec::with_capacity(buf.len());
                out.extend_from_slice(before);
                out.extend_from_slice(v.orig);
                out.extend_from_slice(after);
                std::borrow::Cow::Owned(out)
            }
            _ => std::borrow::Cow::Borrowed(buf),
        }
    }

    /// A fresh context (all script state empty).
    pub fn new(
        msg: &'m mut Msg<'a>,
        lumps: &'m mut Lumps,
        out: &'m mut Vec<u8>,
        net: &'m dyn Outbound,
        udp: Option<&'m UdpSocket>,
        src: Dest,
        worker: usize,
    ) -> Self {
        Ctx {
            msg,
            lumps,
            out,
            net,
            udp,
            src,
            worker,
            last_error: None,
            new_ruri: None,
            dst: None,
            rc: 1,
            ruri_q: None,
            branches: Vec::new(),
            ext: Vec::new(),
            answered: false,
            via_stamp: None,
        }
    }

    /// Per-message module state of type `T`, if set.
    pub fn ext<T: Any>(&self) -> Option<&T> {
        self.ext.iter().find_map(|b| b.downcast_ref::<T>())
    }

    /// Per-message module state of type `T`, if set (mutable).
    pub fn ext_get_mut<T: Any>(&mut self) -> Option<&mut T> {
        self.ext.iter_mut().find_map(|b| b.downcast_mut::<T>())
    }

    /// Per-message module state of type `T`, created on first use.
    pub fn ext_mut<T: Any + Send + Default>(&mut self) -> &mut T {
        let i = match self.ext.iter().position(|b| b.is::<T>()) {
            Some(i) => i,
            None => {
                self.ext.push(Box::new(T::default()));
                self.ext.len().saturating_sub(1)
            }
        };
        #[allow(clippy::expect_used, reason = "slot i holds a T: found by `is::<T>()` or just pushed")]
        self.ext.get_mut(i).and_then(|b| b.downcast_mut::<T>()).expect("type checked above")
    }

    /// The current Request-URI (rewritten or original).
    pub fn ruri(&self) -> &[u8] {
        self.new_ruri.as_deref().or(self.msg.ruri()).unwrap_or_default()
    }

    /// Kamailio's `msg_apply_changes()`: render the pending edits (lumps and
    /// R-URI) into a new buffer in the message arena and parse it again, so
    /// later reads see the edited message. The edits are then consumed.
    pub fn apply_changes(&mut self) -> Result<(), sip_parser::ParseError> {
        if self.lumps.is_empty() && self.new_ruri.is_none() {
            return Ok(());
        }
        let arena = self.msg.headers.bump();
        self.render();
        let buf: &'a [u8] = arena.alloc_slice_copy(self.out);
        let mut m = Msg::parse(buf, arena)?;
        m.parse_headers(HdrFlags::EOH)?;
        *self.msg = m;
        self.lumps.clear();
        self.new_ruri = None;
        Ok(())
    }

    /// Original buffer + lumps (+ R-URI rewrite) → `self.out`.
    pub fn render(&mut self) -> &[u8] {
        self.render_uri(None)
    }

    /// Like `render`, with an explicit Request-URI (one per fork branch).
    pub fn render_uri(&mut self, uri: Option<&[u8]>) -> &[u8] {
        let buf = self.msg.buf;
        self.out.clear();
        let mark = self.lumps.len();
        let new = uri.map(<[u8]>::to_vec).or_else(|| self.new_ruri.clone());
        if let (Some(new), Some(old)) = (new, self.msg.ruri()) {
            // Temporary lump: the rewrite may change again before the next render.
            self.lumps.replace(self.msg.offset_of(old), old.len(), new);
        }
        if let Some(b) = self.ext::<BodyOverride>().cloned() {
            self.body_lumps(&b);
        }
        self.lumps.apply(buf, self.out);
        self.lumps.truncate(mark);
        self.out
    }

    /// The current body (rewritten or original).
    pub fn body(&mut self) -> Vec<u8> {
        if let Some(b) = self.ext::<BodyOverride>() {
            return b.body.clone();
        }
        #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
        let _ = self.msg.parse_headers(sip_parser::HdrFlags::EOH);
        self.msg.body().unwrap_or_default().to_vec()
    }

    /// Replace the body (Content-Length is fixed when rendering).
    pub fn set_body(&mut self, body: Vec<u8>, ctype: Option<String>) {
        let o = self.ext_mut::<BodyOverride>();
        o.body = body;
        if ctype.is_some() {
            o.ctype = ctype;
        }
    }

    fn body_lumps(&mut self, b: &BodyOverride) {
        use sip_parser::{HdrFlags, HdrKind};
        if self.msg.parse_headers(HdrFlags::EOH).is_err() {
            return;
        }
        let buf = self.msg.buf;
        let eoh = self.msg.eoh_offset().unwrap_or(buf.len());
        let body_start = self.msg.body().map_or(buf.len(), |x| self.msg.offset_of(x));
        self.lumps.replace(body_start, buf.len().saturating_sub(body_start), b.body.clone());
        let mut hdrs = Vec::new();
        for h in self.msg.headers.iter() {
            let ct = h.name.eq_ignore_ascii_case(b"content-type") || h.name.eq_ignore_ascii_case(b"c");
            if h.kind == HdrKind::ContentLength || (ct && b.ctype.is_some()) {
                self.lumps.delete(h.start, h.end.saturating_sub(h.start));
            }
        }
        if let Some(ct) = &b.ctype
            && !b.body.is_empty()
        {
            hdrs.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
        }
        hdrs.extend_from_slice(format!("Content-Length: {}\r\n", b.body.len()).as_bytes());
        self.lumps.insert(eoh, hdrs);
    }

    pub fn send(&self, dst: &Dest, data: &[u8]) -> io::Result<()> {
        if HAS_CTX_SEND_HOOKS.load(std::sync::atomic::Ordering::Relaxed) {
            for h in read(ctx_send_hooks()).iter() {
                h(self);
            }
        }
        match (dst.proto, self.udp) {
            // Counted here (the transport's `Outbound::send` counts its own).
            (Proto::Udp, Some(s)) => crate::net::note_send(dst, s.send_to(&crate::net::filtered(dst, data), dst.addr).map(|_| ())),
            _ => self.net.send(dst, data),
        }
    }

    /// Render with lumps applied and send to `dst` (result stays in `self.out`).
    pub fn send_rendered(&mut self, dst: &Dest) -> io::Result<()> {
        self.render();
        let data: &[u8] = self.out;
        self.send(dst, data)
    }

    /// Address for our Via when sending over `proto`.
    pub fn advertise(&self, proto: Proto) -> SocketAddr {
        self.net.advertise(proto).unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 5060)))
    }

    /// Where replies to this request go: its source, except over UDP when
    /// `force_rport` is off and the Via has no `;rport` (and the script
    /// didn't call `force_rport()`): the source IP and the Via's sent-by
    /// port (RFC 3261 §18.2.2).
    pub fn reply_dest(&mut self) -> Dest {
        let src = self.src;
        if src.proto != crate::Proto::Udp || FORCE_RPORT.load(std::sync::atomic::Ordering::Relaxed) || self.ext::<ForceRport>().is_some() {
            return src;
        }
        if !self.msg.is_request() || self.msg.parse_headers(sip_parser::HdrFlags::VIA).is_err() {
            return src;
        }
        match self.msg.via1 {
            Some(v) if v.rport.is_none() => Dest { addr: SocketAddr::new(src.addr.ip(), v.port.unwrap_or(5060)), ..src },
            _ => src,
        }
    }

    /// Stateless reply back to the sender.
    pub fn reply(&mut self, code: u16, reason: &str) -> io::Result<()> {
        self.reply_with(code, reason, b"")
    }

    /// Stateless reply with extra header lines (each ending in CRLF).
    pub fn reply_with(&mut self, code: u16, reason: &str, extra: &[u8]) -> io::Result<()> {
        self.reply_via(code, reason, extra, None).map(|_| ())
    }

    /// sl's `send_reply()`: through the request's transaction while tm
    /// answers for it ([`TxnReply`]), else stateless. `Ok(false)`: the
    /// transaction already had its final, nothing was sent.
    pub fn send_reply(&mut self, code: u16, reason: &str) -> io::Result<bool> {
        let txn = self.ext::<TxnReply>().cloned();
        self.reply_via(code, reason, b"", txn)
    }

    /// tm answers for the request ([`TxnReply`]): `send_reply()` replies
    /// through it (Kamailio: `t_gett()` finds a transaction).
    pub fn in_txn(&self) -> bool {
        self.ext::<TxnReply>().is_some()
    }

    /// Queue `f` for the end of `request_route` ([`ScriptEnd`]).
    pub fn at_script_end(&mut self, f: ScriptEndFn) {
        self.ext_mut::<ScriptEnd>().0.push(f);
    }

    /// Run what [`Ctx::at_script_end`] queued (the script engine calls this
    /// once `request_route` has ended).
    pub fn run_script_end(&mut self) {
        let Some(i) = self.ext.iter().position(|b| b.is::<ScriptEnd>()) else { return };
        let Ok(end) = self.ext.swap_remove(i).downcast::<ScriptEnd>() else { return };
        for f in end.0 {
            f(self);
        }
    }

    fn reply_via(&mut self, code: u16, reason: &str, extra: &[u8], txn: Option<TxnReply>) -> io::Result<bool> {
        self.out.clear();
        // An ACK is never answered (RFC 3261 §17.2.1); Kamailio's sl drops it too.
        if self.msg.method() == Some(sip_parser::Method::Ack) {
            return Ok(true);
        }
        // Borrowed from `ext` (a field apart from `msg` and `out`), and the
        // headers copied only when both sources have some.
        let rx = self.ext.iter().find_map(|b| b.downcast_ref::<ReplyExtra>());
        let hdrs: std::borrow::Cow<'_, [u8]> = match rx.map(|r| r.headers.as_slice()) {
            None | Some([]) => extra.into(),
            Some(h) if extra.is_empty() => h.into(),
            Some(h) => [h, extra].concat().into(),
        };
        let body = rx.and_then(|r| r.body.as_ref()).map(|(t, b)| (t.as_str(), b.as_slice()));
        build_reply_body(self.msg, code, reason, &hdrs, body, self.out).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
        let through_txn = txn.is_some();
        if let Some(t) = txn {
            if !(t.0)(code, self.out) {
                return Ok(false);
            }
        } else {
            let s = sl_stats();
            let [sent, ..] = s;
            crate::stats::inc(sent);
            // 1xx..6xx: the counter of the class.
            if (100..700).contains(&code)
                && let Some(class) = s.get(usize::from(code / 100))
            {
                crate::stats::inc(class);
            }
        }
        if self.ext.iter().any(|e| e.is::<ReplyCapture>()) {
            let copy = self.out.clone();
            self.ext_mut::<ReplyCapture>().0 = Some(copy);
        }
        if let Some(h) = self.ext::<ReplyHook>().cloned() {
            (h.0)(code, self.out);
        }
        // Kamailio's FL_FINAL_REPLY: set by sl's own finals only.
        if code >= 200 && !through_txn {
            self.answered = true;
        }
        let to = self.reply_dest();
        let data: &[u8] = self.out;
        self.send(&to, data).map(|()| true)
    }

    /// Add a target to the destination set (Kamailio core dset.c
    /// `append_branch()`). It holds at most `max_branches - 1` entries, the
    /// R-URI being branch 0 (dset.c:479): past that the branch is refused,
    /// logged ("max nr of branches exceeded"), the error is
    /// E_TOO_MANY_BRANCHES (for `sl_reply_error()`), and this is false.
    pub fn append_branch(&mut self, b: Branch) -> bool {
        if self.branches.len() >= max_branches().saturating_sub(1) {
            crate::elog!("max nr of branches exceeded");
            self.last_error = Some(crate::error::SL_E_TOO_MANY_BRANCHES);
            return false;
        }
        self.branches.push(b);
        true
    }

    /// A final reply was already sent statelessly for this request (by a
    /// function that answers on failure, like registrar's save).
    pub fn answered(&self) -> bool {
        self.answered
    }
}

/// Literal arguments as written in the config file.
#[derive(Clone, Debug)]
pub enum Arg {
    Str(String),
    Int(i64),
    /// A string with variables (`"$fU@$fd"`, `$avp(x)`), evaluated per message.
    Fmt(Arc<crate::pv::Fmt>),
}

impl Arg {
    pub fn str(&self) -> Result<&str, String> {
        match self {
            Arg::Str(s) => Ok(s),
            Arg::Int(i) => Err(format!("expected string, got {i}")),
            Arg::Fmt(_) => Err("this parameter can't contain variables".into()),
        }
    }
    pub fn int(&self) -> Result<i64, String> {
        match self {
            Arg::Int(i) => Ok(*i),
            // Kamailio also takes yes/no, on/off, true/false.
            Arg::Str(s) => s.trim().parse().or_else(|_| match s.trim().to_ascii_lowercase().as_str() {
                "yes" | "on" | "true" => Ok(1),
                "no" | "off" | "false" => Ok(0),
                _ => Err(format!("expected integer, got {s:?}")),
            }),
            Arg::Fmt(_) => Err("this parameter can't contain variables".into()),
        }
    }
    /// A string parameter that may contain variables.
    pub fn dyn_str(&self) -> Result<DynStr, String> {
        Ok(match self {
            Arg::Str(s) => DynStr::Static(s.clone()),
            Arg::Int(i) => DynStr::Static(i.to_string()),
            Arg::Fmt(f) => DynStr::Fmt(f.clone()),
        })
    }
    /// An integer parameter that may be a variable.
    pub fn dyn_int(&self) -> Result<DynInt, String> {
        Ok(match self {
            Arg::Fmt(f) => DynInt::Fmt(f.clone()),
            a => DynInt::Static(a.int()?),
        })
    }
}

/// String parameter: fixed at startup, or a template evaluated per message.
#[derive(Clone, Debug)]
pub enum DynStr {
    Static(String),
    Fmt(Arc<crate::pv::Fmt>),
}

impl DynStr {
    pub fn eval<'s>(&'s self, ctx: &mut Ctx<'_, '_>) -> std::borrow::Cow<'s, str> {
        match self {
            DynStr::Static(s) => std::borrow::Cow::Borrowed(s),
            DynStr::Fmt(f) => std::borrow::Cow::Owned(f.eval(ctx)),
        }
    }
    pub fn is_static(&self) -> bool {
        matches!(self, DynStr::Static(_))
    }
}

/// Integer parameter: fixed, or a variable evaluated per message.
#[derive(Clone, Debug)]
pub enum DynInt {
    Static(i64),
    Fmt(Arc<crate::pv::Fmt>),
}

impl DynInt {
    pub fn eval(&self, ctx: &mut Ctx<'_, '_>) -> Option<i64> {
        match self {
            DynInt::Static(i) => Some(*i),
            DynInt::Fmt(f) => f.eval(ctx).trim().parse().ok(),
        }
    }
}

pub type Fixed = Box<dyn Any + Send + Sync>;
pub type FixupFn = Arc<dyn Fn(&[Arg]) -> Result<Fixed, String> + Send + Sync>;
/// Return value follows Kamailio: >0 true, <0 false, 0 = exit the route.
pub type ExportFn = Arc<dyn Fn(&mut Ctx<'_, '_>, &(dyn Any + Send + Sync)) -> i32 + Send + Sync>;

#[derive(Clone)]
pub struct Export {
    pub module: &'static str,
    pub fixup: FixupFn,
    pub func: ExportFn,
}

pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    /// `mod_init`: register exported functions (and APIs for other modules).
    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String>;
    /// `modparam("<module>", name, value)`, applied before `register`.
    fn set_param(&self, name: &str, _value: &Arg) -> Result<(), String> {
        Err(format!("module {} has no parameter {name:?}", self.name()))
    }
    /// Called for every SIP reply before it is dropped. Return true if consumed.
    fn on_reply(&self, _ctx: &mut Ctx<'_, '_>) -> bool {
        false
    }
    /// Start helper threads (timers, DB flushers…) — Kamailio forks extra
    /// processes for this. `net` sends over any transport.
    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        Ok(())
    }
    /// Connection opened/closed notifications (runs on a transport thread).
    fn on_transport_event(&self, _ev: &TransportEvent) {}
    /// True if the module wants `observe_request` / `observe_reply` (only
    /// those modules are called, so the hooks cost nothing otherwise).
    fn observes(&self) -> bool {
        false
    }
    /// Sees every request before `request_route` (Kamailio: the dialog
    /// module's in-dialog matching hooks).
    fn observe_request(&self, _ctx: &mut Ctx<'_, '_>) {}
    /// Sees every reply before `reply_route` and before tm consumes it
    /// (Kamailio: tm callbacks such as TMCB_RESPONSE_IN).
    fn observe_reply(&self, _ctx: &mut Ctx<'_, '_>) {}
    /// Work in flight that a graceful shutdown should wait for (tm: requests
    /// still waiting for their final reply).
    fn busy(&self) -> usize {
        0
    }
    /// Last call before a graceful exit: persist state (usrloc write-back).
    fn shutdown(&self) {}
    /// The module's parameters (ferrosip.toml validation, `ferrosip
    /// schema`). `None`: no schema yet, values go to `set_param` as given.
    fn params(&self) -> Option<Vec<crate::schema::ParamSpec>> {
        None
    }
    /// Typed signatures of the module's script functions (`.fsr`).
    /// `None`: none declared yet.
    fn functions(&self) -> Option<Vec<crate::sig::FnSig>> {
        None
    }
    /// Modules that must be loaded (and registered) before this one, by
    /// their Kamailio names: ferrosip.toml loads in dependency order.
    fn requires(&self) -> &'static [&'static str] {
        &[]
    }
}

/// The dispatcher the transport layer calls for every received message.
pub trait Handler: Send + Sync {
    fn handle(&self, ctx: &mut Ctx<'_, '_>);
    fn transport_event(&self, _ev: &TransportEvent) {}
    /// A WebSocket upgrade request (`req` = the HTTP request head) passed
    /// the built-in checks; false refuses it with 403
    /// (`event_route[websocket:handshake]` saying `drop`).
    fn ws_handshake(&self, _net: &dyn crate::Outbound, _req: &[u8], _src: Dest) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Registry {
    funcs: HashMap<String, Export>,
    pub modules: Vec<Arc<dyn Module>>,
    apis: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    /// Script routes that modules can trigger (failure/onreply routes).
    pub hub: Arc<crate::route::RouteHub>,
    /// Pseudo-variables by name (`$ru`, `$avp(x)`, …).
    pvs: crate::pv::PvTable,
    /// Management commands (JSON-RPC), served by `RpcTable::serve_unix`.
    pub rpc: Arc<crate::rpc::RpcTable>,
    /// Registration conflicts (a variable or function registered twice),
    /// reported by [`Registry::load`] / [`Registry::check`].
    conflicts: Vec<String>,
}

impl Registry {
    pub fn load(&mut self, m: Arc<dyn Module>) -> Result<(), String> {
        let name = m.name();
        self.modules.push(m.clone());
        m.register(self)?;
        self.check().map_err(|e| format!("module {name}: {e}"))
    }

    /// Fails if a variable or function was registered twice since the last
    /// check (the first registration is kept).
    pub fn check(&mut self) -> Result<(), String> {
        if self.conflicts.is_empty() {
            return Ok(());
        }
        Err(std::mem::take(&mut self.conflicts).join("; "))
    }

    /// Publish a typed API for other modules (Kamailio's `bind_*` / `load_*_api`).
    pub fn provide<T: Any + Send + Sync>(&mut self, api: Arc<T>) {
        self.apis.insert(TypeId::of::<T>(), api);
    }

    /// Register a pseudo-variable (`$name` / `$name(param)`).
    pub fn pv(&mut self, name: &str, spec: crate::pv::PvSpec) {
        match self.pvs.entry(name.to_string()) {
            std::collections::hash_map::Entry::Occupied(_) => self.conflicts.push(format!("variable ${name} registered twice")),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(spec);
            }
        }
    }

    pub fn pvs(&self) -> &crate::pv::PvTable {
        &self.pvs
    }

    /// Bind to an API published by an already-loaded module.
    pub fn api<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.apis.get(&TypeId::of::<T>()).cloned().and_then(|a| a.downcast::<T>().ok())
    }

    /// Register a script function. `fixup` runs once at startup and turns the
    /// literal args into a ready-to-use value `A` (parsed address, enum…);
    /// `func` runs per message and receives that pre-computed value.
    pub fn export<A, FX, F>(&mut self, module: &'static str, name: &str, fixup: FX, func: F)
    where
        A: Any + Send + Sync,
        FX: Fn(&[Arg]) -> Result<A, String> + Send + Sync + 'static,
        F: Fn(&mut Ctx<'_, '_>, &A) -> i32 + Send + Sync + 'static,
    {
        let fixup: FixupFn = Arc::new(move |args| fixup(args).map(|a| Box::new(a) as Fixed));
        let fname = format!("{module}.{name}");
        let func: ExportFn = Arc::new(move |ctx: &mut Ctx<'_, '_>, a: &(dyn Any + Send + Sync)| match a.downcast_ref::<A>() {
            Some(a) => func(ctx, a),
            None => {
                crate::elog!("ferrosip: BUG: {fname}() called with arguments from another function's fixup");
                -1
            }
        });
        match self.funcs.entry(name.to_string()) {
            std::collections::hash_map::Entry::Occupied(_) => self.conflicts.push(format!("function {name} exported twice")),
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(Export { module, fixup, func });
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<&Export> {
        self.funcs.get(name)
    }

    /// Replace what an exported function does, keeping its argument
    /// checks (`ferrosip test` mocks). False if there is no such function.
    /// Must happen before the routes are compiled.
    pub fn override_func(&mut self, name: &str, func: ExportFn) -> bool {
        match self.funcs.get_mut(name) {
            Some(e) => {
                e.func = func;
                true
            }
            None => false,
        }
    }

    /// Every exported function: (name, export).
    pub fn exports(&self) -> impl Iterator<Item = (&String, &Export)> {
        self.funcs.iter()
    }
}

/// Helper for fixups that expect exactly N args.
pub fn want_args(args: &[Arg], n: usize) -> Result<(), String> {
    if args.len() == n { Ok(()) } else { Err(format!("expected {n} argument(s), got {}", args.len())) }
}

/// Exactly `N` arguments, as an array to destructure:
/// `let [uri, q] = args(a)?;`.
pub fn args<const N: usize>(args: &[Arg]) -> Result<&[Arg; N], String> {
    args.try_into().map_err(|_| format!("expected {N} argument(s), got {}", args.len()))
}

/// A Kamailio module parameter that ferrosip accepts but that changes
/// nothing here (the behaviour is fixed, or configured another way). Logged
/// once per parameter at startup, so configs written for Kamailio load and
/// the operator still sees what isn't honoured.
pub fn param_no_effect(module: &str, name: &str) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    let key = format!("{module}.{name}");
    if lock(SEEN.get_or_init(Default::default)).insert(key) {
        crate::elog!("ferrosip: note: modparam(\"{module}\", \"{name}\") is accepted but has no effect in ferrosip");
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    struct Twice;

    impl Module for Twice {
        fn name(&self) -> &'static str {
            "twice"
        }
        fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
            for _ in 0..2 {
                reg.export("twice", "twice_fn", |_: &[Arg]| Ok(()), |_: &mut Ctx, _: &()| 1);
                reg.pv("twice_pv", crate::pv::PvSpec::ro(|_, _| crate::pv::Val::Null));
            }
            Ok(())
        }
    }

    #[test]
    fn registering_twice_is_a_load_error() {
        let mut reg = Registry::default();
        let e = reg.load(Arc::new(Twice)).unwrap_err();
        assert!(e.contains("module twice") && e.contains("function twice_fn exported twice") && e.contains("variable $twice_pv registered twice"), "{e}");
        assert!(reg.check().is_ok(), "reported once");
        assert!(reg.get("twice_fn").is_some(), "the first registration stays");
    }
}

#[cfg(test)]
mod dset_tests {
    use super::*;
    use bumpalo::Bump;

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// Kamailio core dset.c append_branch(): at most max_branches - 1
    /// entries (the R-URI is branch 0), then -1 with E_TOO_MANY_BRANCHES.
    #[test]
    fn destination_set_holds_max_branches_minus_one() {
        let req = b"OPTIONS sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKd\r\nFrom: <sip:b@x>;tag=1\r\n\
To: <sip:a@x>\r\nCall-ID: d\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let mut m = Msg::parse(req, &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        assert_eq!(max_branches(), 12);
        let b = || Branch { uri: b"sip:c@x".to_vec(), ..Default::default() };
        assert!((0..11).all(|_| ctx.append_branch(b())));
        assert!(ctx.last_error.is_none());
        assert!(!ctx.append_branch(b()));
        assert_eq!(ctx.branches.len(), 11);
        assert_eq!(ctx.last_error, Some((500, "Forking capacity exceeded (12/SL)")));
    }

    /// Records what goes out.
    #[derive(Default)]
    struct Sent(std::sync::Mutex<Vec<Vec<u8>>>);
    impl Outbound for Sent {
        fn send(&self, _: &Dest, m: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(m.to_vec());
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// sl's send_reply() goes through the transaction while tm answers for
    /// the request: one final (t_reply.c _reply_light()), not an sl final
    /// (FL_FINAL_REPLY). Script-end callbacks run once, in order.
    #[test]
    fn send_reply_through_the_transaction() {
        let req = b"MESSAGE sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKd\r\nFrom: <sip:b@x>;tag=1\r\n\
To: <sip:a@x>\r\nCall-ID: d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n";
        let arena = Bump::new();
        let mut m = Msg::parse(req, &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let net = Sent::default();
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &net, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        assert!(!ctx.in_txn());
        let finals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let f = finals.clone();
        ctx.ext.push(Box::new(TxnReply(Arc::new(move |code, r| {
            assert!(r.starts_with(format!("SIP/2.0 {code} ").as_bytes()));
            code < 200 || f.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0
        }))));
        assert!(ctx.in_txn());
        assert!(ctx.send_reply(180, "Ringing").unwrap());
        assert!(ctx.send_reply(503, "Mine").unwrap());
        assert!(!ctx.send_reply(500, "Again").unwrap(), "the transaction has its final");
        assert!(!ctx.answered(), "a reply through tm isn't sl's final");
        let sent: Vec<Vec<u8>> = net.0.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        assert!(sent[1].starts_with(b"SIP/2.0 503 Mine\r\n"));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        for i in 0..2 {
            let o = order.clone();
            ctx.at_script_end(Box::new(move |_| o.lock().unwrap().push(i)));
        }
        ctx.run_script_end();
        ctx.run_script_end();
        assert_eq!(*order.lock().unwrap(), [0, 1]);
    }
}
