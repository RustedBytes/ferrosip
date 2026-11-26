//! registrar — REGISTER processing and location lookup (Kamailio `registrar`).
//!
//! * `save("location")` — RFC 3261 §10.3: binds the Contacts of a REGISTER
//!   to the To AoR in usrloc and answers it (200 with the current bindings,
//!   or 400/423/500/503). Bindings are matched by `+sip.instance`/`reg-id`
//!   (RFC 5626) when present, else by Contact URI. Each binding remembers
//!   the transport, address and *connection* the REGISTER came from.
//! * `lookup("location")` — R-URI AoR → best contact (highest q, then most
//!   recent): rewrites the R-URI (`$ru`) and sets the next hop (`$du`) to the
//!   address/connection the client registered from, so `t_relay()` reaches
//!   clients behind NAT and on TCP/TLS/WebSocket connections.
//! * `registered("location"[, uri[, match_option[, match_action]]])` — does
//!   the R-URI (or `uri`) AoR have a binding?
//! * `save(table, flags, uri)`: flags 0x01 memory only, 0x02 no reply,
//!   0x04 one contact per AoR (0x08 accepted, no effect); `uri` is the AoR
//!   to save under. `lookup(table, uri)` looks up `uri`'s AoR.
//! * `lookup_branches`, `unregister(table, uri[, ruid])`,
//!   `reg_fetch_contacts(table, uri, profile)` / `reg_free_contacts` and
//!   `$ulc(profile=>attr)` (kept per message, like `$dbr`).
//!
//! Parameters: `default_expires` (3600), `min_expires` (60), `max_expires`
//! (86400), `max_contacts` (0 = unlimited), `use_received` (1: route to the
//! source of the REGISTER; 0: to the Contact URI for UDP), `use_path` (0),
//! `path_mode` (2).
//!
//! Path (RFC 3327): with `use_path=1` the Path headers of a REGISTER are
//! stored with its contacts; `lookup()` then sends requests to the first
//! Path hop with the whole Path as Route set. `path_mode` 0: store Path
//! without echoing it; 1: Path is mandatory (420 without it) and always
//! echoed; 2: echo Path in the 200 OK if the client said `Supported: path`
//! (the default).
//!
//! Branch flags set before `save()` (`setbflag`) are stored with the
//! contacts and restored by `lookup()` (nathelper's NAT flag).
//!
//! GRUU (RFC 5627, `gruu_enabled`): clients with `+sip.instance` and
//! `Supported: gruu` get `pub-gruu`/`temp-gruu` in the 200; `lookup()` of a
//! GRUU R-URI reaches only that instance. Outbound (RFC 5626,
//! `outbound_mode` 1): `Require: outbound` in the 200 for flows with
//! `reg-id` + instance.

pub mod store;

use sip_core::module::{DynInt, DynStr, ReplyExtra, RuriPath};
use sip_core::pv::{PvIdx, PvParam, PvSpec, Val};
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p, pr};
use sip_core::sig::FnSig;
use sip_core::sync::lock;
use sip_core::{Arg, Branch, Ctx, Dest, Module, Proto, Registry, want_args};
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::util::parse_u32;
use sip_parser::{HdrFlags, HdrKind, Method, parse_uri};
use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use store::{Contact, FL_MEM, Usrloc};

/// `save()` flags (Kamailio registrar).
/// 0x01: the contacts stay in memory (never written to the database).
const SAVE_MEMORY_ONLY: u32 = 0x01;
/// 0x02: no reply; the script answers (the 200's Contact lines are added to
/// the next stateless reply).
const SAVE_NO_REPLY: u32 = 0x02;
/// 0x04: one contact per AoR: bindings this REGISTER doesn't add or
/// refresh are removed.
const SAVE_SINGLE: u32 = 0x04;
/// 0x10: with 0x02, prepare the 200's header lines for the script's reply.
const SAVE_PREPARE_REPLY: u32 = 0x10;
/// Every flag Kamailio knows (0x08, "no expires_range", has no effect).
const SAVE_ALL: u32 = 0x1f;

pub struct Registrar {
    default_expires: AtomicU32,
    min_expires: AtomicU32,
    max_expires: AtomicU32,
    max_contacts: AtomicU32,
    use_received: AtomicBool,
    append_branches: AtomicBool,
    use_path: AtomicBool,
    path_mode: AtomicU32,
    gruu_enabled: AtomicBool,
    outbound_mode: AtomicU32,
    /// xavp whose `match_callid` / `match_contact` / `match_received`
    /// fields `registered()`'s match_option compares with.
    xavp_cfg: Mutex<String>,
    /// xavp `registered()`'s match_action 1 fills from the matched contact.
    xavp_rcd: Mutex<String>,
    ul: OnceLock<Arc<Usrloc>>,
}

impl Default for Registrar {
    fn default() -> Self {
        Self {
            default_expires: AtomicU32::new(3600),
            min_expires: AtomicU32::new(60),
            max_expires: AtomicU32::new(86400),
            max_contacts: AtomicU32::new(0),
            use_received: AtomicBool::new(true),
            append_branches: AtomicBool::new(true),
            use_path: AtomicBool::new(false),
            path_mode: AtomicU32::new(2),
            gruu_enabled: AtomicBool::new(true),
            outbound_mode: AtomicU32::new(0),
            xavp_cfg: Mutex::new(String::new()),
            xavp_rcd: Mutex::new(String::new()),
            ul: OnceLock::new(),
        }
    }
}

/// Owned copy of one Contact entry (the message buffer is borrowed by Ctx).
struct Spec {
    star: bool,
    uri: Vec<u8>,
    expires: Option<u32>,
    q: Option<u16>,
    instance: Option<Vec<u8>>,
    reg_id: Option<u32>,
}

struct RegisterReq {
    aor: Box<[u8]>,
    callid: Vec<u8>,
    cseq: u32,
    expires: Option<u32>,
    user_agent: Vec<u8>,
    contacts: Vec<Spec>,
    /// Path header values joined with `,` (when `use_path`).
    path: Option<Vec<u8>>,
    /// The client supports Path (`Supported: path`).
    path_supported: bool,
    /// `Supported: gruu` / `Supported: outbound`.
    gruu_supported: bool,
    ob_supported: bool,
    /// `sip:user@host` of the To URI (for GRUUs).
    aor_uri: String,
    cflags: u32,
    /// Allow header as METHOD_* bits (`u32::MAX` without one).
    methods: u32,
    /// `save()` flags.
    flags: u32,
}

enum Outcome {
    /// Saved; the 200's header lines (Contact for every current binding…)
    /// and save()'s return code (Kamailio's: 1 inserted, 2 updated, 3
    /// deleted, 4 a query).
    Ok(Vec<u8>, i32),
    Fail(u16, &'static str, String),
}

impl Registrar {
    /// The usrloc bound in `register()`. Every function, pseudo-variable
    /// and RPC that reaches here is exported by `register()` after binding
    /// it (which fails if usrloc is not loaded), so it is always set.
    #[allow(clippy::expect_used, reason = "set in register() before any export that calls it is registered")]
    fn ul(&self) -> &Usrloc {
        self.ul.get().expect("usrloc bound in register()")
    }

    /// `aor_uri`: the AoR to save under (save()'s uri argument) instead of
    /// the To URI.
    fn parse_register(&self, ctx: &mut Ctx<'_, '_>, aor_uri: Option<&str>, flags: u32) -> Result<RegisterReq, &'static str> {
        let m = &mut *ctx.msg;
        m.parse_headers(HdrFlags::EOH).map_err(|_| "Malformed message")?;
        let to = m.get(HdrKind::To).ok_or("Missing To")?;
        let to_uri = match aor_uri {
            Some(u) => parse_uri(u.as_bytes()).ok_or("Bad AoR URI")?,
            None => parse_uri(name_addr(to.body).0).ok_or("Bad To URI")?,
        };
        let user = to_uri.user.ok_or(if aor_uri.is_some() { "AoR URI has no user" } else { "To URI has no user" })?;
        let aor = self.ul().aor(user, to_uri.host);
        let callid = m.get(HdrKind::CallId).ok_or("Missing Call-ID")?.body.to_vec();
        let cseq = m.get(HdrKind::CSeq).ok_or("Missing CSeq")?.body;
        let cseq = parse_u32(cseq.split(|c| c.is_ascii_whitespace()).next().unwrap_or(b"")).ok_or("Bad CSeq")?;
        let expires = match m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"expires")) {
            Some(h) => Some(parse_u32(h.body).ok_or("Bad Expires")?),
            None => None,
        };
        let user_agent = m.get(HdrKind::UserAgent).map_or(vec![], |h| h.body.to_vec());
        let mut allow = m.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"allow")).peekable();
        let methods = if allow.peek().is_some() { allow.flat_map(|h| split_list(h.body)).map(method_bit).fold(0, |a, b| a | b) } else { u32::MAX };
        let mut contacts = Vec::new();
        for h in m.headers.iter().filter(|h| h.kind == HdrKind::Contact) {
            for item in split_list(h.body) {
                let c = parse_contact(item);
                if !c.star && parse_uri(c.uri).is_none() {
                    return Err("Bad Contact URI");
                }
                contacts.push(Spec {
                    star: c.star,
                    uri: c.uri.to_vec(),
                    expires: c.expires,
                    q: c.q,
                    instance: c.instance.map(<[u8]>::to_vec),
                    reg_id: c.reg_id,
                });
            }
        }
        let mut path: Option<Vec<u8>> = None;
        if self.use_path.load(Ordering::Relaxed) {
            for h in m.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"path")) {
                let p = path.get_or_insert_with(Vec::new);
                if !p.is_empty() {
                    p.push(b',');
                }
                p.extend_from_slice(h.body);
            }
        }
        let supports = |tok: &[u8]| {
            m.headers.iter().any(|h| {
                (h.name.eq_ignore_ascii_case(b"supported") || h.name.eq_ignore_ascii_case(b"k") || h.name.eq_ignore_ascii_case(b"require"))
                    && split_list(h.body).iter().any(|t| t.eq_ignore_ascii_case(tok))
            })
        };
        let (path_supported, gruu_supported, ob_supported) = (supports(b"path"), supports(b"gruu"), supports(b"outbound"));
        let aor_uri = format!("sip:{}@{}", String::from_utf8_lossy(user), String::from_utf8_lossy(to_uri.host));
        let cflags = ctx.ext::<sip_core::TxnVars>().map_or(0, |t| t.bflags);
        Ok(RegisterReq {
            aor,
            callid,
            cseq,
            expires,
            user_agent,
            contacts,
            path,
            path_supported,
            gruu_supported,
            ob_supported,
            aor_uri,
            cflags,
            methods,
            flags,
        })
    }

    /// RFC 3261 §10.3 steps 6–8, applied all-or-nothing.
    fn apply(&self, r: &RegisterReq, src: Dest) -> Outcome {
        let (min, max) = (self.min_expires.load(Ordering::Relaxed), self.max_expires.load(Ordering::Relaxed));
        let default = self.default_expires.load(Ordering::Relaxed);
        if r.contacts.iter().any(|c| c.star) && (r.contacts.len() != 1 || r.expires != Some(0)) {
            return Outcome::Fail(400, "Invalid Contact *", String::new()); // §10.3 step 6
        }
        // Expiry per contact; reject too-brief intervals with 423 (§10.3 step 7).
        let mut exps = Vec::with_capacity(r.contacts.len());
        for c in &r.contacts {
            let e = c.expires.or(r.expires).unwrap_or(default);
            if e != 0 && e < min {
                return Outcome::Fail(423, "Interval Too Brief", format!("Min-Expires: {min}\r\n"));
            }
            exps.push(e.min(max));
        }
        let max_contacts = self.max_contacts.load(Ordering::Relaxed) as usize;
        let same = |c: &Spec, b: &Contact| match (&c.instance, &b.instance) {
            (Some(i), Some(j)) => *i == *j && c.reg_id == b.reg_id,
            _ => b.uri == c.uri,
        };
        let cseq_delay = u64::from(self.ul().cseq_delay()) * 1000;
        self.ul().update(&r.aor, |list, now| {
            let mut new = list.clone();
            // save()'s return code (Kamailio's save.c): 4 for a query, 3 for
            // `*`, 1 for a new AoR; else the last change: 1 a binding
            // added, 2 refreshed, 3 removed.
            let mut rc = match r.contacts.first() {
                None => 4,
                Some(c) if c.star => 3,
                Some(_) if list.is_empty() => 1,
                Some(_) => 0,
            };
            let fresh = rc != 0;
            // 0x04: one contact per AoR — drop the bindings this REGISTER
            // neither adds nor refreshes (when it adds or refreshes any).
            if r.flags & SAVE_SINGLE != 0 && r.contacts.iter().zip(&exps).any(|(c, &e)| !c.star && e > 0) {
                new.retain(|b| r.contacts.iter().zip(&exps).any(|(c, &e)| e > 0 && same(c, b)));
            }
            for (c, &e) in r.contacts.iter().zip(&exps) {
                if c.star {
                    // Wildcard removal; respect Call-ID/CSeq ordering per binding.
                    new.retain(|b| b.callid == r.callid && b.cseq >= r.cseq);
                    continue;
                }
                let found = new.iter().enumerate().find(|(_, b)| same(c, b));
                let pos = found.map(|(p, _)| p);
                if let Some((p, b)) = found {
                    // usrloc's get_ucontact(): a contact matched by URI from
                    // the same Call-ID needs a higher CSeq; the same CSeq
                    // within cseq_delay is a retransmission and is skipped.
                    if c.instance.is_none() && b.callid == r.callid && r.cseq <= b.cseq {
                        if r.cseq == b.cseq && b.last_modified.saturating_add(cseq_delay) > now {
                            continue;
                        }
                        return Outcome::Fail(400, "Invalid CSeq number", String::new());
                    }
                    if e == 0 {
                        new.remove(p);
                        if !fresh {
                            rc = 3;
                        }
                        continue;
                    }
                } else if e == 0 {
                    continue;
                } else if max_contacts > 0 && new.len() >= max_contacts {
                    return Outcome::Fail(503, "Too many registered contacts", String::new());
                }
                if !fresh {
                    rc = if pos.is_some() { 2 } else { 1 };
                }
                if e > 0 {
                    let binding = Contact {
                        uri: c.uri.clone(),
                        expires_at: now.saturating_add(u64::from(e).saturating_mul(1000)),
                        q: c.q,
                        callid: r.callid.clone(),
                        cseq: r.cseq,
                        received: src,
                        user_agent: r.user_agent.clone(),
                        instance: c.instance.clone(),
                        reg_id: c.reg_id,
                        last_modified: now,
                        path: r.path.clone(),
                        cflags: r.cflags,
                        flags: if r.flags & SAVE_MEMORY_ONLY != 0 { FL_MEM } else { 0 },
                        methods: r.methods,
                        // A refreshed binding keeps its record id.
                        ruid: pos.and_then(|p| new.get(p)).map_or_else(store::new_ruid, |b| b.ruid.clone()),
                    };
                    match pos.and_then(|p| new.get_mut(p)) {
                        Some(old) => *old = binding,
                        None => new.push(binding),
                    }
                }
            }
            *list = new;
            // Rendered here from the stored bindings rather than returning a
            // deep copy of them (every URI, Call-ID, User-Agent, Path…).
            Outcome::Ok(self.ok_headers(r, list, now), rc.max(1))
        })
    }

    /// Header lines for the 200: all current bindings with their remaining
    /// time (RFC 3261 §10.3 step 8), GRUUs, outbound and Path as negotiated.
    fn ok_headers(&self, req: &RegisterReq, bindings: &[Contact], now: u64) -> Vec<u8> {
        let mut h = Vec::with_capacity(bindings.len().saturating_mul(96).saturating_add(64));
        for b in bindings {
            h.extend_from_slice(b"Contact: <");
            h.extend_from_slice(&b.uri);
            let _ = write!(h, ">;expires={}", b.remaining_secs(now));
            if let Some(i) = &b.instance {
                h.extend_from_slice(b";+sip.instance=\"");
                h.extend_from_slice(i);
                h.push(b'"');
            }
            if let Some(id) = b.reg_id {
                let _ = write!(h, ";reg-id={id}");
            }
            // RFC 5627 GRUUs for clients with an instance id.
            if let Some(i) = b.instance.as_ref().filter(|_| req.gruu_supported && self.gruu_enabled.load(Ordering::Relaxed)) {
                let inst = String::from_utf8_lossy(i);
                let gr = inst.trim_matches(|c| c == '<' || c == '>');
                let host = req.aor_uri.split_once('@').map_or("", |x| x.1);
                let _ = write!(h, ";pub-gruu=\"{};gr={gr}\";temp-gruu=\"sip:tgruu.{}@{host};gr\"", req.aor_uri, temp_gruu(&req.aor_uri, &inst, &b.callid));
            }
            h.extend_from_slice(b"\r\n");
        }
        // RFC 5626: the registrar supports outbound flows.
        if req.ob_supported && self.outbound_mode.load(Ordering::Relaxed) > 0 && bindings.iter().any(|b| b.reg_id.is_some() && b.instance.is_some()) {
            h.extend_from_slice(b"Require: outbound\r\n");
        }
        let path_mode = self.path_mode.load(Ordering::Relaxed);
        if let Some(p) = req.path.as_ref().filter(|_| path_mode == 1 || (path_mode == 2 && req.path_supported)) {
            h.extend_from_slice(b"Path: ");
            h.extend_from_slice(p);
            h.extend_from_slice(b"\r\n");
        }
        h
    }

    fn save(&self, ctx: &mut Ctx<'_, '_>, a: &SaveArgs) -> i32 {
        if ctx.msg.method() != Some(Method::Register) {
            ctx.last_error = Some((500, "save() called for a non-REGISTER"));
            return -1;
        }
        let flags = match &a.flags {
            Some(f) => match parse_flags(&f.eval(ctx)).filter(|&f| f <= SAVE_ALL) {
                Some(f) => f,
                None => {
                    ctx.last_error = Some((500, "save(): bad flags"));
                    return -1;
                }
            },
            None => 0,
        };
        let uri = a.uri.as_ref().map(|u| u.eval(ctx).into_owned());
        // 0x02: no reply. The script answers: reg_send_reply() sends the
        // reply save() would have sent; sl_reply_error() an error; with
        // 0x10 the 200's header lines go into the script's next stateless
        // reply (Kamailio's reg_prepare_reply()).
        let answer = |ctx: &mut Ctx<'_, '_>, code: u16, reason: &'static str, extra: &[u8]| {
            if flags & SAVE_NO_REPLY == 0 {
                let _ = ctx.reply_with(code, reason, extra);
            } else {
                if code >= 300 {
                    ctx.last_error = Some((code, reason));
                }
                if flags & SAVE_PREPARE_REPLY != 0 {
                    ctx.ext_mut::<ReplyExtra>().headers.extend_from_slice(extra);
                }
                // (Prepared lines are already in ReplyExtra: not twice.)
                let rest = if flags & SAVE_PREPARE_REPLY != 0 { vec![] } else { extra.to_vec() };
                *ctx.ext_mut::<PendingReply>() = PendingReply(Some((code, reason, rest)));
            }
        };
        let req = match self.parse_register(ctx, uri.as_deref(), flags) {
            Ok(r) => r,
            Err(why) => {
                answer(ctx, 400, why, b"");
                return -1;
            }
        };
        let path_mode = self.path_mode.load(Ordering::Relaxed);
        if self.use_path.load(Ordering::Relaxed) && path_mode == 1 && req.path.is_none() {
            answer(ctx, 420, "Bad Extension", b"Unsupported: path\r\n");
            return -1;
        }
        let (code, reason, extra, rc) = match self.apply(&req, ctx.src) {
            Outcome::Ok(h, rc) => (200, "OK", h, rc),
            // Kamailio: -2 for too many contacts, -1 for the other errors.
            Outcome::Fail(503, reason, extra) => (503, reason, extra.into_bytes(), -2),
            Outcome::Fail(code, reason, extra) => (code, reason, extra.into_bytes(), -1),
        };
        answer(ctx, code, reason, &extra);
        rc
    }

    /// `reg_send_reply()`: the reply a `save()` with flag 0x02 skipped.
    /// 1 once sent; -1 without such a `save()` before it.
    fn send_reply(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some((code, reason, extra)) = ctx.ext_get_mut::<PendingReply>().and_then(|p| p.0.take()) else { return -1 };
        if ctx.reply_with(code, reason, &extra).is_ok() { 1 } else { -1 }
    }

    /// Where to send requests for this binding.
    fn route(&self, c: &Contact) -> Dest {
        // Path: the first hop of the stored route set (an edge proxy).
        if let Some(d) = c.path.as_deref().and_then(first_path_hop) {
            return d;
        }
        if self.use_received.load(Ordering::Relaxed) || c.received.proto.is_stream() {
            return c.received; // NAT-safe; stream transports must reuse the connection
        }
        let Some(u) = parse_uri(&c.uri) else { return c.received };
        let ip = std::str::from_utf8(u.host).ok().and_then(|h| h.trim_matches(|x| x == '[' || x == ']').parse::<IpAddr>().ok());
        match ip {
            Some(ip) => Dest::new(Proto::Udp, SocketAddr::new(ip, u.port.unwrap_or(5060))),
            None => c.received,
        }
    }

    /// The AoR of a URI (a bare `user@host` is taken as `sip:user@host`).
    fn uri_aor(&self, uri: &[u8]) -> Option<Box<[u8]>> {
        let with_scheme;
        let u = match parse_uri(uri) {
            Some(u) => u,
            None if !uri.contains(&b':') => {
                with_scheme = [&b"sip:"[..], uri].concat();
                parse_uri(&with_scheme)?
            }
            None => return None,
        };
        Some(self.ul().aor(u.user?, u.host))
    }

    /// The contacts `lookup()` gives for a URI, best first: highest q, then
    /// most recently refreshed. A GRUU gives only its instance's contact.
    /// `None` when the URI has no AoR.
    fn contacts_for(&self, uri: &[u8]) -> Option<Vec<Contact>> {
        let gruu = parse_uri(uri).and_then(|u| {
            let gr = u.param(b"gr")?;
            if !gr.is_empty() {
                return Some((self.ul().aor(u.user?, u.host), format!("<{}>", String::from_utf8_lossy(gr))));
            }
            let tok = std::str::from_utf8(u.user?).ok()?.strip_prefix("tgruu.")?;
            let (aor_uri, inst) = temp_gruu_decode(tok)?;
            let a = parse_uri(aor_uri.as_bytes())?;
            Some((self.ul().aor(a.user?, a.host), inst))
        });
        let (aor, instance) = match gruu {
            Some((a, i)) => (a, Some(i)),
            None => (self.uri_aor(uri)?, None),
        };
        let mut cs = self.ul().lookup(&aor);
        if let Some(i) = &instance {
            cs.retain(|c| c.instance.as_deref() == Some(i.as_bytes()));
            cs.truncate(1);
        }
        sort_best_first(&mut cs);
        Some(cs)
    }

    /// Best contact of `uri`'s AoR → R-URI/$du; with `append_branches`
    /// (default, as in Kamailio) every other contact becomes a fork branch
    /// for `t_relay()`.
    fn lookup(&self, ctx: &mut Ctx<'_, '_>, uri: &[u8]) -> i32 {
        let mut it = self.contacts_for(uri).unwrap_or_default().into_iter();
        let Some(best) = it.next() else { return -1 };
        ctx.dst = Some(self.route(&best));
        ctx.ruri_q = best.q;
        if let Some(p) = &best.path {
            *ctx.ext_mut::<RuriPath>() = RuriPath(p.clone());
        } else if let Some(p) = ctx.ext_get_mut::<RuriPath>() {
            p.0.clear();
        }
        if best.cflags != 0 {
            ctx.ext_mut::<sip_core::TxnVars>().bflags |= best.cflags;
        }
        *ctx.ext_mut::<sip_core::module::RuriFlow>() = sip_core::module::RuriFlow { instance: best.instance.clone(), reg_id: best.reg_id };
        self.fill_rcd(ctx, &best);
        ctx.new_ruri = Some(best.uri);
        if self.append_branches.load(Ordering::Relaxed) {
            for c in it {
                // Kamailio registrar lookup.c: a contact the destination set
                // has no room for (max_branches - 1) is dropped, logged, and
                // the next one tried; lookup still succeeds.
                if !ctx.append_branch(self.branch(c)) {
                    sip_core::elog!("failed to append a branch");
                }
            }
        }
        1
    }

    fn branch(&self, c: Contact) -> Branch {
        Branch { dst: Some(self.route(&c)), q: c.q, uri: c.uri, path: c.path, instance: c.instance, reg_id: c.reg_id }
    }

    /// `lookup_branches()` (Kamailio's lookup.c): `lookup()` for the R-URI,
    /// then for every branch without a destination or Path of its own: a
    /// branch whose AoR has contacts becomes the best of them, the others
    /// (with `append_branches`) are added at the end; one without stays as
    /// it is. True when any lookup found contacts.
    fn lookup_branches(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let before = std::mem::take(&mut ctx.branches);
        let ruri = ctx.ruri().to_vec();
        let mut found = self.lookup(ctx, &ruri) > 0;
        let all = self.append_branches.load(Ordering::Relaxed);
        // The R-URI lookup's own extra branches come after the old ones.
        let ruri_extra = std::mem::replace(&mut ctx.branches, Vec::with_capacity(before.len()));
        let mut extra = Vec::new();
        for b in before {
            let cs = if b.dst.is_none() && b.path.is_none() { self.contacts_for(&b.uri).unwrap_or_default() } else { vec![] };
            let mut it = cs.into_iter();
            let Some(best) = it.next() else {
                ctx.branches.push(b);
                continue;
            };
            found = true;
            ctx.branches.push(self.branch(best));
            if all {
                extra.extend(it.map(|c| self.branch(c)));
            }
        }
        // The new contacts are appended in Kamailio's order (the R-URI's,
        // then each branch's), each through append_branch(): past
        // max_branches - 1 they are dropped.
        for b in ruri_extra.into_iter().chain(extra) {
            if !ctx.append_branch(b) {
                sip_core::elog!("failed to append a branch");
            }
        }
        if found { 1 } else { -1 }
    }

    /// `registered(table[, uri[, match_option[, match_action]]])`.
    fn registered(&self, ctx: &mut Ctx<'_, '_>, a: &RegisteredArgs) -> i32 {
        let uri = match &a.uri {
            Some(u) => u.eval(ctx).into_owned().into_bytes(),
            None => ctx.ruri().to_vec(),
        };
        let Some(aor) = self.uri_aor(&uri) else { return -1 };
        let mut cs = self.ul().lookup(&aor);
        // match_option: 1 Call-ID, 2 received address, 4 contact URI, the
        // values from the `xavp_cfg` xavp (Kamailio's registered4()).
        let opt = a.match_option.as_ref().and_then(|m| m.eval(ctx)).unwrap_or(0);
        let cfg = lock(&self.xavp_cfg).clone();
        if opt != 0 && !cfg.is_empty() {
            let item = ctx.ext::<sip_core::TxnVars>().and_then(|t| t.xavps.get(&cfg)).and_then(|v| v.first()).cloned().unwrap_or_default();
            let want = |bit: i64, field: &str| (opt & bit != 0).then(|| item.get(field).map(|v| v.as_str().into_owned())).flatten().filter(|v| !v.is_empty());
            let (callid, received, contact) = (want(1, "match_callid"), want(2, "match_received"), want(4, "match_contact"));
            cs.retain(|c| {
                callid.as_ref().is_none_or(|v| c.callid == v.as_bytes())
                    && contact.as_ref().is_none_or(|v| c.uri == v.as_bytes())
                    && received.as_ref().is_none_or(|v| sip_core::pvcore::dest_to_uri(&c.received) == *v)
            });
        }
        sort_best_first(&mut cs);
        let Some(c) = cs.first() else { return -1 };
        // match_action: the matched contact goes into the `xavp_rcd` xavp
        // unless bit 2 is set. (Bit 1, the contact's own xavp, has nothing
        // to copy: contacts are stored without one.)
        let act = a.match_action.as_ref().and_then(|m| m.eval(ctx)).unwrap_or(0);
        if act & 2 == 0 {
            self.fill_rcd(ctx, c);
        }
        1
    }

    /// Kamailio's xavp_rcd_helper(): the contact's `ruid`, `received`,
    /// `contact`, `expires` (seconds left) and `path` into the `xavp_rcd`
    /// xavp (its first item, made when there is none).
    fn fill_rcd(&self, ctx: &mut Ctx<'_, '_>, c: &Contact) {
        let rcd = lock(&self.xavp_rcd).clone();
        if rcd.is_empty() {
            return;
        }
        let list = ctx.ext_mut::<sip_core::TxnVars>().xavps.entry(rcd).or_default();
        if list.is_empty() {
            list.push(HashMap::new());
        }
        let Some(item) = list.first_mut() else { return };
        item.insert("ruid".to_string(), Val::str(&c.ruid));
        item.insert("received".to_string(), Val::Str(sip_core::pvcore::dest_to_uri(&c.received)));
        item.insert("contact".to_string(), Val::str(&c.uri));
        item.insert("expires".to_string(), Val::Int(i64::from(c.remaining_secs(self.ul().now()))));
        if let Some(p) = &c.path {
            item.insert("path".to_string(), Val::str(p));
        }
    }

    /// `unregister(table, uri[, ruid])` (Kamailio's save.c unregister()):
    /// remove every binding of the AoR (1, also when it had none), or only
    /// the one with that record id (-3 when there is none). An empty `uri`
    /// is the To URI, or with a `ruid` any AoR. -1 when the AoR cannot be
    /// taken from the URI.
    fn unregister(&self, ctx: &mut Ctx<'_, '_>, (uri, ruid): &(DynStr, Option<DynStr>)) -> i32 {
        let uri = uri.eval(ctx).into_owned();
        let ruid = ruid.as_ref().map(|r| r.eval(ctx).into_owned()).filter(|r| !r.is_empty());
        let aor = if !uri.is_empty() {
            self.uri_aor(uri.as_bytes())
        } else if let Some(r) = &ruid {
            let mut found = None;
            self.ul().for_each_contact(|aor, c| {
                if found.is_none() && c.ruid == *r {
                    found = Some(Box::<[u8]>::from(aor));
                }
            });
            match found {
                Some(a) => Some(a),
                None => return -3,
            }
        } else {
            let _ = ctx.msg.parse_headers(HdrFlags::EOH);
            let to = ctx.msg.get(HdrKind::To).map(|h| name_addr(h.body).0.to_vec());
            to.and_then(|t| self.uri_aor(&t))
        };
        let Some(aor) = aor else { return -1 };
        let removed = self.ul().update(&aor, |v, _| {
            let n = v.len();
            match &ruid {
                Some(r) => v.retain(|c| c.ruid != *r),
                None => v.clear(),
            }
            n.saturating_sub(v.len())
        });
        if ruid.is_some() && removed == 0 { -3 } else { 1 }
    }

    /// `reg_fetch_contacts(table, uri, profile)`: keep a copy of the AoR's
    /// contacts for `$ulc(profile=>…)`. False when it has none.
    fn fetch(&self, ctx: &mut Ctx<'_, '_>, (uri, profile): &(DynStr, String)) -> i32 {
        let uri = uri.eval(ctx).into_owned();
        let Some(aor) = self.uri_aor(uri.as_bytes()) else { return -1 };
        let mut contacts = self.ul().lookup(&aor);
        sort_best_first(&mut contacts);
        let n = contacts.len();
        ctx.ext_mut::<Fetched>().0.insert(profile.clone(), Fetch { aor, contacts });
        if n > 0 { 1 } else { -1 }
    }

    /// `$ulc(profile=>attr)`, `$(ulc(profile=>attr)[i])`: contact i (0 =
    /// the first, negative counts from the end).
    fn ulc(&self, ctx: &mut Ctx<'_, '_>, p: &PvParam) -> Val {
        let Some((profile, attr)) = p.fixed::<(String, UlcAttr)>() else { return Val::Null };
        let Some(f) = ctx.ext::<Fetched>().and_then(|f| f.0.get(profile)) else { return Val::Null };
        let ul = self.ul();
        // Kamailio's pv_get_ulc(): a negative index is 0, and every
        // attribute (aor and count too) is $null without a contact there.
        let i = match p.idx {
            None => 0,
            Some(PvIdx::N(n)) => usize::try_from(n.max(0)).unwrap_or(usize::MAX),
            Some(PvIdx::All) => return Val::Null,
        };
        let Some(c) = f.contacts.get(i) else { return Val::Null };
        match attr {
            UlcAttr::Aor => Val::str(&f.aor),
            UlcAttr::Domain => Val::str("location"),
            // The low 32 bits of the hash (Kamailio's aorhash is 32-bit).
            UlcAttr::AorHash => Val::Int(i64::try_from(sip_core::fx_hash(&*f.aor) & 0xFFFF_FFFF).unwrap_or(0)),
            UlcAttr::Count => Val::Int(i64::try_from(f.contacts.len()).unwrap_or(i64::MAX)),
            UlcAttr::Addr => Val::str(&c.uri),
            UlcAttr::Path => Val::str(c.path.as_deref().unwrap_or_default()),
            UlcAttr::Received => Val::Str(sip_core::pvcore::dest_to_uri(&c.received)),
            UlcAttr::Expires => Val::Int(ul.unix_secs(c.expires_at)),
            UlcAttr::CallId => Val::str(&c.callid),
            UlcAttr::Q => Val::Int(c.q.map_or(-1, i64::from)),
            UlcAttr::CSeq => Val::Int(i64::from(c.cseq)),
            UlcAttr::Flags => Val::Int(i64::from(c.flags)),
            UlcAttr::CFlags => Val::Int(i64::from(c.cflags)),
            UlcAttr::UserAgent => Val::str(&c.user_agent),
            UlcAttr::Socket => {
                let proto = c.received.proto;
                let local = ctx.advertise(proto);
                Val::Str(format!("{}:{}", proto.via_name().to_ascii_lowercase(), local))
            }
            UlcAttr::Modified => Val::Int(ul.unix_secs(c.last_modified)),
            UlcAttr::Methods => Val::Int(i64::from(c.methods)),
            UlcAttr::Ruid => Val::str(&c.ruid),
            UlcAttr::Instance => c.instance.as_deref().map_or(Val::Null, Val::str),
            UlcAttr::RegId => Val::Int(i64::from(c.reg_id.unwrap_or(0))),
            // $null for UDP, as Kamailio.
            UlcAttr::ConId => c.received.conn.map_or(Val::Null, |id| Val::Int(i64::try_from(id).unwrap_or(i64::MAX))),
            UlcAttr::ServerId => Val::Int(0),
        }
    }
}

/// Highest q first, then most recently refreshed.
fn sort_best_first(cs: &mut [Contact]) {
    cs.sort_by_key(|c| std::cmp::Reverse((c.q.unwrap_or(1000), c.last_modified)));
}

/// Kamailio's METHOD_* bit of a method name (Allow header).
fn method_bit(m: &[u8]) -> u32 {
    const BITS: &[&str] = &[
        "INVITE",
        "CANCEL",
        "ACK",
        "BYE",
        "INFO",
        "REGISTER",
        "SUBSCRIBE",
        "NOTIFY",
        "MESSAGE",
        "OPTIONS",
        "PRACK",
        "UPDATE",
        "REFER",
        "PUBLISH",
        "KDMQ",
        "GET",
        "POST",
        "PUT",
        "DELETE",
    ];
    BITS.iter().position(|b| b.as_bytes().eq_ignore_ascii_case(m)).map_or(1 << 19, |i| 1 << i)
}

/// `save()` flags: an integer, decimal or `0x` hex.
fn parse_flags(s: &str) -> Option<u32> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse::<i64>().ok().and_then(|n| u32::try_from(n).ok()),
    }
}

/// The reply a `save()` with flag 0x02 did not send, for `reg_send_reply()`.
#[derive(Default)]
struct PendingReply(Option<(u16, &'static str, Vec<u8>)>);

struct SaveArgs {
    flags: Option<DynStr>,
    uri: Option<DynStr>,
}

struct RegisteredArgs {
    uri: Option<DynStr>,
    match_option: Option<DynInt>,
    match_action: Option<DynInt>,
}

/// Contacts kept by `reg_fetch_contacts()` for this message, by profile.
#[derive(Default)]
struct Fetched(HashMap<String, Fetch>);

struct Fetch {
    aor: Box<[u8]>,
    contacts: Vec<Contact>,
}

/// The attributes of `$ulc(profile=>attr)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UlcAttr {
    Aor,
    Domain,
    AorHash,
    Count,
    Addr,
    Path,
    Received,
    Expires,
    CallId,
    Q,
    CSeq,
    Flags,
    CFlags,
    UserAgent,
    Socket,
    Modified,
    Methods,
    Ruid,
    Instance,
    RegId,
    ConId,
    ServerId,
}

impl UlcAttr {
    fn parse(s: &str) -> Option<Self> {
        use UlcAttr::*;
        Some(match s {
            "aor" => Aor,
            "domain" => Domain,
            "aorhash" => AorHash,
            "count" => Count,
            "addr" => Addr,
            "path" => Path,
            "received" => Received,
            "expires" => Expires,
            "callid" => CallId,
            "q" => Q,
            "cseq" => CSeq,
            "flags" => Flags,
            "cflags" => CFlags,
            "user_agent" => UserAgent,
            "socket" => Socket,
            "modified" => Modified,
            "methods" => Methods,
            "ruid" => Ruid,
            "instance" => Instance,
            "regid" => RegId,
            "conid" => ConId,
            "server_id" => ServerId,
            _ => return None,
        })
    }
}

/// temp-gruu user part: hex of "aor NUL instance NUL call-id-hash"
/// (a new one per registration, decodable without state).
fn temp_gruu(aor: &str, instance: &str, callid: &[u8]) -> String {
    let raw = format!("{aor}\0{instance}\0{:x}", sip_core::fx_hash(callid));
    raw.bytes().map(|b| format!("{b:02x}")).collect()
}

fn temp_gruu_decode(tok: &str) -> Option<(String, String)> {
    if !tok.len().is_multiple_of(2) {
        return None;
    }
    // From the wire: a pair that is not ASCII (not on a char boundary) is
    // not hex either.
    let bytes: Option<Vec<u8>> = tok.as_bytes().as_chunks::<2>().0.iter().map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect();
    let s = String::from_utf8(bytes?).ok()?;
    let mut it = s.split('\0');
    Some((it.next()?.to_string(), it.next()?.to_string()))
}

/// Next hop of a Path route set: its first URI.
fn first_path_hop(path: &[u8]) -> Option<Dest> {
    let first = split_list(path).into_iter().next()?;
    sip_core::pvcore::dest_from_uri(name_addr(first).0)
}

fn location_table(a: &[Arg]) -> Result<(), String> {
    match a {
        [t] => check_table(t),
        _ => want_args(a, 1),
    }
}

fn check_table(a: &Arg) -> Result<(), String> {
    match a.str()? {
        "location" => Ok(()),
        t => Err(format!("unknown usrloc table {t:?} (only \"location\")")),
    }
}

/// The table, then `min..=max` arguments in all.
fn table_and(a: &[Arg], min: usize, max: usize) -> Result<(), String> {
    match a.first() {
        Some(t) if (min..=max).contains(&a.len()) => check_table(t),
        _ => Err(if min == max { format!("expected {min} arguments, got {}", a.len()) } else { format!("expected {min} to {max} arguments, got {}", a.len()) }),
    }
}

fn save_fixup(a: &[Arg]) -> Result<SaveArgs, String> {
    table_and(a, 1, 3)?;
    let flags = a.get(1).map(Arg::dyn_str).transpose()?;
    if let Some(DynStr::Static(f)) = &flags {
        match parse_flags(f) {
            None => return Err(format!("save(): flags {f:?} is not a number")),
            Some(n) if n > SAVE_ALL => return Err(format!("save(): bad flags {f:?} (at most 0x1f)")),
            Some(_) => {}
        }
    }
    Ok(SaveArgs { flags, uri: a.get(2).map(Arg::dyn_str).transpose()? })
}

impl Module for Registrar {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            pr("default_expires", Ty::Duration(Unit::Sec), "1h", "Expiry when the REGISTER asks for none"),
            pr("min_expires", Ty::Duration(Unit::Sec), "60s", "Shorter requests get 423 Interval Too Brief"),
            pr("max_expires", Ty::Duration(Unit::Sec), "1d", "Cap on requested expiry (0: no cap)"),
            pr("max_contacts", UINT, "0", "Most contacts per AoR (0: unlimited)"),
            p("use_received", Ty::Bool, "true", "Route to the received address (NAT) instead of the Contact"),
            p("append_branches", Ty::Bool, "true", "lookup() adds every contact as a branch"),
            p("use_path", Ty::Bool, "false", "Store and use Path headers (RFC 3327)"),
            p("path_mode", Ty::Enum(&[("off", "0"), ("lazy", "1"), ("strict", "2")]), "lazy", "Path support required from the UA (strict) or not"),
            p("gruu_enabled", Ty::Bool, "true", "GRUU (RFC 5627)"),
            p("outbound_mode", Ty::Enum(&[("off", "0"), ("on", "1"), ("required", "2")]), "off", "SIP Outbound (RFC 5626)"),
            p("xavp_cfg", Ty::Str, "", "xavp with the match_callid/match_contact/match_received values for registered()'s match_option"),
            p("xavp_rcd", Ty::Str, "", "xavp lookup() and registered() fill with the contact (ruid, contact, received, path, expires)"),
        ])
    }

    fn name(&self) -> &'static str {
        "registrar"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, ctx, opt, sig};
        const SAVE: &[Param] = &[opt("flags", Int), opt("aor", Uri)];
        const URI: &[Param] = &[opt("uri", Uri)];
        const REGISTERED: &[Param] = &[opt("uri", Uri), opt("match_option", Int), opt("match_action", Int)];
        const UNREGISTER: &[Param] = &[arg("aor", Uri), opt("ruid", Str)];
        const FETCH: &[Param] = &[arg("aor", Uri), arg("profile", Str).lit()];
        const FREE: &[Param] = &[arg("profile", Str).lit()];
        Some(vec![
            sig(
                "save",
                "save",
                SAVE,
                Ret::Action,
                "Store the REGISTER's contacts and answer it (200 with the bindings, or the error); flags 1 memory only, 2 no reply, 4 one contact per AoR, 0x10 (with 2) the 200's lines for the script's reply; `aor` instead of the To URI. 1 inserted, 2 updated, 3 deleted, 4 query; -2 too many contacts",
            )
            .fixed(&["location"])
            .allowed(ctx::REQUEST),
            // The same, for code that must run after it (tsilo, msilo): the
            // REGISTER is answered, the route goes on (end it yourself).
            sig("save", "save_and_continue", SAVE, Ret::Bool, "Like save(), but the route goes on after it (true: saved; with flag 2 reply yourself)")
                .fixed(&["location"])
                .allowed(ctx::REQUEST),
            sig("lookup", "lookup", URI, Ret::Bool, "Point the R-URI (and branches) at the registered contacts of the R-URI's AoR (or `uri`'s); false when none")
                .fixed(&["location"]),
            sig("reg_send_reply", "send_reply", &[], Ret::Bool, "Send the reply a save() with flag 2 skipped; false without one"),
            sig("lookup_branches", "lookup_branches", &[], Ret::Bool, "lookup() for the R-URI and for every branch; true when any has contacts").fixed(&["location"]),
            sig(
                "registered",
                "is_registered",
                REGISTERED,
                Ret::Bool,
                "The R-URI's AoR (or `uri`'s) has registered contacts; match_option 1/2/4 also compares Call-ID/received/contact with the xavp_cfg values; the match goes into xavp_rcd unless match_action has bit 2",
            )
            .fixed(&["location"]),
            sig("unregister", "unregister", UNREGISTER, Ret::Bool, "Remove the AoR's contacts, or only the one with this ruid (-3 when it has none); with a ruid the AoR may be \"\"")
                .fixed(&["location"])
                .allowed(ctx::ANY),
            sig("reg_fetch_contacts", "fetch_contacts", FETCH, Ret::Bool, "Copy the AoR's contacts for $ulc(profile=>…); false when it has none")
                .fixed(&["location"])
                .allowed(ctx::ANY),
            sig("reg_free_contacts", "free_contacts", FREE, Ret::Void, "Drop the contacts fetched into this profile").allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = || -> Result<u32, String> { u32::try_from(v.int()?).map_err(|_| format!("{name}: out of range")) };
        match name {
            "default_expires" => self.default_expires.store(n()?, Ordering::Relaxed),
            "min_expires" => self.min_expires.store(n()?, Ordering::Relaxed),
            "max_expires" => self.max_expires.store(n()?, Ordering::Relaxed),
            "max_contacts" => self.max_contacts.store(n()?, Ordering::Relaxed),
            "use_received" => self.use_received.store(n()? != 0, Ordering::Relaxed),
            "append_branches" => self.append_branches.store(n()? != 0, Ordering::Relaxed),
            "use_path" => self.use_path.store(n()? != 0, Ordering::Relaxed),
            "path_mode" => self.path_mode.store(n()?.min(2), Ordering::Relaxed),
            "gruu_enabled" => self.gruu_enabled.store(n()? != 0, Ordering::Relaxed),
            "outbound_mode" => self.outbound_mode.store(n()?.min(2), Ordering::Relaxed),
            "xavp_cfg" => *lock(&self.xavp_cfg) = v.str()?.to_string(),
            "xavp_rcd" => *lock(&self.xavp_rcd) = v.str()?.to_string(),
            _ => return Err(format!("registrar: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let ul = reg.api::<Usrloc>().ok_or("registrar needs usrloc: put loadmodule \"usrloc\" before \"registrar\"")?;
        let _ = self.ul.set(ul);
        let (min, max, def) =
            (self.min_expires.load(Ordering::Relaxed), self.max_expires.load(Ordering::Relaxed), self.default_expires.load(Ordering::Relaxed));
        if min > max || !(min..=max).contains(&def) {
            return Err(format!("need min_expires ({min}) <= default_expires ({def}) <= max_expires ({max})"));
        }
        let me = self.clone();
        reg.export("registrar", "save", save_fixup, move |ctx: &mut Ctx, a: &SaveArgs| me.save(ctx, a));
        let me = self.clone();
        reg.export(
            "registrar",
            "lookup",
            |a: &[Arg]| {
                table_and(a, 1, 2)?;
                a.get(1).map(Arg::dyn_str).transpose()
            },
            move |ctx: &mut Ctx, uri: &Option<DynStr>| {
                let uri = match uri {
                    Some(u) => u.eval(ctx).into_owned().into_bytes(),
                    None => ctx.ruri().to_vec(),
                };
                me.lookup(ctx, &uri)
            },
        );
        let me = self.clone();
        reg.export("registrar", "reg_send_reply", |a: &[Arg]| want_args(a, 0), move |ctx: &mut Ctx, _: &()| me.send_reply(ctx));
        let me = self.clone();
        reg.export("registrar", "lookup_branches", location_table, move |ctx: &mut Ctx, _: &()| me.lookup_branches(ctx));
        let me = self.clone();
        reg.export(
            "registrar",
            "registered",
            |a: &[Arg]| {
                table_and(a, 1, 4)?;
                Ok(RegisteredArgs {
                    uri: a.get(1).map(Arg::dyn_str).transpose()?,
                    match_option: a.get(2).map(Arg::dyn_int).transpose()?,
                    match_action: a.get(3).map(Arg::dyn_int).transpose()?,
                })
            },
            move |ctx: &mut Ctx, a: &RegisteredArgs| me.registered(ctx, a),
        );
        let me = self.clone();
        reg.export(
            "registrar",
            "unregister",
            |a: &[Arg]| {
                table_and(a, 2, 3)?;
                let [_, uri, ruid @ ..] = a else { return Err("unregister(table, uri[, ruid])".into()) };
                Ok((uri.dyn_str()?, ruid.first().map(Arg::dyn_str).transpose()?))
            },
            move |ctx: &mut Ctx, a: &(DynStr, Option<DynStr>)| me.unregister(ctx, a),
        );
        let me = self.clone();
        reg.export(
            "registrar",
            "reg_fetch_contacts",
            |a: &[Arg]| {
                table_and(a, 3, 3)?;
                let [_, uri, profile] = a else { return Err("reg_fetch_contacts(table, uri, profile)".into()) };
                Ok((uri.dyn_str()?, profile.str()?.to_string()))
            },
            move |ctx: &mut Ctx, a: &(DynStr, String)| me.fetch(ctx, a),
        );
        reg.export(
            "registrar",
            "reg_free_contacts",
            |a: &[Arg]| {
                want_args(a, 1)?;
                let [profile] = a else { return Err("reg_free_contacts(profile)".into()) };
                Ok(profile.str()?.to_string())
            },
            |ctx: &mut Ctx, profile: &String| {
                if let Some(f) = ctx.ext_get_mut::<Fetched>() {
                    f.0.remove(profile);
                }
                1
            },
        );
        let me = self.clone();
        reg.pv(
            "ulc",
            PvSpec::ro(move |ctx, p| me.ulc(ctx, p)).with_param().with_fix(|p, _| {
                let (profile, attr) = p.name.split_once("=>").ok_or_else(|| format!("$ulc({}): expected profile=>attribute", p.name))?;
                let attr = UlcAttr::parse(attr.trim()).ok_or_else(|| format!("$ulc({}): unknown attribute {:?}", p.name, attr.trim()))?;
                p.fixed = Some(Arc::new((profile.trim().to_string(), attr)));
                Ok(())
            }),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_flags_decimal_and_hex() {
        assert_eq!(parse_flags("0x02"), Some(2));
        assert_eq!(parse_flags("0X0c"), Some(12));
        assert_eq!(parse_flags(" 5 "), Some(5));
        assert_eq!(parse_flags(""), Some(0));
        assert_eq!(parse_flags("x"), None);
        assert_eq!(parse_flags("-1"), None);
        assert!(save_fixup(&[Arg::Str("location".into()), Arg::Str("0x04".into())]).is_ok());
        assert!(save_fixup(&[Arg::Str("location".into()), Arg::Str("nope".into())]).is_err());
        assert!(save_fixup(&[Arg::Str("aliases".into())]).is_err());
        assert!(save_fixup(&[Arg::Str("location".into()), Arg::Int(2), Arg::Str("sip:a@b".into())]).is_ok());
    }

    #[test]
    fn allow_methods_and_ulc_attributes() {
        assert_eq!(method_bit(b"INVITE"), 1);
        assert_eq!(method_bit(b"message"), 256);
        assert_eq!(method_bit(b"FOO"), 1 << 19);
        assert_eq!(UlcAttr::parse("regid"), Some(UlcAttr::RegId));
        assert_eq!(UlcAttr::parse("reg-id"), None); // Kamailio's name is regid
        assert_eq!(UlcAttr::parse("user_agent"), Some(UlcAttr::UserAgent));
        assert_eq!(UlcAttr::parse("nope"), None);
    }

    #[test]
    fn temp_gruu_decode_rejects_non_hex_without_panicking() {
        let tok = temp_gruu("sip:a@x", "<urn:uuid:1>", b"c1");
        assert_eq!(temp_gruu_decode(&tok), Some(("sip:a@x".into(), "<urn:uuid:1>".into())));
        // A pair cut inside a UTF-8 character is rejected, not sliced.
        assert_eq!(temp_gruu_decode("0\u{e9}0"), None);
        assert_eq!(temp_gruu_decode("\u{e9}00"), None);
        assert_eq!(temp_gruu_decode("zz"), None);
        assert_eq!(temp_gruu_decode("abc"), None);
    }

    // ------------------------------------------------------ registrar tests --

    use bumpalo::Bump;
    use sip_core::{Lumps, Outbound};
    use sip_parser::Msg;

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    fn udp(a: &str) -> Dest {
        Dest::new(Proto::Udp, a.parse().unwrap())
    }

    fn with_ctx<R>(raw: &str, src: Dest, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        let raw = raw.replace("\r\n", "\n").replace('\n', "\r\n");
        let arena = Bump::new();
        let mut m = Msg::parse(raw.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, src, 0);
        f(&mut ctx)
    }

    fn registrar() -> Registrar {
        let r = Registrar::default();
        let _ = r.ul.set(Arc::new(Usrloc::default()));
        r
    }

    /// A REGISTER for alice@a.example with these header lines.
    fn register_msg(callid: &str, cseq: u32, headers: &str) -> String {
        format!(
            "REGISTER sip:a.example SIP/2.0\nVia: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK{cseq}\nFrom: <sip:alice@a.example>;tag=f\n\
To: <sip:alice@a.example>\nCall-ID: {callid}\nCSeq: {cseq} REGISTER\n{headers}Content-Length: 0\n\n"
        )
    }

    /// What save() (without its reply) did: return code, reply code and
    /// reason, and the reply's extra header lines.
    #[derive(Debug, PartialEq)]
    struct Saved {
        rc: i32,
        code: u16,
        reason: &'static str,
        headers: String,
    }

    fn save_as(r: &Registrar, msg: &str, from: Dest, flags: u32) -> Saved {
        with_ctx(msg, from, |ctx| {
            let rc = r.save(ctx, &SaveArgs { flags: Some(DynStr::Static((flags | SAVE_NO_REPLY).to_string())), uri: None });
            let (code, reason, extra) = ctx.ext_get_mut::<PendingReply>().and_then(|p| p.0.take()).unwrap();
            Saved { rc, code, reason, headers: String::from_utf8(extra).unwrap() }
        })
    }

    fn save(r: &Registrar, callid: &str, cseq: u32, headers: &str) -> Saved {
        save_as(r, &register_msg(callid, cseq, headers), udp("198.51.100.1:5060"), 0)
    }

    fn bindings(r: &Registrar) -> Vec<Contact> {
        let mut v = r.ul().lookup(b"alice");
        sort_best_first(&mut v);
        v
    }

    fn remaining(r: &Registrar) -> Vec<u32> {
        let now = r.ul().now();
        let mut v: Vec<(Vec<u8>, u32)> = r.ul().lookup(b"alice").iter().map(|c| (c.uri.clone(), c.remaining_secs(now))).collect();
        v.sort();
        v.into_iter().map(|x| x.1).collect()
    }

    #[test]
    fn registrar_expires_from_contact_header_or_default() {
        // (Expires header, Contact line) → the binding's lifetime (s); None: not stored.
        let cases: &[(&str, &str, Option<u32>)] = &[
            ("", "Contact: <sip:a@198.51.100.1>\n", Some(3600)),
            ("Expires: 120\n", "Contact: <sip:a@198.51.100.1>\n", Some(120)),
            ("Expires: 120\n", "Contact: <sip:a@198.51.100.1>;expires=300\n", Some(300)),
            ("", "Contact: <sip:a@198.51.100.1>;expires=60\n", Some(60)),
            ("", "Contact: <sip:a@198.51.100.1>;expires=999999999\n", Some(86400)),
            ("Expires: 86401\n", "Contact: <sip:a@198.51.100.1>\n", Some(86400)),
            ("Expires: 0\n", "Contact: <sip:a@198.51.100.1>\n", None),
            ("Expires: 3600\n", "Contact: <sip:a@198.51.100.1>;expires=0\n", None),
            ("", "Contact: <sip:a@198.51.100.1>;expires=abc\n", Some(3600)),
        ];
        for (expires, contact, want) in cases {
            let r = registrar();
            let s = save(&r, "c1", 1, &format!("{expires}{contact}"));
            assert_eq!(s.code, 200, "{expires:?} {contact:?}: {s:?}");
            assert_eq!(remaining(&r).first().copied(), *want, "{expires:?} {contact:?}");
        }
    }

    #[test]
    fn registrar_rejects_bad_requests() {
        let r = registrar();
        let fail = |headers: &str| {
            let s = save(&r, "c1", 1, headers);
            (s.rc, s.code, s.reason, s.headers)
        };
        assert_eq!(fail("Contact: <sip:a@198.51.100.1>;expires=30\n"), (-1, 423, "Interval Too Brief", "Min-Expires: 60\r\n".into()));
        assert_eq!(fail("Expires: 59\nContact: <sip:a@198.51.100.1>\n"), (-1, 423, "Interval Too Brief", "Min-Expires: 60\r\n".into()));
        assert_eq!(fail("Contact: *\n").1, 400, "* needs Expires: 0");
        assert_eq!(fail("Expires: 0\nContact: *, <sip:a@198.51.100.1>\n").1, 400, "* must be alone");
        assert_eq!(fail("Expires: 1\nContact: *\n").1, 400);
        assert_eq!(fail("Expires: soon\nContact: <sip:a@198.51.100.1>\n").2, "Bad Expires");
        assert_eq!(fail("Contact: <not a uri>\n").2, "Bad Contact URI");
        let no_user = register_msg("c1", 1, "Contact: <sip:a@198.51.100.1>\n").replace("To: <sip:alice@a.example>", "To: <sip:a.example>");
        assert_eq!(save_as(&r, &no_user, udp("198.51.100.1:5060"), 0).reason, "To URI has no user");
        assert!(bindings(&r).is_empty(), "nothing stored by a failed save");
        // Not a REGISTER: -1, nothing pending.
        let invite = register_msg("c1", 1, "").replace("REGISTER sip", "INVITE sip").replace("1 REGISTER", "1 INVITE");
        let rc = with_ctx(&invite, udp("198.51.100.1:5060"), |ctx| {
            let rc = r.save(ctx, &SaveArgs { flags: None, uri: None });
            assert_eq!(ctx.last_error, Some((500, "save() called for a non-REGISTER")));
            rc
        });
        assert_eq!(rc, -1);
        // Flags beyond 0x1f.
        let rc = with_ctx(&register_msg("c1", 1, ""), udp("198.51.100.1:5060"), |ctx| {
            r.save(ctx, &SaveArgs { flags: Some(DynStr::Static("0x20".into())), uri: None })
        });
        assert_eq!(rc, -1);
    }

    #[test]
    fn registrar_return_codes_follow_kamailio() {
        let r = registrar();
        assert_eq!(save(&r, "c1", 1, "").rc, 4, "a query");
        assert_eq!(save(&r, "c1", 2, "Contact: <sip:a@198.51.100.1>\n").rc, 1, "new AoR");
        assert_eq!(save(&r, "c1", 3, "Contact: <sip:a@198.51.100.1>\n").rc, 2, "refreshed");
        assert_eq!(save(&r, "c1", 4, "Contact: <sip:a@198.51.100.2>\n").rc, 1, "added");
        assert_eq!(save(&r, "c1", 5, "Contact: <sip:a@198.51.100.2>;expires=0\n").rc, 3, "removed");
        assert_eq!(save(&r, "c1", 6, "Contact: <sip:a@198.51.100.3>, <sip:a@198.51.100.1>\n").rc, 2, "the last change decides");
        let q = save(&r, "c1", 7, "");
        assert_eq!(q.rc, 4);
        assert_eq!(q.headers.matches("Contact: ").count(), 2, "a query lists the bindings: {}", q.headers);
        assert_eq!(save(&r, "c1", 8, "Expires: 0\nContact: *\n").rc, 3);
        assert!(bindings(&r).is_empty());
    }

    #[test]
    fn registrar_star_keeps_bindings_of_a_newer_request() {
        let r = registrar();
        save(&r, "other", 50, "Contact: <sip:a@198.51.100.1>\n");
        save(&r, "c1", 10, "Contact: <sip:a@198.51.100.2>\n");
        let s = save(&r, "c1", 5, "Expires: 0\nContact: *\n");
        assert_eq!((s.rc, s.code), (3, 200));
        let left: Vec<Vec<u8>> = bindings(&r).into_iter().map(|c| c.uri).collect();
        assert_eq!(left, [b"sip:a@198.51.100.2".to_vec()], "same Call-ID with a higher CSeq stays (§10.3 step 6)");
    }

    #[test]
    fn registrar_cseq_ordering_and_retransmissions() {
        let r = registrar();
        save(&r, "c1", 10, "Contact: <sip:a@198.51.100.1>;expires=600\n");
        let ruid = bindings(&r)[0].ruid.clone();
        // The same CSeq again at once: a retransmission, nothing changes.
        let s = save(&r, "c1", 10, "Contact: <sip:a@198.51.100.1>;expires=900\n");
        assert_eq!(s.code, 200);
        assert_eq!(remaining(&r), [600]);
        let s = save(&r, "c1", 9, "Contact: <sip:a@198.51.100.1>\n");
        assert_eq!((s.rc, s.code, s.reason), (-1, 400, "Invalid CSeq number"));
        // A new Call-ID may use any CSeq; the record id survives the refresh.
        save(&r, "c2", 1, "Contact: <sip:a@198.51.100.1>;expires=900\n");
        let b = bindings(&r);
        assert_eq!((b.len(), b[0].callid.as_slice(), b[0].cseq, b[0].ruid.as_str()), (1, &b"c2"[..], 1, ruid.as_str()));
        // cseq_delay 0: the same CSeq is out of order, not a retransmission.
        r.ul().set_param("cseq_delay", &Arg::Int(0)).unwrap();
        assert_eq!(save(&r, "c2", 1, "Contact: <sip:a@198.51.100.1>\n").code, 400);
    }

    #[test]
    fn registrar_instance_and_reg_id_identify_a_binding() {
        let r = registrar();
        let c = |ip: &str, reg: u32| format!("Contact: <sip:a@{ip}>;+sip.instance=\"<urn:uuid:1>\";reg-id={reg}\n");
        save(&r, "c1", 1, &c("198.51.100.1", 1));
        // A new address of the same flow replaces it (even with a lower CSeq).
        assert_eq!(save(&r, "c2", 1, &c("198.51.100.9", 1)).rc, 2);
        assert_eq!(bindings(&r).len(), 1);
        assert_eq!(bindings(&r)[0].uri, b"sip:a@198.51.100.9");
        // Another reg-id is another flow.
        assert_eq!(save(&r, "c2", 2, &c("198.51.100.9", 2)).rc, 1);
        assert_eq!(bindings(&r).len(), 2);
    }

    #[test]
    fn registrar_max_contacts_rejects_new_bindings_only() {
        let r = registrar();
        r.set_param("max_contacts", &Arg::Int(2)).unwrap();
        save(&r, "c1", 1, "Contact: <sip:a@198.51.100.1>\n");
        save(&r, "c1", 2, "Contact: <sip:a@198.51.100.2>\n");
        let s = save(&r, "c1", 3, "Contact: <sip:a@198.51.100.3>\n");
        assert_eq!((s.rc, s.code, s.reason), (-2, 503, "Too many registered contacts"));
        assert_eq!(bindings(&r).len(), 2, "nothing evicted");
        assert_eq!(save(&r, "c1", 4, "Contact: <sip:a@198.51.100.1>\n").rc, 2, "a refresh at the limit is fine");
        // Removing one and adding one in the same request fits.
        assert_eq!(save(&r, "c1", 5, "Contact: <sip:a@198.51.100.2>;expires=0, <sip:a@198.51.100.3>\n").code, 200);
        // All or nothing: the 503 leaves the earlier contacts of the request unsaved.
        let s = save(&r, "c1", 6, "Contact: <sip:a@198.51.100.1>;expires=0, <sip:a@198.51.100.4>, <sip:a@198.51.100.5>\n");
        assert_eq!(s.code, 503);
        assert_eq!(bindings(&r).len(), 2);
        // Expired bindings don't count.
        r.ul().update(b"alice", |v, now| v.iter_mut().for_each(|c| c.expires_at = now));
        assert_eq!(save(&r, "c1", 7, "Contact: <sip:a@198.51.100.6>, <sip:a@198.51.100.7>\n").code, 200);
    }

    #[test]
    fn registrar_single_contact_flag_drops_the_others() {
        let r = registrar();
        save(&r, "c1", 1, "Contact: <sip:a@198.51.100.1>, <sip:a@198.51.100.2>\n");
        let s = save_as(&r, &register_msg("c1", 2, "Contact: <sip:a@198.51.100.3>\n"), udp("198.51.100.1:5060"), SAVE_SINGLE);
        assert_eq!(s.code, 200);
        assert_eq!(bindings(&r).iter().map(|c| c.uri.clone()).collect::<Vec<_>>(), [b"sip:a@198.51.100.3".to_vec()]);
        // A removal alone keeps the others.
        save(&r, "c1", 3, "Contact: <sip:a@198.51.100.4>\n");
        save_as(&r, &register_msg("c1", 4, "Contact: <sip:a@198.51.100.4>;expires=0\n"), udp("198.51.100.1:5060"), SAVE_SINGLE);
        assert_eq!(bindings(&r).len(), 1);
        // Memory-only flag.
        save_as(&r, &register_msg("c1", 5, "Contact: <sip:a@198.51.100.5>\n"), udp("198.51.100.1:5060"), SAVE_MEMORY_ONLY);
        assert!(bindings(&r).iter().any(|c| c.uri == b"sip:a@198.51.100.5" && c.flags == FL_MEM));
    }

    #[test]
    fn registrar_reply_lists_bindings_with_remaining_time() {
        let r = registrar();
        let s = save(&r, "c1", 1, "Contact: <sip:a@198.51.100.1>;expires=120;q=0.5\n");
        assert_eq!(s.headers, "Contact: <sip:a@198.51.100.1>;expires=120\r\n");
        let b = bindings(&r);
        assert_eq!((b[0].q, b[0].received, b[0].cseq), (Some(500), udp("198.51.100.1:5060"), 1));
    }

    fn contact(r: &Registrar, uri: &str, q: Option<u16>, modified: u64, received: Dest) -> Contact {
        let now = r.ul().now();
        Contact {
            uri: uri.into(),
            expires_at: now.saturating_add(60_000),
            q,
            callid: b"c".to_vec(),
            cseq: 1,
            received,
            user_agent: vec![],
            instance: None,
            reg_id: None,
            last_modified: modified,
            path: None,
            cflags: 0,
            flags: 0,
            methods: u32::MAX,
            ruid: store::new_ruid(),
        }
    }

    #[test]
    fn contacts_are_ordered_by_q_then_recency() {
        let r = registrar();
        let src = udp("198.51.100.1:5060");
        let mut cs = vec![
            contact(&r, "sip:low", Some(100), 9, src),
            contact(&r, "sip:none-old", None, 1, src),
            contact(&r, "sip:full-new", Some(1000), 5, src),
            contact(&r, "sip:half", Some(500), 7, src),
            contact(&r, "sip:zero", Some(0), 8, src),
        ];
        sort_best_first(&mut cs);
        let order: Vec<&[u8]> = cs.iter().map(|c| c.uri.as_slice()).collect();
        assert_eq!(order, [&b"sip:full-new"[..], b"sip:none-old", b"sip:half", b"sip:low", b"sip:zero"], "no q counts as 1.0");
    }

    #[test]
    fn lookup_rewrites_the_ruri_and_forks_to_the_rest() {
        let r = registrar();
        let tcp = Dest { proto: Proto::Tcp, addr: "198.51.100.7:40000".parse().unwrap(), conn: Some(42), no_connect: false };
        let mut best = contact(&r, "sip:a@10.0.0.1:5062", Some(900), 1, udp("198.51.100.1:5060"));
        best.cflags = 1 << 3;
        let second = contact(&r, "sip:a@10.0.0.2", Some(500), 2, tcp);
        let expired = Contact { expires_at: r.ul().now(), ..contact(&r, "sip:a@10.0.0.3", Some(1000), 3, udp("198.51.100.3:5060")) };
        r.ul().update(b"alice", |v, _| v.extend([second, best, expired]));
        let invite = "INVITE sip:alice@a.example SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: <sip:b@x>;tag=1\nTo: <sip:alice@a.example>\nCall-ID: i\nCSeq: 1 INVITE\nContent-Length: 0\n\n";
        with_ctx(invite, udp("192.0.2.1:5060"), |ctx| {
            assert_eq!(r.lookup(ctx, b"sip:alice@a.example"), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:a@10.0.0.1:5062"[..]));
            assert_eq!((ctx.dst, ctx.ruri_q), (Some(udp("198.51.100.1:5060")), Some(900)), "NAT-safe: the REGISTER's source");
            assert_eq!(ctx.ext::<sip_core::TxnVars>().unwrap().bflags, 1 << 3, "branch flags restored");
            assert_eq!(ctx.branches.len(), 1, "the expired contact is left out");
            assert_eq!((ctx.branches[0].uri.as_slice(), ctx.branches[0].dst, ctx.branches[0].q), (&b"sip:a@10.0.0.2"[..], Some(tcp), Some(500)));
            assert_eq!(r.lookup(ctx, b"sip:nobody@a.example"), -1);
            assert_eq!(r.lookup(ctx, b"sip:a.example"), -1, "no user");
        });
        // use_received 0: UDP goes to the Contact address, streams still reuse the connection.
        r.set_param("use_received", &Arg::Int(0)).unwrap();
        r.set_param("append_branches", &Arg::Int(0)).unwrap();
        with_ctx(invite, udp("192.0.2.1:5060"), |ctx| {
            r.lookup(ctx, b"sip:alice@a.example");
            assert_eq!(ctx.dst, Some(udp("10.0.0.1:5062")));
            assert!(ctx.branches.is_empty(), "append_branches 0");
        });
        let c = contact(&r, "sip:a@host.example", None, 0, udp("198.51.100.1:5060"));
        assert_eq!(r.route(&c), udp("198.51.100.1:5060"), "a hostname Contact: the source");
        assert_eq!(r.route(&Contact { received: tcp, ..c.clone() }), tcp);
        assert_eq!(r.route(&Contact { path: Some(b"<sip:10.9.9.9:5070;lr>,<sip:10.9.9.8;lr>".to_vec()), ..c }), udp("10.9.9.9:5070"), "Path: its first hop");
    }

    #[test]
    fn path_is_stored_echoed_and_required_by_mode() {
        let paths = "Path: <sip:edge1;lr>\nPath: <sip:edge2;lr>, <sip:edge3;lr>\n";
        // (path_mode, Supported: path, echoed)
        for (mode, supported, echoed) in [(0, true, false), (1, false, true), (2, false, false), (2, true, true)] {
            let r = registrar();
            r.set_param("use_path", &Arg::Int(1)).unwrap();
            r.set_param("path_mode", &Arg::Int(mode)).unwrap();
            let sup = if supported { "Supported: path\n" } else { "" };
            let s = save(&r, "c1", 1, &format!("{paths}{sup}Contact: <sip:a@10.0.0.1>\n"));
            assert_eq!(
                s.headers.contains("\r\nPath: <sip:edge1;lr>,<sip:edge2;lr>, <sip:edge3;lr>\r\n"),
                echoed,
                "mode {mode} supported {supported}: {}",
                s.headers
            );
            assert_eq!(bindings(&r)[0].path.as_deref(), Some(&b"<sip:edge1;lr>,<sip:edge2;lr>, <sip:edge3;lr>"[..]));
        }
        let r = registrar();
        r.set_param("use_path", &Arg::Int(1)).unwrap();
        r.set_param("path_mode", &Arg::Int(1)).unwrap();
        let s = save(&r, "c1", 1, "Contact: <sip:a@10.0.0.1>\n");
        assert_eq!((s.rc, s.code, s.headers.as_str()), (-1, 420, "Unsupported: path\r\n"), "mode 1 needs Path");
        let r = registrar();
        save(&r, "c1", 1, &format!("{paths}Contact: <sip:a@10.0.0.1>\n"));
        assert_eq!(bindings(&r)[0].path, None, "use_path 0: ignored");
    }

    #[test]
    fn gruus_are_issued_and_reach_only_their_instance() {
        let r = registrar();
        let inst = "+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000A95A0E128>\"";
        let s = save(&r, "c1", 1, &format!("Supported: gruu\nContact: <sip:a@10.0.0.1>;{inst};expires=600, <sip:a@10.0.0.2>\n"));
        let line = s.headers.lines().find(|l| l.contains("10.0.0.1")).unwrap();
        let pub_gruu = "sip:alice@a.example;gr=urn:uuid:00000000-0000-1000-8000-000A95A0E128";
        assert!(line.contains(&format!(";pub-gruu=\"{pub_gruu}\"")), "{line}");
        let temp = line.split(";temp-gruu=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        assert!(temp.starts_with("sip:tgruu.") && temp.ends_with("@a.example;gr"), "{temp}");
        let tok = temp.strip_prefix("sip:tgruu.").unwrap().split('@').next().unwrap();
        assert_eq!(temp_gruu_decode(tok), Some(("sip:alice@a.example".into(), "<urn:uuid:00000000-0000-1000-8000-000A95A0E128>".into())));
        assert_eq!(temp, format!("sip:tgruu.{}@a.example;gr", temp_gruu("sip:alice@a.example", "<urn:uuid:00000000-0000-1000-8000-000A95A0E128>", b"c1")));
        for uri in [pub_gruu, temp.as_str()] {
            let cs = r.contacts_for(uri.as_bytes()).unwrap();
            assert_eq!(cs.iter().map(|c| c.uri.as_slice()).collect::<Vec<_>>(), [&b"sip:a@10.0.0.1"[..]], "{uri}");
        }
        assert_eq!(r.contacts_for(b"sip:alice@a.example").unwrap().len(), 2, "the AoR reaches both");
        assert!(r.contacts_for(b"sip:alice@a.example;gr=urn:uuid:other").unwrap().is_empty());
        // Without Supported: gruu, or disabled: none.
        assert!(!save(&r, "c1", 2, &format!("Contact: <sip:a@10.0.0.1>;{inst}\n")).headers.contains("gruu"));
        r.set_param("gruu_enabled", &Arg::Int(0)).unwrap();
        assert!(!save(&r, "c1", 3, &format!("Supported: gruu\nContact: <sip:a@10.0.0.1>;{inst}\n")).headers.contains("gruu"));
    }

    #[test]
    fn temp_gruu_round_trips_and_changes_with_the_call_id() {
        for (aor, inst, cid) in [("sip:a@x", "<urn:uuid:1>", &b"c1"[..]), ("sip:b@y.example", "", b""), ("sip:c@z", "\u{e9}", b"x")] {
            let tok = temp_gruu(aor, inst, cid);
            assert!(tok.bytes().all(|b| b.is_ascii_hexdigit()), "{tok}");
            assert_eq!(temp_gruu_decode(&tok), Some((aor.to_string(), inst.to_string())));
        }
        assert_ne!(temp_gruu("sip:a@x", "i", b"c1"), temp_gruu("sip:a@x", "i", b"c2"));
        assert_eq!(temp_gruu_decode(""), None);
        assert_eq!(temp_gruu_decode("6162"), None, "no separator");
    }

    #[test]
    fn outbound_require_needs_instance_reg_id_support_and_mode() {
        let flow = "Contact: <sip:a@10.0.0.1>;+sip.instance=\"<urn:uuid:1>\";reg-id=1\n";
        for (mode, supported, contact, want) in
            [(1, true, flow, true), (0, true, flow, false), (1, false, flow, false), (1, true, "Contact: <sip:a@10.0.0.1>\n", false)]
        {
            let r = registrar();
            r.set_param("outbound_mode", &Arg::Int(mode)).unwrap();
            let sup = if supported { "Supported: outbound, path\n" } else { "" };
            assert_eq!(save(&r, "c1", 1, &format!("{sup}{contact}")).headers.contains("Require: outbound\r\n"), want, "mode {mode} supported {supported}");
        }
    }

    #[test]
    fn registered_unregister_and_fetch() {
        let r = registrar();
        r.set_param("xavp_cfg", &Arg::Str("cfg".into())).unwrap();
        r.set_param("xavp_rcd", &Arg::Str("rcd".into())).unwrap();
        save(&r, "c1", 1, "Contact: <sip:a@10.0.0.1>;q=0.1\n");
        save(&r, "c2", 1, "Contact: <sip:a@10.0.0.2>;q=0.9\n");
        let msg = register_msg("x", 1, "");
        let args = |uri: &str, opt: i64, act: i64| RegisteredArgs {
            uri: Some(DynStr::Static(uri.into())),
            match_option: Some(DynInt::Static(opt)),
            match_action: Some(DynInt::Static(act)),
        };
        with_ctx(&msg, udp("198.51.100.1:5060"), |ctx| {
            assert_eq!(r.registered(ctx, &args("sip:alice@a.example", 0, 0)), 1);
            let rcd = &ctx.ext::<sip_core::TxnVars>().unwrap().xavps["rcd"][0];
            assert_eq!(rcd["contact"].as_str(), "sip:a@10.0.0.2", "the best binding");
            assert_eq!(r.registered(ctx, &args("alice@a.example", 0, 0)), 1, "a bare user@host");
            assert_eq!(r.registered(ctx, &args("sip:bob@a.example", 0, 0)), -1);
            assert_eq!(r.registered(ctx, &args("sip:a.example", 0, 0)), -1);
            let mut cfg = HashMap::new();
            cfg.insert("match_callid".to_string(), Val::str("c1"));
            cfg.insert("match_contact".to_string(), Val::str("sip:a@10.0.0.2"));
            ctx.ext_mut::<sip_core::TxnVars>().xavps.insert("cfg".into(), vec![cfg]);
            ctx.ext_mut::<sip_core::TxnVars>().xavps.remove("rcd");
            assert_eq!(r.registered(ctx, &args("sip:alice@a.example", 1, 2)), 1, "Call-ID c1");
            assert!(!ctx.ext::<sip_core::TxnVars>().unwrap().xavps.contains_key("rcd"), "match_action 2: no xavp");
            assert_eq!(r.registered(ctx, &args("sip:alice@a.example", 5, 0)), -1, "Call-ID c1 and contact .2 are different bindings");
            assert_eq!(r.registered(ctx, &args("sip:alice@a.example", 2, 0)), 1, "no match_received field: ignored");
            // fetch: best first.
            assert_eq!(r.fetch(ctx, &(DynStr::Static("sip:alice@a.example".into()), "p".into())), 1);
            let f = &ctx.ext::<Fetched>().unwrap().0["p"];
            assert_eq!(f.contacts.iter().map(|c| c.q).collect::<Vec<_>>(), [Some(900), Some(100)]);
            assert_eq!(r.fetch(ctx, &(DynStr::Static("sip:bob@a.example".into()), "q".into())), -1);
            assert_eq!(ctx.ext::<Fetched>().unwrap().0["q"].contacts.len(), 0);
            // unregister one by ruid, then all.
            let ruid = bindings(&r)[1].ruid.clone();
            let un =
                |ctx: &mut Ctx<'_, '_>, uri: &str, ruid: Option<&str>| r.unregister(ctx, &(DynStr::Static(uri.into()), ruid.map(|x| DynStr::Static(x.into()))));
            assert_eq!(un(ctx, "sip:alice@a.example", Some("nope")), -3);
            assert_eq!(un(ctx, "", Some(&ruid)), 1, "any AoR by ruid");
            assert_eq!(bindings(&r).len(), 1);
            assert_eq!(un(ctx, "", Some(&ruid)), -3, "gone");
            assert_eq!(un(ctx, "sip:a.example", None), -1, "no user");
            assert_eq!(un(ctx, "", None), 1, "the To URI");
            assert!(bindings(&r).is_empty());
            assert_eq!(un(ctx, "sip:alice@a.example", None), 1, "also when it had none");
        });
    }

    #[test]
    fn registrar_parameters_and_helpers() {
        let r = Registrar::default();
        assert!(r.set_param("max_contacts", &Arg::Int(-1)).is_err());
        assert!(r.set_param("default_expires", &Arg::Int(1 << 33)).is_err());
        r.set_param("path_mode", &Arg::Int(9)).unwrap();
        assert_eq!(r.path_mode.load(Ordering::Relaxed), 2);
        assert!(r.set_param("bogus", &Arg::Int(1)).is_err());
        assert_eq!(first_path_hop(b"<sip:10.0.0.1:5070;transport=tcp;lr>, <sip:10.0.0.2>"), Some(Dest::new(Proto::Tcp, "10.0.0.1:5070".parse().unwrap())));
        assert_eq!(first_path_hop(b""), None);
        assert!(location_table(&[Arg::Str("location".into())]).is_ok());
        assert!(location_table(&[Arg::Str("loc".into())]).is_err());
        assert!(table_and(&[Arg::Str("location".into())], 2, 3).unwrap_err().contains("2 to 3"));
        assert!(table_and(&[Arg::Str("location".into())], 2, 2).unwrap_err().contains("expected 2 arguments"));
        assert_eq!(parse_flags("4294967296"), None);
        assert_eq!(parse_flags("0x1F"), Some(31));
        let allow = register_msg("c1", 1, "Allow: INVITE, ACK\nAllow: bye\nContact: <sip:a@10.0.0.1>\n");
        let rr = registrar();
        save_as(&rr, &allow, udp("198.51.100.1:5060"), 0);
        assert_eq!(bindings(&rr)[0].methods, 1 | 4 | 8);
        save(&rr, "c1", 2, "Contact: <sip:a@10.0.0.1>\n");
        assert_eq!(bindings(&rr)[0].methods, u32::MAX, "no Allow: everything");
    }
}
