//! `uac` — the proxy acting as a client:
//! * `uac_replace_from([display,] uri)` / `uac_replace_to([display,] uri)`
//!   with automatic restore (`restore_mode` "auto"): replies and later
//!   in-dialog requests in both directions get the right From/To again.
//!   The originals are kept in memory per Call-ID + From tag for
//!   `restore_ttl` seconds (Kamailio encodes them into a Record-Route
//!   parameter instead). `uac_restore_from()` / `uac_restore_to()` exist
//!   for "manual" mode configs.
//! * `uac_auth()` in a failure_route answers a 401/407: credentials from
//!   `modparam("uac", "credential", "user:realm:password")` or from
//!   `auth_username_avp` / `auth_password_avp` / `auth_realm_avp`.
//! * `uac_req_send()` sends the request described by `$uac_req(method|ruri|
//!   furi|turi|ouri|hdrs|body|callid)` through tm.
//! * Remote registrations from the `uacreg` table (`reg_db_url`):
//!   REGISTER with digest auth, refreshed at half the expiry, retried
//!   every `reg_retry_interval`; `uac_reg_lookup(uuid, $dst)`,
//!   `uac_reg_status(uuid)`; RPC `uac.reg_dump`, `uac.reg_reload`,
//!   `uac.reg_refresh <l_uuid>`.

use crate::{args, hdr_span, rand_u64, split_nameaddr};
use md5::{Digest as _, Md5};
use mod_txn::{Tm, UacRequest};
use sip_core::module::{DynStr, FailureReply};
use sip_core::pv::{PvRef, PvSpec, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry, ShardedMap, want_args};
use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

// ---------------------------------------------------------- reply helpers --

pub(crate) fn status(reply: &[u8]) -> u16 {
    reply.get(8..11).and_then(|c| std::str::from_utf8(c).ok()).and_then(|c| c.parse().ok()).unwrap_or(0)
}

pub(crate) fn reason(reply: &[u8]) -> String {
    let line = reply.split(|&c| c == b'\r').next().unwrap_or(b"");
    String::from_utf8_lossy(line.get(12..).unwrap_or(b"")).into_owned()
}

fn header<'a>(msg: &'a [u8], name: &str) -> Option<&'a str> {
    let head = msg.windows(4).position(|w| w == b"\r\n\r\n").and_then(|end| msg.get(..end)).unwrap_or(msg);
    std::str::from_utf8(head).ok()?.split("\r\n").skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

pub(crate) fn to_tag(reply: &[u8]) -> Option<String> {
    let to = header(reply, "To").or_else(|| header(reply, "t"))?;
    param(name_addr(to.as_bytes()).1, b"tag").map(|t| String::from_utf8_lossy(t).into_owned())
}

pub(crate) fn parse_ip(b: &[u8]) -> Option<IpAddr> {
    std::str::from_utf8(b).ok()?.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

/// A digest algorithm the UAC can answer (RFC 7616, for SIP RFC 8760).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DigestAlg {
    Md5,
    Sha256,
    Sha512_256,
}

impl DigestAlg {
    /// Lower-case hex of the digest of `parts` joined by ':'.
    fn hex(self, parts: &[&str]) -> String {
        let joined = parts.join(":");
        let bytes: Vec<u8> = match self {
            DigestAlg::Md5 => Md5::digest(joined.as_bytes()).to_vec(),
            DigestAlg::Sha256 => ring::digest::digest(&ring::digest::SHA256, joined.as_bytes()).as_ref().to_vec(),
            DigestAlg::Sha512_256 => ring::digest::digest(&ring::digest::SHA512_256, joined.as_bytes()).as_ref().to_vec(),
        };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn token(self, sess: bool) -> String {
        let base = match self {
            DigestAlg::Md5 => "MD5",
            DigestAlg::Sha256 => "SHA-256",
            DigestAlg::Sha512_256 => "SHA-512-256",
        };
        if sess { format!("{base}-sess") } else { base.to_string() }
    }
}

#[cfg(test)]
fn md5hex(parts: &[&str]) -> String {
    DigestAlg::Md5.hex(parts)
}

/// The algorithm a Digest challenge asks for and whether it is a `-sess`
/// variant; no `algorithm` means MD5. None: not a Digest challenge, or an
/// algorithm we can't answer.
fn challenge_alg(ch: &str) -> Option<(DigestAlg, bool)> {
    let scheme = ch.trim_start().get(..6)?;
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let a = chal_param(ch, "algorithm").unwrap_or_else(|| "MD5".into()).to_ascii_uppercase();
    let (base, sess) = a.strip_suffix("-SESS").map_or((a.as_str(), false), |b| (b, true));
    let alg = match base {
        "MD5" => DigestAlg::Md5,
        "SHA-256" => DigestAlg::Sha256,
        "SHA-512-256" => DigestAlg::Sha512_256,
        _ => return None,
    };
    Some((alg, sess))
}

/// Every value of a header (one challenge per header line).
fn headers<'a>(msg: &'a [u8], name: &str) -> Vec<&'a str> {
    let head = msg.windows(4).position(|w| w == b"\r\n\r\n").and_then(|end| msg.get(..end)).unwrap_or(msg);
    let Ok(text) = std::str::from_utf8(head) else { return vec![] };
    text.split("\r\n")
        .skip(1)
        .filter_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then_some(v.trim())
        })
        .collect()
}

/// The challenge to answer: a server lists its challenges in its order of
/// preference (RFC 8760, e.g. SHA-256 before MD5), so the first one with an
/// algorithm we support, a realm and a nonce, and for which `usable(realm)`
/// holds.
fn pick_challenge(reply: &[u8], name: &str, mut usable: impl FnMut(&str) -> bool) -> Option<(String, String)> {
    headers(reply, name).into_iter().find_map(|ch| {
        challenge_alg(ch)?;
        chal_param(ch, "nonce")?;
        let realm = chal_param(ch, "realm")?;
        usable(&realm).then(|| (ch.to_string(), realm))
    })
}

/// `key="value"` / `key=value` from a challenge.
fn chal_param(ch: &str, key: &str) -> Option<String> {
    // ASCII lowercasing keeps every byte offset, so `lower`'s match
    // offsets are valid in `ch`. `key=` cannot overlap itself.
    let lower = ch.to_ascii_lowercase();
    let pat = format!("{key}=");
    lower.match_indices(&pat).find_map(|(at, _)| {
        let ok = at.checked_sub(1).is_none_or(|before| matches!(lower.as_bytes().get(before), Some(b' ' | b',' | b'\t')));
        let v = ch.get(at..)?.get(pat.len()..)?.trim_start();
        ok.then(|| match v.strip_prefix('"') {
            Some(q) => q.split('"').next().unwrap_or(q).to_string(),
            None => v.split([',', ' ']).next().unwrap_or(v).to_string(),
        })
    })
}

/// Authorization header value answering `challenge`.
fn digest_answer(challenge: &str, user: &str, pass: &str, method: &str, uri: &str) -> Option<String> {
    digest_answer_with(challenge, user, pass, method, uri, &format!("{:016x}", rand_u64()))
}

/// [`digest_answer`] with a given client nonce (RFC 7616 §3.4).
fn digest_answer_with(challenge: &str, user: &str, pass: &str, method: &str, uri: &str, cnonce: &str) -> Option<String> {
    let (alg, sess) = challenge_alg(challenge)?;
    let realm = chal_param(challenge, "realm")?;
    let nonce = chal_param(challenge, "nonce")?;
    let qop = chal_param(challenge, "qop").filter(|q| q.split(',').any(|x| x.trim() == "auth"));
    let opaque = chal_param(challenge, "opaque");
    let mut ha1 = alg.hex(&[user, &realm, pass]);
    if sess {
        ha1 = alg.hex(&[&ha1, &nonce, cnonce]);
    }
    let ha2 = alg.hex(&[method, uri]);
    let mut h = format!("Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", algorithm={}", alg.token(sess));
    if qop.is_some() {
        let resp = alg.hex(&[&ha1, &nonce, "00000001", cnonce, "auth", &ha2]);
        h.push_str(&format!(", qop=auth, nc=00000001, cnonce=\"{cnonce}\", response=\"{resp}\""));
    } else {
        if sess {
            h.push_str(&format!(", cnonce=\"{cnonce}\""));
        }
        h.push_str(&format!(", response=\"{}\"", alg.hex(&[&ha1, &nonce, &ha2])));
    }
    if let Some(o) = opaque {
        h.push_str(&format!(", opaque=\"{o}\""));
    }
    Some(h)
}

// ----------------------------------------------------------- From/To swap --

#[derive(Clone, Debug, Default)]
struct Swap {
    /// (original name-addr, replacement name-addr)
    from: Option<(String, String)>,
    to: Option<(String, String)>,
    expires: u64,
}

/// Replace the name-addr part of a From/To header if its URI is `old`'s.
fn swap_hdr(ctx: &mut Ctx<'_, '_>, kind: HdrKind, old: &str, new: &str) -> bool {
    let Some((start, _, body)) = hdr_span(ctx, kind) else { return false };
    let (head, uri, _) = split_nameaddr(&body);
    let (_, old_uri, _) = split_nameaddr(old);
    if !uri.eq_ignore_ascii_case(&old_uri) {
        return false;
    }
    // The header body may start with whitespace the parser kept.
    let off = body.find(head.as_str()).unwrap_or(0);
    ctx.lumps.replace(start.saturating_add(off), head.len(), new.as_bytes().to_vec());
    true
}

fn callid_tags(ctx: &mut Ctx<'_, '_>) -> Option<(String, String, Option<String>)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let cid = s(ctx.msg.get(HdrKind::CallId)?.body);
    let ft = param(name_addr(ctx.msg.get(HdrKind::From)?.body).1, b"tag").map(s)?;
    let tt = ctx.msg.get(HdrKind::To).and_then(|h| param(name_addr(h.body).1, b"tag")).map(s);
    Some((cid, ft, tt))
}

// --------------------------------------------------------- registrations --

#[derive(Clone, Debug, PartialEq, Eq)]
enum RegState {
    Idle,
    Registering,
    Registered,
    Failed(u16),
    AuthFailed,
    Disabled,
}

#[derive(Clone, Debug)]
struct Reg {
    l_uuid: String,
    l_username: String,
    l_domain: String,
    r_username: String,
    r_domain: String,
    realm: String,
    auth_username: String,
    auth_password: String,
    auth_proxy: String,
    expires: u64,
    state: RegState,
    next_at: u64,
    registered_until: u64,
    callid: String,
    cseq: u32,
}

/// `$uac_req(...)` for `uac_req_send()`.
#[derive(Default)]
struct ReqSpec {
    method: String,
    ruri: String,
    furi: String,
    turi: String,
    ouri: String,
    hdrs: String,
    body: String,
    callid: String,
}

pub struct Uac {
    auto_restore: std::sync::atomic::AtomicBool,
    restore_ttl: AtomicU64,
    credentials: Mutex<Vec<(String, String, String)>>,
    avp_names: Mutex<[Option<String>; 3]>,
    avps: OnceLock<[Option<PvRef>; 3]>,
    swaps: ShardedMap<(String, String), Swap>,
    reg_db_url: Mutex<Option<String>>,
    reg_contact: Mutex<String>,
    reg_retry: AtomicU64,
    regs: RwLock<Vec<Arc<Mutex<Reg>>>>,
    tm: OnceLock<Arc<Tm>>,
}

impl Default for Uac {
    fn default() -> Self {
        Self {
            auto_restore: std::sync::atomic::AtomicBool::new(true),
            restore_ttl: AtomicU64::new(43200),
            credentials: Mutex::new(Vec::new()),
            avp_names: Mutex::new([None, None, None]),
            avps: OnceLock::new(),
            swaps: ShardedMap::new(64),
            reg_db_url: Mutex::new(None),
            reg_contact: Mutex::new("127.0.0.1:5060".into()),
            reg_retry: AtomicU64::new(60),
            regs: RwLock::new(Vec::new()),
            tm: OnceLock::new(),
        }
    }
}

impl Uac {
    fn replace(&self, ctx: &mut Ctx<'_, '_>, kind: HdrKind, display: Option<String>, uri: String) -> i32 {
        let Some((cid, ftag, _)) = callid_tags(ctx) else { return -1 };
        let Some((start, _, body)) = hdr_span(ctx, kind) else { return -1 };
        let (head, old_uri, _) = split_nameaddr(&body);
        let new_head = match display {
            Some(d) if d.is_empty() => format!("<{uri}>"),
            Some(d) => format!("\"{}\" <{uri}>", d.trim_matches('"')),
            None if head.contains('<') => head.replacen(&old_uri, &uri, 1),
            None => format!("<{uri}>"),
        };
        let off = body.find(head.as_str()).unwrap_or(0);
        ctx.lumps.replace(start.saturating_add(off), head.len(), new_head.clone().into_bytes());
        let exp = unix_secs().saturating_add(self.restore_ttl.load(Ordering::Relaxed));
        self.swaps.alter((cid, ftag), |cur| {
            let mut s = cur.unwrap_or_default();
            let pair = Some((head.clone(), new_head.clone()));
            if kind == HdrKind::From {
                s.from = pair;
            } else {
                s.to = pair;
            }
            s.expires = exp;
            (Some(s), ())
        });
        1
    }

    /// Apply the stored replacements to an in-dialog request or a reply.
    fn restore(&self, ctx: &mut Ctx<'_, '_>) {
        if self.swaps.is_empty() {
            return;
        }
        let Some((cid, ftag, ttag)) = callid_tags(ctx) else { return };
        let req = ctx.msg.is_request();
        if req && ttag.is_none() {
            return; // initial request (or its retransmission): the script decides
        }
        if let Some(s) = self.swaps.get_cloned(&(cid.clone(), ftag)) {
            // Caller side: requests go out replaced, replies come back restored.
            let dir = |p: &(String, String)| if req { (p.0.clone(), p.1.clone()) } else { (p.1.clone(), p.0.clone()) };
            if let Some(p) = &s.from {
                let (o, n) = dir(p);
                swap_hdr(ctx, HdrKind::From, &o, &n);
            }
            if let Some(p) = &s.to {
                let (o, n) = dir(p);
                swap_hdr(ctx, HdrKind::To, &o, &n);
            }
        } else if let Some(s) = ttag.and_then(|t| self.swaps.get_cloned(&(cid, t))) {
            // Callee side: its requests carry the replaced values in To/From.
            if let Some((orig, new)) = &s.from {
                if req {
                    swap_hdr(ctx, HdrKind::To, new, orig);
                } else {
                    swap_hdr(ctx, HdrKind::To, orig, new);
                }
            }
            if let Some((orig, new)) = &s.to {
                if req {
                    swap_hdr(ctx, HdrKind::From, new, orig);
                } else {
                    swap_hdr(ctx, HdrKind::From, orig, new);
                }
            }
        }
    }

    fn creds_for(&self, ctx: &mut Ctx<'_, '_>, realm: &str) -> Option<(String, String)> {
        if let Some([Some(u), Some(p), r]) = self.avps.get() {
            let (u, p) = (u.get(ctx).as_str().into_owned(), p.get(ctx).as_str().into_owned());
            let r = r.as_ref().map(|r| r.get(ctx).as_str().into_owned());
            if !u.is_empty() && r.as_deref().is_none_or(|r| r.is_empty() || r == realm) {
                return Some((u, p));
            }
        }
        lock(&self.credentials).iter().find(|(_, r, _)| r == realm).map(|(u, _, p)| (u.clone(), p.clone()))
    }

    fn uac_auth(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some(FailureReply(reply)) = ctx.ext::<FailureReply>().cloned() else { return -1 };
        let code = status(&reply);
        let (chal_hdr, auth_hdr) = match code {
            401 => ("WWW-Authenticate", "Authorization"),
            407 => ("Proxy-Authenticate", "Proxy-Authorization"),
            _ => return -1,
        };
        let mut found = None;
        let picked = pick_challenge(&reply, chal_hdr, |realm| {
            found = self.creds_for(ctx, realm);
            found.is_some()
        });
        let (Some((ch, _)), Some((user, pass))) = (picked, found) else {
            let realms: Vec<String> = headers(&reply, chal_hdr).iter().filter_map(|c| chal_param(c, "realm")).collect();
            sip_core::log::log(sip_core::log::L_WARN, &format!("uac_auth: no usable challenge or no credentials (realms {realms:?})"));
            return -1;
        };
        let method = match ctx.msg.first {
            sip_parser::FirstLine::Request { method_raw, .. } => String::from_utf8_lossy(method_raw).into_owned(),
            _ => return -1,
        };
        let uri = String::from_utf8_lossy(ctx.ruri()).into_owned();
        let Some(ans) = digest_answer(&ch, &user, &pass, &method, &uri) else { return -1 };
        let at = ctx.msg.first_line_end;
        ctx.lumps.insert(at, format!("{auth_hdr}: {ans}\r\n").into_bytes());
        1
    }

    fn load_regs(&self) -> Result<usize, String> {
        let Some(url) = lock(&self.reg_db_url).clone() else { return Ok(0) };
        let db = sip_db::connect(&url)?;
        let rows = db.query(
            "uacreg",
            &["l_uuid", "l_username", "l_domain", "r_username", "r_domain", "realm", "auth_username", "auth_password", "auth_proxy", "expires", "flags"],
            &[],
        )?;
        let old: Vec<Reg> = read(&self.regs).iter().map(|r| lock(r).clone()).collect();
        let mut v = Vec::new();
        for r in rows.rows {
            let t = |i: usize| r.get(i).map(sip_db::DbVal::text).unwrap_or_default();
            let flags = r.get(10).and_then(sip_db::DbVal::int).unwrap_or(0);
            let prev = old.iter().find(|o| o.l_uuid == t(0));
            v.push(Arc::new(Mutex::new(Reg {
                l_uuid: t(0),
                l_username: t(1),
                l_domain: t(2),
                r_username: t(3),
                r_domain: t(4),
                realm: t(5),
                auth_username: t(6),
                auth_password: t(7),
                auth_proxy: t(8),
                expires: u64::try_from(r.get(9).and_then(sip_db::DbVal::int).unwrap_or(3600)).unwrap_or(0).max(30),
                state: if flags & 1 != 0 { RegState::Disabled } else { prev.map_or(RegState::Idle, |p| p.state.clone()) },
                next_at: prev.map_or(0, |p| p.next_at),
                registered_until: prev.map_or(0, |p| p.registered_until),
                callid: prev.map_or_else(|| format!("uacreg-{:x}", rand_u64()), |p| p.callid.clone()),
                cseq: prev.map_or(0, |p| p.cseq),
            })));
        }
        let n = v.len();
        *write(&self.regs) = v;
        Ok(n)
    }

    fn send_register(self: &Arc<Self>, reg: &Arc<Mutex<Reg>>, auth: Option<String>) {
        let Some(tm) = self.tm.get() else { return };
        let req = {
            let mut r = lock(reg);
            // A 32-bit number: wrap rather than panic (2^32 re-registrations are out of reach).
            r.cseq = r.cseq.wrapping_add(1);
            r.state = RegState::Registering;
            let aor = format!("sip:{}@{}", r.r_username, r.r_domain);
            let ruri = format!("sip:{}", r.r_domain);
            let contact = lock(&self.reg_contact).clone();
            let mut headers =
                format!("From: <{aor}>;tag={:x}\r\nTo: <{aor}>\r\nContact: <sip:{}@{contact}>\r\nExpires: {}\r\n", rand_u64() >> 16, r.l_uuid, r.expires);
            if let Some(a) = &auth {
                headers.push_str(a);
            }
            let dst = if r.auth_proxy.is_empty() { None } else { sip_core::pvcore::dest_from_uri(r.auth_proxy.as_bytes()) };
            UacRequest { method: "REGISTER".into(), ruri, dst, call_id: Some(r.callid.clone()), cseq: r.cseq, headers, ..Default::default() }
        };
        let me = self.clone();
        let rg = reg.clone();
        let had_auth = auth.is_some();
        let ruri = req.ruri.clone();
        let res = tm.t_uac(
            req,
            Some(Box::new(move |code, reply| {
                let retry = me.reg_retry.load(Ordering::Relaxed);
                match code {
                    200..=299 => {
                        let mut r = lock(&rg);
                        let exp = header(reply, "Expires").and_then(|e| e.parse::<u64>().ok()).unwrap_or(r.expires).max(10);
                        r.state = RegState::Registered;
                        r.registered_until = unix_secs().saturating_add(exp);
                        r.next_at = unix_secs().saturating_add(exp / 2);
                    }
                    401 | 407 if !had_auth => {
                        let (ch, ah) = if code == 401 { ("WWW-Authenticate", "Authorization") } else { ("Proxy-Authenticate", "Proxy-Authorization") };
                        let ans = {
                            let r = lock(&rg);
                            let user = if r.auth_username.is_empty() { r.r_username.clone() } else { r.auth_username.clone() };
                            pick_challenge(reply, ch, |_| true).and_then(|(c, _)| digest_answer(&c, &user, &r.auth_password, "REGISTER", &ruri))
                        };
                        match ans {
                            Some(a) => me.send_register(&rg, Some(format!("{ah}: {a}\r\n"))),
                            None => {
                                let mut r = lock(&rg);
                                r.state = RegState::AuthFailed;
                                r.next_at = unix_secs().saturating_add(retry);
                            }
                        }
                    }
                    401 | 407 => {
                        let mut r = lock(&rg);
                        r.state = RegState::AuthFailed;
                        r.next_at = unix_secs().saturating_add(retry);
                    }
                    c => {
                        let mut r = lock(&rg);
                        r.state = RegState::Failed(c);
                        r.next_at = unix_secs().saturating_add(retry);
                    }
                }
            })),
        );
        if let Err(e) = res {
            let mut r = lock(reg);
            sip_core::log::log(sip_core::log::L_ERR, &format!("uac: REGISTER for {}: {e}", r.l_uuid));
            r.state = RegState::Failed(0);
            r.next_at = unix_secs().saturating_add(self.reg_retry.load(Ordering::Relaxed));
        }
    }

    fn reg_tick(self: &Arc<Self>) {
        let t = unix_secs();
        let due: Vec<Arc<Mutex<Reg>>> = read(&self.regs)
            .iter()
            .filter(|r| {
                let g = lock(r);
                g.state != RegState::Disabled && g.state != RegState::Registering && g.next_at <= t
            })
            .cloned()
            .collect();
        for r in due {
            self.send_register(&r, None);
        }
    }

    fn reg_json(r: &Reg) -> sip_core::serde_json::Value {
        json!({"l_uuid": r.l_uuid, "l_username": r.l_username, "l_domain": r.l_domain, "r_username": r.r_username, "r_domain": r.r_domain,
            "realm": r.realm, "auth_username": r.auth_username, "auth_proxy": r.auth_proxy, "expires": r.expires,
            "state": format!("{:?}", r.state), "registered_until": r.registered_until, "cseq": r.cseq})
    }
}

impl Module for Uac {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const NAMED: &[Param] = &[arg("display", Str), arg("uri", Uri)];
        const LOOKUP: &[Param] = &[arg("uuid", Str), arg("out", Var)];
        const URI: &[Param] = &[arg("uri", Uri)];
        const UUID: &[Param] = &[arg("uuid", Str)];
        Some(vec![
            sig("uac_replace_from", "replace_from", URI, Ret::Bool, "Replace the From URI (restored in the dialog's later messages)"),
            sig("uac_replace_from", "replace_from_named", NAMED, Ret::Bool, "Replace the From display name and URI (\"\" drops the display name)"),
            sig("uac_replace_to", "replace_to", URI, Ret::Bool, "Replace the To URI (restored in the dialog's later messages)"),
            sig("uac_replace_to", "replace_to_named", NAMED, Ret::Bool, "Replace the To display name and URI (\"\" drops the display name)"),
            sig("uac_restore_from", "restore_from", &[], Ret::Void, "Restore a From replaced earlier in the dialog"),
            sig("uac_restore_to", "restore_to", &[], Ret::Void, "Restore a To replaced earlier in the dialog"),
            sig("uac_auth", "auth", &[], Ret::Bool, "Answer the 401/407 challenge with the configured credentials").allowed(ctx::FAILURE),
            sig("uac_req_send", "send_request", &[], Ret::Bool, "Send the request described in $uac_req(…)").allowed(ctx::ANY),
            sig("uac_reg_lookup", "lookup_registration", LOOKUP, Ret::Bool, "The local address of remote registration `uuid`, into `out`").allowed(ctx::ANY),
            sig("uac_reg_status", "is_registered", UUID, Ret::Bool, "Remote registration `uuid` is registered").allowed(ctx::ANY),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p(
                "restore_mode",
                Ty::Enum(&[("auto", "auto"), ("manual", "manual"), ("none", "none")]),
                "auto",
                "\"auto\": restore replaced From/To automatically in replies and in-dialog requests",
            ),
            p("restore_ttl", Ty::Duration(Unit::Sec), "12h", "How long the original From/To are kept"),
            p("credential", Ty::List(&Ty::Str), "", "Credentials for uac_auth, \"user:realm:password\""),
            p("auth_username_avp", Ty::Str, "", "AVP with the uac_auth username"),
            p("auth_password_avp", Ty::Str, "", "AVP with the uac_auth password"),
            p("auth_realm_avp", Ty::Str, "", "AVP with the uac_auth realm"),
            p("reg_db_url", Ty::Str, "", "Database with the uacreg table (remote registrations)"),
            p("reg_contact_addr", Ty::Str, "127.0.0.1:5060", "Address in the Contact of remote registrations"),
            p("reg_retry_interval", Ty::Duration(Unit::Sec), "60s", "Retry a failed remote registration after this"),
        ])
    }

    fn name(&self) -> &'static str {
        "uac"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut avps = lock(&self.avp_names);
        let [user_avp, password_avp, realm_avp] = &mut *avps;
        match name {
            "restore_mode" => self.auto_restore.store(v.str()? == "auto", Ordering::Relaxed),
            "restore_ttl" => self.restore_ttl.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "credential" => {
                let s = v.str()?;
                let mut it = s.splitn(3, ':');
                let (Some(u), Some(r), Some(p)) = (it.next(), it.next(), it.next()) else {
                    return Err(format!("uac credential {s:?}: expected user:realm:password"));
                };
                lock(&self.credentials).push((u.into(), r.into(), p.into()));
            }
            "auth_username_avp" => *user_avp = Some(v.str()?.into()),
            "auth_password_avp" => *password_avp = Some(v.str()?.into()),
            "auth_realm_avp" => *realm_avp = Some(v.str()?.into()),
            "reg_db_url" => *lock(&self.reg_db_url) = Some(v.str()?.into()),
            "reg_contact_addr" => *lock(&self.reg_contact) = v.str()?.into(),
            "reg_retry_interval" => self.reg_retry.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "restore_dlg"
            | "rr_from_store_param"
            | "rr_to_store_param"
            | "restore_passwd"
            | "reg_timer_interval"
            | "reg_hash_size"
            | "reg_db_table"
            | "reg_keep_callid"
            | "reg_random_delay"
            | "reg_active"
            | "reg_gc_interval"
            | "auth_hdr_avp"
            | "uac_auth_mode" => {}
            _ => return Err(format!("uac: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let names = lock(&self.avp_names).clone();
        let p = |n: &Option<String>| n.as_ref().map(|s| parse_pv(s, reg.pvs())).transpose();
        let _ = self.avps.set([p(&names[0])?, p(&names[1])?, p(&names[2])?]);
        let tm = reg.api::<Tm>().ok_or("uac needs tm: put loadmodule \"tm\" before \"uac\"")?;
        let _ = self.tm.set(tm);
        let n = self.load_regs()?;
        if n > 0 {
            sip_core::log::log(sip_core::log::L_INFO, &format!("uac: {n} remote registrations"));
        }
        let m = "uac";
        let fix = |a: &[Arg]| -> Result<(Option<DynStr>, DynStr), String> {
            match a {
                [uri] => Ok((None, uri.dyn_str()?)),
                [display, uri] => Ok((Some(display.dyn_str()?), uri.dyn_str()?)),
                _ => Err("expected [display,] uri".into()),
            }
        };
        for (name, kind) in [("uac_replace_from", HdrKind::From), ("uac_replace_to", HdrKind::To)] {
            let me = self.clone();
            reg.export(m, name, fix, move |ctx: &mut Ctx, (d, u): &(Option<DynStr>, DynStr)| {
                let d = d.as_ref().map(|d| d.eval(ctx).into_owned());
                let u = u.eval(ctx).into_owned();
                me.replace(ctx, kind, d, u)
            });
        }
        for name in ["uac_restore_from", "uac_restore_to"] {
            let me = self.clone();
            reg.export(
                m,
                name,
                |a: &[Arg]| want_args(a, 0),
                move |ctx: &mut Ctx, _: &()| {
                    if !me.auto_restore.load(Ordering::Relaxed) {
                        me.restore(ctx);
                    }
                    1
                },
            );
        }
        let me = self.clone();
        reg.export(
            m,
            "uac_auth",
            |a: &[Arg]| if a.len() > 1 { Err("expected at most 1 argument".to_string()) } else { Ok(()) },
            move |ctx: &mut Ctx, _: &()| me.uac_auth(ctx),
        );
        // $uac_req(key) + uac_req_send()
        reg.pv(
            "uac_req",
            PvSpec::rw(
                |ctx, p| {
                    let Some(r) = ctx.ext::<ReqSpec>() else { return Val::Null };
                    let v = match p.name.as_str() {
                        "method" => &r.method,
                        "ruri" => &r.ruri,
                        "furi" => &r.furi,
                        "turi" => &r.turi,
                        "ouri" => &r.ouri,
                        "hdrs" => &r.hdrs,
                        "body" => &r.body,
                        "callid" => &r.callid,
                        _ => return Val::Null,
                    };
                    Val::str(v)
                },
                |ctx, p, v| {
                    let r = ctx.ext_mut::<ReqSpec>();
                    let s = if v.is_null() { String::new() } else { v.as_str().into_owned() };
                    match p.name.as_str() {
                        "all" if v.is_null() => *r = ReqSpec::default(),
                        "method" => r.method = s,
                        "ruri" => r.ruri = s,
                        "furi" => r.furi = s,
                        "turi" => r.turi = s,
                        "ouri" => r.ouri = s,
                        "hdrs" => r.hdrs = s,
                        "body" => r.body = s,
                        "callid" => r.callid = s,
                        k => return Err(format!("$uac_req({k}): unknown field")),
                    }
                    Ok(())
                },
            )
            .with_param(),
        );
        let me = self.clone();
        reg.export(
            m,
            "uac_req_send",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let (Some(r), Some(tm)) = (ctx.ext::<ReqSpec>(), me.tm.get()) else { return -1 };
                if r.method.is_empty() || r.ruri.is_empty() {
                    return -1;
                }
                let mut headers = r.hdrs.replace("\r\n", "\n").replace('\n', "\r\n");
                if !headers.is_empty() && !headers.ends_with("\r\n") {
                    headers.push_str("\r\n");
                }
                let req = UacRequest {
                    method: r.method.clone(),
                    ruri: r.ruri.clone(),
                    dst: if r.ouri.is_empty() { None } else { sip_core::pvcore::dest_from_uri(r.ouri.as_bytes()) },
                    from: (!r.furi.is_empty()).then(|| r.furi.clone()),
                    to: (!r.turi.is_empty()).then(|| r.turi.clone()),
                    call_id: (!r.callid.is_empty()).then(|| r.callid.clone()),
                    headers,
                    body: r.body.clone().into_bytes(),
                    ..Default::default()
                };
                if tm.t_uac(req, None).is_ok() { 1 } else { -1 }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "uac_reg_lookup",
            |a: &[Arg]| -> Result<(DynStr, PvRef), String> {
                let [u, out] = args(a)?;
                let out = match out {
                    Arg::Fmt(f) => f.single_pv().cloned().ok_or("expected a variable")?,
                    _ => return Err("expected a variable".into()),
                };
                Ok((u.dyn_str()?, out))
            },
            move |ctx: &mut Ctx, (u, out): &(DynStr, PvRef)| {
                let mut uuid = u.eval(ctx).into_owned();
                if let Some(p) = parse_uri(uuid.as_bytes()).and_then(|p| p.user) {
                    uuid = String::from_utf8_lossy(p).into_owned();
                }
                let found = read(&me.regs).iter().find_map(|r| {
                    let g = lock(r);
                    (g.l_uuid == uuid).then(|| format!("sip:{}@{}", g.l_username, g.l_domain))
                });
                match found {
                    Some(v) => {
                        if out.set(ctx, Val::Str(v)).is_ok() {
                            1
                        } else {
                            -1
                        }
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "uac_reg_status",
            |a: &[Arg]| {
                let [u] = args(a)?;
                u.dyn_str()
            },
            move |ctx: &mut Ctx, u: &DynStr| {
                let uuid = u.eval(ctx).into_owned();
                let st = read(&me.regs).iter().find_map(|r| {
                    let g = lock(r);
                    (g.l_uuid == uuid).then(|| g.state.clone())
                });
                match st {
                    Some(RegState::Registered) => 1,
                    Some(_) => -2,
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.rpc.add("uac.reg_dump", "Remote registrations", move |_| Ok(json!(read(&me.regs).iter().map(|r| Uac::reg_json(&lock(r))).collect::<Vec<_>>())));
        let me = self.clone();
        reg.rpc.add("uac.reg_reload", "Reload the uacreg table", move |_| me.load_regs().map(|n| json!(n)));
        let me = self.clone();
        reg.rpc.add("uac.reg_refresh", "uac.reg_refresh <l_uuid>: register now", move |p| {
            let uuid = sip_core::rpc::str_param(p, 0)?;
            let r = read(&me.regs).iter().find(|r| lock(r).l_uuid == uuid).cloned().ok_or("no such registration")?;
            lock(&r).next_at = 0;
            Ok(json!(0))
        });
        Ok(())
    }

    fn observes(&self) -> bool {
        self.auto_restore.load(Ordering::Relaxed)
    }

    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        self.restore(ctx);
    }

    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        self.restore(ctx);
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        std::thread::Builder::new()
            .name("uac-timer".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let t = unix_secs();
                    self.swaps.retain(|_, s| s.expires > t);
                    self.reg_tick();
                }
            })
            .map_err(|e| format!("cannot start the uac timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_and_challenges() {
        let ch = r#"Digest realm="x", nonce="abc", qop="auth,auth-int", opaque="o1""#;
        assert_eq!(chal_param(ch, "realm").as_deref(), Some("x"));
        assert_eq!(chal_param(ch, "opaque").as_deref(), Some("o1"));
        let a = digest_answer(r#"Digest realm="x", nonce="n""#, "alice", "secret", "REGISTER", "sip:h").unwrap();
        let ha1 = md5hex(&["alice", "x", "secret"]);
        let ha2 = md5hex(&["REGISTER", "sip:h"]);
        assert!(a.contains(&format!("response=\"{}\"", md5hex(&[&ha1, "n", &ha2]))));
        assert!(digest_answer(ch, "a", "b", "INVITE", "sip:x").unwrap().contains("qop=auth, nc=00000001"));
        assert_eq!(status(b"SIP/2.0 407 Proxy Auth Required\r\n"), 407);
        assert_eq!(reason(b"SIP/2.0 407 Proxy Auth Required\r\n"), "Proxy Auth Required");
        assert_eq!(to_tag(b"SIP/2.0 200 OK\r\nTo: <sip:b@x>;tag=9\r\n\r\n").as_deref(), Some("9"));
    }

    use crate::testutil::{FakeNet, crlf, rendered, request, udp, with_ctx};

    #[test]
    fn digest_response_matches_rfc_2617_example() {
        // RFC 2617 §3.5.
        let ha1 = md5hex(&["Mufasa", "testrealm@host.com", "Circle Of Life"]);
        let ha2 = md5hex(&["GET", "/dir/index.html"]);
        assert_eq!(ha1, "939e7578ed9e3c518a452acee763bce9");
        let resp = md5hex(&[&ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b", "auth", &ha2]);
        assert_eq!(resp, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn digest_answer_with_qop_uses_its_cnonce() {
        let ch = r#"Digest realm="r", nonce="n1", qop="auth-int,auth", opaque="op""#;
        let a = digest_answer(ch, "u", "p", "INVITE", "sip:b@x").unwrap();
        let cnonce = chal_param(&a, "cnonce").unwrap();
        let ha1 = md5hex(&["u", "r", "p"]);
        let ha2 = md5hex(&["INVITE", "sip:b@x"]);
        let want = md5hex(&[&ha1, "n1", "00000001", &cnonce, "auth", &ha2]);
        assert_eq!(chal_param(&a, "response").as_deref(), Some(want.as_str()));
        assert!(a.starts_with(r#"Digest username="u", realm="r", nonce="n1", uri="sip:b@x", algorithm=MD5, qop=auth, nc=00000001"#), "{a}");
        assert!(a.ends_with(r#", opaque="op""#), "{a}");
        // Only auth-int offered: answered without qop.
        let a = digest_answer(r#"Digest realm="r", nonce="n1", qop="auth-int""#, "u", "p", "INVITE", "sip:b@x").unwrap();
        assert!(!a.contains("qop") && !a.contains("opaque"), "{a}");
        assert_eq!(digest_answer(r#"Digest nonce="n""#, "u", "p", "INVITE", "sip:b@x"), None, "no realm");
        assert_eq!(digest_answer(r#"Digest realm="r""#, "u", "p", "INVITE", "sip:b@x"), None, "no nonce");
    }

    #[test]
    fn challenge_parameters() {
        let ch = r#"Digest REALM="Big Co", xnonce="no", nonce=abc,stale=TRUE, algorithm= MD5"#;
        let cases = [("realm", Some("Big Co")), ("nonce", Some("abc")), ("stale", Some("TRUE")), ("algorithm", Some("MD5")), ("opaque", None)];
        for (k, want) in cases {
            assert_eq!(chal_param(ch, k).as_deref(), want, "{k}");
        }
        assert_eq!(chal_param("realm=\"unterminated", "realm").as_deref(), Some("unterminated"));
    }

    #[test]
    fn reply_helpers() {
        let r = b"SIP/2.0 401 Unauthorized\r\nt: <sip:b@x>;tag=99\r\nWWW-Authenticate: Digest realm=\"r\"\r\n\r\nTo: <sip:z@x>;tag=body";
        assert_eq!((status(r), reason(r)), (401, "Unauthorized".to_string()));
        assert_eq!(to_tag(r).as_deref(), Some("99"), "compact form, and the body is not searched");
        assert_eq!(header(r, "www-authenticate"), Some("Digest realm=\"r\""));
        assert_eq!(header(r, "Contact"), None);
        assert_eq!((status(b"SIP/2.0"), reason(b"SIP/2.0")), (0, String::new()));
        assert_eq!(status(b"SIP/2.0 abc x\r\n"), 0);
        assert_eq!(parse_ip(b"[::1]"), "::1".parse().ok());
        assert_eq!(parse_ip(b"host"), None);
    }

    fn header_line(out: &str, name: &str) -> String {
        out.lines().find(|l| l.starts_with(name)).unwrap_or_default().to_string()
    }

    #[test]
    fn replace_from_and_to_rewrite_the_name_addr() {
        let net = FakeNet(None);
        let uac = Uac::default();
        let cases: &[(HdrKind, Option<&str>, &str, &str)] = &[
            (HdrKind::From, None, "From: \"Alice\" <sip:alice@a.example>;tag=ft", "From: \"Alice\" <sip:anon@anon.invalid>;tag=ft"),
            (HdrKind::From, Some("Anonymous"), "From: \"Alice\" <sip:alice@a.example>;tag=ft", "From: \"Anonymous\" <sip:anon@anon.invalid>;tag=ft"),
            (HdrKind::From, Some("\"Q\""), "From: <sip:alice@a.example>;tag=ft", "From: \"Q\" <sip:anon@anon.invalid>;tag=ft"),
            (HdrKind::From, Some(""), "From: \"Alice\" <sip:alice@a.example>;tag=ft", "From: <sip:anon@anon.invalid>;tag=ft"),
            (HdrKind::From, None, "From: sip:alice@a.example;tag=ft", "From: <sip:anon@anon.invalid>;tag=ft"),
            (HdrKind::To, None, "To: <sip:bob@b.example>", "To: <sip:anon@anon.invalid>"),
        ];
        for (kind, display, from_line, want) in cases {
            let base = request("INVITE", "sip:bob@b.example", "");
            let original = if *kind == HdrKind::From { "From: \"Alice\" <sip:alice@a.example>;tag=ft" } else { "To: <sip:bob@b.example>" };
            let msg = base.replace(original, from_line);
            let out = with_ctx(&msg, udp("192.0.2.1:5060"), &net, |ctx| {
                assert_eq!(uac.replace(ctx, *kind, display.map(String::from), "sip:anon@anon.invalid".into()), 1);
                rendered(ctx)
            });
            let name = if *kind == HdrKind::From { "From:" } else { "To:" };
            assert_eq!(header_line(&out, name), *want, "{from_line} with display {display:?}");
        }
        let no_tag = request("INVITE", "sip:bob@b.example", "").replace(";tag=ft", "");
        assert_eq!(with_ctx(&no_tag, udp("192.0.2.1:5060"), &net, |ctx| uac.replace(ctx, HdrKind::From, None, "sip:x@y".into())), -1, "no From tag: no key");
    }

    /// Runs `restore` on `msg` and returns its From and To lines.
    fn restored(uac: &Uac, msg: &str) -> (String, String) {
        let net = FakeNet(None);
        with_ctx(msg, udp("192.0.2.1:5060"), &net, |ctx| {
            uac.restore(ctx);
            let out = rendered(ctx);
            (header_line(&out, "From:"), header_line(&out, "To:"))
        })
    }

    #[test]
    fn replaced_from_is_restored_in_both_directions() {
        let uac = Uac::default();
        let net = FakeNet(None);
        let invite = request("INVITE", "sip:bob@b.example", "");
        with_ctx(&invite, udp("192.0.2.1:5060"), &net, |ctx| uac.replace(ctx, HdrKind::From, None, "sip:anon@anon.invalid".into()));
        // Initial request again (retransmission): left to the script.
        assert_eq!(restored(&uac, &invite).0, "From: \"Alice\" <sip:alice@a.example>;tag=ft");
        let msg = |first: &str, from: &str, to: &str| {
            crlf(&format!("{first}\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: {from}\nTo: {to}\nCall-ID: cid-1\nCSeq: 2 BYE\nContent-Length: 0\n\n"))
        };
        // The callee's reply carries the replacement: back to the original.
        let reply = msg("SIP/2.0 200 OK", "\"Alice\" <sip:anon@anon.invalid>;tag=ft", "<sip:bob@b.example>;tag=tt");
        assert_eq!(restored(&uac, &reply).0, "From: \"Alice\" <sip:alice@a.example>;tag=ft");
        // The caller's in-dialog request: replaced again.
        let bye = msg("BYE sip:bob@b.example SIP/2.0", "\"Alice\" <sip:alice@a.example>;tag=ft", "<sip:bob@b.example>;tag=tt");
        assert_eq!(restored(&uac, &bye).0, "From: \"Alice\" <sip:anon@anon.invalid>;tag=ft");
        // The callee's request: its To carries the replacement.
        let back = msg("BYE sip:alice@a.example SIP/2.0", "<sip:bob@b.example>;tag=tt", "\"Alice\" <sip:anon@anon.invalid>;tag=ft");
        assert_eq!(restored(&uac, &back).1, "To: \"Alice\" <sip:alice@a.example>;tag=ft");
        // ... and the caller's reply to it gets the replacement again.
        let back_reply = msg("SIP/2.0 200 OK", "<sip:bob@b.example>;tag=tt", "\"Alice\" <sip:alice@a.example>;tag=ft");
        assert_eq!(restored(&uac, &back_reply).1, "To: \"Alice\" <sip:anon@anon.invalid>;tag=ft");
        // Another dialog: untouched.
        let other = bye.replace("cid-1", "cid-2");
        assert_eq!(restored(&uac, &other).0, "From: \"Alice\" <sip:alice@a.example>;tag=ft");
        // A From URI that isn't the stored one is not swapped.
        let foreign = msg("SIP/2.0 200 OK", "<sip:mallory@m.example>;tag=ft", "<sip:bob@b.example>;tag=tt");
        assert_eq!(restored(&uac, &foreign).0, "From: <sip:mallory@m.example>;tag=ft");
    }

    #[test]
    fn swap_hdr_compares_uris_case_insensitively() {
        let net = FakeNet(None);
        let msg = request("INVITE", "sip:bob@b.example", "");
        let out = with_ctx(&msg, udp("192.0.2.1:5060"), &net, |ctx| {
            assert!(swap_hdr(ctx, HdrKind::From, "<SIP:ALICE@A.EXAMPLE>", "<sip:x@y>"));
            rendered(ctx)
        });
        assert_eq!(header_line(&out, "From:"), "From: <sip:x@y>;tag=ft");
        assert!(!with_ctx(&msg, udp("192.0.2.1:5060"), &net, |ctx| swap_hdr(ctx, HdrKind::From, "<sip:other@a.example>", "<sip:x@y>")));
    }

    /// RFC 7616 §3.9.1 inputs (its published MD5 and SHA-256 responses);
    /// the SHA-512-256 and -sess values computed independently.
    #[test]
    fn digest_answers_every_algorithm() {
        let ch = |alg: &str, qop: bool| {
            format!(
                "Digest realm=\"http-auth@example.org\", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\"{}{}",
                if alg.is_empty() { String::new() } else { format!(", algorithm={alg}") },
                if qop { ", qop=\"auth\"" } else { "" }
            )
        };
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let answer = |c: &str| digest_answer_with(c, "Mufasa", "Circle of Life", "GET", "/dir/index.html", cnonce).unwrap();
        // (challenged algorithm, qop, the token answered, response)
        let cases = [
            ("MD5", true, "MD5", "8ca523f5e9506fed4657c9700eebdbec"),
            ("", true, "MD5", "8ca523f5e9506fed4657c9700eebdbec"),
            ("SHA-256", true, "SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"),
            ("sha-256", true, "SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"),
            ("SHA-512-256", true, "SHA-512-256", "430d05014cecc49cab6fbe03176d41a1da86cbfe24a16580e22aaad928d960d0"),
            ("SHA-512-256", false, "SHA-512-256", "93e9122020ea0624d2ca801426d5bfbeb93d10ff4cc24cb410af3920fa4730e7"),
            ("SHA-256-sess", true, "SHA-256-sess", "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7"),
            ("SHA-256-sess", false, "SHA-256-sess", "30bc0742357e535c85094121d22cf826b794be0667e19537beb7b28f2251c274"),
            ("MD5-sess", true, "MD5-sess", "e783283f46242139c486a698fec7211d"),
            ("MD5-sess", false, "MD5-sess", "37a7f42db2090a3fcac4e26e747d4fc8"),
        ];
        for (alg, qop, token, want) in cases {
            let a = answer(&ch(alg, qop));
            assert_eq!(chal_param(&a, "response").as_deref(), Some(want), "{alg} qop={qop}: {a}");
            assert_eq!(chal_param(&a, "algorithm").as_deref(), Some(token), "{a}");
            let sess = token.ends_with("-sess");
            assert_eq!(chal_param(&a, "cnonce").is_some(), qop || sess, "cnonce with qop or -sess: {a}");
        }
        for unsupported in ["SHA-512", "AKAv1-MD5", "XYZ"] {
            assert_eq!(digest_answer(&ch(unsupported, true), "u", "p", "GET", "/"), None, "{unsupported}");
        }
        assert_eq!(digest_answer(r#"Basic realm="r", nonce="n""#, "u", "p", "GET", "/"), None, "not a Digest challenge");
    }

    #[test]
    fn the_first_supported_challenge_is_answered() {
        let reply = |chs: &[&str]| {
            let mut r = String::from("SIP/2.0 401 Unauthorized\r\n");
            for c in chs {
                r.push_str(&format!("WWW-Authenticate: {c}\r\n"));
            }
            r.push_str("\r\n");
            r.into_bytes()
        };
        let sha = r#"Digest realm="r", nonce="n1", algorithm=SHA-256"#;
        let md5 = r#"Digest realm="r", nonce="n2", algorithm=MD5"#;
        let any = |_: &str| true;
        let pick = |chs: &[&str]| pick_challenge(&reply(chs), "WWW-Authenticate", any).map(|(c, _)| c);
        assert_eq!(pick(&[sha, md5]).as_deref(), Some(sha), "the server's preferred one");
        assert_eq!(pick(&[md5, sha]).as_deref(), Some(md5), "the server's order, not ours");
        let sha512 = r#"Digest realm="r", nonce="n0", algorithm=SHA-512"#;
        assert_eq!(pick(&[sha512, r#"Basic realm="r""#, sha]).as_deref(), Some(sha), "unsupported ones are skipped");
        assert_eq!(pick(&[r#"Digest realm="r", algorithm=SHA-256"#, md5]).as_deref(), Some(md5), "no nonce: skipped");
        assert_eq!(pick(&[sha512]), None);
        let other = r#"Digest realm="other", nonce="n3", algorithm=SHA-256"#;
        let only_r = |realm: &str| realm == "r";
        assert_eq!(pick_challenge(&reply(&[other, md5]), "WWW-Authenticate", only_r).map(|(c, _)| c).as_deref(), Some(md5), "a realm with credentials");
    }

    #[test]
    fn uac_auth_answers_401_and_407() {
        let uac = Uac::default();
        uac.set_param("credential", &Arg::Str("alice:r1:pa:ss".into())).unwrap();
        assert_eq!(lock(&uac.credentials)[0], ("alice".into(), "r1".into(), "pa:ss".into()), "the password may hold colons");
        assert!(uac.set_param("credential", &Arg::Str("alice:r1".into())).is_err());
        let net = FakeNet(None);
        let run = |reply: &str| {
            with_ctx(&request("INVITE", "sip:bob@b.example", ""), udp("192.0.2.1:5060"), &net, |ctx| {
                ctx.ext.push(Box::new(FailureReply(crlf(reply).into_bytes())));
                let rc = uac.uac_auth(ctx);
                (rc, rendered(ctx))
            })
        };
        let (rc, out) = run("SIP/2.0 407 Proxy Authentication Required\nProxy-Authenticate: Digest realm=\"r1\", nonce=\"n\"\n\n");
        assert_eq!(rc, 1);
        let ha1 = md5hex(&["alice", "r1", "pa:ss"]);
        let resp = md5hex(&[&ha1, "n", &md5hex(&["INVITE", "sip:bob@b.example"])]);
        let want = format!(
            "INVITE sip:bob@b.example SIP/2.0\r\nProxy-Authorization: Digest username=\"alice\", realm=\"r1\", nonce=\"n\", uri=\"sip:bob@b.example\", algorithm=MD5, response=\"{resp}\"\r\nVia:"
        );
        assert!(out.starts_with(&want), "{out}");
        let (rc, out) = run(
            "SIP/2.0 407 X\nProxy-Authenticate: Digest realm=\"r1\", nonce=\"n\", algorithm=SHA-512\nProxy-Authenticate: Digest realm=\"r1\", nonce=\"n\", algorithm=SHA-256, qop=\"auth\"\nProxy-Authenticate: Digest realm=\"r1\", nonce=\"n\"\n\n",
        );
        assert_eq!(rc, 1);
        assert!(
            out.contains("Proxy-Authorization: Digest username=\"alice\", realm=\"r1\", nonce=\"n\", uri=\"sip:bob@b.example\", algorithm=SHA-256, qop=auth"),
            "{out}"
        );
        let (rc, out) = run("SIP/2.0 401 Unauthorized\nWWW-Authenticate: Digest realm=\"r1\", nonce=\"n\"\n\n");
        assert_eq!(rc, 1);
        assert!(out.contains("\r\nAuthorization: Digest username=\"alice\""), "{out}");
        assert_eq!(run("SIP/2.0 401 Unauthorized\nWWW-Authenticate: Digest realm=\"other\", nonce=\"n\"\n\n").0, -1, "no credentials for the realm");
        assert_eq!(run("SIP/2.0 403 Forbidden\nWWW-Authenticate: Digest realm=\"r1\", nonce=\"n\"\n\n").0, -1);
        assert_eq!(run("SIP/2.0 401 Unauthorized\n\n").0, -1, "no challenge");
        let no_reply = with_ctx(&request("INVITE", "sip:b@x", ""), udp("192.0.2.1:5060"), &net, |ctx| uac.uac_auth(ctx));
        assert_eq!(no_reply, -1, "outside failure_route");
    }

    #[test]
    fn uac_parameters() {
        let uac = Uac::default();
        uac.set_param("restore_mode", &Arg::Str("manual".into())).unwrap();
        assert!(!uac.observes());
        uac.set_param("restore_ttl", &Arg::Int(0)).unwrap();
        assert_eq!(uac.restore_ttl.load(Ordering::Relaxed), 1);
        uac.set_param("reg_retry_interval", &Arg::Int(-3)).unwrap();
        assert_eq!(uac.reg_retry.load(Ordering::Relaxed), 1);
        assert!(uac.set_param("reg_active", &Arg::Int(1)).is_ok());
        assert!(uac.set_param("bogus", &Arg::Int(1)).is_err());
    }

    #[test]
    fn replaced_to_is_restored_in_both_directions() {
        let uac = Uac::default();
        let net = FakeNet(None);
        let invite = request("INVITE", "sip:bob@b.example", "");
        with_ctx(&invite, udp("192.0.2.1:5060"), &net, |ctx| uac.replace(ctx, HdrKind::To, Some("Office".into()), "sip:desk@b.example".into()));
        let msg = |first: &str, from: &str, to: &str| {
            crlf(&format!("{first}\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: {from}\nTo: {to}\nCall-ID: cid-1\nCSeq: 2 BYE\nContent-Length: 0\n\n"))
        };
        // Caller side (the stored From tag is in From).
        let reply = msg("SIP/2.0 200 OK", "<sip:alice@a.example>;tag=ft", "\"Office\" <sip:desk@b.example>;tag=tt");
        assert_eq!(restored(&uac, &reply).1, "To: <sip:bob@b.example>;tag=tt");
        let bye = msg("BYE sip:bob@b.example SIP/2.0", "<sip:alice@a.example>;tag=ft", "<sip:bob@b.example>;tag=tt");
        assert_eq!(restored(&uac, &bye).1, "To: \"Office\" <sip:desk@b.example>;tag=tt");
        // Callee side (the stored From tag is in To): its From carries the replacement.
        let back = msg("BYE sip:alice@a.example SIP/2.0", "\"Office\" <sip:desk@b.example>;tag=tt", "<sip:alice@a.example>;tag=ft");
        assert_eq!(restored(&uac, &back).0, "From: <sip:bob@b.example>;tag=tt");
        let back_reply = msg("SIP/2.0 200 OK", "<sip:bob@b.example>;tag=tt", "<sip:alice@a.example>;tag=ft");
        assert_eq!(restored(&uac, &back_reply).0, "From: \"Office\" <sip:desk@b.example>;tag=tt");
    }

    use crate::testutil::{RecNet, TextDir, call, fixup_err, fmt, registry, reply_to, rpc, start_tm};
    use sip_core::serde_json::{Value, json};

    fn pv(reg: &Registry, name: &str) -> PvRef {
        parse_pv(name, reg.pvs()).unwrap()
    }

    #[test]
    fn uac_register_needs_tm_and_valid_avp_names() {
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        let e = reg.load(Arc::new(Uac::default())).unwrap_err();
        assert!(e.contains("uac needs tm"), "{e}");
        let uac = Uac::default();
        uac.set_param("auth_realm_avp", &Arg::Str("$nope(".into())).unwrap();
        assert!(registry().0.load(Arc::new(uac)).is_err());
    }

    #[test]
    fn uac_script_functions_restore_auth_and_fixups() {
        let uac = Arc::new(Uac::default());
        uac.set_param("restore_mode", &Arg::Str("manual".into())).unwrap();
        for (p, v) in [("auth_username_avp", "$avp(au)"), ("auth_password_avp", "$avp(ap)"), ("auth_realm_avp", "$avp(ar)")] {
            uac.set_param(p, &Arg::Str(v.into())).unwrap();
        }
        uac.set_param("credential", &Arg::Str("listed:r2:pw2".into())).unwrap();
        let (mut reg, _) = registry();
        reg.load(uac.clone()).unwrap();
        let net = FakeNet(None);
        let invite = request("INVITE", "sip:bob@b.example", "");
        with_ctx(&invite, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "uac_replace_from", &[Arg::Str("Anon".into()), Arg::Str("sip:anon@anon.invalid".into())]), 1);
            assert_eq!(call(&reg, ctx, "uac_replace_to", &[fmt(&reg, "sip:$rU@c.example")]), 1);
            assert_eq!(header_line(&rendered(ctx), "To:"), "To: <sip:bob@c.example>");
        });
        // Manual mode: only the script functions restore.
        let bye = crlf(
            "BYE sip:bob@b.example SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\nFrom: \"Alice\" <sip:alice@a.example>;tag=ft\n\
To: <sip:bob@b.example>;tag=tt\nCall-ID: cid-1\nCSeq: 2 BYE\nContent-Length: 0\n\n",
        );
        let out = with_ctx(&bye, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "uac_restore_from", &[]), 1);
            rendered(ctx)
        });
        assert_eq!(header_line(&out, "From:"), "From: \"Anon\" <sip:anon@anon.invalid>;tag=ft");
        uac.set_param("restore_mode", &Arg::Str("auto".into())).unwrap();
        let out = with_ctx(&bye, udp("192.0.2.1:5060"), &net, |ctx| {
            assert_eq!(call(&reg, ctx, "uac_restore_to", &[]), 1);
            rendered(ctx)
        });
        assert_eq!(out, bye, "auto mode: done by the observer, not twice");

        // Credentials from AVPs: the realm AVP, if set, must match.
        let challenge = |realm: &str| format!("SIP/2.0 407 X\r\nProxy-Authenticate: Digest realm=\"{realm}\", nonce=\"n\"\r\n\r\n");
        let auth = |realm: &str, avps: &[(&str, &str)]| {
            with_ctx(&invite, udp("192.0.2.1:5060"), &net, |ctx| {
                for (n, v) in avps {
                    pv(&reg, n).set(ctx, Val::str(*v)).unwrap();
                }
                ctx.ext.push(Box::new(FailureReply(challenge(realm).into_bytes())));
                let rc = call(&reg, ctx, "uac_auth", &[]);
                (rc, header_line(&rendered(ctx), "Proxy-Authorization:"))
            })
        };
        let (rc, h) = auth("r1", &[("$avp(au)", "avpuser"), ("$avp(ap)", "avppw")]);
        assert_eq!(rc, 1);
        assert!(h.starts_with("Proxy-Authorization: Digest username=\"avpuser\", realm=\"r1\""), "{h}");
        let resp = md5hex(&[&md5hex(&["avpuser", "r1", "avppw"]), "n", &md5hex(&["INVITE", "sip:bob@b.example"])]);
        assert!(h.contains(&format!("response=\"{resp}\"")), "{h}");
        assert_eq!(auth("r1", &[("$avp(au)", "avpuser"), ("$avp(ap)", "avppw"), ("$avp(ar)", "r1")]).0, 1);
        assert_eq!(auth("r1", &[("$avp(au)", "avpuser"), ("$avp(ap)", "avppw"), ("$avp(ar)", "other")]).0, -1, "realm AVP differs");
        let (rc, h) = auth("r2", &[("$avp(au)", "avpuser"), ("$avp(ap)", "avppw"), ("$avp(ar)", "other")]);
        assert_eq!(rc, 1, "falls back to the credential list");
        assert!(h.contains("username=\"listed\""), "{h}");
        assert_eq!(auth("r1", &[("$avp(ap)", "avppw")]).0, -1, "no username AVP, no listed credential");
        // Not answerable on a reply.
        let reply = crlf(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n",
        );
        let rc = with_ctx(&reply, udp("192.0.2.1:5060"), &net, |ctx| {
            ctx.ext.push(Box::new(FailureReply(challenge("r2").into_bytes())));
            call(&reg, ctx, "uac_auth", &[])
        });
        assert_eq!(rc, -1);

        let s = |v: &str| Arg::Str(v.into());
        let cases: &[(&str, Vec<Arg>, &str)] = &[
            ("uac_replace_from", vec![], "expected [display,] uri"),
            ("uac_replace_to", vec![s("a"), s("b"), s("c")], "expected [display,] uri"),
            ("uac_auth", vec![s("a"), s("b")], "expected at most 1 argument"),
            ("uac_reg_lookup", vec![s("u"), s("out")], "expected a variable"),
            ("uac_reg_lookup", vec![s("u"), fmt(&reg, "x$var(o)")], "expected a variable"),
            ("uac_restore_from", vec![s("x")], "expected 0 argument(s), got 1"),
        ];
        for (f, args, want) in cases {
            assert_eq!(fixup_err(&reg, f, args).as_deref(), Some(*want), "{f}{args:?}");
        }
    }

    #[test]
    fn uac_req_variables_and_send() {
        let (mut reg, tm) = registry();
        reg.load(Arc::new(Uac::default())).unwrap();
        let net = Arc::new(RecNet::default());
        let fields = ["method", "ruri", "furi", "turi", "ouri", "hdrs", "body", "callid"];
        let req = request("OPTIONS", "sip:x@y", "");
        let sent = with_ctx(&req, udp("192.0.2.1:5060"), &*net, |ctx| {
            assert_eq!(pv(&reg, "$uac_req(method)").get(ctx), Val::Null, "nothing set yet");
            assert_eq!(call(&reg, ctx, "uac_req_send", &[]), -1);
            for f in fields {
                pv(&reg, &format!("$uac_req({f})")).set(ctx, Val::str(format!("v-{f}"))).unwrap();
            }
            let got: Vec<String> = fields.iter().map(|f| pv(&reg, &format!("$uac_req({f})")).get(ctx).as_str().into_owned()).collect();
            assert_eq!(got, fields.map(|f| format!("v-{f}")));
            assert_eq!(pv(&reg, "$uac_req(bogus)").get(ctx), Val::Null);
            assert_eq!(pv(&reg, "$uac_req(bogus)").set(ctx, Val::str("x")).unwrap_err(), "$uac_req(bogus): unknown field");
            pv(&reg, "$uac_req(all)").set(ctx, Val::Null).unwrap();
            assert_eq!(pv(&reg, "$uac_req(method)").get(ctx), Val::str(""), "all = $null clears every field");
            let set = |ctx: &mut Ctx<'_, '_>, f: &str, v: &str| pv(&reg, &format!("$uac_req({f})")).set(ctx, Val::str(v)).unwrap();
            set(ctx, "method", "MESSAGE");
            assert_eq!(call(&reg, ctx, "uac_req_send", &[]), -1, "no R-URI");
            set(ctx, "ruri", "sip:bob@192.0.2.20");
            assert_eq!(call(&reg, ctx, "uac_req_send", &[]), -1, "tm not started");
            start_tm(&tm, &net);
            set(ctx, "furi", "sip:alice@a.example");
            set(ctx, "turi", "sip:bob@b.example");
            set(ctx, "ouri", "sip:192.0.2.30:5080;transport=tcp");
            set(ctx, "hdrs", "X-A: 1\nX-B: 2");
            set(ctx, "body", "hello");
            set(ctx, "callid", "my-call");
            pv(&reg, "$uac_req(ouri)").set(ctx, Val::str("sip:192.0.2.30:5080;transport=tcp")).unwrap();
            assert_eq!(call(&reg, ctx, "uac_req_send", &[]), 1);
            net.sent()
        });
        assert_eq!(sent.len(), 1);
        let (dst, m) = &sent[0];
        assert_eq!((dst.proto, dst.addr.to_string()), (sip_core::Proto::Tcp, "192.0.2.30:5080".to_string()), "the outbound proxy");
        assert!(m.starts_with("MESSAGE sip:bob@192.0.2.20 SIP/2.0\r\n"), "{m}");
        for want in ["\r\nFrom: <sip:alice@a.example>;tag=", "\r\nTo: <sip:bob@b.example>\r\n", "\r\nCall-ID: my-call\r\n", "\r\nX-A: 1\r\nX-B: 2\r\n"] {
            assert!(m.contains(want), "{want:?} in {m}");
        }
        assert!(m.ends_with("\r\n\r\nhello"), "{m}");
    }

    const UACREG: &str = "l_uuid(string) l_username(string) l_domain(string) r_username(string) r_domain(string) realm(string) \
auth_username(string) auth_password(string) auth_proxy(string) expires(int,null) flags(int)\n";

    fn state(reg: &Registry, uuid: &str) -> String {
        let dump = rpc(reg, "uac.reg_dump", json!([])).unwrap();
        dump.as_array().unwrap().iter().find(|r| r["l_uuid"] == uuid).map(|r| r["state"].as_str().unwrap().to_string()).unwrap_or_default()
    }

    #[test]
    fn uac_remote_registrations() {
        let dir = TextDir::new(&[(
            "uacreg",
            &format!(
                "{UACREG}u1:alice:l.example:ra:192.0.2.5:r:authu:secret::60:0\nu2:bob:l.example:rb:192.0.2.6:r::pw:sip\\:192.0.2.9\\:5080:10:0\n\
u3:carol:l.example:rc:192.0.2.7:r:::::1\nu4:dave:l.example:rd:192.0.2.8:r::pw:::0\nu5:erin:l.example:re:192.0.2.10:r::pw::120:0\n"
            ),
        )]);
        let uac = Arc::new(Uac::default());
        uac.set_param("reg_db_url", &Arg::Str(dir.url())).unwrap();
        uac.set_param("reg_contact_addr", &Arg::Str("192.0.2.1:5060".into())).unwrap();
        let (mut reg, tm) = registry();
        reg.load(uac.clone()).unwrap();
        let dump = rpc(&reg, "uac.reg_dump", json!([])).unwrap();
        let exp: Vec<&Value> = dump.as_array().unwrap().iter().map(|r| &r["expires"]).collect();
        assert_eq!(exp, [&json!(60), &json!(30), &json!(3600), &json!(3600), &json!(120)], "at least 30, 3600 by default");
        assert_eq!(state(&reg, "u3"), "Disabled");

        // tm not started yet: every due registration fails at once.
        uac.reg_tick();
        assert_eq!(state(&reg, "u1"), "Failed(0)");
        assert_eq!(state(&reg, "u3"), "Disabled", "disabled ones are never sent");
        let net = Arc::new(RecNet::default());
        start_tm(&tm, &net);
        uac.reg_tick();
        assert!(net.sent().is_empty(), "the failed ones wait for reg_retry_interval");
        for u in ["u1", "u2", "u4", "u5"] {
            assert_eq!(rpc(&reg, "uac.reg_refresh", json!([u])).unwrap(), json!(0));
        }
        assert_eq!(rpc(&reg, "uac.reg_refresh", json!(["nope"])).unwrap_err(), "no such registration");
        uac.reg_tick();
        assert_eq!(state(&reg, "u1"), "Registering");
        let sent = net.sent();
        let find = |who: &str| sent.iter().find(|(_, m)| m.contains(&format!("To: <sip:{who}@"))).cloned().unwrap();
        let (d2, r2) = find("rb");
        assert_eq!(d2.addr.to_string(), "192.0.2.9:5080", "auth_proxy is the destination");
        assert!(r2.starts_with("REGISTER sip:192.0.2.6 SIP/2.0\r\n") && r2.contains("\r\nContact: <sip:u2@192.0.2.1:5060>\r\nExpires: 30\r\n"), "{r2}");
        let answer = |req: &str, code: u16, extra: &str| {
            with_ctx(&reply_to(req, code, extra), udp("192.0.2.5:5060"), &*net, |ctx| assert!(tm.on_reply(ctx), "{req}"));
        };
        let www = "WWW-Authenticate: Digest realm=\"r\", nonce=\"n1\"\n";
        // u1: challenged, answered with the auth username, then registered.
        answer(&find("ra").1, 401, www);
        let again = net.sent().last().cloned().unwrap().1;
        assert!(again.contains("\r\nAuthorization: Digest username=\"authu\", realm=\"r\", nonce=\"n1\", uri=\"sip:192.0.2.5\""), "{again}");
        assert!(again.contains("\r\nCSeq: 3 REGISTER\r\n"), "one more than the first (2; 1 went to the failed attempt): {again}");
        answer(&again, 200, "Expires: 4\n");
        assert_eq!(state(&reg, "u1"), "Registered");
        let u1 = rpc(&reg, "uac.reg_dump", json!([])).unwrap()[0].clone();
        let until = u1["registered_until"].as_u64().unwrap();
        assert!((unix_secs() + 9..=unix_secs() + 10).contains(&until), "an Expires below 10 counts as 10: {until}");
        // u2: a challenge without a nonce cannot be answered.
        answer(&r2, 407, "Proxy-Authenticate: Digest realm=\"r\"\n");
        assert_eq!(state(&reg, "u2"), "AuthFailed");
        // u4: challenged again after answering.
        answer(&find("rd").1, 401, www);
        let again = net.sent().last().cloned().unwrap().1;
        assert!(again.contains("Authorization: Digest username=\"rd\""), "no auth_username: the remote one");
        answer(&again, 401, www);
        assert_eq!(state(&reg, "u4"), "AuthFailed");
        // u5: refused.
        answer(&find("re").1, 503, "");
        assert_eq!(state(&reg, "u5"), "Failed(503)");

        // A reload keeps the state of the registrations it still has.
        assert_eq!(rpc(&reg, "uac.reg_reload", json!([])).unwrap(), json!(5));
        assert_eq!(state(&reg, "u1"), "Registered");

        let net2 = FakeNet(None);
        with_ctx(&request("OPTIONS", "sip:x@y", ""), udp("192.0.2.1:5060"), &net2, |ctx| {
            let st = |ctx: &mut Ctx<'_, '_>, u: &str| call(&reg, ctx, "uac_reg_status", &[Arg::Str(u.into())]);
            assert_eq!((st(ctx, "u1"), st(ctx, "u5"), st(ctx, "u3"), st(ctx, "nope")), (1, -2, -2, -1));
            let lookup = |ctx: &mut Ctx<'_, '_>, u: &str, out: &str| call(&reg, ctx, "uac_reg_lookup", &[Arg::Str(u.into()), fmt(&reg, out)]);
            assert_eq!(lookup(ctx, "sip:u2@whatever", "$var(o)"), 1, "the user part of a URI is the uuid");
            assert_eq!(pv(&reg, "$var(o)").get(ctx).as_str(), "sip:bob@l.example");
            assert_eq!(lookup(ctx, "u1", "$var(o)"), 1);
            assert_eq!(pv(&reg, "$var(o)").get(ctx).as_str(), "sip:alice@l.example");
            assert_eq!(lookup(ctx, "nope", "$var(o)"), -1);
            assert_eq!(lookup(ctx, "u1", "$ci"), -1, "a read-only variable");
        });
    }
}
