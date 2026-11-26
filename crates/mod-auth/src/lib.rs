//! auth — SIP digest authentication (RFC 2617, RFC 3261 §22, RFC 8760
//! SHA-256), the equivalent of Kamailio's `auth` + `auth_db` modules with a
//! users file instead of a database table.
//!
//! Script functions (Kamailio names and return codes):
//! * `www_authorize(realm, table)` / `proxy_authorize(realm, table)` — check
//!   the `Authorization` / `Proxy-Authorization` credentials.
//! * `auth_check(realm, table, flags)` — www for REGISTER, proxy otherwise;
//!   flags & 1 also requires the To (REGISTER) / From user to be the
//!   authenticated user (else -8).
//! * `www_challenge(realm, flags)` / `proxy_challenge(realm, flags)` /
//!   `auth_challenge(realm, flags)` — reply 401/407 with a fresh nonce
//!   (flags & 1: offer `qop=auth`, & 2: `qop=auth-int`); `stale=true` when the last check found
//!   an expired/replayed nonce.
//! * `consume_credentials()` — remove the used credentials header before relaying.
//! * `has_credentials(realm)` — the request has credentials for the realm.
//! * `pv_www_authenticate(realm, passwd, flags[, method])` /
//!   `pv_proxy_authenticate(realm, passwd, flags)`, also named
//!   `pv_*_authorize` — check against a password (or HA1, flags & 1) from
//!   the script; `pv_*_authorize(realm)` with one argument takes the user
//!   and password from the `username_spec` / `password_spec` variables.
//! * `auth_get_www_authenticate(realm, flags, pvdest)` — a WWW-Authenticate
//!   challenge into a variable.
//! * `pv_auth_check(realm, passwd, flags, checks)` — pv_*_authenticate on
//!   Authorization (REGISTER) or Proxy-Authorization; checks & 1: the user
//!   must be the From user (To for REGISTER / PUBLISH), else -8.
//! * `auth_algorithm(alg)` — the challenge / default algorithm from now on
//!   (MD5, SHA-256, SHA-512, SHA-512-256).
//!
//! Return codes (Kamailio's): 1 ok, -1 error (malformed, wrong URI, bad
//! nonce), -2 wrong password, -3 unknown user, -4 stale nonce, -5 no
//! credentials, -6 nonce reused (one_time_nonce), -8 user mismatch. `realm` may be a literal or `$td` / `$fd` / `$rd` (To / From
//! / R-URI domain).
//!
//! Nonces are stateless (Kamailio style): hex(expiry ms ‖ index ‖ HMAC-SHA256
//! (secret, expiry ‖ index ‖ realm)[..16]), so any worker can verify any nonce.
//! With `qop`, the nonce-count is tracked per nonce index in a shared array
//! of atomics (Kamailio `nc_enabled`): a repeated or lower `nc` is a replay
//! and is answered as stale.
//!
//! Parameters: `users_file`, `nonce_expire` (300 s), `algorithm` ("MD5";
//! e.g. "SHA-256,MD5" offers both; also `SHA-512`, `SHA-512-256`, and
//! each as `-sess`), `use_domain`,
//! `secret` (random), `qop`, `nonce_count`, `one_time_nonce`,
//! `realm_prefix`, `add_authinfo_hdr`, `username_spec`, `password_spec`,
//! `calculate_ha1`.
//! Users file lines: `user password`, `user md5:<HA1 hex>`, `user sha256:<HA1 hex>`.
//!
//! Credentials come from `users_file`, or from a database table when the
//! `auth_db` module is loaded (Kamailio's `auth_db`): the `table` argument
//! of `www_authorize(realm, table)` & co. names the table (`subscriber`),
//! read through sip-db (`db_url` = `text:///dir` or `sqlite:///file`).
//! auth_db parameters: `db_url`, `calculate_ha1` (0: use the `ha1` column;
//! 1: compute it from `password`), `use_domain` (match `domain` = realm),
//! `user_column`, `domain_column`, `password_column`, `load_credentials`
//! (`"rpid;email"`: columns copied into `$avp(name)` after a successful check).

use md5::{Digest as _, Md5};
use ring::digest::{SHA256, SHA512, SHA512_256, digest};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use sip_core::module::{DynInt, DynStr, ReplyExtra};
use sip_core::pv::{PvRef, Val, parse_pv};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::{lock, read, write};
use sip_core::time::unix_ms;
use sip_core::{Arg, Ctx, Module, Registry, want_args};
use sip_parser::uri::name_addr;
use sip_parser::util::trim;
use sip_parser::{HdrFlags, HdrKind, Method, parse_uri};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// Kamailio's auth API codes (`auth_cfg_result_t`).
pub const OK: i32 = 1;
pub const ERROR: i32 = -1;
pub const INVALID_PASSWORD: i32 = -2;
pub const USER_UNKNOWN: i32 = -3;
pub const STALE_NONCE: i32 = -4;
pub const NO_CREDENTIALS: i32 = -5;
pub const NONCE_REUSED: i32 = -6;
pub const USER_MISMATCH: i32 = -8;

/// Nonce-count slots (indices wrap; an evicted slot makes its nonce stale).
const NC_POOL: usize = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Alg {
    Md5,
    Sha256,
    Sha512,
    Sha512_256,
}

impl Alg {
    fn parse(s: &[u8]) -> Option<Self> {
        if s.eq_ignore_ascii_case(b"MD5") {
            Some(Alg::Md5)
        } else if s.eq_ignore_ascii_case(b"SHA-256") {
            Some(Alg::Sha256)
        } else if s.eq_ignore_ascii_case(b"SHA-512") {
            Some(Alg::Sha512)
        } else if s.eq_ignore_ascii_case(b"SHA-512-256") {
            Some(Alg::Sha512_256)
        } else {
            None
        }
    }
    /// Lower-case hex digest of `parts` joined by ':'.
    fn h(self, parts: &[&[u8]]) -> String {
        let mut buf = Vec::with_capacity(128);
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                buf.push(b':');
            }
            buf.extend_from_slice(p);
        }
        match self {
            Alg::Md5 => hex(&Md5::digest(&buf)),
            Alg::Sha256 => hex(digest(&SHA256, &buf).as_ref()),
            Alg::Sha512 => hex(digest(&SHA512, &buf).as_ref()),
            Alg::Sha512_256 => hex(digest(&SHA512_256, &buf).as_ref()),
        }
    }
    /// The algorithm of a stored HA1, by its length (64 hex digits:
    /// SHA-256 or SHA-512-256, 128: SHA-512).
    fn of_ha1(h: &str) -> Self {
        match h.len() {
            128 => Alg::Sha512,
            64 => Alg::Sha256,
            _ => Alg::Md5,
        }
    }
    /// Length of the hex digest.
    fn hex_len(self) -> usize {
        match self {
            Alg::Md5 => 32,
            Alg::Sha256 | Alg::Sha512_256 => 64,
            Alg::Sha512 => 128,
        }
    }
}

/// A digest algorithm (RFC 7616 §3.3): the hash, and whether it is the
/// `-sess` variant, whose HA1 is H(H(user:realm:password):nonce:cnonce).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DigestAlg {
    pub hash: Alg,
    pub sess: bool,
}

impl DigestAlg {
    const MD5: DigestAlg = DigestAlg { hash: Alg::Md5, sess: false };

    fn name(self) -> &'static str {
        match (self.hash, self.sess) {
            (Alg::Md5, false) => "MD5",
            (Alg::Md5, true) => "MD5-sess",
            (Alg::Sha256, false) => "SHA-256",
            (Alg::Sha256, true) => "SHA-256-sess",
            (Alg::Sha512, false) => "SHA-512",
            (Alg::Sha512, true) => "SHA-512-sess",
            (Alg::Sha512_256, false) => "SHA-512-256",
            (Alg::Sha512_256, true) => "SHA-512-256-sess",
        }
    }
    fn parse(s: &[u8]) -> Option<Self> {
        let (base, sess) = match s.len().checked_sub(5).and_then(|i| s.split_at_checked(i)) {
            Some((base, suffix)) if suffix.eq_ignore_ascii_case(b"-sess") => (base, true),
            _ => (s, false),
        };
        Some(DigestAlg { hash: Alg::parse(base)?, sess })
    }
    /// HA1 from the user's H(user:realm:password).
    fn ha1(self, base: String, nonce: &[u8], cnonce: &[u8]) -> String {
        if self.sess { self.hash.h(&[base.as_bytes(), nonce, cnonce]) } else { base }
    }
}

/// `qop` parameter → challenge flag bits (1 auth, 2 auth-int).
fn parse_qop(s: &str) -> Result<u32, String> {
    s.split(',').map(str::trim).filter(|q| !q.is_empty()).try_fold(0, |acc, q| match q.to_ascii_lowercase().as_str() {
        "auth" => Ok(acc | 1),
        "auth-int" => Ok(acc | 2),
        _ => Err(format!("auth: unknown qop {q:?} (auth, auth-int)")),
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &[u8]) -> Option<Vec<u8>> {
    // from_str_radix alone would take a sign ("+f").
    if !s.len().is_multiple_of(2) || !s.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    s.chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok()).collect()
}

/// Constant-time comparison (no early exit on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone, Debug)]
enum Secret {
    Password(String),
    Ha1(Alg, String),
}

/// The realm: a literal or a template (`$td`, `$fd`, `$rd`, …), evaluated
/// per request (domains lower-cased so challenge and check always agree).
type Realm = DynStr;

/// Exactly `N` arguments, as an array to destructure.
fn fixed_args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

fn realm_spec(a: &Arg) -> Result<Realm, String> {
    a.dyn_str()
}

/// `pv_www_authenticate(realm, passwd, flags[, method])` arguments.
struct PvAuthArgs {
    realm: Realm,
    passwd: Realm,
    flags: sip_core::module::DynInt,
    method: Option<Realm>,
}

/// `pv_auth_check(realm, passwd, flags, checks)` arguments.
struct PvCheckArgs {
    realm: Realm,
    passwd: Realm,
    flags: DynInt,
    checks: DynInt,
}

/// Per-message auth state for challenge/consume after authorize.
#[derive(Default)]
struct AuthState {
    stale: bool,
    /// (offset, len) of the credentials header that was checked.
    used: Option<(usize, usize)>,
    /// (nonce index, nc) already accepted for this request: checking the
    /// same credentials again (another auth.check) isn't a replay.
    nc_ok: Option<(u32, u32)>,
    /// Authentication-Info was added to the reply (add_authinfo_hdr).
    authinfo: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Www,
    Proxy,
}

impl Kind {
    fn header(self) -> &'static [u8] {
        match self {
            Kind::Www => b"Authorization",
            Kind::Proxy => b"Proxy-Authorization",
        }
    }
}

/// Finds the secret of (user, realm).
type SecretLookup<'a> = dyn Fn(&mut Ctx<'_, '_>, &str, &[u8]) -> Result<Option<Found>, ()> + 'a;

/// A user's secret plus extra columns to load as AVPs.
type Found = (Secret, Vec<(String, String)>);

/// Database credentials (auth_db).
#[derive(Clone, Debug)]
pub struct DbCreds {
    url: String,
    user_col: String,
    domain_col: String,
    password_col: String,
    ha1_col: String,
    calculate_ha1: bool,
    use_domain: bool,
    load: Vec<String>,
}

pub struct Auth {
    /// Replaced by RPC `auth.reload`.
    users: std::sync::RwLock<Option<Arc<HashMap<String, Secret>>>>,
    db: OnceLock<DbCreds>,
    users_file: Mutex<Option<String>>,
    algorithms: Mutex<Vec<DigestAlg>>,
    nonce_expire: AtomicU64,
    secret: Mutex<Option<Vec<u8>>>,
    key: OnceLock<hmac::Key>,
    nc: Box<[AtomicU64]>,
    next_index: AtomicU32,
    /// Challenge qop (flag bits 1 auth, 2 auth-int) when the call sets none.
    qop: AtomicU32,
    /// Track each nonce's nonce-count (Kamailio `nc_enabled`).
    nonce_count: AtomicBool,
    /// Each nonce is accepted once (Kamailio `otn_enabled`).
    one_time_nonce: AtomicBool,
    /// Stripped from a realm taken from the To/From URI.
    realm_prefix: Mutex<String>,
    add_authinfo_hdr: AtomicBool,
    /// `username_spec` / `password_spec`, resolved in register().
    pv_names: Mutex<(Option<String>, Option<String>)>,
    pv_specs: OnceLock<(PvRef, PvRef)>,
    /// `password_spec` holds the plain password (else the HA1).
    calculate_ha1: AtomicBool,
    /// pv_auth_check(): the identity check compares hosts too.
    use_domain: AtomicBool,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            users: std::sync::RwLock::new(None),
            db: OnceLock::new(),
            users_file: Mutex::new(None),
            algorithms: Mutex::new(vec![DigestAlg::MD5]),
            nonce_expire: AtomicU64::new(300),
            secret: Mutex::new(None),
            key: OnceLock::new(),
            nc: (0..NC_POOL).map(|_| AtomicU64::new(u64::MAX)).collect(),
            next_index: AtomicU32::new(1),
            qop: AtomicU32::new(0),
            nonce_count: AtomicBool::new(true),
            one_time_nonce: AtomicBool::new(false),
            realm_prefix: Mutex::new(String::new()),
            add_authinfo_hdr: AtomicBool::new(false),
            pv_names: Mutex::new((None, None)),
            pv_specs: OnceLock::new(),
            calculate_ha1: AtomicBool::new(false),
            use_domain: AtomicBool::new(false),
        }
    }
}

enum NonceCheck {
    Valid(u32),
    Expired,
    Invalid,
}

/// Parsed `Digest k=v, …` credentials (borrowed from the message).
#[derive(Default, Debug)]
struct Creds<'a> {
    username: &'a [u8],
    realm: &'a [u8],
    nonce: &'a [u8],
    uri: &'a [u8],
    response: &'a [u8],
    algorithm: Option<&'a [u8]>,
    cnonce: Option<&'a [u8]>,
    qop: Option<&'a [u8]>,
    nc: Option<&'a [u8]>,
}

/// The value of the header at `off..off + len` of `buf` (after its `Name:`).
fn header_value(buf: &[u8], off: usize, len: usize) -> &[u8] {
    let header = off.checked_add(len).and_then(|end| buf.get(off..end)).unwrap_or_default();
    header.splitn(2, |&b| b == b':').nth(1).unwrap_or_default()
}

/// The comma-separated `k=v` items of credentials; a comma or a `\"`
/// inside a quoted-string (RFC 2617 quoted-pair) doesn't end it.
fn split_params(s: &[u8]) -> Vec<&[u8]> {
    let (mut out, mut rest, mut quoted, mut escaped) = (Vec::new(), s, false, false);
    while let Some(i) = rest.iter().position(|&c| {
        let end = c == b',' && !quoted;
        match c {
            _ if escaped => escaped = false,
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            _ => {}
        }
        end
    }) {
        let (item, tail) = rest.split_at(i);
        out.push(trim(item));
        rest = tail.get(1..).unwrap_or_default();
    }
    out.push(trim(rest));
    out
}

fn parse_creds(body: &[u8]) -> Option<Creds<'_>> {
    let (scheme, params) = trim(body).split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case(b"Digest ") {
        return None;
    }
    let mut c = Creds::default();
    for p in split_params(params) {
        let mut kv = p.splitn(2, |&x| x == b'=');
        let (k, v) = (trim(kv.next()?), trim(kv.next()?));
        let v = v.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\"")).unwrap_or(v);
        match k.to_ascii_lowercase().as_slice() {
            b"username" => c.username = v,
            b"realm" => c.realm = v,
            b"nonce" => c.nonce = v,
            b"uri" => c.uri = v,
            b"response" => c.response = v,
            b"algorithm" => c.algorithm = Some(v),
            b"cnonce" => c.cnonce = Some(v),
            b"qop" => c.qop = Some(v),
            b"nc" => c.nc = Some(v),
            _ => {}
        }
    }
    (!c.username.is_empty() && !c.nonce.is_empty() && !c.response.is_empty()).then_some(c)
}

impl Auth {
    #[allow(clippy::expect_used, reason = "register() sets the key before any function or RPC that makes or checks nonces is registered")]
    fn key(&self) -> &hmac::Key {
        self.key.get().expect("key set in register()")
    }

    /// The nonce-count slot of nonce `index`; slots are reused modulo [`NC_POOL`].
    fn nc_slot(&self, index: u32) -> Option<&AtomicU64> {
        self.nc.get(index as usize % NC_POOL)
    }

    fn nonce_mac(&self, expires: u64, index: u32, realm: &[u8]) -> [u8; 16] {
        let mut ctx = hmac::Context::with_key(self.key());
        ctx.update(&expires.to_be_bytes());
        ctx.update(&index.to_be_bytes());
        ctx.update(realm);
        let tag = ctx.sign();
        // HMAC-SHA256: 32 bytes, the first 16 kept.
        let mut mac = [0u8; 16];
        mac.iter_mut().zip(tag.as_ref()).for_each(|(m, &t)| *m = t);
        mac
    }

    fn new_nonce(&self, realm: &[u8]) -> String {
        // Saturating: a huge configured lifetime must not wrap into an already-expired nonce.
        let expires = unix_ms().saturating_add(self.nonce_expire.load(Ordering::Relaxed).saturating_mul(1000));
        let index = self.next_index.fetch_add(1, Ordering::Relaxed);
        // Reserve the nonce-count slot: (index, last nc = 0).
        if let Some(slot) = self.nc_slot(index) {
            slot.store(u64::from(index) << 32, Ordering::Relaxed);
        }
        let mut raw = Vec::with_capacity(28);
        raw.extend_from_slice(&expires.to_be_bytes());
        raw.extend_from_slice(&index.to_be_bytes());
        raw.extend_from_slice(&self.nonce_mac(expires, index, realm));
        hex(&raw)
    }

    fn check_nonce(&self, nonce: &[u8], realm: &[u8]) -> NonceCheck {
        let Some(raw) = unhex(nonce).filter(|r| r.len() == 28) else { return NonceCheck::Invalid };
        // 28 bytes: expires(8) index(4) mac(16).
        let Some((expires, rest)) = raw.split_first_chunk() else { return NonceCheck::Invalid };
        let Some((index, mac)) = rest.split_first_chunk() else { return NonceCheck::Invalid };
        let (expires, index) = (u64::from_be_bytes(*expires), u32::from_be_bytes(*index));
        if !ct_eq(mac, &self.nonce_mac(expires, index, realm)) {
            return NonceCheck::Invalid;
        }
        if unix_ms() > expires {
            return NonceCheck::Expired;
        }
        NonceCheck::Valid(index)
    }

    /// RFC 2617 nonce-count: must increase for each use of a nonce.
    fn accept_nc(&self, index: u32, nc: u32) -> bool {
        let Some(slot) = self.nc_slot(index) else { return false };
        let mut cur = slot.load(Ordering::Acquire);
        loop {
            if cur >> 32 != u64::from(index) || u64::from(nc) <= cur & 0xffff_ffff {
                return false; // slot reused by a newer nonce, or a replay
            }
            match slot.compare_exchange_weak(cur, u64::from(index) << 32 | u64::from(nc), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    /// The realm: `spec` evaluated, or for "" the host of the To URI (a
    /// REGISTER's Authorization) or the From URI; then without
    /// `realm_prefix`, which Kamailio strips from every realm it checks or
    /// challenges for (`strip_realm()` in api.c and challenge.c).
    fn realm(&self, spec: &Realm, ctx: &mut Ctx<'_, '_>, kind: Kind) -> Vec<u8> {
        let r = spec.eval(ctx).into_owned();
        let mut realm = if !r.is_empty() {
            if spec.is_static() { r.into_bytes() } else { r.to_ascii_lowercase().into_bytes() }
        } else {
            let hk = if kind == Kind::Www && ctx.msg.method() == Some(Method::Register) { HdrKind::To } else { HdrKind::From };
            let _ = ctx.msg.parse_headers(HdrFlags::of(hk));
            ctx.msg.get(hk).and_then(|h| parse_uri(name_addr(h.body).0)).map(|u| u.host.to_ascii_lowercase()).unwrap_or_default()
        };
        let prefix = lock(&self.realm_prefix);
        if !prefix.is_empty() && realm.starts_with(prefix.as_bytes()) {
            realm.drain(..prefix.len());
        }
        realm
    }

    /// The stored secret for `user` (and extra columns to load as AVPs).
    fn secret(&self, user: &str, realm: &[u8], table: &str) -> Result<Option<Found>, ()> {
        if let Some(db) = self.db.get() {
            let conn = sip_db::connect(&db.url).map_err(|_| ())?;
            let mut cols: Vec<&str> = vec![if db.calculate_ha1 { &db.password_col } else { &db.ha1_col }];
            cols.extend(db.load.iter().map(String::as_str));
            let mut f: Vec<(&str, sip_db::DbVal)> = vec![(&db.user_col, sip_db::DbVal::Str(user.into()))];
            if db.use_domain {
                f.push((&db.domain_col, sip_db::DbVal::Str(String::from_utf8_lossy(realm).into_owned())));
            }
            let rows = conn.query(table, &cols, &f).map_err(|_| ())?;
            let Some((v, extra)) = rows.rows.first().and_then(|r| r.split_first()) else { return Ok(None) };
            let v = v.text();
            let secret = if db.calculate_ha1 { Secret::Password(v) } else { Secret::Ha1(Alg::of_ha1(&v), v.to_ascii_lowercase()) };
            let extra = db.load.iter().zip(extra).map(|(c, v)| (c.clone(), v.text())).collect();
            return Ok(Some((secret, extra)));
        }
        let users = read(&self.users).clone();
        match users {
            Some(u) => Ok(u.get(user).cloned().map(|s| (s, vec![]))),
            None => Err(()),
        }
    }

    fn authorize(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, table: &str, kind: Kind) -> i32 {
        self.authorize_with(ctx, realm, kind, &|_, user, realm| self.secret(user, realm, table))
    }

    /// pv_www_authorize / pv_proxy_authorize: the secret is in the
    /// `password_spec` variable, for the user in `username_spec`.
    fn pv_authorize(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, kind: Kind) -> i32 {
        let Some((user_pv, pass_pv)) = self.pv_specs.get() else {
            sip_core::elog!("auth: pv_www_authorize/pv_proxy_authorize need modparam(\"auth\", \"username_spec\" and \"password_spec\")");
            return ERROR;
        };
        let calc = self.calculate_ha1.load(Ordering::Relaxed);
        self.authorize_with(ctx, realm, kind, &|ctx, user, _| {
            let u = user_pv.get(ctx);
            if u.is_null() || !u.as_str().eq_ignore_ascii_case(user) {
                return Ok(None);
            }
            let p = pass_pv.get(ctx);
            let p = if p.is_null() { String::new() } else { p.as_str().into_owned() };
            if p.is_empty() {
                return Ok(None);
            }
            Ok(Some((if calc { Secret::Password(p) } else { Secret::Ha1(Alg::of_ha1(&p), p.to_ascii_lowercase()) }, vec![])))
        })
    }

    /// Kamailio's `pv_www_authenticate(realm, passwd, flags[, method])` /
    /// `pv_proxy_authenticate(realm, passwd, flags)` (also named
    /// `pv_*_authorize` with three arguments): the password for the
    /// credentials' user is `passwd`, an HA1 with flag 1. On failure, flags
    /// 2 / 4 / 8 put a challenge (no qop / qop=auth / qop=auth-int) into
    /// `$avp(digest_challenge)`.
    fn pv_authenticate(&self, ctx: &mut Ctx<'_, '_>, a: &PvAuthArgs, kind: Kind) -> i32 {
        let passwd = a.passwd.eval(ctx).into_owned();
        let flags = a.flags.eval(ctx).unwrap_or(0);
        let method = a.method.as_ref().map(|m| m.eval(ctx).into_owned());
        self.pv_authenticate_with(ctx, &a.realm, &passwd, flags, method.as_deref(), kind)
    }

    fn pv_authenticate_with(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, passwd: &str, flags: i64, method: Option<&str>, kind: Kind) -> i32 {
        let ret = self.authorize_full(ctx, realm, kind, method.map(str::as_bytes), &|_, _, _| {
            if flags & 1 == 0 {
                return Ok(Some((Secret::Password(passwd.to_string()), vec![])));
            }
            // An HA1 must have the hash's length (pv_authenticate()).
            match passwd.len() {
                32 | 64 | 128 => Ok(Some((Secret::Ha1(Alg::of_ha1(passwd), passwd.to_ascii_lowercase()), vec![]))),
                _ => Err(()),
            }
        });
        if ret < 0 && flags & 14 != 0 {
            let qop = if flags & 8 != 0 {
                2
            } else if flags & 4 != 0 {
                1
            } else {
                0
            };
            let realm = self.realm(realm, ctx, kind);
            let stale = ctx.ext::<AuthState>().is_some_and(|s| s.stale);
            let hname = if kind == Kind::Proxy { "Proxy-Authenticate" } else { "WWW-Authenticate" };
            let hf = self.challenge_hdrs(&realm, hname, qop, stale);
            ctx.ext_mut::<sip_core::TxnVars>().avps.entry("digest_challenge".to_string()).or_default().insert(0, sip_core::Val::Str(hf));
        }
        ret
    }

    /// Kamailio's `pv_auth_check(realm, passwd, flags, checks)`
    /// (auth_mod.c pv_auth_check() / w_pv_auth_check()): ACK and CANCEL
    /// pass; REGISTER is checked against Authorization, anything else
    /// against Proxy-Authorization, as pv_*_authenticate with `flags`.
    /// `checks` & 1: the credentials' user must be the From user (To for
    /// REGISTER / PUBLISH, which also need From user = To user, the hosts
    /// too with `use_domain`; PUBLISH also R-URI user = From user), else -8.
    fn pv_auth_check(&self, ctx: &mut Ctx<'_, '_>, a: &PvCheckArgs) -> i32 {
        if matches!(ctx.msg.method(), Some(Method::Ack | Method::Cancel)) {
            return OK;
        }
        let passwd = a.passwd.eval(ctx).into_owned();
        let flags = a.flags.eval(ctx).unwrap_or(0);
        let checks = a.checks.eval(ctx).unwrap_or(0);
        if a.realm.eval(ctx).is_empty() || passwd.is_empty() {
            sip_core::elog!("auth: pv_auth_check: empty realm or password");
            return ERROR;
        }
        let register = ctx.msg.method() == Some(Method::Register);
        let kind = if register { Kind::Www } else { Kind::Proxy };
        let ret = self.pv_authenticate_with(ctx, &a.realm, &passwd, flags, None, kind);
        if ret != OK || checks & 1 == 0 {
            return ret;
        }
        let Some((off, len)) = ctx.ext::<AuthState>().and_then(|s| s.used) else { return ERROR };
        // digest.username.user: the user name before an '@'.
        let creds_user =
            parse_creds(header_value(ctx.msg.buf, off, len)).map(|c| c.username.split(|&b| b == b'@').next().unwrap_or_default().to_vec()).unwrap_or_default();
        let publish = matches!(&ctx.msg.first, sip_parser::FirstLine::Request { method_raw, .. } if method_raw.eq_ignore_ascii_case(b"PUBLISH"));
        let uri_of = |ctx: &mut Ctx<'_, '_>, hk: HdrKind| -> Option<(Vec<u8>, Vec<u8>)> {
            let _ = ctx.msg.parse_headers(HdrFlags::of(hk));
            let u = parse_uri(name_addr(ctx.msg.get(hk)?.body).0)?;
            Some((u.user.unwrap_or_default().to_vec(), u.host.to_vec()))
        };
        let Some(from) = uri_of(ctx, HdrKind::From) else { return ERROR };
        if !(register || publish) {
            return if creds_user == from.0 { OK } else { USER_MISMATCH };
        }
        let Some(to) = uri_of(ctx, HdrKind::To) else { return ERROR };
        let use_domain = self.use_domain.load(Ordering::Relaxed);
        if creds_user != to.0 || from.0 != to.0 || (use_domain && from.1 != to.1) {
            return USER_MISMATCH;
        }
        if publish {
            let Some(ru) = ctx.msg.ruri().and_then(|r| parse_uri(r).map(|u| (u.user.unwrap_or_default().to_vec(), u.host.to_vec()))) else {
                return ERROR;
            };
            if from.0 != ru.0 || (use_domain && from.1 != ru.1) {
                return USER_MISMATCH;
            }
        }
        OK
    }

    /// Kamailio's `auth_algorithm(alg)` (auth_mod.c ki_auth_algorithm()):
    /// the algorithm of the challenges and of credentials without
    /// `algorithm=` from now on: "MD5" ("" too), "SHA-256", "SHA-512" or
    /// "SHA-512-256" (exact case); anything else is -1.
    fn set_algorithm(&self, alg: &str) -> i32 {
        let hash = match alg {
            "" | "MD5" => Alg::Md5,
            "SHA-256" => Alg::Sha256,
            "SHA-512" => Alg::Sha512,
            "SHA-512-256" => Alg::Sha512_256,
            _ => {
                sip_core::elog!("auth: auth_algorithm: invalid algorithm {alg:?} (MD5, SHA-256, SHA-512 or SHA-512-256)");
                return ERROR;
            }
        };
        *lock(&self.algorithms) = vec![DigestAlg { hash, sess: false }];
        OK
    }

    /// has_credentials: Authorization or Proxy-Authorization for the realm.
    fn has_credentials(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm) -> i32 {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let realm = self.realm(realm, ctx, Kind::Www);
        let found = ctx
            .msg
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(Kind::Www.header()) || h.name.eq_ignore_ascii_case(Kind::Proxy.header()))
            .any(|h| parse_creds(h.body).is_some_and(|c| c.realm == realm.as_slice()));
        if found { 1 } else { -1 }
    }

    /// Digest check with the secret coming from `lookup(user, realm)`.
    fn authorize_with(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, kind: Kind, lookup: &SecretLookup<'_>) -> i32 {
        self.authorize_full(ctx, realm, kind, None, lookup)
    }

    /// `authorize_with()`, with another method for HA2 than the request's.
    fn authorize_full(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, kind: Kind, method: Option<&[u8]>, lookup: &SecretLookup<'_>) -> i32 {
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return ERROR;
        }
        let realm = self.realm(realm, ctx, kind);
        let method = match (method, &ctx.msg.first) {
            (Some(m), _) => m,
            (None, sip_parser::FirstLine::Request { method_raw, .. }) => method_raw,
            _ => return ERROR,
        };
        let ruri = ctx.msg.ruri().unwrap_or_default();
        // Pick the credentials for our realm (a request may carry several).
        let found = ctx.msg.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(kind.header())).find_map(|h| {
            let c = parse_creds(h.body)?;
            (c.realm == realm.as_slice()).then_some((h.start, h.end.checked_sub(h.start)?, c))
        });
        let Some((off, len, c)) = found else { return NO_CREDENTIALS };
        let st = ctx.ext_mut::<AuthState>();
        st.used = Some((off, len));
        st.stale = false;

        let algs = lock(&self.algorithms).clone();
        // Any configured hash, plain or -sess (Kamailio takes MD5-sess
        // credentials whenever MD5 is in use). Without `algorithm=`: MD5
        // when offered, else the first algorithm (Kamailio: the default
        // one, auth_get_digest_alg_info() in api.c).
        let default = match algs.first() {
            Some(first) if !algs.iter().any(|a| a.hash == Alg::Md5) => DigestAlg { hash: first.hash, sess: false },
            _ => DigestAlg::MD5,
        };
        let Some(alg) = c.algorithm.map_or(Some(default), DigestAlg::parse).filter(|a| algs.iter().any(|x| x.hash == a.hash)) else { return ERROR };
        // The digest is bound to the request URI it was computed for.
        if c.uri != ruri {
            return ERROR;
        }
        let index = match self.check_nonce(c.nonce, &realm) {
            NonceCheck::Valid(i) => i,
            NonceCheck::Expired => {
                ctx.ext_mut::<AuthState>().stale = true;
                return STALE_NONCE;
            }
            NonceCheck::Invalid => return ERROR,
        };
        // qop: none, "auth", or "auth-int" (the body is part of HA2).
        let qop: Option<&[u8]> = match c.qop {
            None => None,
            Some(q) if q.eq_ignore_ascii_case(b"auth") => Some(b"auth"),
            Some(q) if q.eq_ignore_ascii_case(b"auth-int") => Some(b"auth-int"),
            Some(_) => return ERROR,
        };
        // qop and -sess need the client nonce (and qop the nonce-count).
        if (qop.is_some() && (c.nc.is_none() || c.cnonce.is_none())) || (alg.sess && c.cnonce.is_none()) {
            return ERROR;
        }
        let Ok(user) = std::str::from_utf8(c.username) else { return ERROR };
        let (secret, extra) = match lookup(ctx, user, &realm) {
            Ok(Some(s)) => s,
            Ok(None) => return USER_UNKNOWN,
            Err(()) => return ERROR,
        };
        let h = alg.hash;
        let base = match &secret {
            Secret::Password(p) => h.h(&[c.username, &realm, p.as_bytes()]),
            // (by length: a 64-digit HA1 is SHA-256 or SHA-512-256)
            Secret::Ha1(a, stored) if a.hex_len() == h.hex_len() => stored.clone(),
            Secret::Ha1(..) => return INVALID_PASSWORD, // stored HA1 is for another algorithm
        };
        let cnonce = c.cnonce.unwrap_or_default();
        let ha1 = alg.ha1(base, c.nonce, cnonce);
        let ha2 = if qop == Some(b"auth-int") {
            let body = ctx.msg.body().unwrap_or_default();
            h.h(&[method, c.uri, h.h(&[body]).as_bytes()])
        } else {
            h.h(&[method, c.uri])
        };
        let nc_raw = c.nc.unwrap_or_default();
        let expected = match qop {
            Some(q) => h.h(&[ha1.as_bytes(), c.nonce, nc_raw, cnonce, q, ha2.as_bytes()]),
            None => h.h(&[ha1.as_bytes(), c.nonce, ha2.as_bytes()]),
        };
        if !ct_eq(expected.as_bytes(), &c.response.to_ascii_lowercase()) {
            return INVALID_PASSWORD;
        }
        // Replays: with one_time_nonce each nonce is taken once (its
        // nonce-count slot is set to the maximum); else, with qop, the
        // nonce-count must grow.
        let otn = self.one_time_nonce.load(Ordering::Relaxed);
        if otn || (qop.is_some() && self.nonce_count.load(Ordering::Relaxed)) {
            let nc = if otn { Some(u32::MAX) } else { std::str::from_utf8(nc_raw).ok().and_then(|n| u32::from_str_radix(n, 16).ok()) };
            let again = nc.is_some_and(|n| ctx.ext::<AuthState>().and_then(|s| s.nc_ok) == Some((index, n)));
            if !again && !nc.is_some_and(|n| self.accept_nc(index, n)) {
                ctx.ext_mut::<AuthState>().stale = true;
                // Kamailio (nonce.c check_nonce()): a one-time nonce used
                // again is "reused" (-6); a replayed nonce-count makes the
                // nonce stale (-4).
                return if otn { NONCE_REUSED } else { STALE_NONCE };
            }
            ctx.ext_mut::<AuthState>().nc_ok = nc.map(|n| (index, n));
        }
        // add_authinfo_hdr: Authentication-Info with rspauth (RFC 2617
        // §3.2.3: HA2 without the method; an empty reply body for auth-int).
        if let Some(q) = qop
            && self.add_authinfo_hdr.load(Ordering::Relaxed)
            && !ctx.ext::<AuthState>().is_some_and(|s| s.authinfo)
        {
            let ha2 = if q == b"auth-int" { h.h(&[b"", c.uri, h.h(&[b""]).as_bytes()]) } else { h.h(&[b"", c.uri]) };
            let rspauth = h.h(&[ha1.as_bytes(), c.nonce, nc_raw, cnonce, q, ha2.as_bytes()]);
            let line = format!(
                "Authentication-Info: qop={}, rspauth=\"{rspauth}\", cnonce=\"{}\", nc={}\r\n",
                String::from_utf8_lossy(q),
                String::from_utf8_lossy(cnonce),
                String::from_utf8_lossy(nc_raw)
            );
            ctx.ext_mut::<ReplyExtra>().headers.extend_from_slice(line.as_bytes());
            ctx.ext_mut::<AuthState>().authinfo = true;
        }
        if !extra.is_empty() {
            let avps = &mut ctx.ext_mut::<sip_core::TxnVars>().avps;
            for (k, v) in extra {
                avps.entry(k).or_default().push(sip_core::Val::Str(v));
            }
        }
        OK
    }

    fn check_identity(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, table: &str, kind: Kind, identity: bool) -> i32 {
        let r = self.authorize(ctx, realm, table, kind);
        if r != OK || !identity {
            return r;
        }
        let Some((off, len)) = ctx.ext::<AuthState>().and_then(|s| s.used) else { return ERROR };
        let user = parse_creds(header_value(ctx.msg.buf, off, len)).map(|c| c.username.to_vec()).unwrap_or_default();
        let hk = if ctx.msg.method() == Some(Method::Register) { HdrKind::To } else { HdrKind::From };
        let id_user = ctx.msg.get(hk).and_then(|h| parse_uri(name_addr(h.body).0)).and_then(|u| u.user).map(<[u8]>::to_vec);
        if id_user.as_deref() == Some(user.as_slice()) { OK } else { USER_MISMATCH }
    }

    /// The challenge header lines, one per algorithm, preferred first (RFC
    /// 8760 §2.4). `flags`: 1 qop=auth, 2 qop=auth-int (which wins over
    /// 1, as in Kamailio's auth_challenge_helper()), 16 stale=true, 32 no
    /// `algorithm=` for MD5. Only the flags choose the qop (the `qop`
    /// parameter does not).
    fn challenge_hdrs(&self, realm: &[u8], hname: &str, flags: i64, stale: bool) -> String {
        let realm_s = String::from_utf8_lossy(realm);
        let qop = if flags & 2 != 0 { 2 } else { u32::from(flags & 1 != 0) };
        let stale = stale || flags & 16 != 0;
        let mut out = String::new();
        for alg in lock(&self.algorithms).iter() {
            out.push_str(&format!("{hname}: Digest realm=\"{realm_s}\", nonce=\"{}\"", self.new_nonce(realm)));
            match qop {
                1 => out.push_str(", qop=\"auth\""),
                2 => out.push_str(", qop=\"auth-int\""),
                _ => {}
            }
            if !(flags & 32 != 0 && *alg == DigestAlg::MD5) {
                out.push_str(&format!(", algorithm={}", alg.name()));
            }
            if stale {
                out.push_str(", stale=true");
            }
            out.push_str("\r\n");
        }
        out
    }

    fn challenge(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, kind: Kind, flags: i64) -> i32 {
        let realm = self.realm(realm, ctx, kind);
        let stale = ctx.ext::<AuthState>().is_some_and(|s| s.stale);
        let (code, reason, hname) = match kind {
            Kind::Www => (401, "Unauthorized", "WWW-Authenticate"),
            Kind::Proxy => (407, "Proxy Authentication Required", "Proxy-Authenticate"),
        };
        let extra = self.challenge_hdrs(&realm, hname, flags, stale);
        if ctx.reply_with(code, reason, extra.as_bytes()).is_ok() { 1 } else { -1 }
    }

    fn load_users(path: &str) -> Result<HashMap<String, Secret>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("auth users_file {path}: {e}"))?;
        let mut users = HashMap::new();
        for (line, n) in text.lines().zip(1..) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(user), Some(cred), None) = (it.next(), it.next(), it.next()) else {
                return Err(format!("{path}:{}: expected `user password` or `user md5:|sha256:<HA1>`", n));
            };
            let secret = match cred.split_once(':') {
                Some(("md5", h)) if h.len() == 32 && unhex(h.as_bytes()).is_some() => Secret::Ha1(Alg::Md5, h.to_ascii_lowercase()),
                Some(("sha256", h)) if h.len() == 64 && unhex(h.as_bytes()).is_some() => Secret::Ha1(Alg::Sha256, h.to_ascii_lowercase()),
                Some(("md5" | "sha256", _)) => return Err(format!("{path}:{}: malformed HA1", n)),
                _ => Secret::Password(cred.to_string()),
            };
            users.insert(user.to_string(), secret);
        }
        Ok(users)
    }
}

impl Module for Auth {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("users_file", Ty::Str, "", "File of `user password` (or `user md5:HA1` / `user sha256:HA1`) lines, instead of a database"),
            p("nonce_expire", Ty::Duration(Unit::Sec), "5m", "Nonce lifetime"),
            p("secret", Ty::Str, "random", "Nonce secret (set it to share nonces between servers)"),
            p("algorithm", Ty::Str, "MD5", "Digest algorithms offered, comma-separated (MD5, SHA-256, SHA-512, SHA-512-256, each also -sess)"),
            p("qop", Ty::Str, "", "Accepted for Kamailio configs (auth, auth-int); challenges take their qop from the flags"),
            p("nonce_count", Ty::Bool, "true", "Track each nonce's nonce-count: a repeated or lower nc makes the nonce stale (-4)"),
            p("one_time_nonce", Ty::Bool, "false", "Accept each nonce once (every request needs a new challenge)"),
            p("realm_prefix", Ty::Str, "", "Prefix stripped from every realm checked or challenged for"),
            p("add_authinfo_hdr", Ty::Bool, "false", "Add Authentication-Info (rspauth) to the reply of a request authenticated with qop"),
            p("username_spec", Ty::Str, "", "Variable with the user name for pv_www_authorize / pv_proxy_authorize (e.g. $avp(user))"),
            p("password_spec", Ty::Str, "", "Variable with the password, or the HA1 without calculate_ha1, for pv_*_authorize"),
        ])
    }

    fn name(&self) -> &'static str {
        "auth"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, opt_or, sig};
        const AUTHORIZE: &[Param] = &[arg("realm", Str).eg("\"example.com\""), opt_or("table", Str, "subscriber").lit()];
        const CHECK: &[Param] = &[arg("realm", Str).eg("\"example.com\""), opt_or("table", Str, "subscriber").lit(), opt_or("flags", Int, "1").lit()];
        const CHALLENGE: &[Param] = &[arg("realm", Str).eg("\"example.com\""), opt_or("qop", Int, "0").lit()];
        const REALM: &[Param] = &[arg("realm", Str).eg("\"example.com\"")];
        const PV_AUTH: &[Param] = &[arg("realm", Str).eg("\"example.com\""), opt("passwd", Str), opt("flags", Int)];
        const PV_AUTHENTICATE: &[Param] = &[arg("realm", Str).eg("\"example.com\""), arg("passwd", Str), arg("flags", Int), opt("method", Str)];
        const PV_AUTHENTICATE3: &[Param] = &[arg("realm", Str).eg("\"example.com\""), arg("passwd", Str), arg("flags", Int)];
        const PV_CHECK: &[Param] = &[arg("realm", Str).eg("\"example.com\""), arg("passwd", Str), arg("flags", Int), arg("checks", Int)];
        const ALG: &[Param] = &[arg("alg", Str).eg("\"SHA-256\"")];
        const GET_WWW: &[Param] = &[arg("realm", Str).eg("\"example.com\""), arg("flags", Int), arg("out", Var)];
        Some(vec![
            sig("www_authorize", "www_authorize", AUTHORIZE, Ret::Bool, "The Authorization credentials are valid for the realm (\"\": the To host)")
                .allowed(ctx::REQUEST),
            sig(
                "proxy_authorize",
                "proxy_authorize",
                AUTHORIZE,
                Ret::Bool,
                "The Proxy-Authorization credentials are valid for the realm (\"\": the From host)",
            )
            .allowed(ctx::REQUEST),
            sig("auth_check", "check", CHECK, Ret::Bool, "Valid credentials (WWW for REGISTER, else Proxy); flags 1: the user must be the To/From user")
                .allowed(ctx::REQUEST),
            sig(
                "pv_www_authorize",
                "pv_www_authorize",
                PV_AUTH,
                Ret::Bool,
                "The Authorization credentials match `passwd` (an HA1 with flags 1); with the realm alone, the user and password in the username_spec / password_spec variables",
            )
            .allowed(ctx::REQUEST),
            sig(
                "pv_proxy_authorize",
                "pv_proxy_authorize",
                PV_AUTH,
                Ret::Bool,
                "The Proxy-Authorization credentials match `passwd` (an HA1 with flags 1); with the realm alone, the user and password in the username_spec / password_spec variables",
            )
            .allowed(ctx::REQUEST),
            sig(
                "pv_www_authenticate",
                "pv_www_authenticate",
                PV_AUTHENTICATE,
                Ret::Bool,
                "The Authorization credentials match `passwd` (an HA1 with flags 1; `method` for HA2 instead of the request's); flags 2/4/8 put a challenge in $avp(digest_challenge) on failure",
            )
            .allowed(ctx::REQUEST),
            sig(
                "pv_proxy_authenticate",
                "pv_proxy_authenticate",
                PV_AUTHENTICATE3,
                Ret::Bool,
                "The Proxy-Authorization credentials match `passwd` (an HA1 with flags 1); flags 2/4/8 put a challenge in $avp(digest_challenge) on failure",
            )
            .allowed(ctx::REQUEST),
            sig(
                "pv_auth_check",
                "pv_check",
                PV_CHECK,
                Ret::Bool,
                "Credentials (WWW for REGISTER, else Proxy) match `passwd` (flags as pv_www_authenticate); checks 1: the user must be the From user (To for REGISTER / PUBLISH)",
            )
            .allowed(ctx::REQUEST),
            sig(
                "auth_algorithm",
                "set_algorithm",
                ALG,
                Ret::Bool,
                "The digest algorithm of challenges and of credentials without one from now on: MD5, SHA-256, SHA-512 or SHA-512-256",
            )
            .allowed(ctx::REQUEST),
            sig("has_credentials", "has_credentials", REALM, Ret::Bool, "The request has Authorization or Proxy-Authorization credentials for the realm")
                .allowed(ctx::REQUEST),
            sig(
                "auth_get_www_authenticate",
                "get_www_authenticate",
                GET_WWW,
                Ret::Bool,
                "A WWW-Authenticate challenge (header lines with CRLF) into `out`; flags as for www_challenge",
            )
            .allowed(ctx::ANY),
            sig("www_challenge", "www_challenge", CHALLENGE, Ret::Action, "Answer 401 with a digest challenge (qop: 1 auth, 2 auth-int, 3 both)")
                .allowed(ctx::REQUEST),
            sig("proxy_challenge", "proxy_challenge", CHALLENGE, Ret::Action, "Answer 407 with a digest challenge (qop: 1 auth, 2 auth-int, 3 both)")
                .allowed(ctx::REQUEST),
            sig(
                "auth_challenge",
                "challenge",
                CHALLENGE,
                Ret::Action,
                "Answer 401 (REGISTER) or 407 with a digest challenge (qop: 1 auth, 2 auth-int, 3 both)",
            )
            .allowed(ctx::REQUEST),
            sig("consume_credentials", "consume_credentials", &[], Ret::Bool, "Remove the checked credentials header before relaying").allowed(ctx::REQUEST),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "users_file" => *lock(&self.users_file) = Some(v.str()?.to_string()),
            "nonce_expire" => self.nonce_expire.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "secret" => *lock(&self.secret) = Some(v.str()?.as_bytes().to_vec()),
            "algorithm" => {
                let algs = v
                    .str()?
                    .split(',')
                    .map(|a| {
                        DigestAlg::parse(a.trim().as_bytes())
                            .ok_or_else(|| format!("auth: unknown algorithm {a:?} (MD5, SHA-256, SHA-512, SHA-512-256, each also -sess)"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if algs.is_empty() {
                    return Err("auth: algorithm list is empty".into());
                }
                *lock(&self.algorithms) = algs;
            }
            "qop" => self.qop.store(parse_qop(v.str()?)?, Ordering::Relaxed),
            "nonce_count" => self.nonce_count.store(v.int()? != 0, Ordering::Relaxed),
            "one_time_nonce" => self.one_time_nonce.store(v.int()? != 0, Ordering::Relaxed),
            "realm_prefix" => *lock(&self.realm_prefix) = v.str()?.to_string(),
            "add_authinfo_hdr" => self.add_authinfo_hdr.store(v.int()? != 0, Ordering::Relaxed),
            // Not in the schema: in ferrosip.toml `use_domain` is auth_db's.
            "use_domain" => self.use_domain.store(v.int()? != 0, Ordering::Relaxed),
            "username_spec" => lock(&self.pv_names).0 = Some(v.str()?.to_string()).filter(|s| !s.is_empty()),
            "password_spec" => lock(&self.pv_names).1 = Some(v.str()?.to_string()).filter(|s| !s.is_empty()),
            // Not in the schema: in ferrosip.toml `calculate_ha1` is auth_db's.
            "calculate_ha1" => self.calculate_ha1.store(v.int()? != 0, Ordering::Relaxed),
            _ => return Err(format!("auth: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        // Credentials: users_file, or the auth_db module (loaded after auth).
        if let Some(path) = lock(&self.users_file).clone() {
            *write(&self.users) = Some(Arc::new(Self::load_users(&path)?));
            let me = self.clone();
            reg.rpc.add("auth.reload", "Re-read users_file", move |_| {
                let users = Self::load_users(&path)?;
                let n = users.len();
                *write(&me.users) = Some(Arc::new(users));
                Ok(sip_core::serde_json::json!(n))
            });
        }
        reg.provide(self.clone());
        let names = lock(&self.pv_names).clone();
        match names {
            (Some(u), Some(pw)) => {
                let up = parse_pv(&u, reg.pvs()).map_err(|e| format!("auth: username_spec {u:?}: {e}"))?;
                let pp = parse_pv(&pw, reg.pvs()).map_err(|e| format!("auth: password_spec {pw:?}: {e}"))?;
                let _ = self.pv_specs.set((up, pp));
            }
            (None, None) => {}
            _ => return Err("auth: set both username_spec and password_spec".into()),
        }
        let secret = match lock(&self.secret).clone() {
            Some(s) => s,
            None => {
                let mut s = vec![0u8; 32];
                SystemRandom::new().fill(&mut s).map_err(|_| "auth: no randomness")?;
                s
            }
        };
        let _ = self.key.set(hmac::Key::new(hmac::HMAC_SHA256, &secret));
        // Nonce indices start at a random point so restarts don't reuse them.
        let mut r = [0u8; 4];
        let _ = SystemRandom::new().fill(&mut r);
        self.next_index.store(u32::from_be_bytes(r) | 1, Ordering::Relaxed);

        let two = |a: &[Arg]| -> Result<(Realm, String), String> {
            let [realm, table] = fixed_args(a)?;
            Ok((realm_spec(realm)?, table.str()?.to_string()))
        };
        let realm_flags = |a: &[Arg]| -> Result<(Realm, i64), String> {
            let [realm, flags] = fixed_args(a)?;
            Ok((realm_spec(realm)?, flags.int()?))
        };
        let me = self.clone();
        reg.export("auth", "www_authorize", two, move |ctx: &mut Ctx, (r, t): &(Realm, String)| me.authorize(ctx, r, t, Kind::Www));
        let me = self.clone();
        reg.export("auth", "proxy_authorize", two, move |ctx: &mut Ctx, (r, t): &(Realm, String)| me.authorize(ctx, r, t, Kind::Proxy));
        let me = self.clone();
        reg.export(
            "auth",
            "auth_check",
            |a: &[Arg]| {
                let [realm, table, flags] = fixed_args(a)?;
                Ok((realm_spec(realm)?, table.str()?.to_string(), flags.int()?))
            },
            move |ctx: &mut Ctx, (r, t, flags): &(Realm, String, i64)| {
                let kind = if ctx.msg.method() == Some(Method::Register) { Kind::Www } else { Kind::Proxy };
                me.check_identity(ctx, r, t, kind, flags & 1 != 0)
            },
        );
        let one = |a: &[Arg]| {
            let [realm] = fixed_args(a)?;
            realm_spec(realm)
        };
        // pv_*_authorize: Kamailio's (realm, passwd, flags), the names it
        // keeps for pv_*_authenticate; one argument is the older API with
        // username_spec / password_spec.
        enum PvAuth {
            Old(Realm),
            New(PvAuthArgs),
        }
        let pv_args = |max: usize| {
            move |a: &[Arg]| -> Result<PvAuth, String> {
                match a {
                    [realm] => Ok(PvAuth::Old(realm_spec(realm)?)),
                    [realm, passwd, flags, method @ ..] if a.len() <= max => Ok(PvAuth::New(PvAuthArgs {
                        realm: realm_spec(realm)?,
                        passwd: passwd.dyn_str()?,
                        flags: flags.dyn_int()?,
                        method: method.first().map(Arg::dyn_str).transpose()?,
                    })),
                    _ => Err(format!("expected realm, passwd, flags (got {} arguments)", a.len())),
                }
            }
        };
        for (name, kind, old, max) in [
            ("pv_www_authorize", Kind::Www, true, 3),
            ("pv_proxy_authorize", Kind::Proxy, true, 3),
            ("pv_www_authenticate", Kind::Www, false, 4),
            ("pv_proxy_authenticate", Kind::Proxy, false, 3),
        ] {
            let me = self.clone();
            let parse = pv_args(max);
            reg.export(
                "auth",
                name,
                move |a: &[Arg]| match parse(a)? {
                    PvAuth::Old(_) if !old => Err(format!("{name}: expected realm, passwd, flags")),
                    x => Ok(x),
                },
                move |ctx: &mut Ctx, a: &PvAuth| match a {
                    PvAuth::Old(r) => me.pv_authorize(ctx, r, kind),
                    PvAuth::New(a) => me.pv_authenticate(ctx, a, kind),
                },
            );
        }
        let me = self.clone();
        reg.export(
            "auth",
            "pv_auth_check",
            |a: &[Arg]| {
                let [realm, passwd, flags, checks] = fixed_args(a)?;
                Ok(PvCheckArgs { realm: realm_spec(realm)?, passwd: passwd.dyn_str()?, flags: flags.dyn_int()?, checks: checks.dyn_int()? })
            },
            move |ctx: &mut Ctx, a: &PvCheckArgs| me.pv_auth_check(ctx, a),
        );
        let me = self.clone();
        reg.export(
            "auth",
            "auth_algorithm",
            |a: &[Arg]| {
                let [alg] = fixed_args(a)?;
                alg.dyn_str()
            },
            move |ctx: &mut Ctx, alg: &DynStr| {
                let alg = alg.eval(ctx).into_owned();
                me.set_algorithm(&alg)
            },
        );
        let me = self.clone();
        reg.export("auth", "has_credentials", one, move |ctx: &mut Ctx, r: &Realm| me.has_credentials(ctx, r));
        let me = self.clone();
        reg.export(
            "auth",
            "auth_get_www_authenticate",
            |a: &[Arg]| {
                let [realm, flags, out] = fixed_args(a)?;
                let out = match out {
                    Arg::Fmt(f) => f.single_pv().cloned().filter(PvRef::settable).ok_or("expected a writable variable")?,
                    _ => return Err("expected a writable variable".into()),
                };
                Ok((realm_spec(realm)?, flags.dyn_int()?, out))
            },
            move |ctx: &mut Ctx, (r, f, out): &(Realm, DynInt, PvRef)| {
                let realm = me.realm(r, ctx, Kind::Www);
                let flags = f.eval(ctx).unwrap_or(0);
                let h = me.challenge_hdrs(&realm, "WWW-Authenticate", flags, false);
                if out.set(ctx, Val::Str(h)).is_ok() { 1 } else { -1 }
            },
        );
        let me = self.clone();
        reg.export("auth", "www_challenge", realm_flags, move |ctx: &mut Ctx, (r, f): &(Realm, i64)| me.challenge(ctx, r, Kind::Www, *f));
        let me = self.clone();
        reg.export("auth", "proxy_challenge", realm_flags, move |ctx: &mut Ctx, (r, f): &(Realm, i64)| me.challenge(ctx, r, Kind::Proxy, *f));
        let me = self.clone();
        reg.export("auth", "auth_challenge", realm_flags, move |ctx: &mut Ctx, (r, f): &(Realm, i64)| {
            let kind = if ctx.msg.method() == Some(Method::Register) { Kind::Www } else { Kind::Proxy };
            me.challenge(ctx, r, kind, *f)
        });
        reg.export(
            "auth",
            "consume_credentials",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| match ctx.ext::<AuthState>().and_then(|s| s.used) {
                Some((off, len)) => {
                    ctx.lumps.delete(off, len);
                    1
                }
                None => -1,
            },
        );
        Ok(())
    }
}

/// `auth_db`: credentials from a database table for the auth functions.
pub struct AuthDb {
    cfg: Mutex<DbCreds>,
}

impl Default for AuthDb {
    fn default() -> Self {
        Self {
            cfg: Mutex::new(DbCreds {
                url: String::new(),
                user_col: "username".into(),
                domain_col: "domain".into(),
                password_col: "password".into(),
                ha1_col: "ha1".into(),
                calculate_ha1: false,
                use_domain: false,
                load: vec![],
            }),
        }
    }
}

impl Module for AuthDb {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Credentials database"),
            p("user_column", Ty::Str, "username", "Column with the user name"),
            p("domain_column", Ty::Str, "domain", "Column with the domain"),
            p("password_column", Ty::Str, "password", "Column with the plain password (read with calculate_ha1)"),
            p("password_column_2", Ty::Str, "ha1", "Column with the HA1 (read without calculate_ha1): MD5, or SHA-256 when 64 hex digits"),
            p("calculate_ha1", Ty::Bool, "false", "The column holds plain passwords"),
            p("use_domain", Ty::Bool, "false", "Match the domain too"),
            p("load_credentials", Ty::Str, "", "Extra columns to load into AVPs, ';'-separated"),
        ])
    }

    fn name(&self) -> &'static str {
        "auth_db"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut c = lock(&self.cfg);
        match name {
            "db_url" => c.url = v.str()?.into(),
            "user_column" => c.user_col = v.str()?.into(),
            "domain_column" => c.domain_col = v.str()?.into(),
            "password_column" => c.password_col = v.str()?.into(),
            "password_column_2" => c.ha1_col = v.str()?.into(),
            "calculate_ha1" => c.calculate_ha1 = v.int()? != 0,
            "use_domain" => c.use_domain = v.int()? != 0,
            "load_credentials" => c.load = v.str()?.split(';').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
            "version_table" | "force_default_realm" => {}
            _ => return Err(format!("auth_db: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let auth = reg.api::<Auth>().ok_or("auth_db needs auth: put loadmodule \"auth\" before \"auth_db\"")?;
        let c = lock(&self.cfg).clone();
        if c.url.is_empty() {
            return Err("auth_db: modparam(\"auth_db\", \"db_url\", …) is required".into());
        }
        sip_db::connect(&c.url)?;
        auth.db.set(c).map_err(|_| "auth_db loaded twice".to_string())
    }
}

// --------------------------------------------------------- auth_ephemeral --

/// `auth_ephemeral`: time-limited credentials shared with a web service
/// (the TURN REST API scheme): username `expiry:user` (or `user:expiry`
/// with `username_format=0`), password = base64(HMAC-SHA1(secret,
/// username)). Functions `autheph_check(realm)`, `autheph_www(realm)`,
/// `autheph_proxy(realm)` (digest with that password; -1 for an expired
/// username, as Kamailio) and `autheph_authenticate(username, password)`. Parameters:
/// `secret` (repeatable; any matches), `username_format` (1),
/// `sha_algorithm` (0 SHA-1, 1 SHA-256, 2 SHA-384, 3 SHA-512).
pub struct AuthEphemeral {
    secrets: Mutex<Vec<String>>,
    ts_first: std::sync::atomic::AtomicBool,
    alg: AtomicU32,
    auth: OnceLock<Arc<Auth>>,
}

impl Default for AuthEphemeral {
    fn default() -> Self {
        Self { secrets: Mutex::new(Vec::new()), ts_first: std::sync::atomic::AtomicBool::new(true), alg: AtomicU32::new(0), auth: OnceLock::new() }
    }
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let [b0, b1, b2] = [0, 1, 2].map(|i| c.get(i).map_or(0, |&x| u32::from(x)));
        let n = b0 << 16 | b1 << 8 | b2;
        // The first c.len() + 1 sextets carry data, the rest is padding.
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            match T.get((n >> shift & 63) as usize) {
                Some(&x) if i <= c.len() => o.push(char::from(x)),
                _ => o.push('='),
            }
        }
    }
    o
}

impl AuthEphemeral {
    fn password(&self, secret: &str, username: &str) -> String {
        let alg = match self.alg.load(Ordering::Relaxed) {
            1 => hmac::HMAC_SHA256,
            2 => hmac::HMAC_SHA384,
            3 => hmac::HMAC_SHA512,
            _ => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        };
        base64(hmac::sign(&hmac::Key::new(alg, secret.as_bytes()), username.as_bytes()).as_ref())
    }

    /// The username hasn't expired yet.
    fn valid(&self, username: &str) -> bool {
        let ts = if self.ts_first.load(Ordering::Relaxed) { username.split(':').next() } else { username.rsplit(':').next() };
        ts.and_then(|t| t.parse::<u64>().ok()).is_some_and(|t| t >= unix_ms() / 1000)
    }

    fn check(&self, ctx: &mut Ctx<'_, '_>, realm: &Realm, kind: Kind) -> i32 {
        let Some(auth) = self.auth.get() else { return ERROR };
        let secrets = lock(&self.secrets).clone();
        let mut last = INVALID_PASSWORD;
        for secret in &secrets {
            let r = auth.authorize_with(ctx, realm, kind, &|_, user, _| {
                if !self.valid(user) {
                    return Err(()); // Kamailio: AUTH_ERROR for an expired username
                }
                Ok(Some((Secret::Password(self.password(secret, user)), vec![])))
            });
            if r != INVALID_PASSWORD {
                return r;
            }
            last = r;
        }
        last
    }
}

impl Module for AuthEphemeral {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("secret", Ty::List(&Ty::Str), "", "Shared secrets for the ephemeral passwords; any one may match (one per entry)"),
            p(
                "username_format",
                Ty::Enum(&[("username-timestamp", "0"), ("timestamp-username", "1")]),
                "timestamp-username",
                "Where the expiry timestamp is in the username",
            ),
            p("sha_algorithm", Ty::Enum(&[("sha1", "0"), ("sha256", "1"), ("sha384", "2"), ("sha512", "3")]), "sha1", "HMAC algorithm for the passwords"),
        ])
    }

    fn name(&self) -> &'static str {
        "auth_ephemeral"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const REALM: &[Param] = &[arg("realm", Str).eg("\"example.com\"")];
        const USER_PASS: &[Param] = &[arg("user", Str).eg("\"1700000000:alice\""), arg("password", Str)];
        Some(vec![
            sig("autheph_check", "check", REALM, Ret::Bool, "Valid ephemeral (time-limited) credentials, WWW for REGISTER, else Proxy").allowed(ctx::REQUEST),
            sig("autheph_www", "check_www", REALM, Ret::Bool, "Valid ephemeral credentials in Authorization").allowed(ctx::REQUEST),
            sig("autheph_proxy", "check_proxy", REALM, Ret::Bool, "Valid ephemeral credentials in Proxy-Authorization").allowed(ctx::REQUEST),
            sig("autheph_authenticate", "authenticate", USER_PASS, Ret::Bool, "This ephemeral user name and password are valid and not expired")
                .allowed(ctx::ANY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "secret" => lock(&self.secrets).push(v.str()?.to_string()),
            "username_format" => self.ts_first.store(v.int()? != 0, Ordering::Relaxed),
            "sha_algorithm" => self.alg.store(u32::try_from(v.int()?.clamp(0, 3)).unwrap_or(0), Ordering::Relaxed),
            "username_delimiter" if v.str()? == ":" => {}
            _ => return Err(format!("auth_ephemeral: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let auth = reg.api::<Auth>().ok_or("auth_ephemeral needs auth: put loadmodule \"auth\" before \"auth_ephemeral\"")?;
        let _ = self.auth.set(auth);
        if lock(&self.secrets).is_empty() {
            return Err("auth_ephemeral: modparam(\"auth_ephemeral\", \"secret\", …) is required".into());
        }
        let one = |a: &[Arg]| {
            let [realm] = fixed_args(a)?;
            realm_spec(realm)
        };
        let me = self.clone();
        reg.export("auth_ephemeral", "autheph_check", one, move |ctx: &mut Ctx, r: &Realm| {
            let kind = if ctx.msg.method() == Some(Method::Register) { Kind::Www } else { Kind::Proxy };
            me.check(ctx, r, kind)
        });
        let me = self.clone();
        reg.export("auth_ephemeral", "autheph_www", one, move |ctx: &mut Ctx, r: &Realm| me.check(ctx, r, Kind::Www));
        let me = self.clone();
        reg.export("auth_ephemeral", "autheph_proxy", one, move |ctx: &mut Ctx, r: &Realm| me.check(ctx, r, Kind::Proxy));
        let me = self.clone();
        reg.export(
            "auth_ephemeral",
            "autheph_authenticate",
            |a: &[Arg]| {
                let [user, passwd] = fixed_args(a)?;
                Ok((user.dyn_str()?, passwd.dyn_str()?))
            },
            move |ctx: &mut Ctx, (u, p): &(DynStr, DynStr)| {
                let (u, p) = (u.eval(ctx).into_owned(), p.eval(ctx).into_owned());
                if !me.valid(&u) {
                    return ERROR;
                }
                let ok = lock(&me.secrets).iter().any(|s| ct_eq(me.password(s, &u).as_bytes(), p.as_bytes()));
                if ok { OK } else { INVALID_PASSWORD }
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        let a = Auth::default();
        let _ = a.key.set(hmac::Key::new(hmac::HMAC_SHA256, b"k"));
        a
    }

    #[test]
    fn rfc2617_vector() {
        // RFC 2617 §3.5 example (HTTP, qop=auth).
        let ha1 = Alg::Md5.h(&[b"Mufasa", b"testrealm@host.com", b"Circle Of Life"]);
        let ha2 = Alg::Md5.h(&[b"GET", b"/dir/index.html"]);
        let r = Alg::Md5.h(&[ha1.as_bytes(), b"dcd98b7102dd2f0e8b11d0f600bfb0c093", b"00000001", b"0a4f113b", b"auth", ha2.as_bytes()]);
        assert_eq!(r, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn rfc7616_vectors() {
        // RFC 7616 §3.9.1 (MD5 and SHA-256, qop=auth).
        let nonce = b"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
        let cnonce = b"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
        let resp = |alg: DigestAlg| {
            let base = alg.hash.h(&[b"Mufasa", b"http-auth@example.org", b"Circle of Life"]);
            let ha1 = alg.ha1(base, nonce, cnonce);
            let ha2 = alg.hash.h(&[b"GET", b"/dir/index.html"]);
            alg.hash.h(&[ha1.as_bytes(), nonce, b"00000001", cnonce, b"auth", ha2.as_bytes()])
        };
        let alg = |s: &str| DigestAlg::parse(s.as_bytes()).unwrap();
        assert_eq!(resp(alg("MD5")), "8ca523f5e9506fed4657c9700eebdbec");
        assert_eq!(resp(alg("SHA-256")), "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1");
        // -sess: HA1 = H(H(user:realm:password):nonce:cnonce), same inputs
        // (values from Python's hashlib).
        let md5s = alg("md5-SESS");
        assert_eq!(md5s, DigestAlg { hash: Alg::Md5, sess: true });
        assert_eq!(md5s.ha1(Alg::Md5.h(&[b"Mufasa", b"http-auth@example.org", b"Circle of Life"]), nonce, cnonce), "2b3d906f52651c3136e1502b3d6f38ee");
        assert_eq!(resp(md5s), "e783283f46242139c486a698fec7211d");
        assert_eq!(resp(alg("SHA-256-sess")), "2fd51b3a77ad75bad6afad6003e818d767133c46d9e2749e7f5232ae1ea3efd7");
        assert_eq!(alg("SHA-256-sess").name(), "SHA-256-sess");
        assert!(DigestAlg::parse(b"SHA-512-256").is_some() && DigestAlg::parse(b"SHA-1").is_none() && DigestAlg::parse(b"-sess").is_none());
    }

    #[test]
    fn auth_algorithm() {
        let a = auth();
        assert_eq!(a.set_algorithm("SHA-512-256"), OK);
        let h = a.challenge_hdrs(b"ex.com", "WWW-Authenticate", 0, false);
        assert!(h.ends_with(", algorithm=SHA-512-256\r\n") && h.matches("WWW-Authenticate").count() == 1, "{h}");
        assert_eq!(a.set_algorithm("sha-256"), ERROR, "names are case-sensitive, as in Kamailio");
        assert_eq!(a.set_algorithm(""), OK);
        assert!(a.challenge_hdrs(b"ex.com", "X", 0, false).ends_with(", algorithm=MD5\r\n"));
        // SHA-512 / SHA-512-256 digests (values from Python's hashlib).
        assert_eq!(Alg::Sha512.h(&[b"a", b"b"]).len(), 128);
        assert_eq!(Alg::Sha512_256.h(&[b"abc"]), "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
        assert_eq!(Alg::of_ha1(&"0".repeat(128)), Alg::Sha512);
    }

    #[test]
    fn qop_param() {
        assert_eq!(parse_qop(""), Ok(0));
        assert_eq!(parse_qop("auth"), Ok(1));
        assert_eq!(parse_qop("auth-int, auth"), Ok(3));
        assert!(parse_qop("bogus").is_err());
    }

    #[test]
    fn challenge_flags() {
        let a = auth();
        let h = a.challenge_hdrs(b"ex.com", "WWW-Authenticate", 0, false);
        assert!(h.starts_with("WWW-Authenticate: Digest realm=\"ex.com\", nonce=\"") && h.ends_with(", algorithm=MD5\r\n") && !h.contains("qop"), "{h}");
        // The qop parameter doesn't change challenges (Kamailio: flags only).
        a.qop.store(1, Ordering::Relaxed);
        assert!(!a.challenge_hdrs(b"ex.com", "WWW-Authenticate", 0, false).contains("qop"));
        let h = a.challenge_hdrs(b"ex.com", "WWW-Authenticate", 1 | 16 | 32, false);
        assert!(h.contains("qop=\"auth\"") && h.contains("stale=true") && !h.contains("algorithm"), "{h}");
        assert!(a.challenge_hdrs(b"ex.com", "X", 2, false).contains("qop=\"auth-int\""));
        assert!(a.challenge_hdrs(b"ex.com", "X", 3, false).contains("qop=\"auth-int\","));
    }

    #[test]
    fn nonce_lifecycle() {
        let a = auth();
        let n = a.new_nonce(b"r");
        let NonceCheck::Valid(i) = a.check_nonce(n.as_bytes(), b"r") else { panic!() };
        assert!(matches!(a.check_nonce(n.as_bytes(), b"other"), NonceCheck::Invalid), "bound to realm");
        let mut forged = n.clone().into_bytes();
        forged[50] = if forged[50] == b'0' { b'1' } else { b'0' }; // inside the MAC
        assert!(matches!(a.check_nonce(&forged, b"r"), NonceCheck::Invalid));
        assert!(a.accept_nc(i, 1) && a.accept_nc(i, 2));
        assert!(!a.accept_nc(i, 2) && !a.accept_nc(i, 1), "replay rejected");
        a.nonce_expire.store(0, Ordering::Relaxed);
        let n = a.new_nonce(b"r");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(matches!(a.check_nonce(n.as_bytes(), b"r"), NonceCheck::Expired));
    }

    #[test]
    fn huge_nonce_expire_does_not_wrap() {
        let a = auth();
        a.set_param("nonce_expire", &Arg::Int(i64::MAX)).unwrap();
        let n = a.new_nonce(b"r");
        assert!(matches!(a.check_nonce(n.as_bytes(), b"r"), NonceCheck::Valid(_)));
    }

    #[test]
    fn credentials_parsing() {
        let c = parse_creds(
            br#"Digest username="bob", realm="ex.com",nonce="abc", uri="sip:ex.com", response="f00", algorithm=SHA-256, qop=auth, nc=00000001, cnonce="x,y""#,
        )
        .unwrap();
        assert_eq!((c.username, c.realm, c.uri), (&b"bob"[..], &b"ex.com"[..], &b"sip:ex.com"[..]));
        assert_eq!((c.algorithm, c.nc, c.cnonce), (Some(&b"SHA-256"[..]), Some(&b"00000001"[..]), Some(&b"x,y"[..])));
        assert!(parse_creds(b"Basic Zm9v").is_none());
        assert!(parse_creds(b"Dig").is_none());
        assert!(parse_creds(br#"Digest username="bob", nonce="abc", response="f00", stray"#).is_none());
        assert_eq!(DigestAlg::parse(b"md5-SESS"), Some(DigestAlg { hash: Alg::Md5, sess: true }));
        assert_eq!(DigestAlg::parse(b"MD5"), Some(DigestAlg::MD5));
        assert_eq!(header_value(b"X: y\r\nAuthorization: Digest a=b\r\n", 6, 25), b" Digest a=b");
        assert_eq!(header_value(b"short", 3, usize::MAX), b"");
    }

    #[test]
    fn ephemeral_base64() {
        assert_eq!(base64(b"hello world!?"), "aGVsbG8gd29ybGQhPw==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }
    struct NoNet;

    impl sip_core::Outbound for NoNet {
        fn send(&self, _: &sip_core::Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: sip_core::Proto) -> Option<std::net::SocketAddr> {
            None
        }
    }

    /// Runs `f` on a context for the request (`\n` → CRLF, Content-Length added).
    fn with_req<R>(method: &str, ruri: &str, hdrs: &str, body: &str, f: impl FnOnce(&mut Ctx<'_, '_>) -> R) -> R {
        let raw = format!(
            "{method} {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKa\nFrom: <sip:alice@ex.com>;tag=1\nTo: <sip:alice@ex.com>\n\
             Call-ID: c1\nCSeq: 1 {method}\n{hdrs}Content-Length: {}\n\n",
            body.len()
        )
        .replace('\n', "\r\n")
            + body;
        let arena = bumpalo::Bump::new();
        let mut m = sip_parser::Msg::parse(raw.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (sip_core::Lumps::default(), Vec::new());
        let dest = sip_core::Dest::new(sip_core::Proto::Udp, std::net::SocketAddr::from(([127, 0, 0, 1], 5060)));
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, dest, 0);
        f(&mut ctx)
    }

    fn lit(s: &str) -> Realm {
        DynStr::Static(s.into())
    }

    /// An Auth with users alice (password "secret") and bob (MD5 HA1 of "pw").
    fn auth_with_users() -> Auth {
        let a = auth();
        let mut users = HashMap::new();
        users.insert("alice".to_string(), Secret::Password("secret".into()));
        users.insert("bob".to_string(), Secret::Ha1(Alg::Md5, Alg::Md5.h(&[b"bob", b"ex.com", b"pw"])));
        *write(&a.users) = Some(Arc::new(users));
        a
    }

    /// The digest credentials a client would send.
    struct Client<'a> {
        user: &'a str,
        realm: &'a str,
        password: &'a str,
        method: &'a str,
        uri: &'a str,
        alg: DigestAlg,
        /// (qop, nc, cnonce)
        qop: Option<(&'a str, &'a str, &'a str)>,
        body: &'a str,
        alg_param: bool,
    }

    impl Client<'_> {
        fn header(&self, name: &str, nonce: &str) -> String {
            let h = self.alg.hash;
            let base = h.h(&[self.user.as_bytes(), self.realm.as_bytes(), self.password.as_bytes()]);
            let cnonce = self.qop.map_or("", |q| q.2);
            let ha1 = self.alg.ha1(base, nonce.as_bytes(), cnonce.as_bytes());
            let ha2 = match self.qop {
                Some(("auth-int", ..)) => h.h(&[self.method.as_bytes(), self.uri.as_bytes(), h.h(&[self.body.as_bytes()]).as_bytes()]),
                _ => h.h(&[self.method.as_bytes(), self.uri.as_bytes()]),
            };
            let (resp, extra) = match self.qop {
                Some((q, nc, cn)) => (
                    h.h(&[ha1.as_bytes(), nonce.as_bytes(), nc.as_bytes(), cn.as_bytes(), q.as_bytes(), ha2.as_bytes()]),
                    format!(", qop={q}, nc={nc}, cnonce=\"{cn}\""),
                ),
                None => (h.h(&[ha1.as_bytes(), nonce.as_bytes(), ha2.as_bytes()]), String::new()),
            };
            let alg = if self.alg_param { format!(", algorithm={}", self.alg.name()) } else { String::new() };
            format!(
                "{name}: Digest username=\"{}\", realm=\"{}\", nonce=\"{nonce}\", uri=\"{}\", response=\"{resp}\"{alg}{extra}\n",
                self.user, self.realm, self.uri
            )
        }
    }

    fn alice() -> Client<'static> {
        Client {
            user: "alice",
            realm: "ex.com",
            password: "secret",
            method: "REGISTER",
            uri: "sip:ex.com",
            alg: DigestAlg::MD5,
            qop: None,
            body: "",
            alg_param: false,
        }
    }

    /// www_authorize("ex.com") on a REGISTER carrying `hdr`.
    fn www(a: &Auth, hdr: &str, body: &str) -> i32 {
        with_req("REGISTER", "sip:ex.com", hdr, body, |ctx| a.authorize(ctx, &lit("ex.com"), "", Kind::Www))
    }

    #[test]
    fn authorize_return_codes() {
        let a = auth_with_users();
        let n = a.new_nonce(b"ex.com");
        let ok = alice().header("Authorization", &n);
        assert_eq!(www(&a, &ok, ""), OK);
        // One hex digit of the MAC changed.
        let mut forged = n.clone().into_bytes();
        forged[40] = if forged[40] == b'0' { b'1' } else { b'0' };
        let forged = String::from_utf8(forged).unwrap();
        // (what, header, expected)
        let cases = [
            ("wrong password", Client { password: "nope", ..alice() }.header("Authorization", &n), INVALID_PASSWORD),
            ("unknown user", Client { user: "carol", ..alice() }.header("Authorization", &n), USER_UNKNOWN),
            ("no credentials", String::new(), NO_CREDENTIALS),
            ("credentials for another realm", Client { realm: "other.com", ..alice() }.header("Authorization", &n), NO_CREDENTIALS),
            ("Proxy-Authorization for www_authorize", alice().header("Proxy-Authorization", &n), NO_CREDENTIALS),
            ("uri is not the R-URI", Client { uri: "sip:other.com", ..alice() }.header("Authorization", &n), ERROR),
            ("forged nonce", alice().header("Authorization", &forged), ERROR),
            ("nonce for another realm", alice().header("Authorization", &a.new_nonce(b"other.com")), ERROR),
            (
                "algorithm not offered",
                Client { alg: DigestAlg { hash: Alg::Sha256, sess: false }, alg_param: true, ..alice() }.header("Authorization", &n),
                ERROR,
            ),
            ("unknown qop", Client { qop: Some(("bogus", "00000001", "c")), ..alice() }.header("Authorization", &n), ERROR),
            ("qop without nc", alice().header("Authorization", &n).replace("\"\n", "\", qop=auth, cnonce=\"c\"\n"), ERROR),
            ("-sess without cnonce", Client { alg: DigestAlg { hash: Alg::Md5, sess: true }, alg_param: true, ..alice() }.header("Authorization", &n), ERROR),
        ];
        for (what, hdr, want) in cases {
            assert_eq!(www(&a, &hdr, ""), want, "{what}: {hdr}");
        }
        // The stored HA1 (bob) works; a response in upper case hex too.
        assert_eq!(www(&a, &Client { user: "bob", password: "pw", ..alice() }.header("Authorization", &n), ""), OK);
        let upper = {
            let h = alice().header("Authorization", &n);
            let (pre, rest) = h.split_once("response=\"").unwrap();
            let (resp, post) = rest.split_once('"').unwrap();
            format!("{pre}response=\"{}\"{post}", resp.to_ascii_uppercase())
        };
        assert_eq!(www(&a, &upper, ""), OK);
    }

    #[test]
    fn several_credentials_pick_the_realm() {
        let a = auth_with_users();
        let n = a.new_nonce(b"ex.com");
        let hdrs = Client { realm: "other.com", password: "x", ..alice() }.header("Authorization", &n) + &alice().header("Authorization", &n);
        assert_eq!(www(&a, &hdrs, ""), OK);
    }

    #[test]
    fn expired_nonce_is_stale_and_challenged_stale() {
        let a = auth_with_users();
        // An expired nonce with a valid MAC (expiry 1 ms after the epoch).
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(&7u32.to_be_bytes());
        raw.extend_from_slice(&a.nonce_mac(1, 7, b"ex.com"));
        let n = hex(&raw);
        let hdr = alice().header("Authorization", &n);
        with_req("REGISTER", "sip:ex.com", &hdr, "", |ctx| {
            assert_eq!(a.authorize(ctx, &lit("ex.com"), "", Kind::Www), STALE_NONCE);
            assert!(ctx.ext::<AuthState>().is_some_and(|s| s.stale));
        });
    }

    #[test]
    fn nonce_count_must_grow_with_qop() {
        let a = auth_with_users();
        let n = a.new_nonce(b"ex.com");
        let with_nc = |nc| Client { qop: Some(("auth", nc, "0a4f113b")), ..alice() }.header("Authorization", &n);
        assert_eq!(www(&a, &with_nc("00000001"), ""), OK);
        assert_eq!(www(&a, &with_nc("00000001"), ""), STALE_NONCE, "replayed nc");
        assert_eq!(www(&a, &with_nc("00000003"), ""), OK, "nc may skip");
        assert_eq!(www(&a, &with_nc("00000002"), ""), STALE_NONCE, "lower nc");
        assert_eq!(www(&a, &with_nc("0000000a"), ""), OK, "nc is hex");
        // Checking the same credentials twice in one request is no replay.
        let hdr = with_nc("0000000b");
        with_req("REGISTER", "sip:ex.com", &hdr, "", |ctx| {
            assert_eq!(a.authorize(ctx, &lit("ex.com"), "", Kind::Www), OK);
            assert_eq!(a.authorize(ctx, &lit("ex.com"), "", Kind::Www), OK);
        });
        // Without nonce_count, the same nc is accepted again.
        a.nonce_count.store(false, Ordering::Relaxed);
        assert_eq!(www(&a, &with_nc("00000001"), ""), OK);
        // Without qop the nonce-count isn't tracked.
        a.nonce_count.store(true, Ordering::Relaxed);
        let plain = alice().header("Authorization", &n);
        assert_eq!((www(&a, &plain, ""), www(&a, &plain, "")), (OK, OK));
    }

    #[test]
    fn one_time_nonce_is_taken_once() {
        let a = auth_with_users();
        a.one_time_nonce.store(true, Ordering::Relaxed);
        let n = a.new_nonce(b"ex.com");
        let hdr = alice().header("Authorization", &n);
        assert_eq!(www(&a, &hdr, ""), OK);
        assert_eq!(www(&a, &hdr, ""), NONCE_REUSED);
    }

    #[test]
    fn nonce_count_slot_reused_by_a_newer_nonce_rejects_the_old_one() {
        let a = auth();
        let n = a.new_nonce(b"r");
        let NonceCheck::Valid(i) = a.check_nonce(n.as_bytes(), b"r") else { panic!("{n}") };
        // The index NC_POOL later lands in the same slot.
        a.next_index.store(i.wrapping_add(u32::try_from(NC_POOL).unwrap()), Ordering::Relaxed);
        let _newer = a.new_nonce(b"r");
        assert!(!a.accept_nc(i, 1), "evicted");
        assert!(a.accept_nc(i.wrapping_add(u32::try_from(NC_POOL).unwrap()), 1));
        assert!(!a.accept_nc(i.wrapping_add(1), 1), "a slot never handed out");
    }

    #[test]
    fn auth_int_sess_and_sha256() {
        let a = auth_with_users();
        *lock(&a.algorithms) = vec![DigestAlg { hash: Alg::Sha256, sess: false }, DigestAlg::MD5];
        let n = a.new_nonce(b"ex.com");
        let body = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n";
        let int = Client { qop: Some(("auth-int", "00000001", "cn")), body, ..alice() };
        assert_eq!(www(&a, &int.header("Authorization", &n), body), OK);
        // The body is part of HA2.
        let other = Client { qop: Some(("auth-int", "00000002", "cn")), body, ..alice() };
        assert_eq!(www(&a, &other.header("Authorization", &n), "v=1\r\n"), INVALID_PASSWORD);
        let sha = Client { alg: DigestAlg { hash: Alg::Sha256, sess: false }, alg_param: true, ..alice() };
        assert_eq!(www(&a, &sha.header("Authorization", &n), ""), OK);
        let sha_sess = Client { alg: DigestAlg { hash: Alg::Sha256, sess: true }, alg_param: true, qop: Some(("auth", "00000003", "cn")), ..alice() };
        assert_eq!(www(&a, &sha_sess.header("Authorization", &n), ""), OK);
        let md5_sess = Client { alg: DigestAlg { hash: Alg::Md5, sess: true }, alg_param: true, qop: Some(("auth", "00000004", "cn")), ..alice() };
        assert_eq!(www(&a, &md5_sess.header("Authorization", &n), ""), OK);
        // Without algorithm=: MD5 when offered.
        assert_eq!(www(&a, &alice().header("Authorization", &n), ""), OK);
        // bob's HA1 is MD5: not usable for a SHA-256 response.
        let bob = Client { user: "bob", password: "pw", alg: DigestAlg { hash: Alg::Sha256, sess: false }, alg_param: true, ..alice() };
        assert_eq!(www(&a, &bob.header("Authorization", &n), ""), INVALID_PASSWORD);
        // SHA-256 only: credentials without algorithm= are SHA-256.
        *lock(&a.algorithms) = vec![DigestAlg { hash: Alg::Sha256, sess: false }];
        assert_eq!(www(&a, &Client { alg: DigestAlg { hash: Alg::Sha256, sess: false }, ..alice() }.header("Authorization", &n), ""), OK);
        assert_eq!(www(&a, &alice().header("Authorization", &n), ""), INVALID_PASSWORD);
    }

    #[test]
    fn authentication_info_carries_rspauth() {
        let a = auth_with_users();
        a.add_authinfo_hdr.store(true, Ordering::Relaxed);
        let n = a.new_nonce(b"ex.com");
        let c = Client { qop: Some(("auth", "00000001", "0a4f113b")), ..alice() };
        let hdr = c.header("Authorization", &n);
        let extra = with_req("REGISTER", "sip:ex.com", &hdr, "", |ctx| {
            assert_eq!(a.authorize(ctx, &lit("ex.com"), "", Kind::Www), OK);
            String::from_utf8(ctx.ext::<ReplyExtra>().unwrap().headers.clone()).unwrap()
        });
        let ha1 = Alg::Md5.h(&[b"alice", b"ex.com", b"secret"]);
        let ha2 = Alg::Md5.h(&[b"", b"sip:ex.com"]);
        let rspauth = Alg::Md5.h(&[ha1.as_bytes(), n.as_bytes(), b"00000001", b"0a4f113b", b"auth", ha2.as_bytes()]);
        assert_eq!(extra, format!("Authentication-Info: qop=auth, rspauth=\"{rspauth}\", cnonce=\"0a4f113b\", nc=00000001\r\n"));
    }

    #[test]
    fn realm_from_to_or_from_and_realm_prefix() {
        let a = auth();
        let realm = |method: &str, kind: Kind| {
            with_req(method, "sip:ex.com", "", "", |ctx| {
                let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                a.realm(&lit(""), ctx, kind)
            })
        };
        assert_eq!(realm("REGISTER", Kind::Www), b"ex.com");
        assert_eq!(realm("INVITE", Kind::Proxy), b"ex.com");
        *lock(&a.realm_prefix) = "e".into();
        assert_eq!(realm("REGISTER", Kind::Www), b"x.com");
        assert_eq!(with_req("INVITE", "sip:x", "", "", |ctx| a.realm(&lit("ex.org"), ctx, Kind::Proxy)), b"x.org");
        assert_eq!(with_req("INVITE", "sip:x", "", "", |ctx| a.realm(&lit("Ab.org"), ctx, Kind::Proxy)), b"Ab.org", "a literal keeps its case");
    }

    #[test]
    fn has_credentials_looks_at_both_headers() {
        let a = auth();
        let hdr = |name: &str, realm: &str| format!("{name}: Digest username=\"u\", realm=\"{realm}\", nonce=\"n\", uri=\"sip:x\", response=\"r\"\n");
        let cases = [
            (hdr("Authorization", "ex.com"), 1),
            (hdr("Proxy-Authorization", "ex.com"), 1),
            (hdr("Authorization", "other.com"), -1),
            (hdr("Authorization", "other.com") + &hdr("Proxy-Authorization", "ex.com"), 1),
            ("Authorization: Basic Zm9v\n".to_string(), -1),
            (String::new(), -1),
        ];
        for (h, want) in cases {
            assert_eq!(with_req("INVITE", "sip:x", &h, "", |ctx| a.has_credentials(ctx, &lit("ex.com"))), want, "{h}");
        }
    }

    #[test]
    fn the_checked_credentials_header_is_the_whole_line() {
        let a = auth_with_users();
        let n = a.new_nonce(b"ex.com");
        let hdr = format!("X-Before: 1\n{}X-After: 2\n", alice().header("Proxy-Authorization", &n));
        let out = with_req("INVITE", "sip:ex.com", &hdr, "", |ctx| {
            assert_eq!(a.authorize(ctx, &lit("ex.com"), "", Kind::Proxy), INVALID_PASSWORD, "HA2 uses INVITE");
            let (off, len) = ctx.ext::<AuthState>().unwrap().used.unwrap();
            // What consume_credentials() removes.
            ctx.lumps.delete(off, len);
            let mut out = Vec::new();
            ctx.lumps.apply(ctx.msg.buf, &mut out);
            String::from_utf8(out).unwrap()
        });
        assert!(out.contains("X-Before: 1\r\nX-After: 2\r\n") && !out.contains("Proxy-Authorization"), "{out}");
    }

    #[test]
    fn check_identity_compares_the_to_or_from_user() {
        let a = auth_with_users();
        let n = a.new_nonce(b"ex.com");
        assert_eq!(
            with_req("REGISTER", "sip:ex.com", &alice().header("Authorization", &n), "", |ctx| a.check_identity(ctx, &lit("ex.com"), "", Kind::Www, true)),
            OK
        );
        let bob = Client { user: "bob", password: "pw", ..alice() };
        assert_eq!(
            with_req("REGISTER", "sip:ex.com", &bob.header("Authorization", &n), "", |ctx| a.check_identity(ctx, &lit("ex.com"), "", Kind::Www, true)),
            USER_MISMATCH
        );
        assert_eq!(
            with_req("REGISTER", "sip:ex.com", &bob.header("Authorization", &n), "", |ctx| a.check_identity(ctx, &lit("ex.com"), "", Kind::Www, false)),
            OK
        );
    }

    #[test]
    fn credentials_with_spacing_and_unquoted_values() {
        let c = parse_creds(b"  digest   username=bob ,realm = \"r\" , nonce=n,uri=\"sip:x\",response=abc  ").unwrap();
        assert_eq!((c.username, c.realm, c.nonce, c.response), (&b"bob"[..], &b"r"[..], &b"n"[..], &b"abc"[..]));
        // Escaped quotes stay as sent (Kamailio hashes the raw value).
        let c = parse_creds(br#"Digest username="a\"b", nonce="n", response="r""#).unwrap();
        assert_eq!(c.username, br#"a\"b"#);
        // username, nonce and response are required.
        for missing in ["username", "nonce", "response"] {
            let all = [("username", "u"), ("nonce", "n"), ("response", "r")];
            let s = all.iter().filter(|(k, _)| *k != missing).map(|(k, v)| format!("{k}=\"{v}\"")).collect::<Vec<_>>().join(", ");
            assert!(parse_creds(format!("Digest {s}").as_bytes()).is_none(), "without {missing}");
        }
    }

    #[test]
    fn users_file_lines() {
        let path = std::env::temp_dir().join(format!("mod-auth-users-{}.txt", std::process::id()));
        let ha1 = "0123456789ABCDEF0123456789abcdef";
        std::fs::write(&path, format!("# comment\n\nalice secret\nbob md5:{ha1}\ncarol sha256:{}\n", "a".repeat(64))).unwrap();
        let u = Auth::load_users(path.to_str().unwrap()).unwrap();
        assert!(matches!(u.get("alice"), Some(Secret::Password(p)) if p == "secret"));
        assert!(matches!(u.get("bob"), Some(Secret::Ha1(Alg::Md5, h)) if *h == ha1.to_ascii_lowercase()));
        assert!(matches!(u.get("carol"), Some(Secret::Ha1(Alg::Sha256, _))));
        for bad in ["alice", "alice a b", "bob md5:abc", "bob sha256:zz", &format!("bob md5:{}", "g".repeat(32))] {
            std::fs::write(&path, bad).unwrap();
            assert!(Auth::load_users(path.to_str().unwrap()).is_err(), "{bad:?}");
        }
        // Other prefixes are passwords.
        std::fs::write(&path, "dave sha1:xyz").unwrap();
        assert!(matches!(Auth::load_users(path.to_str().unwrap()).unwrap().get("dave"), Some(Secret::Password(p)) if p == "sha1:xyz"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn set_param_values() {
        let a = auth();
        assert!(a.set_param("algorithm", &Arg::Str("SHA-256, md5-sess".into())).is_ok());
        assert_eq!(*lock(&a.algorithms), [DigestAlg { hash: Alg::Sha256, sess: false }, DigestAlg { hash: Alg::Md5, sess: true }]);
        assert!(a.set_param("algorithm", &Arg::Str("SHA-1".into())).is_err());
        assert!(a.set_param("qop", &Arg::Str("auth,bogus".into())).is_err());
        a.set_param("nonce_expire", &Arg::Int(-5)).unwrap();
        assert_eq!(a.nonce_expire.load(Ordering::Relaxed), 1, "at least 1 s");
        assert!(a.set_param("nope", &Arg::Int(1)).is_err());
        // Challenges list the algorithms in order.
        let h = a.challenge_hdrs(b"r", "WWW-Authenticate", 0, true);
        let lines: Vec<&str> = h.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("algorithm=SHA-256, stale=true") && lines[1].ends_with("algorithm=MD5-sess, stale=true"), "{h}");
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(unhex(b"00ff7A"), Some(vec![0, 255, 0x7a]));
        assert_eq!(unhex(b"abc"), None);
        assert_eq!(unhex(b"zz"), None);
        assert_eq!(unhex(b"+1"), None, "a sign is not a hex digit");
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac") && !ct_eq(b"ab", b"abc"));
        assert_eq!(Alg::of_ha1(&"0".repeat(32)), Alg::Md5);
        assert_eq!(Alg::of_ha1(&"0".repeat(64)), Alg::Sha256);
    }

    #[test]
    fn ephemeral_usernames_and_passwords() {
        let e = AuthEphemeral::default();
        // (username, valid with the timestamp first)
        for (u, want) in [("1:alice", false), ("99999999999:alice", true), ("alice", false), (":alice", false), ("99999999999", true)] {
            assert_eq!(e.valid(u), want, "{u}");
        }
        e.ts_first.store(false, Ordering::Relaxed);
        for (u, want) in [("alice:99999999999", true), ("alice:1", false), ("99999999999:alice", false)] {
            assert_eq!(e.valid(u), want, "{u}");
        }
        // base64(HMAC-SHA1("secret", "1600000000:alice")), as Python's hmac computes it.
        assert_eq!(e.password("secret", "1600000000:alice"), "UQpbzqLy8wUgAxlVOh3KKXno2lk=");
        e.alg.store(1, Ordering::Relaxed);
        assert_eq!(e.password("secret", "1600000000:alice"), "BqL6QJxyGm5j9spoWvF0N8jdWyaGUqkDxlNUk8NKYBs=");
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }
}
