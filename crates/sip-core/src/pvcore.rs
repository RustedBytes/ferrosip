//! Core pseudo-variables and script storage (Kamailio `pv` module basics).
//!
//! * Message fields: `$ru $rU $rd $rp $rz $du $fu $fU $fd $fn $ft $tu $tU $td
//!   $tn $tt $ci $cs $rm $rs $rr $si $sp $pr/$proto $Ri $Rp $hdr(X) $hdrc(X)
//!   $ua $ct $cT $rb $ml $mb $conid $af`.
//! * Digest credentials (Kamailio's `pv_get_authattr`): `$au $ad $aU $ar
//!   $adu $aa $adn $adc $adr $ado`.
//! * Storage: `$var(x)` (per message), `$avp(x)` / `$xavp(r=>f)` and message
//!   flags (`TxnVars`, carried into the transaction by tm, so failure and
//!   reply routes see them), `$shv(x)` (shared by all workers).
//! * Misc: `$rc $retcode $null $Ts $RANDOM $pp $env(NAME)`.

use crate::module::{Ctx, Registry};
use crate::net::{Dest, Proto};
use crate::pv::{PvIdx, PvParam, PvSpec, Val};
use crate::shm::ShardedMap;
use sip_parser::uri::{name_addr, param};
use sip_parser::util::split_once;
use sip_parser::{HdrFlags, HdrKind, parse_uri};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

/// Per-message `$var(x)` values.
#[derive(Default)]
pub struct Vars(pub HashMap<String, Val>);

/// State that belongs to the *transaction* (Kamailio AVPs/XAVPs/flags): tm
/// stores it with the transaction and restores it in failure/reply routes.
#[derive(Clone, Default, Debug)]
pub struct TxnVars {
    /// name → values, most recent last.
    pub avps: HashMap<String, Vec<Val>>,
    /// name → items (most recent first), each a field map.
    pub xavps: HashMap<String, Vec<HashMap<String, Val>>>,
    /// Message flags (`setflag(n)`).
    pub flags: u64,
    /// Branch flags of the R-URI branch (`setbflag(n)`); registrar stores
    /// them with a contact (e.g. nathelper's `nat_bflag`) and restores them
    /// on `lookup()`.
    pub bflags: u32,
}

fn shv() -> &'static ShardedMap<String, Val> {
    static SHV: OnceLock<ShardedMap<String, Val>> = OnceLock::new();
    SHV.get_or_init(|| ShardedMap::new(64))
}

fn header_body(ctx: &mut Ctx<'_, '_>, kind: HdrKind) -> Option<Vec<u8>> {
    #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
    let _ = ctx.msg.parse_headers(HdrFlags::of(kind));
    ctx.msg.get(kind).map(|h| h.body.to_vec())
}

/// (uri, display name, tag) of a From/To-style header.
fn nameaddr_parts(body: &[u8]) -> (Vec<u8>, Vec<u8>, Option<Vec<u8>>) {
    let (uri, params) = name_addr(body);
    // The display name is what precedes `<` (none without one).
    let display = split_once(body, b'<').map_or(&b""[..], |(display, _)| display);
    (uri.to_vec(), display_name(display), param(params, b"tag").map(<[u8]>::to_vec))
}

/// The display name as text: a quoted-string loses its quotes and its
/// escapes (`"Jo \"B\" O\\B"` gives `Jo "B" O\B`, RFC 3261 §25.1); a token
/// sequence is kept as written.
fn display_name(raw: &[u8]) -> Vec<u8> {
    let t = raw.trim_ascii();
    let Some(inner) = t.strip_prefix(b"\"").and_then(|x| x.strip_suffix(b"\"")).filter(|_| t.len() >= 2) else { return t.to_vec() };
    let mut out = Vec::with_capacity(inner.len());
    let mut it = inner.iter();
    while let Some(&c) = it.next() {
        if c == b'\\' {
            if let Some(&n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod display_tests {
    use super::display_name;

    #[test]
    fn quoted_display_names_are_unescaped() {
        assert_eq!(display_name(br#" "Jo \"The Boss\" O\\Brien" "#), br#"Jo "The Boss" O\Brien"#.to_vec());
        assert_eq!(display_name(br#""Bob \"B\"""#), br#"Bob "B""#.to_vec());
        assert_eq!(display_name(b"Alice Smith "), b"Alice Smith".to_vec());
        assert_eq!(display_name(br#""""#), b"".to_vec());
        assert_eq!(display_name(b""), b"".to_vec());
    }
}

/// A digest credentials field (`$au $ar $adu $ad $aU $aa $adn $adc $adr $ado`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AuthField {
    User,
    Realm,
    Uri,
    Domain,
    Whole,
    Alg,
    Nonce,
    Cnonce,
    Response,
    Opaque,
}

/// One field of the `Digest` credentials (quotes removed): `username` is
/// split at '@' into user and domain, as Kamailio's digest parser does.
fn digest_field(body: &[u8], field: AuthField) -> Option<Vec<u8>> {
    let (scheme, params) = body.trim_ascii().split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case(b"Digest ") {
        return None;
    }
    let key: &[u8] = match field {
        AuthField::User | AuthField::Domain | AuthField::Whole => b"username",
        AuthField::Realm => b"realm",
        AuthField::Uri => b"uri",
        AuthField::Alg => b"algorithm",
        AuthField::Nonce => b"nonce",
        AuthField::Cnonce => b"cnonce",
        AuthField::Response => b"response",
        AuthField::Opaque => b"opaque",
    };
    let mut val: &[u8] = b"";
    for p in sip_parser::uri::split_list(params) {
        let Some((k, v)) = split_once(p, b'=') else { continue };
        if k.trim_ascii().eq_ignore_ascii_case(key) {
            let v = v.trim_ascii();
            val = v.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\"")).unwrap_or(v);
            break;
        }
    }
    Some(match (field, split_once(val, b'@')) {
        (AuthField::User, Some((user, _))) => user.to_vec(),
        (AuthField::Domain, Some((_, domain))) => domain.to_vec(),
        (AuthField::Domain, None) => Vec::new(),
        _ => val.to_vec(),
    })
}

/// Kamailio's `pv_get_authattr()` (pv_core.c): from the first
/// Proxy-Authorization header, else the first Authorization; null for
/// ACK / CANCEL, without credentials, or for an empty `$adu`.
fn auth_attr(c: &mut Ctx<'_, '_>, field: AuthField) -> Val {
    if matches!(c.msg.method(), Some(sip_parser::Method::Ack | sip_parser::Method::Cancel)) || c.msg.parse_headers(HdrFlags::EOH).is_err() {
        return Val::Null;
    }
    let find = |name: &[u8]| c.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.body);
    let Some(body) = find(b"Proxy-Authorization").or_else(|| find(b"Authorization")) else { return Val::Null };
    match digest_field(body, field) {
        Some(v) if field == AuthField::Uri && v.is_empty() => Val::Null,
        Some(v) => Val::str(v),
        None => Val::Null,
    }
}

#[cfg(test)]
mod auth_attr_tests {
    use super::{AuthField, digest_field};

    #[test]
    fn digest_fields() {
        let b = br#"Digest username="alice@ex.com", realm="ex.com", nonce="n1", uri="sip:ex.com", response="r", opaque="o,p", cnonce="c", nc=00000001, qop=auth, algorithm=SHA-256"#;
        let f = |x| digest_field(b, x).map(|v| String::from_utf8(v).unwrap());
        assert_eq!(f(AuthField::User).as_deref(), Some("alice"));
        assert_eq!(f(AuthField::Domain).as_deref(), Some("ex.com"));
        assert_eq!(f(AuthField::Whole).as_deref(), Some("alice@ex.com"));
        assert_eq!(f(AuthField::Realm).as_deref(), Some("ex.com"));
        assert_eq!(f(AuthField::Opaque).as_deref(), Some("o,p"));
        assert_eq!(f(AuthField::Alg).as_deref(), Some("SHA-256"));
        assert_eq!((f(AuthField::Nonce).as_deref(), f(AuthField::Cnonce).as_deref(), f(AuthField::Response).as_deref()), (Some("n1"), Some("c"), Some("r")));
        let b = br#"Digest username="bob", realm="r""#;
        assert_eq!(digest_field(b, AuthField::Domain), Some(vec![]));
        assert_eq!(digest_field(b, AuthField::User), Some(b"bob".to_vec()));
        assert_eq!(digest_field(b, AuthField::Alg), Some(vec![]));
        assert_eq!(digest_field(b"Basic Zm9v", AuthField::User), None);
    }
}

/// Rebuild a SIP URI with one part replaced.
pub fn rebuild_uri(uri: &[u8], user: Option<Option<&str>>, host: Option<&str>, port: Option<Option<u16>>) -> Option<Vec<u8>> {
    let u = parse_uri(uri)?;
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let user = match user {
        Some(x) => x.map(str::to_string),
        None => u.user.map(s),
    };
    let host = host.map_or_else(|| s(u.host), str::to_string);
    let port = port.unwrap_or(u.port);
    let mut out = format!("{}:", s(u.scheme));
    if let Some(us) = user.filter(|x| !x.is_empty()) {
        out.push_str(&us);
        out.push('@');
    }
    out.push_str(&host);
    if let Some(p) = port {
        out.push_str(&format!(":{p}"));
    }
    if !u.params.is_empty() {
        out.push(';');
        out.push_str(&s(u.params));
    }
    Some(out.into_bytes())
}

/// Next hop from a SIP URI (`;transport=`, `sips:`, default ports). Host
/// names are resolved (blocking) — fine for config-time and rare paths.
pub fn dest_from_uri(uri: &[u8]) -> Option<Dest> {
    let u = parse_uri(uri)?;
    let t = u.param(b"transport").map(|t| t.to_ascii_lowercase());
    let proto = match t.as_deref() {
        Some(b"tcp") if u.is_sips() => Proto::Tls,
        Some(b"tcp") => Proto::Tcp,
        Some(b"tls") => Proto::Tls,
        Some(b"ws") if u.is_sips() => Proto::Wss,
        Some(b"ws") => Proto::Ws,
        Some(b"wss") => Proto::Wss,
        _ if u.is_sips() => Proto::Tls,
        _ => Proto::Udp,
    };
    let port = u.port.unwrap_or(if proto.is_tls() { 5061 } else { 5060 });
    let host = std::str::from_utf8(u.host).ok()?.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(Dest::new(proto, SocketAddr::new(ip, port)));
    }
    Dest::parse(&format!("{}:{host}:{port}", proto.via_name().to_ascii_lowercase())).ok()
}

/// `sip:ip:port;transport=x` for a destination.
pub fn dest_to_uri(d: &Dest) -> String {
    let host = match d.addr.ip() {
        IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };
    let scheme = if d.proto == Proto::Tls { "sips" } else { "sip" };
    let mut s = format!("{scheme}:{host}:{}", d.addr.port());
    match d.proto {
        Proto::Udp | Proto::Tls => {}
        p => s.push_str(&format!(";transport={}", p.via_name().to_ascii_lowercase())),
    }
    s
}

fn req_ruri(ctx: &Ctx<'_, '_>) -> Option<Vec<u8>> {
    ctx.msg.is_request().then(|| ctx.ruri().to_vec())
}

fn avp_index(v: &[Val], idx: &Option<PvIdx>) -> Option<usize> {
    match idx {
        None => v.len().checked_sub(1),
        Some(PvIdx::N(n)) if *n >= 0 => usize::try_from(*n).ok().and_then(|n| v.len().checked_sub(n.checked_add(1)?)),
        // negative: from the oldest (`[-1]` is the first value added)
        Some(PvIdx::N(n)) => n.checked_neg().and_then(|n| usize::try_from(n).ok()).map(|n| n.saturating_sub(1)).filter(|&i| i < v.len()),
        Some(PvIdx::All) => None,
    }
}

/// `$xavp(root[idx]=>field)` → (root, index given?, index, field).
#[derive(Clone, Debug)]
struct XavpRef {
    root: String,
    idx: Option<usize>,
    field: Option<String>,
}

/// Most empty `$xavp` items an assignment creates to reach its index.
const MAX_XAVP_GAP: usize = 1024;

fn parse_xavp(p: &str) -> Result<XavpRef, String> {
    let (r, f) = match p.split_once("=>") {
        Some((r, f)) => (r.trim(), Some(f.trim().to_string())),
        None => (p.trim(), None),
    };
    let (root, idx) = match r.split_once('[') {
        Some((n, i)) => (n, Some(i.trim_end_matches(']').trim().parse::<usize>().map_err(|_| format!("bad index in {p:?}"))?)),
        None => (r, None),
    };
    Ok(XavpRef { root: root.to_string(), idx, field: f })
}

/// Kamailio's core R-URI rewriting functions.
enum UriEdit {
    Strip(usize),
    StripTail(usize),
    Prefix(crate::module::DynStr),
    User(crate::module::DynStr),
    Host(crate::module::DynStr),
    Port(crate::module::DynStr),
    HostPort(crate::module::DynStr),
}

fn register_uri_edits(reg: &mut Registry) {
    use crate::module::{Arg, args};
    type Make = fn(&Arg) -> Result<UriEdit, String>;
    let fns: [(&[&str], Make); 7] = [
        (&["strip"], |a| Ok(UriEdit::Strip(usize::try_from(a.int()?).map_err(|_| "expected a count >= 0")?))),
        (&["strip_tail"], |a| Ok(UriEdit::StripTail(usize::try_from(a.int()?).map_err(|_| "expected a count >= 0")?))),
        (&["prefix"], |a| Ok(UriEdit::Prefix(a.dyn_str()?))),
        (&["rewriteuser", "setuser"], |a| Ok(UriEdit::User(a.dyn_str()?))),
        (&["rewritehost", "sethost"], |a| Ok(UriEdit::Host(a.dyn_str()?))),
        (&["rewriteport", "setport"], |a| Ok(UriEdit::Port(a.dyn_str()?))),
        (&["rewritehostport", "sethostport"], |a| Ok(UriEdit::HostPort(a.dyn_str()?))),
    ];
    for (names, make) in fns {
        for &name in names {
            reg.export(
                "core",
                name,
                move |a: &[Arg]| {
                    let [arg] = args(a)?;
                    make(arg)
                },
                |ctx: &mut Ctx, e: &UriEdit| {
                    let Some(cur) = req_ruri(ctx) else { return -1 };
                    let Some(u) = parse_uri(&cur) else { return -1 };
                    let user = String::from_utf8_lossy(u.user.unwrap_or_default()).into_owned();
                    let new = match e {
                        UriEdit::Strip(k) => rebuild_uri(&cur, Some(Some(user.get(*k..).unwrap_or(""))), None, None),
                        UriEdit::StripTail(k) => rebuild_uri(&cur, Some(Some(strip_tail(&user, *k))), None, None),
                        UriEdit::Prefix(p) => rebuild_uri(&cur, Some(Some(&format!("{}{user}", p.eval(ctx)))), None, None),
                        UriEdit::User(v) => {
                            let v = v.eval(ctx).into_owned();
                            rebuild_uri(&cur, Some((!v.is_empty()).then_some(v.as_str())), None, None)
                        }
                        UriEdit::Host(v) => rebuild_uri(&cur, None, Some(&v.eval(ctx)), None),
                        UriEdit::Port(v) => {
                            let v = v.eval(ctx).into_owned();
                            let port = if v.is_empty() {
                                None
                            } else {
                                match v.parse() {
                                    Ok(p) => Some(p),
                                    Err(_) => return -1,
                                }
                            };
                            rebuild_uri(&cur, None, None, Some(port))
                        }
                        UriEdit::HostPort(v) => {
                            let v = v.eval(ctx).into_owned();
                            let (h, p) = match v.rsplit_once(':').filter(|(h, _)| !h.ends_with(':')) {
                                Some((h, p)) => match p.parse() {
                                    Ok(p) => (h.to_string(), Some(p)),
                                    Err(_) => return -1,
                                },
                                None => (v, None),
                            };
                            rebuild_uri(&cur, None, Some(&h), Some(p))
                        }
                    };
                    match new {
                        Some(n) => {
                            ctx.new_ruri = Some(n);
                            1
                        }
                        None => -1,
                    }
                },
            );
        }
    }
}

/// `s` without its last `k` bytes; a character cut in two goes as a whole
/// (the user part may hold any UTF-8 a peer sent).
fn strip_tail(s: &str, k: usize) -> &str {
    s.get(..s.floor_char_boundary(s.len().saturating_sub(k))).unwrap_or_default()
}

/// A parsed Kamailio select.
enum Select {
    /// `cfg_get.group.name`
    Cfg(String),
    /// `via[n]` (1-based; `via` alone is the first)
    Via(usize),
    /// Same value as a variable (`to.tag` = `$tt`, `ruri.host` = `$rd`, …).
    Pv(crate::pv::PvRef),
}

fn parse_select(name: &str, t: &crate::pv::PvTable) -> Result<Select, String> {
    if let Some(n) = name.strip_prefix("cfg_get.") {
        return if crate::cfgvars::exists(n) {
            Ok(Select::Cfg(n.to_string()))
        } else {
            Err(format!("no config variable {n} (declare it: {n} = \"…\" desc \"…\")"))
        };
    }
    if name == "via" || name == "via[1]" {
        return Ok(Select::Via(1));
    }
    if let Some(n) = name.strip_prefix("via[").and_then(|r| r.strip_suffix(']')) {
        return n.parse().ok().filter(|&n| n > 0).map(Select::Via).ok_or_else(|| format!("@{name}: bad index"));
    }
    let pv = match name {
        "ruri" | "ruri.uri" => "$ru",
        "ruri.user" => "$rU",
        "ruri.host" => "$rd",
        "ruri.port" => "$rp",
        "from" | "from.uri" => "$fu",
        "from.uri.user" | "from.user" => "$fU",
        "from.uri.host" | "from.host" => "$fd",
        "from.tag" => "$ft",
        "from.name" => "$fn",
        "to" | "to.uri" => "$tu",
        "to.uri.user" | "to.user" => "$tU",
        "to.uri.host" | "to.host" => "$td",
        "to.tag" => "$tt",
        "to.name" => "$tn",
        "call_id" | "callid" => "$ci",
        "method" => "$rm",
        "src.ip" => "$si",
        "src.port" => "$sp",
        "dst.ip" => "$Ri",
        "dst.port" => "$Rp",
        "msg.len" => "$ml",
        "contact.uri" => "$ct",
        _ => return Err(format!("unsupported select @{name} (use the matching $variable)")),
    };
    Ok(Select::Pv(crate::pv::parse_pv(pv, t)?))
}

pub(crate) fn register(reg: &mut Registry) {
    register_uri_edits(reg);
    let ro = |reg: &mut Registry, name: &str, f: fn(&mut Ctx<'_, '_>) -> Val| reg.pv(name, PvSpec::ro(move |c, _| f(c)));
    let uri_part = |c: &mut Ctx<'_, '_>, which: u8| -> Val {
        let Some(r) = req_ruri(c) else { return Val::Null };
        let Some(u) = parse_uri(&r) else { return Val::Null };
        match which {
            b'U' => Val::opt(u.user),
            b'd' => Val::str(u.host),
            b'p' => u.port.map_or(Val::Null, |p| Val::Int(i64::from(p))),
            _ => Val::str(u.scheme),
        }
    };
    // --- Request-URI and destination -----------------------------------
    reg.pv(
        "ru",
        PvSpec::rw(
            |c, _| Val::opt(req_ruri(c)),
            |c, _, v| {
                c.new_ruri = (!v.is_null()).then(|| v.as_str().as_bytes().to_vec());
                Ok(())
            },
        ),
    );
    for (name, which) in [("rU", b'U'), ("rd", b'd'), ("rp", b'p'), ("rz", b'z')] {
        reg.pv(
            name,
            PvSpec::rw(
                move |c, _| uri_part(c, which),
                move |c, _, v| {
                    let cur = req_ruri(c).ok_or("not a request")?;
                    let s = v.as_str().into_owned();
                    let new = match which {
                        b'U' => rebuild_uri(&cur, Some((!v.is_null()).then_some(s.as_str())), None, None),
                        b'd' => rebuild_uri(&cur, None, Some(&s), None),
                        b'p' => rebuild_uri(&cur, None, None, Some(v.as_int().and_then(|p| u16::try_from(p).ok()))),
                        _ => return Err("$rz is read-only".into()),
                    };
                    c.new_ruri = Some(new.ok_or("bad R-URI")?);
                    Ok(())
                },
            ),
        );
    }
    reg.pv(
        "du",
        PvSpec::rw(
            |c, _| c.dst.as_ref().map_or(Val::Null, |d| Val::Str(dest_to_uri(d))),
            |c, _, v| {
                c.dst = if v.is_null() { None } else { Some(dest_from_uri(v.as_str().as_bytes()).ok_or("bad destination URI")?) };
                Ok(())
            },
        ),
    );
    // --- From / To ------------------------------------------------------
    for (pfx, kind) in [("f", HdrKind::From), ("t", HdrKind::To)] {
        for (sfx, part) in [("u", 0u8), ("U", 1), ("d", 2), ("n", 3), ("t", 4)] {
            reg.pv(
                &format!("{pfx}{sfx}"),
                PvSpec::ro(move |c, _| {
                    let Some(b) = header_body(c, kind) else { return Val::Null };
                    let (uri, name, tag) = nameaddr_parts(&b);
                    match part {
                        0 => Val::str(uri),
                        1 => Val::opt(parse_uri(&uri).and_then(|u| u.user)),
                        2 => Val::opt(parse_uri(&uri).map(|u| u.host)),
                        3 => Val::str(name),
                        _ => Val::opt(tag),
                    }
                }),
            );
        }
    }
    // --- Headers and message ---------------------------------------------
    ro(reg, "ci", |c| Val::opt(header_body(c, HdrKind::CallId)));
    ro(reg, "cs", |c| {
        header_body(c, HdrKind::CSeq)
            .and_then(|b| String::from_utf8_lossy(&b).split_whitespace().next().and_then(|n| n.parse().ok()))
            .map_or(Val::Null, Val::Int)
    });
    ro(reg, "rm", |c| match c.msg.first {
        sip_parser::FirstLine::Request { method_raw, .. } => Val::str(method_raw),
        _ => header_body(c, HdrKind::CSeq).map_or(Val::Null, |b| Val::str(String::from_utf8_lossy(&b).split_whitespace().nth(1).unwrap_or(""))),
    });
    ro(reg, "rs", |c| c.msg.status().map_or(Val::Null, |s| Val::Int(i64::from(s))));
    ro(reg, "rr", |c| match c.msg.first {
        sip_parser::FirstLine::Response { reason, .. } => Val::str(reason),
        _ => Val::Null,
    });
    ro(reg, "ua", |c| Val::opt(header_body(c, HdrKind::UserAgent)));
    ro(reg, "ct", |c| Val::opt(header_body(c, HdrKind::Contact)));
    ro(reg, "cT", |c| {
        #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
        let _ = c.msg.parse_headers(HdrFlags::EOH);
        Val::opt(c.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"content-type") || h.name.eq_ignore_ascii_case(b"c")).map(|h| h.body))
    });
    ro(reg, "rb", |c| {
        #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
        let _ = c.msg.parse_headers(HdrFlags::EOH);
        Val::opt(c.msg.body())
    });
    ro(reg, "ml", |c| Val::count(c.received().len()));
    ro(reg, "mb", |c| Val::str(c.received()));
    // $sel(…) — Kamailio selects (also written `@to.tag`): the common
    // ones map onto variables; anything else fails at load time.
    reg.pv(
        "sel",
        PvSpec::ro(|c, p| match p.fixed::<Select>() {
            Some(Select::Cfg(n)) => crate::cfgvars::get(n).unwrap_or_default(),
            Some(Select::Via(n)) => {
                #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
                let _ = c.msg.parse_headers(HdrFlags::EOH);
                let vias: Vec<&[u8]> =
                    c.msg.headers.iter().filter(|h| h.kind == HdrKind::Via).flat_map(|h| h.body.split(|&b| b == b',')).map(|v| v.trim_ascii()).collect();
                Val::opt(vias.get(n.saturating_sub(1)).copied())
            }
            Some(Select::Pv(r)) => r.get(c),
            None => Val::Null,
        })
        .with_param()
        .with_fix(|p, t| {
            let sel = parse_select(&p.name, t)?;
            p.fixed = Some(std::sync::Arc::new(sel));
            Ok(())
        }),
    );
    // $msg(len | buf | body | body_len | hdrs | fline): the message as received.
    reg.pv(
        "msg",
        PvSpec::ro(|c, p| {
            #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
            let _ = c.msg.parse_headers(HdrFlags::EOH);
            let buf = c.msg.buf;
            let fline = buf.get(..c.msg.first_line_end).unwrap_or(buf);
            match p.name.as_str() {
                "len" => Val::count(c.received().len()),
                "buf" => Val::str(c.received()),
                "body" => Val::opt(c.msg.body()),
                "body_len" => Val::count(c.msg.body().map_or(0, <[u8]>::len)),
                "fline" => Val::str(fline.strip_suffix(b"\r\n").unwrap_or(fline)),
                "hdrs" => Val::str(buf.get(fline.len()..c.msg.eoh_offset().unwrap_or(buf.len())).unwrap_or_default()),
                _ => Val::Null,
            }
        })
        .with_param(),
    );
    let hdr = |c: &mut Ctx<'_, '_>, p: &PvParam, count: bool| -> Val {
        #[allow(clippy::let_underscore_must_use, reason = "a malformed header is then simply not found")]
        let _ = c.msg.parse_headers(HdrFlags::EOH);
        let name = p.name.as_bytes();
        let kind = sip_parser::kind_of(name);
        let all: Vec<&[u8]> =
            c.msg.headers.iter().filter(|h| if kind == HdrKind::Other { h.name.eq_ignore_ascii_case(name) } else { h.kind == kind }).map(|h| h.body).collect();
        if count {
            return Val::count(all.len());
        }
        match &p.idx {
            Some(PvIdx::All) => {
                if all.is_empty() {
                    Val::Null
                } else {
                    Val::str(all.join(&b", "[..]))
                }
            }
            Some(PvIdx::N(n)) => {
                let i = if *n < 0 { i64::try_from(all.len()).unwrap_or(i64::MAX).saturating_add(*n) } else { *n };
                usize::try_from(i).ok().and_then(|i| all.get(i)).map_or(Val::Null, Val::str)
            }
            None => Val::opt(all.first()),
        }
    };
    reg.pv("hdr", PvSpec::ro(move |c, p| hdr(c, p, false)).with_param());
    reg.pv("hdrc", PvSpec::ro(move |c, p| hdr(c, p, true)).with_param());
    // --- Transport ---------------------------------------------------------
    ro(reg, "si", |c| Val::Str(c.src.addr.ip().to_string()));
    ro(reg, "sp", |c| Val::Int(i64::from(c.src.addr.port())));
    ro(reg, "pr", |c| Val::Str(c.src.proto.via_name().to_ascii_lowercase()));
    ro(reg, "proto", |c| Val::Str(c.src.proto.via_name().to_ascii_lowercase()));
    ro(reg, "af", |c| Val::Str(if c.src.addr.is_ipv4() { "INET" } else { "INET6" }.into()));
    ro(reg, "conid", |c| c.src.conn.and_then(|i| i64::try_from(i).ok()).map_or(Val::Null, Val::Int));
    ro(reg, "Ri", |c| c.net.advertise(c.src.proto).map_or(Val::Null, |a| Val::Str(a.ip().to_string())));
    ro(reg, "Rp", |c| c.net.advertise(c.src.proto).map_or(Val::Null, |a| Val::Int(i64::from(a.port()))));
    // --- Digest credentials (Kamailio pv_get_authattr, pv_core.c) ----------
    for (name, field) in [
        ("au", AuthField::User),
        ("ar", AuthField::Realm),
        ("adu", AuthField::Uri),
        ("ad", AuthField::Domain),
        ("aU", AuthField::Whole),
        ("aa", AuthField::Alg),
        ("adn", AuthField::Nonce),
        ("adc", AuthField::Cnonce),
        ("adr", AuthField::Response),
        ("ado", AuthField::Opaque),
    ] {
        reg.pv(name, PvSpec::ro(move |c, _| auth_attr(c, field)));
    }
    // --- Misc --------------------------------------------------------------
    ro(reg, "null", |_| Val::Null);
    ro(reg, "rc", |c| Val::Int(i64::from(c.rc)));
    ro(reg, "retcode", |c| Val::Int(i64::from(c.rc)));
    ro(reg, "Ts", |_| {
        Val::Int(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)))
    });
    ro(reg, "RANDOM", |_| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u128(std::time::Instant::now().elapsed().as_nanos());
        // 31 random bits, like Kamailio's rand(): always fits and is non-negative.
        Val::Int(i64::from(u32::try_from(h.finish() >> 33).unwrap_or(0)))
    });
    ro(reg, "pp", |_| Val::Int(i64::from(std::process::id())));
    reg.pv("env", PvSpec::ro(|_, p| std::env::var(&p.name).map_or(Val::Null, Val::Str)).with_param());
    // --- Storage -----------------------------------------------------------
    reg.pv(
        "var",
        PvSpec::rw(
            |c, p| c.ext::<Vars>().and_then(|v| v.0.get(&p.name)).cloned().unwrap_or_default(),
            |c, p, v| {
                let vars = &mut c.ext_mut::<Vars>().0;
                if v.is_null() {
                    vars.remove(&p.name);
                } else {
                    vars.insert(p.name.clone(), v);
                }
                Ok(())
            },
        )
        .with_param(),
    );
    reg.pv(
        "avp",
        PvSpec::rw(
            |c, p| {
                let Some(v) = c.ext::<TxnVars>().and_then(|t| t.avps.get(&p.name)) else { return Val::Null };
                if p.idx == Some(PvIdx::All) {
                    return Val::Str(v.iter().rev().map(|x| x.as_str().into_owned()).collect::<Vec<_>>().join(","));
                }
                avp_index(v, &p.idx).and_then(|i| v.get(i)).cloned().unwrap_or_default()
            },
            |c, p, v| {
                let list = c.ext_mut::<TxnVars>().avps.entry(p.name.clone()).or_default();
                match (&p.idx, v.is_null()) {
                    (Some(PvIdx::All), true) => list.clear(),
                    (Some(PvIdx::All), false) => *list = vec![v],
                    (None, false) => list.push(v),
                    (idx, null) => {
                        if let Some(i) = avp_index(list, idx).filter(|&i| i < list.len()) {
                            if null {
                                list.remove(i);
                            } else if let Some(slot) = list.get_mut(i) {
                                *slot = v;
                            }
                        }
                    }
                }
                Ok(())
            },
        )
        .with_param(),
    );
    reg.pv(
        "xavp",
        PvSpec::rw(
            |c, p| {
                let Some(x) = p.fixed::<XavpRef>() else { return Val::Null };
                let Some(items) = c.ext::<TxnVars>().and_then(|t| t.xavps.get(&x.root)) else { return Val::Null };
                let Some(item) = items.get(x.idx.unwrap_or(0)) else { return Val::Null };
                match &x.field {
                    Some(f) => item.get(f).cloned().unwrap_or_default(),
                    None => Val::count(items.len()),
                }
            },
            |c, p, v| {
                let Some(x) = p.fixed::<XavpRef>().cloned() else { return Err("$xavp: unparsed name".into()) };
                let items = c.ext_mut::<TxnVars>().xavps.entry(x.root.clone()).or_default();
                match (x.idx, x.field) {
                    (None, None) if v.is_null() => items.clear(),
                    (Some(i), None) if v.is_null() => {
                        if i < items.len() {
                            items.remove(i);
                        }
                    }
                    // No index: a new item at the front (Kamailio semantics).
                    (None, Some(f)) => {
                        let mut m = HashMap::new();
                        m.insert(f, v);
                        items.insert(0, m);
                    }
                    (Some(i), Some(f)) => {
                        // Empty items fill the gap up to `i`, but not an
                        // absurd one: the index comes from the script.
                        if i.saturating_sub(items.len()) > MAX_XAVP_GAP {
                            return Err(format!("$xavp({}[{i}]): index too far past the end", x.root));
                        }
                        if items.len() <= i {
                            items.resize_with(i.saturating_add(1), HashMap::new);
                        }
                        let Some(item) = items.get_mut(i) else { return Err("$xavp: index out of range".into()) };
                        if v.is_null() {
                            item.remove(&f);
                        } else {
                            item.insert(f, v);
                        }
                    }
                    _ => return Err("$xavp(root) can only be assigned $null".into()),
                }
                Ok(())
            },
        )
        .with_param()
        .with_fix(|p, _| {
            p.fixed = Some(std::sync::Arc::new(parse_xavp(&p.name)?));
            Ok(())
        }),
    );
    reg.pv(
        "shv",
        PvSpec::rw(
            |_, p| shv().get_cloned(p.name.as_str()).unwrap_or_default(),
            |_, p, v| {
                if v.is_null() {
                    shv().remove(p.name.as_str());
                } else {
                    shv().insert(p.name.clone(), v);
                }
                Ok(())
            },
        )
        .with_param(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_rebuild() {
        let u = b"sip:alice@example.com:5070;transport=tcp";
        assert_eq!(rebuild_uri(u, Some(Some("bob")), None, None).unwrap(), b"sip:bob@example.com:5070;transport=tcp");
        assert_eq!(rebuild_uri(u, None, Some("10.0.0.1"), Some(None)).unwrap(), b"sip:alice@10.0.0.1;transport=tcp");
        assert_eq!(rebuild_uri(b"sip:x", Some(Some("u")), None, None).unwrap(), b"sip:u@x");
    }

    #[test]
    fn dest_roundtrip() {
        let d = dest_from_uri(b"sip:10.0.0.1:5080;transport=tcp").unwrap();
        assert_eq!((d.proto, d.addr.to_string()), (Proto::Tcp, "10.0.0.1:5080".to_string()));
        assert_eq!(dest_to_uri(&d), "sip:10.0.0.1:5080;transport=tcp");
        assert_eq!(dest_from_uri(b"sips:10.0.0.1").unwrap().addr.port(), 5061);
    }

    /// strip_tail() on an R-URI whose user part has a multi-byte character
    /// removes whole characters, never slicing inside one.
    #[test]
    fn strip_tail_inside_a_multibyte_user() {
        struct NoNet;
        impl crate::net::Outbound for NoNet {
            fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
            fn advertise(&self, _: Proto) -> Option<SocketAddr> {
                None
            }
        }
        let mut reg = Registry::default();
        register_uri_edits(&mut reg);
        let f = reg.get("strip_tail").unwrap();
        let req = "OPTIONS sip:ab\u{e9}@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKd\r\nFrom: <sip:b@x>;tag=1\r\n\
To: <sip:a@x>\r\nCall-ID: d\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let arena = bumpalo::Bump::new();
        let mut m = sip_parser::Msg::parse(req.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (crate::lumps::Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        let one = (f.fixup)(&[crate::module::Arg::Int(1)]).unwrap();
        assert_eq!((f.func)(&mut ctx, one.as_ref()), 1);
        assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:ab@x"[..]));
        assert_eq!(strip_tail("ab\u{e9}", 3), "a");
        assert_eq!(strip_tail("ab", 5), "");
    }

    /// `$xavp(r[huge]=>f) = …` is refused instead of pushing empty items without end.
    #[test]
    fn xavp_index_far_past_the_end() {
        struct NoNet;
        impl crate::net::Outbound for NoNet {
            fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
            fn advertise(&self, _: Proto) -> Option<SocketAddr> {
                None
            }
        }
        let mut reg = Registry::default();
        register(&mut reg);
        let req = "OPTIONS sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKd\r\n\r\n";
        let arena = bumpalo::Bump::new();
        let mut m = sip_parser::Msg::parse(req.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (crate::lumps::Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &NoNet, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        let pv = |s: &str| crate::pv::parse_pv(s, reg.pvs()).unwrap();
        assert!(pv("$xavp(r[2]=>f)").set(&mut ctx, Val::count(7)).is_ok());
        assert_eq!(pv("$xavp(r)").get(&mut ctx), Val::count(3), "two empty items fill the gap");
        assert!(pv("$xavp(r[9223372036854775807]=>f)").set(&mut ctx, Val::count(1)).is_err());
        assert_eq!(pv("$xavp(r)").get(&mut ctx), Val::count(3));
    }

    #[test]
    fn xavp_paths() {
        let x = parse_xavp("caller[1]=>name").unwrap();
        assert_eq!((x.root.as_str(), x.idx, x.field.as_deref()), ("caller", Some(1), Some("name")));
        assert!(parse_xavp("r[x]=>y").is_err());
    }
}

#[cfg(test)]
mod pv_tests {
    use super::*;
    use crate::lumps::Lumps;
    use crate::module::Arg;
    use crate::pv::{PvRef, parse_pv};

    struct Net;
    impl crate::net::Outbound for Net {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            Some(SocketAddr::from(([192, 0, 2, 7], 5062)))
        }
    }

    const INVITE: &str = "INVITE sip:alice@example.com:5070;transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK2\r\n\
Via: SIP/2.0/TCP 10.0.0.3;branch=z9hG4bK3\r\n\
From: \"Bob \\\"B\\\"\" <sip:bob@example.org>;tag=ft1\r\n\
To: sip:alice@example.com\r\n\
Call-ID: cid-1@host\r\n\
CSeq: 42 INVITE\r\n\
X-A: one\r\n\
x-a: two\r\n\
X-A: three\r\n\
Contact: <sip:bob@10.0.0.1:5060>\r\n\
User-Agent: tester\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\r\nabcd";

    const REPLY: &str = "SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\n\
From: <sip:a@b>;tag=1\r\nTo: \"Carol\" <sip:c@d>;tag=2\r\nCall-ID: x\r\nCSeq: 7 INVITE\r\nContent-Length: 0\r\n\r\n";

    fn udp_src() -> Dest {
        Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 5060)))
    }

    /// Runs `f` with a context for `raw` and a resolver for variable names.
    fn with_msg(raw: &str, src: Dest, f: impl FnOnce(&mut Ctx<'_, '_>, &dyn Fn(&str) -> PvRef)) {
        let mut reg = Registry::default();
        register(&mut reg);
        let arena = bumpalo::Bump::new();
        let mut m = sip_parser::Msg::parse(raw.as_bytes(), &arena).unwrap();
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut m, &mut lumps, &mut out, &Net, None, src, 0);
        let pv = |s: &str| parse_pv(s, reg.pvs()).unwrap_or_else(|e| panic!("{s}: {e}"));
        f(&mut ctx, &pv);
    }

    fn s(v: &str) -> Val {
        Val::Str(v.into())
    }

    #[test]
    fn request_fields_read_from_the_message() {
        with_msg(INVITE, udp_src(), |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$ru", s("sip:alice@example.com:5070;transport=tcp")),
                ("$rU", s("alice")),
                ("$rd", s("example.com")),
                ("$rp", Val::Int(5070)),
                ("$rz", s("sip")),
                ("$fu", s("sip:bob@example.org")),
                ("$fU", s("bob")),
                ("$fd", s("example.org")),
                ("$fn", s("Bob \"B\"")),
                ("$ft", s("ft1")),
                ("$tu", s("sip:alice@example.com")),
                ("$tU", s("alice")),
                ("$td", s("example.com")),
                ("$tn", s("")),
                ("$tt", Val::Null),
                ("$ci", s("cid-1@host")),
                ("$cs", Val::Int(42)),
                ("$rm", s("INVITE")),
                ("$rs", Val::Null),
                ("$rr", Val::Null),
                ("$ua", s("tester")),
                ("$ct", s("<sip:bob@10.0.0.1:5060>")),
                ("$cT", s("application/sdp")),
                ("$rb", s("abcd")),
                ("$ml", Val::count(INVITE.len())),
                ("$msg(len)", Val::count(INVITE.len())),
                ("$msg(body)", s("abcd")),
                ("$msg(body_len)", Val::Int(4)),
                ("$msg(fline)", s("INVITE sip:alice@example.com:5070;transport=tcp SIP/2.0")),
                ("$msg(nope)", Val::Null),
                ("$du", Val::Null),
                ("$null", Val::Null),
                ("$rc", Val::Int(1)),
                ("$retcode", Val::Int(1)),
                ("$au", Val::Null),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
            let hdrs = pv("$msg(hdrs)").get(c).as_str().into_owned();
            assert!(
                hdrs.starts_with("Via: ")
                    && hdrs.ends_with(
                        "X-A: three\r\nContact: <sip:bob@10.0.0.1:5060>\r\nUser-Agent: tester\r\nContent-Type: application/sdp\r\nContent-Length: 4\r\n"
                    ),
                "{hdrs:?}"
            );
        });
    }

    #[test]
    fn hdr_indexes_count_from_either_end() {
        with_msg(INVITE, udp_src(), |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$hdr(X-A)", s("one")),
                ("$hdr(x-a)[0]", s("one")),
                ("$hdr(X-A)[1]", s("two")),
                ("$hdr(X-A)[2]", s("three")),
                ("$hdr(X-A)[3]", Val::Null),
                ("$hdr(X-A)[-1]", s("three")),
                ("$hdr(X-A)[-3]", s("one")),
                ("$hdr(X-A)[-4]", Val::Null),
                ("$hdr(X-A)[*]", s("one, two, three")),
                ("$hdr(X-B)[*]", Val::Null),
                ("$hdr(X-B)", Val::Null),
                ("$hdrc(X-A)", Val::Int(3)),
                ("$hdrc(X-B)", Val::Int(0)),
                ("$hdrc(Via)", Val::Int(2)),
                ("$hdr(Via)[1]", s("SIP/2.0/TCP 10.0.0.3;branch=z9hG4bK3")),
                ("$hdr(call-id)", s("cid-1@host")),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
        });
    }

    #[test]
    fn selects_map_onto_variables_and_vias() {
        with_msg(INVITE, udp_src(), |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$sel(via)", s("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1")),
                ("$sel(via[2])", s("SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK2")),
                ("$sel(via[3])", s("SIP/2.0/TCP 10.0.0.3;branch=z9hG4bK3")),
                ("$sel(via[4])", Val::Null),
                ("$sel(ruri.user)", s("alice")),
                ("$sel(from.tag)", s("ft1")),
                ("$sel(call_id)", s("cid-1@host")),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
        });
        let mut reg = Registry::default();
        register(&mut reg);
        for bad in ["$sel(via[0])", "$sel(via[x])", "$sel(foo.bar)"] {
            assert!(parse_pv(bad, reg.pvs()).is_err(), "{bad}");
        }
    }

    #[test]
    fn transport_variables_for_an_ipv6_stream_source() {
        let mut src = Dest::new(Proto::Tcp, "[2001:db8::5]:5070".parse().unwrap());
        src.conn = Some(9);
        with_msg(INVITE, src, |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$si", s("2001:db8::5")),
                ("$sp", Val::Int(5070)),
                ("$pr", s("tcp")),
                ("$proto", s("tcp")),
                ("$af", s("INET6")),
                ("$conid", Val::Int(9)),
                ("$Ri", s("192.0.2.7")),
                ("$Rp", Val::Int(5062)),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
        });
        with_msg(INVITE, udp_src(), |c, pv| {
            assert_eq!(pv("$af").get(c), s("INET"));
            assert_eq!(pv("$conid").get(c), Val::Null);
        });
    }

    #[test]
    fn reply_fields_and_request_only_variables() {
        with_msg(REPLY, udp_src(), |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$rs", Val::Int(486)),
                ("$rr", s("Busy Here")),
                ("$rm", s("INVITE")),
                ("$cs", Val::Int(7)),
                ("$ru", Val::Null),
                ("$rU", Val::Null),
                ("$rd", Val::Null),
                ("$rp", Val::Null),
                ("$tt", s("2")),
                ("$tn", s("Carol")),
                ("$ft", s("1")),
                ("$rb", s("")),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
            assert!(pv("$rU").set(c, s("x")).is_err(), "no R-URI in a reply");
            assert!(pv("$rd").set(c, s("x")).is_err());
            assert!(pv("$ci").set(c, s("x")).is_err(), "read-only");
        });
    }

    #[test]
    fn ruri_part_setters_rebuild_the_uri() {
        with_msg(INVITE, udp_src(), |c, pv| {
            let steps: &[(&str, Val, &str)] = &[
                ("$rU", s("bob"), "sip:bob@example.com:5070;transport=tcp"),
                ("$rd", s("10.1.1.1"), "sip:bob@10.1.1.1:5070;transport=tcp"),
                ("$rp", Val::Int(5080), "sip:bob@10.1.1.1:5080;transport=tcp"),
                ("$rp", s("5090"), "sip:bob@10.1.1.1:5090;transport=tcp"),
                ("$rp", Val::Null, "sip:bob@10.1.1.1;transport=tcp"),
                ("$rU", Val::Null, "sip:10.1.1.1;transport=tcp"),
                ("$rU", s("carol"), "sip:carol@10.1.1.1;transport=tcp"),
                ("$ru", s("sips:x@y"), "sips:x@y"),
            ];
            for (name, v, want) in steps {
                pv(name).set(c, v.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(String::from_utf8_lossy(c.new_ruri.as_deref().unwrap_or_default()), *want, "after {name} = {v:?}");
                assert_eq!(pv("$ru").get(c), s(want), "$ru reads the rewritten URI");
            }
            assert_eq!(pv("$rz").get(c), s("sips"));
            assert!(pv("$rz").set(c, s("sip")).is_err(), "$rz is read-only");
            assert!(pv("$(rU{s.len})").set(c, s("x")).is_err(), "a variable with transformations is read-only");
            pv("$ru").set(c, Val::Null).unwrap();
            assert_eq!(pv("$rU").get(c), s("alice"), "$ru = $null drops the rewrite");
        });
    }

    #[test]
    fn du_set_get_and_clear() {
        with_msg(INVITE, udp_src(), |c, pv| {
            pv("$du").set(c, s("sip:10.0.0.9:5080;transport=TCP")).unwrap();
            assert_eq!(c.dst, Some(Dest::new(Proto::Tcp, "10.0.0.9:5080".parse().unwrap())));
            assert_eq!(pv("$du").get(c), s("sip:10.0.0.9:5080;transport=tcp"));
            assert!(pv("$du").set(c, s("not a uri")).is_err());
            assert!(c.dst.is_some(), "a failed assignment keeps the old value");
            pv("$du").set(c, Val::Null).unwrap();
            assert_eq!(c.dst, None);
        });
    }

    #[test]
    fn var_set_get_and_null_removes() {
        with_msg(INVITE, udp_src(), |c, pv| {
            assert_eq!(pv("$var(x)").get(c), Val::Null);
            pv("$var(x)").set(c, Val::Int(5)).unwrap();
            pv("$var(y)").set(c, s("")).unwrap();
            assert_eq!((pv("$var(x)").get(c), pv("$var(y)").get(c)), (Val::Int(5), s("")));
            pv("$var(x)").set(c, Val::Null).unwrap();
            assert_eq!(pv("$var(x)").get(c), Val::Null);
            assert!(!c.ext::<Vars>().unwrap().0.contains_key("x"));
        });
    }

    /// `$avp(x)[0]` is the value added last; negative indexes count from the
    /// oldest (`[-1]` is the first value added), as in Kamailio.
    #[test]
    fn avp_indexes_newest_first() {
        with_msg(INVITE, udp_src(), |c, pv| {
            for v in ["a", "b", "c"] {
                pv("$avp(x)").set(c, s(v)).unwrap();
            }
            let cases: &[(&str, Val)] = &[
                ("$avp(x)", s("c")),
                ("$avp(x)[0]", s("c")),
                ("$avp(x)[1]", s("b")),
                ("$avp(x)[2]", s("a")),
                ("$avp(x)[3]", Val::Null),
                ("$avp(x)[-1]", s("a")),
                ("$avp(x)[-2]", s("b")),
                ("$avp(x)[-3]", s("c")),
                ("$avp(x)[-4]", Val::Null),
                ("$avp(x)[*]", s("c,b,a")),
                ("$avp(nope)", Val::Null),
                ("$avp(nope)[*]", Val::Null),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
        });
    }

    #[test]
    fn avp_assignments_by_index() {
        with_msg(INVITE, udp_src(), |c, pv| {
            let all = |c: &mut Ctx<'_, '_>| pv("$avp(x)[*]").get(c);
            for v in ["a", "b", "c"] {
                pv("$avp(x)").set(c, s(v)).unwrap();
            }
            pv("$avp(x)[1]").set(c, s("B")).unwrap();
            assert_eq!(all(c), s("c,B,a"), "[1] replaces the second newest");
            pv("$avp(x)[-1]").set(c, s("A")).unwrap();
            assert_eq!(all(c), s("c,B,A"), "[-1] replaces the oldest");
            pv("$avp(x)[7]").set(c, s("z")).unwrap();
            assert_eq!(all(c), s("c,B,A"), "an index past the end changes nothing");
            pv("$avp(x)[0]").set(c, Val::Null).unwrap();
            assert_eq!(all(c), s("B,A"), "[0] = $null deletes the newest");
            pv("$avp(x)[-1]").set(c, Val::Null).unwrap();
            assert_eq!(all(c), s("B"));
            pv("$avp(x)[*]").set(c, s("only")).unwrap();
            assert_eq!(all(c), s("only"), "[*] = v replaces all");
            pv("$avp(x)").set(c, Val::Int(2)).unwrap();
            assert_eq!(pv("$avp(x)").get(c), Val::Int(2), "integers stay integers");
            pv("$avp(x)[*]").set(c, Val::Null).unwrap();
            assert_eq!(pv("$avp(x)").get(c), Val::Null, "[*] = $null deletes all");
        });
    }

    #[test]
    fn avp_index_table() {
        let v = [Val::Int(0), Val::Int(1), Val::Int(2)]; // oldest first
        let cases: &[(Option<PvIdx>, Option<usize>)] = &[
            (None, Some(2)),
            (Some(PvIdx::N(0)), Some(2)),
            (Some(PvIdx::N(2)), Some(0)),
            (Some(PvIdx::N(3)), None),
            (Some(PvIdx::N(-1)), Some(0)),
            (Some(PvIdx::N(-3)), Some(2)),
            (Some(PvIdx::N(-4)), None),
            (Some(PvIdx::N(i64::MIN)), None),
            (Some(PvIdx::N(i64::MAX)), None),
            (Some(PvIdx::All), None),
        ];
        for (idx, want) in cases {
            assert_eq!(avp_index(&v, idx), *want, "{idx:?}");
        }
        assert_eq!(avp_index(&[], &None), None);
    }

    #[test]
    fn xavp_items_fields_and_deletes() {
        with_msg(INVITE, udp_src(), |c, pv| {
            assert_eq!(pv("$xavp(r)").get(c), Val::Null);
            pv("$xavp(r=>a)").set(c, s("1")).unwrap();
            pv("$xavp(r[0]=>b)").set(c, s("2")).unwrap();
            assert_eq!((pv("$xavp(r=>a)").get(c), pv("$xavp(r=>b)").get(c)), (s("1"), s("2")), "[0]=> adds to the first item");
            pv("$xavp(r=>a)").set(c, s("new")).unwrap();
            assert_eq!(pv("$xavp(r)").get(c), Val::Int(2), "no index: a new item in front");
            assert_eq!(pv("$xavp(r=>a)").get(c), s("new"));
            assert_eq!(pv("$xavp(r=>b)").get(c), Val::Null, "the new item has only a");
            assert_eq!(pv("$xavp(r[1]=>a)").get(c), s("1"));
            assert_eq!(pv("$xavp(r[1]=>b)").get(c), s("2"));
            assert_eq!(pv("$xavp(r[2]=>a)").get(c), Val::Null);
            pv("$xavp(r[1]=>b)").set(c, Val::Null).unwrap();
            assert_eq!(pv("$xavp(r[1]=>b)").get(c), Val::Null, "=> $null removes the field");
            assert!(pv("$xavp(r)").set(c, s("x")).is_err(), "only $null can be assigned to the root");
            pv("$xavp(r[0])").set(c, Val::Null).unwrap();
            assert_eq!((pv("$xavp(r)").get(c), pv("$xavp(r=>a)").get(c)), (Val::Int(1), s("1")), "[0] = $null removes the first item");
            pv("$xavp(r[5])").set(c, Val::Null).unwrap();
            assert_eq!(pv("$xavp(r)").get(c), Val::Int(1), "deleting past the end is a no-op");
            pv("$xavp(r)").set(c, Val::Null).unwrap();
            assert_eq!(pv("$xavp(r=>a)").get(c), Val::Null, "root = $null clears it");
            assert_eq!(pv("$xavp( s [ 0 ] => f )").get(c), Val::Null);
        });
    }

    #[test]
    fn digest_credentials_prefer_proxy_authorization() {
        let req = "INVITE sip:a@x SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1;branch=z9hG4bK1\r\nFrom: <sip:b@x>;tag=1\r\nTo: <sip:a@x>\r\n\
Call-ID: c\r\nCSeq: 1 INVITE\r\nAuthorization: Digest username=\"wrong\", realm=\"w\"\r\n\
Proxy-Authorization: Digest username=\"alice@ex.com\", realm=\"ex.com\", uri=\"\", nonce=\"n\"\r\nContent-Length: 0\r\n\r\n";
        with_msg(req, udp_src(), |c, pv| {
            let cases: &[(&str, Val)] = &[
                ("$au", s("alice")),
                ("$ad", s("ex.com")),
                ("$aU", s("alice@ex.com")),
                ("$ar", s("ex.com")),
                ("$adn", s("n")),
                ("$adu", Val::Null),
                ("$ado", s("")),
            ];
            for (name, want) in cases {
                assert_eq!(&pv(name).get(c), want, "{name}");
            }
        });
        let ack = req.replace("INVITE", "ACK");
        with_msg(&ack, udp_src(), |c, pv| assert_eq!(pv("$au").get(c), Val::Null, "never for ACK"));
    }

    fn call(c: &mut Ctx<'_, '_>, name: &str, arg: Arg) -> i32 {
        let mut reg = Registry::default();
        register(&mut reg);
        let f = reg.get(name).unwrap_or_else(|| panic!("{name}"));
        let fixed = (f.fixup)(&[arg]).unwrap_or_else(|e| panic!("{name}: {e}"));
        (f.func)(c, fixed.as_ref())
    }

    #[test]
    fn uri_edit_functions() {
        let s = |v: &str| Arg::Str(v.into());
        let cases: &[(&str, Arg, i32, &str)] = &[
            ("strip", Arg::Int(2), 1, "sip:ice@example.com:5070;transport=tcp"),
            ("strip", Arg::Int(99), 1, "sip:example.com:5070;transport=tcp"),
            ("strip_tail", Arg::Int(2), 1, "sip:ali@example.com:5070;transport=tcp"),
            ("prefix", s("+49"), 1, "sip:+49alice@example.com:5070;transport=tcp"),
            ("rewriteuser", s("bob"), 1, "sip:bob@example.com:5070;transport=tcp"),
            ("setuser", s(""), 1, "sip:example.com:5070;transport=tcp"),
            ("rewritehost", s("h.test"), 1, "sip:alice@h.test:5070;transport=tcp"),
            ("rewriteport", s("5099"), 1, "sip:alice@example.com:5099;transport=tcp"),
            ("setport", s(""), 1, "sip:alice@example.com;transport=tcp"),
            ("rewriteport", s("abc"), -1, ""),
            ("rewriteport", s("70000"), -1, ""),
            ("rewritehostport", s("h.test:5080"), 1, "sip:alice@h.test:5080;transport=tcp"),
            ("sethostport", s("h.test"), 1, "sip:alice@h.test;transport=tcp"),
            ("rewritehostport", s("[2001:db8::1]:5080"), 1, "sip:alice@[2001:db8::1]:5080;transport=tcp"),
            ("rewritehostport", s("[2001:db8::1]"), 1, "sip:alice@[2001:db8::1];transport=tcp"),
            ("rewritehostport", s("h.test:x"), -1, ""),
        ];
        for (name, arg, rc, want) in cases {
            with_msg(INVITE, udp_src(), |c, _| {
                assert_eq!(call(c, name, arg.clone()), *rc, "{name}({arg:?})");
                if *rc > 0 {
                    assert_eq!(String::from_utf8_lossy(c.new_ruri.as_deref().unwrap_or_default()), *want, "{name}({arg:?})");
                } else {
                    assert_eq!(c.new_ruri, None, "{name}({arg:?}) leaves the R-URI alone");
                }
            });
        }
        with_msg(REPLY, udp_src(), |c, _| assert_eq!(call(c, "rewritehost", s("x")), -1, "no R-URI in a reply"));
        let mut reg = Registry::default();
        register(&mut reg);
        assert!((reg.get("strip").unwrap().fixup)(&[Arg::Int(-1)]).is_err(), "negative count");
    }

    #[test]
    fn rebuild_uri_cases() {
        // (uri, user, host, port, result)
        type Case = (&'static str, Option<Option<&'static str>>, Option<&'static str>, Option<Option<u16>>, Option<&'static str>);
        let cases: &[Case] = &[
            ("sip:a@h", None, None, None, Some("sip:a@h")),
            ("sips:a@h:5061;x=1", Some(None), None, None, Some("sips:h:5061;x=1")),
            ("sip:a@h", Some(Some("")), None, None, Some("sip:h")),
            ("sip:[2001:db8::1]:5070", Some(Some("u")), None, None, Some("sip:u@[2001:db8::1]:5070")),
            ("sip:a@h", None, None, Some(Some(1)), Some("sip:a@h:1")),
            ("sip:a@h:9", None, Some("k"), Some(None), Some("sip:a@k")),
            ("tel:+123", None, None, None, Some("tel:+123")),
            ("garbage", None, None, None, None),
        ];
        for (uri, user, host, port, want) in cases {
            let got = rebuild_uri(uri.as_bytes(), *user, *host, *port).map(|v| String::from_utf8(v).unwrap());
            assert_eq!(got.as_deref(), *want, "{uri} {user:?} {host:?} {port:?}");
        }
    }

    #[test]
    fn dest_from_uri_transport_and_default_port() {
        let cases: &[(&str, Option<(Proto, &str)>)] = &[
            ("sip:10.0.0.1", Some((Proto::Udp, "10.0.0.1:5060"))),
            ("sip:10.0.0.1;transport=TCP", Some((Proto::Tcp, "10.0.0.1:5060"))),
            ("sip:10.0.0.1;transport=tls", Some((Proto::Tls, "10.0.0.1:5061"))),
            ("sips:10.0.0.1;transport=tcp", Some((Proto::Tls, "10.0.0.1:5061"))),
            ("sips:10.0.0.1:7000", Some((Proto::Tls, "10.0.0.1:7000"))),
            ("sip:10.0.0.1;transport=ws", Some((Proto::Ws, "10.0.0.1:5060"))),
            ("sips:10.0.0.1;transport=ws", Some((Proto::Wss, "10.0.0.1:5061"))),
            ("sip:10.0.0.1;transport=wss", Some((Proto::Wss, "10.0.0.1:5061"))),
            ("sip:10.0.0.1;transport=sctp", Some((Proto::Udp, "10.0.0.1:5060"))),
            ("sip:u@[2001:db8::1]:5070;transport=tcp", Some((Proto::Tcp, "[2001:db8::1]:5070"))),
            ("sip:[::1]", Some((Proto::Udp, "[::1]:5060"))),
            ("nonsense", None),
        ];
        for (uri, want) in cases {
            let got = dest_from_uri(uri.as_bytes()).map(|d| (d.proto, d.addr.to_string()));
            assert_eq!(got, want.map(|(p, a)| (p, a.to_string())), "{uri}");
        }
    }

    #[test]
    fn dest_to_uri_formats_each_transport() {
        let d = |p, a: &str| Dest::new(p, a.parse().unwrap());
        let cases = [
            (d(Proto::Udp, "10.0.0.1:5060"), "sip:10.0.0.1:5060"),
            (d(Proto::Tcp, "10.0.0.1:5060"), "sip:10.0.0.1:5060;transport=tcp"),
            (d(Proto::Tls, "10.0.0.1:5061"), "sips:10.0.0.1:5061"),
            (d(Proto::Ws, "10.0.0.1:80"), "sip:10.0.0.1:80;transport=ws"),
            (d(Proto::Wss, "10.0.0.1:443"), "sip:10.0.0.1:443;transport=wss"),
            (d(Proto::Udp, "[2001:db8::1]:5060"), "sip:[2001:db8::1]:5060"),
        ];
        for (dest, want) in cases {
            assert_eq!(dest_to_uri(&dest), want);
            assert_eq!(dest_from_uri(want.as_bytes()), Some(dest), "round trip of {want}");
        }
    }

    #[test]
    fn xavp_name_parsing() {
        type Case = (&'static str, Option<(&'static str, Option<usize>, Option<&'static str>)>);
        let cases: &[Case] = &[
            ("r", Some(("r", None, None))),
            ("r=>f", Some(("r", None, Some("f")))),
            ("r[3]", Some(("r", Some(3), None))),
            (" r[ 2 ] => f ", Some(("r", Some(2), Some("f")))),
            ("r[-1]=>f", None),
            ("r[]=>f", None),
        ];
        for (p, want) in cases {
            let got = parse_xavp(p).ok();
            assert_eq!(got.as_ref().map(|x| (x.root.as_str(), x.idx, x.field.as_deref())), *want, "{p:?}");
        }
    }

    #[test]
    fn display_name_and_tag_of_name_addr_forms() {
        let cases: &[(&str, &str, &str, Option<&str>)] = &[
            ("<sip:a@b>;tag=1", "sip:a@b", "", Some("1")),
            ("sip:a@b;tag=2", "sip:a@b", "", Some("2")),
            ("Alice <sip:a@b>", "sip:a@b", "Alice", None),
            ("\"A, B\" <sip:a@b;tag=x>;tag=y", "sip:a@b;tag=x", "A, B", Some("y")),
        ];
        for (body, uri, name, tag) in cases {
            let (u, n, t) = nameaddr_parts(body.as_bytes());
            assert_eq!((String::from_utf8_lossy(&u).as_ref(), String::from_utf8_lossy(&n).as_ref()), (*uri, *name), "{body}");
            assert_eq!(t.as_deref(), tag.map(str::as_bytes), "{body}");
        }
    }
}
