//! Message utility modules (Kamailio names, one `loadmodule` each):
//! `sl`, `textops`, `textopsx`, `siputils`, `sanity`, `xlog`, `cfgutils`,
//! `corex`, `kex`, `statistics`, `counters`, `pv`, `ipops`, `exec`.
//!
//! They're small and share helpers, so they live in one crate; each is its
//! own `Module` and is only active when loaded.

use regex::bytes::Regex;
use sip_core::module::DynStr;
use sip_core::pv::PvRef;
use sip_core::{Arg, Ctx, Module};
use sip_parser::{HdrFlags, HdrKind, kind_of};
use std::sync::Arc;

mod exec;
mod misc;
mod sip;
mod text;
#[cfg(test)]
mod unit_tests;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] =
    &["sl", "siputils", "sanity", "textops", "textopsx", "xlog", "cfgutils", "corex", "kex", "statistics", "counters", "pv", "ipops", "blst", "exec"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "sl" => Arc::new(sip::Sl),
        "siputils" => Arc::new(sip::SipUtils),
        "sanity" => Arc::new(sip::Sanity::default()),
        "textops" => Arc::new(text::TextOps),
        "textopsx" => Arc::new(text::TextOpsX),
        "xlog" => Arc::new(misc::Xlog),
        "cfgutils" => Arc::new(misc::CfgUtils::default()),
        "corex" => Arc::new(misc::Corex),
        "kex" => Arc::new(misc::Kex),
        "statistics" => Arc::new(misc::Statistics),
        "counters" => Arc::new(misc::Counters),
        "pv" => Arc::new(misc::PvMod),
        "ipops" => Arc::new(misc::IpOps),
        "blst" => Arc::new(misc::Blst),
        "exec" => Arc::new(exec::Exec::default()),
        _ => return None,
    })
}

// ------------------------------------------------------------- helpers ---

/// A header name: a known kind (also matches compact forms) or a name.
#[derive(Clone, Debug)]
pub(crate) enum HdrMatch {
    Kind(HdrKind),
    Name(Vec<u8>),
}

impl HdrMatch {
    pub(crate) fn new(name: &str) -> Self {
        match kind_of(name.as_bytes()) {
            HdrKind::Other => HdrMatch::Name(name.as_bytes().to_ascii_lowercase()),
            k => HdrMatch::Kind(k),
        }
    }
    pub(crate) fn matches(&self, h: &sip_parser::Header<'_>) -> bool {
        match self {
            HdrMatch::Kind(k) => h.kind == *k,
            HdrMatch::Name(n) => h.name.eq_ignore_ascii_case(n),
        }
    }
}

/// (start, end, name, body, kind) of a header, owned so lumps can be added.
pub(crate) type OwnedHdr = (usize, usize, Vec<u8>, Vec<u8>, HdrKind);

pub(crate) fn headers(ctx: &mut Ctx<'_, '_>) -> Vec<OwnedHdr> {
    if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return vec![];
    }
    ctx.msg.headers.iter().map(|h| (h.start, h.end, h.name.to_vec(), h.body.to_vec(), h.kind)).collect()
}

pub(crate) fn re(a: &Arg) -> Result<Regex, String> {
    Regex::new(a.str()?).map_err(|e| format!("bad regex: {e}"))
}

pub(crate) fn re_ci(s: &str) -> Result<Regex, String> {
    Regex::new(&format!("(?i){s}")).map_err(|e| format!("bad regex: {e}"))
}

/// An argument that must be a single variable (`$avp(x)`), for outputs.
pub(crate) fn pv_arg(a: &Arg) -> Result<PvRef, String> {
    match a {
        Arg::Fmt(f) => f.single_pv().cloned().ok_or_else(|| "expected a single variable".into()),
        _ => Err("expected a variable like $var(x)".into()),
    }
}

/// `want_args`, as an array to destructure: `let [name, value] = args(a)?;`.
pub(crate) fn args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    <&[Arg; N]>::try_from(a).map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

/// `dyn_args` with exactly `N` arguments, as an array to destructure.
pub(crate) fn dyn_arr<const N: usize>(a: &[Arg]) -> Result<[DynStr; N], String> {
    <[DynStr; N]>::try_from(dyn_args(a, N, N)?).map_err(|_| format!("expected {N} argument(s)"))
}

pub(crate) fn dyn_args(a: &[Arg], min: usize, max: usize) -> Result<Vec<DynStr>, String> {
    if a.len() < min || a.len() > max {
        return Err(if min == max { format!("expected {min} argument(s)") } else { format!("expected {min}..{max} arguments") });
    }
    a.iter().map(Arg::dyn_str).collect()
}

/// A sed-style substitution `/re/repl/flags` (any delimiter; flags i, g).
#[derive(Clone, Debug)]
pub(crate) struct Subst {
    pub re: Regex,
    pub repl: DynStr,
    pub global: bool,
}

impl Subst {
    /// From a function argument: variables are allowed in the replacement.
    pub(crate) fn from_arg(a: &Arg) -> Result<Self, String> {
        use sip_core::pv::{Fmt, FmtPart};
        let f = match a {
            Arg::Str(s) => return Self::parse(s, &sip_core::pv::PvTable::new()),
            Arg::Fmt(f) => f,
            Arg::Int(_) => return Err("expected /regex/replacement/flags".into()),
        };
        let delim = match f.0.first() {
            Some(FmtPart::Lit(l)) => l.chars().next().ok_or("empty substitution")?,
            _ => return Err("substitution must start with a delimiter".into()),
        };
        // Split the template on unescaped delimiters in literal parts.
        let (mut sections, mut section): (Vec<Vec<FmtPart>>, Vec<FmtPart>) = (Vec::new(), Vec::new());
        let mut first = true;
        for p in &f.0 {
            match p {
                FmtPart::Pv(r) => section.push(FmtPart::Pv(r.clone())),
                FmtPart::Lit(l) => {
                    let (mut cur, mut esc) = (String::new(), false);
                    for c in l.chars() {
                        if first {
                            first = false;
                            continue; // the leading delimiter
                        }
                        if esc {
                            if c != delim {
                                cur.push('\\');
                            }
                            cur.push(c);
                            esc = false;
                        } else if c == '\\' {
                            esc = true;
                        } else if c == delim {
                            section.push(FmtPart::Lit(std::mem::take(&mut cur)));
                            sections.push(std::mem::take(&mut section));
                        } else {
                            cur.push(c);
                        }
                    }
                    section.push(FmtPart::Lit(cur));
                }
            }
        }
        sections.push(section);
        let Ok([pat, repl, flags]) = <[Vec<FmtPart>; 3]>::try_from(sections) else {
            return Err(format!("substitution must look like {delim}regex{delim}replacement{delim}flags"));
        };
        let lit = |s: &[FmtPart]| -> Result<String, String> {
            s.iter()
                .map(|p| match p {
                    FmtPart::Lit(l) => Ok(l.clone()),
                    FmtPart::Pv(_) => Err("variables are only allowed in the replacement".to_string()),
                })
                .collect()
        };
        let (pat, flags) = (lit(&pat)?, lit(&flags)?);
        let re = Regex::new(&format!("{}{}", if flags.contains('i') { "(?i)" } else { "" }, pat)).map_err(|e| format!("bad regex: {e}"))?;
        Ok(Subst { re, repl: DynStr::Fmt(Arc::new(Fmt(repl))), global: flags.contains('g') })
    }

    pub(crate) fn parse(s: &str, reg: &sip_core::pv::PvTable) -> Result<Self, String> {
        let mut it = s.chars();
        let d = it.next().ok_or("empty substitution")?;
        let (mut parts, mut cur, mut esc) = (Vec::new(), String::new(), false);
        for c in it {
            if esc {
                if c != d {
                    cur.push('\\');
                }
                cur.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == d {
                parts.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        parts.push(cur);
        let Ok([pat, repl, flags]) = <[String; 3]>::try_from(parts) else {
            return Err(format!("substitution must look like {d}regex{d}replacement{d}flags"));
        };
        let ci = flags.contains('i');
        let re = Regex::new(&format!("{}{}", if ci { "(?i)" } else { "" }, pat)).map_err(|e| format!("bad regex: {e}"))?;
        let repl = if repl.contains('$') { DynStr::Fmt(Arc::new(sip_core::pv::parse_fmt(&repl, reg)?)) } else { DynStr::Static(repl) };
        Ok(Subst { re, repl, global: flags.contains('g') })
    }

    /// Apply to `input`; None when nothing matched.
    pub(crate) fn apply(&self, ctx: &mut Ctx<'_, '_>, input: &[u8]) -> Option<Vec<u8>> {
        if !self.re.is_match(input) {
            return None;
        }
        let repl = sed_repl(&self.repl.eval(ctx));
        let out = if self.global { self.re.replace_all(input, repl.as_bytes()) } else { self.re.replace(input, repl.as_bytes()) };
        Some(out.into_owned())
    }
}

/// Kamailio replacement syntax → regex crate: `\1` → `${1}`, `$` → `$$`.
pub(crate) fn sed_repl(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(d) if d.is_ascii_digit() => o.push_str(&format!("${{{d}}}")),
                Some('n') => o.push('\n'),
                Some('r') => o.push('\r'),
                Some('t') => o.push('\t'),
                Some(x) => o.push(x),
                None => o.push('\\'),
            },
            '$' => o.push_str("$$"),
            c => o.push(c),
        }
    }
    o
}

/// RFC 7231 date (`Date:` header), from Unix seconds.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "days < 2^48 (u64 seconds / 86400), so no intermediate comes near i64's range; weekday is rem_euclid(7) of 7 names, mo is 1..=12 of 12"
)]
pub(crate) fn http_date(secs: u64) -> String {
    // u64::MAX / 86400 < i64::MAX: the conversion never fails.
    let days = i64::try_from(secs / 86400).unwrap_or(i64::MAX);
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, rem % 3600 / 60, rem % 60);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][usize::try_from(days.rem_euclid(7)).unwrap_or(0)];
    let mn = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][usize::try_from(mo - 1).unwrap_or(0)];
    format!("{wd}, {d:02} {mn} {y} {h:02}:{m:02}:{s:02} GMT")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_repl() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(sed_repl(r"x\1y$"), "x${1}y$$");
    }

    #[test]
    fn subst_parsing() {
        let t = sip_core::pv::PvTable::new();
        let s = Subst::parse(r"/^sip:(.*)@old\.com/sip:\1@new.com/i", &t).unwrap();
        assert!(!s.global && s.re.is_match(b"SIP:bob@OLD.com"));
        assert!(Subst::parse("/a/b", &t).is_err());
        let s = Subst::parse(r"#a\#b#c#g", &t).unwrap();
        assert!(s.global && s.re.is_match(b"a#b"), "escaped delimiter");
    }
}
