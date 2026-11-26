//! `textops` / `textopsx`: header and body manipulation by name or regex.

use crate::{HdrMatch, Subst, args, dyn_args, dyn_arr, headers, re, re_ci};
use regex::bytes::Regex;
use sip_core::module::{DynInt, DynStr, ReplyExtra, rc};
use sip_core::schema::ParamSpec;
use sip_core::sig::{FnSig, Param};
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Registry, want_args};
use sip_parser::{HdrFlags, HdrKind};
use std::sync::Arc;

pub struct TextOps;
pub struct TextOpsX;

/// A header line from a template: CRLF appended when missing.
fn line(ctx: &mut Ctx<'_, '_>, t: &DynStr) -> Vec<u8> {
    let mut s = t.eval(ctx).into_owned().into_bytes();
    if !s.ends_with(b"\r\n") {
        while matches!(s.last(), Some(b'\r' | b'\n')) {
            s.pop();
        }
        s.extend_from_slice(b"\r\n");
    }
    s
}

fn name_arg(a: Option<&Arg>) -> Result<Option<HdrMatch>, String> {
    a.map(|x| x.str().map(HdrMatch::new)).transpose()
}

fn ctype_of(ctx: &mut Ctx<'_, '_>) -> Vec<u8> {
    headers(ctx).into_iter().find(|h| h.2.eq_ignore_ascii_case(b"content-type") || h.2.eq_ignore_ascii_case(b"c")).map(|h| h.3).unwrap_or_default()
}

/// Glob match (`*`, `?`, `[abc]`, `[!a-z]`) for `fnmatch`; a `[` without
/// `]` matches nothing.
///
/// Iterative, backtracking only to the last `*` (each other token matches
/// exactly one byte): O(len(p)·len(s)) time and constant stack, whatever
/// the input — the value is often a header from the wire.
pub(crate) fn glob(p: &[u8], s: &[u8]) -> bool {
    let (mut p_at, mut s_at) = (p, s);
    // Where to retry after a mismatch: just past the last `*`, and the
    // input that `*` hasn't swallowed yet.
    let mut star: Option<(&[u8], &[u8])> = None;
    loop {
        if let Some((b'*', after)) = p_at.split_first() {
            star = Some((after, s_at));
            p_at = after;
            continue;
        }
        match s_at.split_first() {
            None if p_at.is_empty() => return true,
            Some((&c, s_rest)) => {
                if let Some(p_rest) = glob_one(p_at, c) {
                    (p_at, s_at) = (p_rest, s_rest);
                    continue;
                }
            }
            None => {}
        }
        // Mismatch: the last `*` takes one more byte.
        let Some((p_star, Some((_, s_star)))) = star.map(|(sp, ss)| (sp, ss.split_first())) else { return false };
        star = Some((p_star, s_star));
        (p_at, s_at) = (p_star, s_star);
    }
}

/// The pattern after its first token (not `*`) if that token matches `c`.
fn glob_one(p: &[u8], c: u8) -> Option<&[u8]> {
    let (&first, rest) = p.split_first()?;
    match first {
        b'?' => Some(rest),
        b'[' => {
            let mut parts = rest.splitn(2, |&x| x == b']');
            let (set, after) = (parts.next()?, parts.next()?);
            let (neg, mut set) = match set.split_first() {
                Some((b'!', set)) => (true, set),
                _ => (false, set),
            };
            let mut hit = false;
            loop {
                set = match set {
                    [lo, b'-', hi, more @ ..] => {
                        hit |= (*lo..=*hi).contains(&c);
                        more
                    }
                    [x, more @ ..] => {
                        hit |= *x == c;
                        more
                    }
                    [] => break,
                };
            }
            (hit != neg).then_some(after)
        }
        _ => (first == c).then_some(rest),
    }
}

impl Module for TextOps {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "textops"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const NAME: &[Param] = &[arg("name", Str).lit()];
        const RE: &[Param] = &[arg("regex", Str).lit().eg("\"^X-.*\"")];
        const RE_EXCEPT: &[Param] = &[arg("regex", Str).lit().eg("\"^X-.*\""), arg("keep", Str).lit().eg("\"^X-Keep\"")];
        const AFTER: &[Param] = &[arg("text", Str), opt("after", Str).lit()];
        const BEFORE: &[Param] = &[arg("text", Str), opt("before", Str).lit()];
        const URIHF: &[Param] = &[arg("prefix", Str), arg("suffix", Str)];
        const SEARCH_HF: &[Param] = &[arg("name", Str).lit(), arg("regex", Str).lit().eg("\"^x\""), opt("which", Enum(&["a", "f", "l"])).lit()];
        const RE_TEXT: &[Param] = &[arg("regex", Str).lit().eg("\"a+\""), arg("text", Str)];
        const SUBST: &[Param] = &[arg("expr", Str).eg("\"/a/b/g\"")];
        const SUBST_HF: &[Param] = &[arg("name", Str).lit(), arg("expr", Str).eg("\"/a/b/g\"")];
        const CTYPE: &[Param] = &[opt("content_type", Str).lit().eg("\"application/sdp\"")];
        const METHODS: &[Param] = &[arg("methods", Str).lit().eg("\"INVITE|BYE\"")];
        const BODY: &[Param] = &[arg("body", Str), arg("content_type", Str)];
        const TEXT: &[Param] = &[arg("text", Str)];
        const STR_PREFIX: &[Param] = &[arg("s", Str), arg("prefix", Str)];
        const TWO: &[Param] = &[arg("a", Str), arg("b", Str)];
        const FIND: &[Param] = &[arg("s", Str), arg("needle", Str)];
        Some(vec![
            sig("is_present_hf", "has_header", NAME, Ret::Bool, "The message has a header with this name").allowed(ctx::ANY),
            sig("is_present_hf_re", "has_header_re", RE, Ret::Bool, "The message has a header whose name matches this regex (case-insensitive)")
                .allowed(ctx::ANY),
            sig("append_hf", "append_header", AFTER, Ret::Bool, "Add a header line at the end of the headers (or after the first `after` header)")
                .allowed(ctx::ANY),
            sig("append_urihf", "append_uri_header", URIHF, Ret::Bool, "Add a header made of prefix, the R-URI and suffix"),
            sig("insert_hf", "insert_header", BEFORE, Ret::Bool, "Add a header line first (or before the first `before` header)").allowed(ctx::ANY),
            sig("remove_hf", "remove_header", NAME, Ret::Bool, "Remove every header with this name (false when none)").allowed(ctx::ANY),
            sig("remove_hf_re", "remove_header_re", RE, Ret::Bool, "Remove every header whose name matches this regex (case-insensitive)").allowed(ctx::ANY),
            sig("remove_hf_exp", "remove_header_except", RE_EXCEPT, Ret::Bool, "Remove headers whose name matches `regex` but not `keep`").allowed(ctx::ANY),
            sig("search", "search", RE, Ret::Bool, "The whole message matches this regex").allowed(ctx::ANY),
            sig("search_body", "search_body", RE, Ret::Bool, "The body matches this regex").allowed(ctx::ANY),
            sig("search_hf", "search_header", SEARCH_HF, Ret::Bool, "A header's value matches the regex: any (a), the first (f) or the last (l) one")
                .allowed(ctx::ANY),
            sig("search_append", "search_append", RE_TEXT, Ret::Bool, "Insert text after the first match of the regex in the message").allowed(ctx::ANY),
            sig("replace", "replace", RE_TEXT, Ret::Bool, "Replace the first match of the regex in the message (\\1 for groups)").allowed(ctx::ANY),
            sig("replace_all", "replace_all", RE_TEXT, Ret::Bool, "Replace every match of the regex in the message (\\1 for groups)").allowed(ctx::ANY),
            sig("replace_body", "replace_body", RE_TEXT, Ret::Bool, "Replace the first match of the regex in the body").allowed(ctx::ANY),
            sig("replace_body_all", "replace_body_all", RE_TEXT, Ret::Bool, "Replace every match of the regex in the body").allowed(ctx::ANY),
            sig("replace_body_atonce", "replace_body_at_once", RE_TEXT, Ret::Bool, "Replace every match of the regex in the body, in one pass")
                .allowed(ctx::ANY),
            sig("subst", "subst", SUBST, Ret::Bool, "sed-style `/regex/replacement/flags` on the headers (flags: i, g)").allowed(ctx::ANY),
            sig("subst_uri", "subst_uri", SUBST, Ret::Bool, "sed-style `/regex/replacement/flags` on the R-URI"),
            sig("subst_user", "subst_user", SUBST, Ret::Bool, "sed-style `/regex/replacement/flags` on the R-URI's user part"),
            sig("subst_body", "subst_body", SUBST, Ret::Bool, "sed-style `/regex/replacement/flags` on the body").allowed(ctx::ANY),
            sig("subst_hf", "subst_header", SUBST_HF, Ret::Bool, "sed-style `/regex/replacement/flags` on the first header with this name").allowed(ctx::ANY),
            sig("has_body", "has_body", CTYPE, Ret::Bool, "The message has a body (of this content type)").allowed(ctx::ANY),
            sig("is_method", "is_method", METHODS, Ret::Bool, "The method (a reply's CSeq method) is one of these, `|`-separated").allowed(ctx::ANY),
            sig("set_body", "set_body", BODY, Ret::Bool, "Replace the body and its Content-Type").allowed(ctx::ANY),
            sig("set_reply_body", "set_reply_body", BODY, Ret::Bool, "Body (and Content-Type) of the next reply sent from the script"),
            sig("append_to_reply", "append_to_reply", TEXT, Ret::Bool, "Add a header line to the next reply sent from the script"),
            sig("append_time", "append_time", &[], Ret::Bool, "Add a Date header to the next reply sent from the script"),
            sig("starts_with", "starts_with", STR_PREFIX, Ret::Bool, "`s` starts with `prefix`").allowed(ctx::ANY),
            sig("cmp_str", "equals", TWO, Ret::Bool, "The two strings are equal").allowed(ctx::ANY),
            sig("cmp_istr", "equals_nocase", TWO, Ret::Bool, "The two strings are equal, ignoring ASCII case").allowed(ctx::ANY),
            sig("str_find", "contains", FIND, Ret::Bool, "`needle` occurs in `s`").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "textops";
        reg.export(
            m,
            "is_present_hf",
            |a: &[Arg]| {
                let [h] = args(a)?;
                Ok(HdrMatch::new(h.str()?))
            },
            |ctx: &mut Ctx, h: &HdrMatch| {
                let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                rc(ctx.msg.headers.iter().any(|x| h.matches(x)))
            },
        );
        reg.export(
            m,
            "is_present_hf_re",
            |a: &[Arg]| {
                let [r] = args(a)?;
                re_ci(r.str()?)
            },
            |ctx: &mut Ctx, r: &Regex| rc(headers(ctx).iter().any(|h| r.is_match(&h.2))),
        );

        // append_hf(txt[, after_hdr]) / insert_hf(txt[, before_hdr])
        let hf_fix = |a: &[Arg]| -> Result<(DynStr, Option<HdrMatch>), String> {
            let (text, hdr) = match a {
                [text] => (text, None),
                [text, hdr] => (text, Some(hdr)),
                _ => return Err("expected (text[, header])".into()),
            };
            Ok((text.dyn_str()?, name_arg(hdr)?))
        };
        reg.export(m, "append_hf", hf_fix, |ctx: &mut Ctx, (t, after): &(DynStr, Option<HdrMatch>)| {
            let l = line(ctx, t);
            if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                return -1;
            }
            let at = match after {
                Some(h) => match ctx.msg.headers.iter().find(|x| h.matches(x)) {
                    Some(x) => x.end,
                    None => return -1,
                },
                None => ctx.msg.eoh_offset().unwrap_or(ctx.msg.buf.len()),
            };
            ctx.lumps.insert(at, l);
            1
        });
        // append_urihf(prefix, suffix): a header made of prefix, the R-URI
        // and suffix (`append_urihf("CC-Diversion: ", "\r\n")`).
        reg.export(
            m,
            "append_urihf",
            |a: &[Arg]| {
                let [p, s] = args(a)?;
                Ok((p.dyn_str()?, s.dyn_str()?))
            },
            |ctx: &mut Ctx, (p, s): &(DynStr, DynStr)| {
                let (pre, suf) = (p.eval(ctx).into_owned(), s.eval(ctx).into_owned());
                let mut l = format!("{pre}{}{suf}", String::from_utf8_lossy(ctx.ruri())).into_bytes();
                if !l.ends_with(b"\r\n") {
                    l.extend_from_slice(b"\r\n");
                }
                if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                    return -1;
                }
                let at = ctx.msg.eoh_offset().unwrap_or(ctx.msg.buf.len());
                ctx.lumps.insert(at, l);
                1
            },
        );
        reg.export(m, "insert_hf", hf_fix, |ctx: &mut Ctx, (t, before): &(DynStr, Option<HdrMatch>)| {
            let l = line(ctx, t);
            if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
                return -1;
            }
            let at = match before {
                Some(h) => match ctx.msg.headers.iter().find(|x| h.matches(x)) {
                    Some(x) => x.start,
                    None => return -1,
                },
                None => ctx.msg.first_line_end,
            };
            ctx.lumps.insert(at, l);
            1
        });

        reg.export(
            m,
            "remove_hf",
            |a: &[Arg]| {
                let [h] = args(a)?;
                Ok(HdrMatch::new(h.str()?))
            },
            |ctx: &mut Ctx, h: &HdrMatch| {
                let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                let hits: Vec<(usize, usize)> = ctx.msg.headers.iter().filter(|x| h.matches(x)).map(|x| (x.start, x.end)).collect();
                for (s, e) in &hits {
                    ctx.lumps.delete(*s, e.saturating_sub(*s));
                }
                if hits.is_empty() { -1 } else { i32::try_from(hits.len()).unwrap_or(i32::MAX) }
            },
        );
        reg.export(
            m,
            "remove_hf_re",
            |a: &[Arg]| {
                let [r] = args(a)?;
                re_ci(r.str()?)
            },
            |ctx: &mut Ctx, r: &Regex| {
                let hits: Vec<_> = headers(ctx).into_iter().filter(|h| r.is_match(&h.2)).collect();
                for h in &hits {
                    ctx.lumps.delete(h.0, h.1.saturating_sub(h.0));
                }
                if hits.is_empty() { -1 } else { i32::try_from(hits.len()).unwrap_or(i32::MAX) }
            },
        );
        reg.export(
            m,
            "remove_hf_exp",
            |a: &[Arg]| {
                let [r, skip] = args(a)?;
                Ok((re_ci(r.str()?)?, re_ci(skip.str()?)?))
            },
            |ctx: &mut Ctx, (r, skip): &(Regex, Regex)| {
                let hits: Vec<_> = headers(ctx).into_iter().filter(|h| r.is_match(&h.2) && !skip.is_match(&h.2)).collect();
                for h in &hits {
                    ctx.lumps.delete(h.0, h.1.saturating_sub(h.0));
                }
                if hits.is_empty() { -1 } else { i32::try_from(hits.len()).unwrap_or(i32::MAX) }
            },
        );

        // search(re) on the whole message; search_body(re); search_hf(hf, re[, flags])
        reg.export(
            m,
            "search",
            |a: &[Arg]| {
                let [r] = args(a)?;
                re(r)
            },
            |ctx: &mut Ctx, r: &Regex| rc(r.is_match(ctx.msg.buf)),
        );
        reg.export(
            m,
            "search_body",
            |a: &[Arg]| {
                let [r] = args(a)?;
                re(r)
            },
            |ctx: &mut Ctx, r: &Regex| rc(r.is_match(&ctx.body())),
        );
        reg.export(
            m,
            "search_hf",
            |a: &[Arg]| {
                let (h, r, flag) = match a {
                    [h, r] => (h, r, None),
                    [h, r, flag] => (h, r, Some(flag)),
                    _ => return Err("search_hf(header, regex[, flags a|f|l])".into()),
                };
                let flag = flag.map(|f| f.str().map(str::to_string)).transpose()?.unwrap_or_else(|| "a".into());
                Ok((HdrMatch::new(h.str()?), re(r)?, flag))
            },
            |ctx: &mut Ctx, (h, r, f): &(HdrMatch, Regex, String)| {
                let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                let bodies: Vec<&[u8]> = ctx.msg.headers.iter().filter(|x| h.matches(x)).map(|x| x.body).collect();
                rc(match f.as_str() {
                    "f" => bodies.first().is_some_and(|b| r.is_match(b)),
                    "l" => bodies.last().is_some_and(|b| r.is_match(b)),
                    _ => bodies.iter().any(|b| r.is_match(b)),
                })
            },
        );
        reg.export(
            m,
            "search_append",
            |a: &[Arg]| {
                let [r, t] = args(a)?;
                Ok((re(r)?, t.dyn_str()?))
            },
            |ctx: &mut Ctx, (r, t): &(Regex, DynStr)| {
                let Some(mt) = r.find(ctx.msg.buf) else { return -1 };
                let end = mt.end();
                let txt = t.eval(ctx).into_owned();
                ctx.lumps.insert(end, txt.into_bytes());
                1
            },
        );

        // replace(re, txt) / replace_all(re, txt): in the whole message.
        for (name, all) in [("replace", false), ("replace_all", true)] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [r, t] = args(a)?;
                    Ok((re(r)?, t.dyn_str()?))
                },
                move |ctx: &mut Ctx, (r, t): &(Regex, DynStr)| {
                    let repl = crate::sed_repl(&t.eval(ctx));
                    let buf = ctx.msg.buf;
                    let mut n = 0i32;
                    for c in r.captures_iter(buf) {
                        let Some(mt) = c.get(0) else { continue };
                        let mut out = Vec::new();
                        c.expand(repl.as_bytes(), &mut out);
                        ctx.lumps.replace(mt.start(), mt.len(), out);
                        n = n.saturating_add(1);
                        if !all {
                            break;
                        }
                    }
                    if n == 0 { -1 } else { n }
                },
            );
        }
        // Body variants operate on the (possibly already rewritten) body.
        for (name, all) in [("replace_body", false), ("replace_body_all", true), ("replace_body_atonce", true)] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [r, t] = args(a)?;
                    Ok((re(r)?, t.dyn_str()?))
                },
                move |ctx: &mut Ctx, (r, t): &(Regex, DynStr)| {
                    let body = ctx.body();
                    if !r.is_match(&body) {
                        return -1;
                    }
                    let repl = crate::sed_repl(&t.eval(ctx));
                    let nb = if all { r.replace_all(&body, repl.as_bytes()) } else { r.replace(&body, repl.as_bytes()) }.into_owned();
                    ctx.set_body(nb, None);
                    1
                },
            );
        }

        // subst('/re/repl/flags') family.
        for name in ["subst", "subst_uri", "subst_user", "subst_body", "subst_hf"] {
            reg.export(
                m,
                name,
                move |a: &[Arg]| {
                    // One optional argument more (Kamailio's ignored flags).
                    let (h, s) = match (name == "subst_hf", a) {
                        (true, [h, s] | [h, s, _]) => (Some(HdrMatch::new(h.str()?)), s),
                        (false, [s] | [s, _]) => (None, s),
                        _ => return Err(format!("{name}: wrong number of arguments")),
                    };
                    Ok((h, Subst::from_arg(s)?))
                },
                move |ctx: &mut Ctx, (h, s): &(Option<HdrMatch>, Subst)| match name {
                    "subst" => {
                        // The body's start is known once the headers are parsed.
                        let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                        let buf = ctx.msg.buf;
                        let first_body = ctx.msg.body().map_or(buf.len(), |b| ctx.msg.offset_of(b));
                        // Header part only (body edits go through subst_body).
                        let head = buf.get(..first_body).unwrap_or(buf);
                        let mut n = 0i32;
                        let repl = crate::sed_repl(&s.repl.eval(ctx));
                        for c in s.re.captures_iter(head) {
                            let Some(mt) = c.get(0) else { continue };
                            let mut out = Vec::new();
                            c.expand(repl.as_bytes(), &mut out);
                            ctx.lumps.replace(mt.start(), mt.len(), out);
                            n = n.saturating_add(1);
                            if !s.global {
                                break;
                            }
                        }
                        if n == 0 { -1 } else { n }
                    }
                    "subst_uri" | "subst_user" => {
                        let uri = ctx.ruri().to_vec();
                        let target = if name == "subst_user" {
                            sip_parser::parse_uri(&uri).and_then(|u| u.user).map(<[u8]>::to_vec).unwrap_or_default()
                        } else {
                            uri.clone()
                        };
                        let Some(new) = s.apply(ctx, &target) else { return -1 };
                        let new_uri = if name == "subst_user" {
                            match sip_core::pvcore::rebuild_uri(&uri, Some(Some(&String::from_utf8_lossy(&new))), None, None) {
                                Some(u) => u,
                                None => return -1,
                            }
                        } else {
                            new
                        };
                        ctx.new_ruri = Some(new_uri);
                        1
                    }
                    "subst_body" => {
                        let body = ctx.body();
                        match s.apply(ctx, &body) {
                            Some(nb) => {
                                ctx.set_body(nb, None);
                                1
                            }
                            None => -1,
                        }
                    }
                    _ => {
                        // The fixup always sets the header for subst_hf.
                        let Some(h) = h.as_ref() else { return -1 };
                        let _ = ctx.msg.parse_headers(HdrFlags::EOH);
                        let found = ctx.msg.headers.iter().find(|x| h.matches(x)).map(|x| (ctx.msg.offset_of(x.body), x.body.to_vec()));
                        let Some((off, body)) = found else { return -1 };
                        let Some(nb) = s.apply(ctx, &body) else { return -1 };
                        ctx.lumps.replace(off, body.len(), nb);
                        1
                    }
                },
            );
        }

        reg.export(
            m,
            "has_body",
            |a: &[Arg]| {
                if a.len() > 1 {
                    return Err("has_body([content-type])".into());
                }
                a.first().map(|x| x.str().map(|s| s.to_ascii_lowercase())).transpose()
            },
            |ctx: &mut Ctx, ct: &Option<String>| {
                if ctx.body().is_empty() {
                    return -1;
                }
                match ct {
                    None => 1,
                    Some(t) => {
                        let have = String::from_utf8_lossy(&ctype_of(ctx)).to_ascii_lowercase();
                        rc(have.split(';').next().unwrap_or("").trim() == t || have.contains(t.as_str()))
                    }
                }
            },
        );
        reg.export(
            m,
            "is_method",
            |a: &[Arg]| {
                let [ms] = args(a)?;
                Ok(ms.str()?.split('|').map(|s| s.trim().to_ascii_uppercase()).collect::<Vec<_>>())
            },
            |ctx: &mut Ctx, ms: &Vec<String>| {
                let m = match ctx.msg.first {
                    sip_parser::FirstLine::Request { method_raw, .. } => String::from_utf8_lossy(method_raw).to_ascii_uppercase(),
                    _ => {
                        let cs = headers(ctx).into_iter().find(|h| h.4 == HdrKind::CSeq).map(|h| h.3).unwrap_or_default();
                        String::from_utf8_lossy(&cs).split_whitespace().nth(1).unwrap_or("").to_ascii_uppercase()
                    }
                };
                rc(ms.contains(&m))
            },
        );
        reg.export(
            m,
            "set_body",
            |a: &[Arg]| {
                let [b, t] = dyn_arr(a)?;
                Ok((b, t))
            },
            |ctx: &mut Ctx, (b, t): &(DynStr, DynStr)| {
                let (b, t) = (b.eval(ctx).into_owned(), t.eval(ctx).into_owned());
                ctx.set_body(b.into_bytes(), Some(t));
                1
            },
        );
        reg.export(
            m,
            "set_reply_body",
            |a: &[Arg]| {
                let [b, t] = dyn_arr(a)?;
                Ok((b, t))
            },
            |ctx: &mut Ctx, (b, t): &(DynStr, DynStr)| {
                let (b, t) = (b.eval(ctx).into_owned(), t.eval(ctx).into_owned());
                ctx.ext_mut::<ReplyExtra>().body = Some((t, b.into_bytes()));
                1
            },
        );
        reg.export(
            m,
            "append_to_reply",
            |a: &[Arg]| {
                let [t] = args(a)?;
                t.dyn_str()
            },
            |ctx: &mut Ctx, t: &DynStr| {
                let l = line(ctx, t);
                ctx.ext_mut::<ReplyExtra>().headers.extend_from_slice(&l);
                1
            },
        );
        reg.export(
            m,
            "append_time",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                let d = format!("Date: {}\r\n", crate::http_date(unix_secs()));
                ctx.ext_mut::<ReplyExtra>().headers.extend_from_slice(d.as_bytes());
                1
            },
        );
        // String helpers (textops / textopsx).
        reg.export(
            m,
            "starts_with",
            |a: &[Arg]| {
                let [s, p] = dyn_arr(a)?;
                Ok((s, p))
            },
            |ctx: &mut Ctx, (s, p): &(DynStr, DynStr)| {
                let (s, p) = (s.eval(ctx).into_owned(), p.eval(ctx).into_owned());
                rc(s.starts_with(&p))
            },
        );
        for (name, ci) in [("cmp_str", false), ("cmp_istr", true)] {
            reg.export(
                m,
                name,
                |a: &[Arg]| {
                    let [x, y] = dyn_arr(a)?;
                    Ok((x, y))
                },
                move |ctx: &mut Ctx, (x, y): &(DynStr, DynStr)| {
                    let (x, y) = (x.eval(ctx).into_owned(), y.eval(ctx).into_owned());
                    rc(if ci { x.eq_ignore_ascii_case(&y) } else { x == y })
                },
            );
        }
        reg.export(
            m,
            "str_find",
            |a: &[Arg]| {
                let [x, y] = dyn_arr(a)?;
                Ok((x, y))
            },
            |ctx: &mut Ctx, (x, y): &(DynStr, DynStr)| {
                let (x, y) = (x.eval(ctx).into_owned(), y.eval(ctx).into_owned());
                x.find(&y).map_or(-1, |i| i32::try_from(i).map_or(i32::MAX, |i| i.saturating_add(1)))
            },
        );
        Ok(())
    }
}

impl Module for TextOpsX {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "textopsx"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const STATUS: &[Param] = &[arg("code", Int), arg("reason", Str)];
        const RE: &[Param] = &[arg("regex", Str).lit().eg("\"^X-.*\"")];
        const GLOB: &[Param] = &[arg("value", Str), arg("pattern", Str).eg("\"+49*\"")];
        Some(vec![
            sig("msg_apply_changes", "apply_changes", &[], Ret::Bool, "Apply the pending header/body changes to the message now").allowed(ctx::ANY),
            sig("remove_body", "remove_body", &[], Ret::Bool, "Remove the body (false when there is none)").allowed(ctx::ANY),
            sig("change_reply_status", "change_reply_status", STATUS, Ret::Bool, "Change the code and reason of the reply being processed").allowed(ctx::REPLY),
            sig("keep_hf", "keep_headers", RE, Ret::Bool, "Remove every header whose name doesn't match the regex (mandatory ones stay)").allowed(ctx::ANY),
            sig("fnmatch", "fnmatch", GLOB, Ret::Bool, "The value matches the shell glob (`*`, `?`, `[a-z]`)").allowed(ctx::ANY),
        ])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let m = "textopsx";
        reg.export(m, "msg_apply_changes", |a: &[Arg]| want_args(a, 0), |ctx: &mut Ctx, _: &()| rc(ctx.apply_changes().is_ok()));
        reg.export(
            m,
            "remove_body",
            |a: &[Arg]| want_args(a, 0),
            |ctx: &mut Ctx, _: &()| {
                if ctx.body().is_empty() {
                    return -1;
                }
                ctx.set_body(Vec::new(), Some(String::new()));
                1
            },
        );
        // change_reply_status(code, reason) — in reply routes.
        reg.export(
            m,
            "change_reply_status",
            |a: &[Arg]| {
                let [c, r] = args(a)?;
                Ok((c.dyn_int()?, r.dyn_str()?))
            },
            |ctx: &mut Ctx, (c, r): &(DynInt, DynStr)| {
                if ctx.msg.is_request() {
                    return -1;
                }
                let Some(code) = c.eval(ctx).filter(|c| (100..700).contains(c)) else { return -1 };
                let reason = r.eval(ctx).into_owned();
                let eol = ctx.msg.first_line_end;
                ctx.lumps.replace(0, eol, format!("SIP/2.0 {code} {reason}\r\n").into_bytes());
                1
            },
        );
        // keep_hf(re): drop every header not matching (mandatory ones stay).
        reg.export(
            m,
            "keep_hf",
            |a: &[Arg]| {
                let [r] = args(a)?;
                re_ci(r.str()?)
            },
            |ctx: &mut Ctx, r: &Regex| {
                let keep = |k: HdrKind, n: &[u8]| {
                    matches!(
                        k,
                        HdrKind::Via
                            | HdrKind::From
                            | HdrKind::To
                            | HdrKind::CallId
                            | HdrKind::CSeq
                            | HdrKind::ContentLength
                            | HdrKind::MaxForwards
                            | HdrKind::Contact
                            | HdrKind::Route
                            | HdrKind::RecordRoute
                    ) || n.eq_ignore_ascii_case(b"content-type")
                        || r.is_match(n)
                };
                let mut n = 0i32;
                for h in headers(ctx) {
                    if !keep(h.4, &h.2) {
                        ctx.lumps.delete(h.0, h.1.saturating_sub(h.0));
                        n = n.saturating_add(1);
                    }
                }
                n.max(1)
            },
        );
        reg.export(
            m,
            "fnmatch",
            |a: &[Arg]| match dyn_args(a, 2, 3)?.as_slice() {
                [v, p, ..] => Ok((v.clone(), p.clone())),
                _ => Err("expected 2..3 arguments".into()),
            },
            |ctx: &mut Ctx, (v, p): &(DynStr, DynStr)| {
                let (v, p) = (v.eval(ctx).into_owned(), p.eval(ctx).into_owned());
                rc(glob(p.as_bytes(), v.as_bytes()))
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn globbing() {
        assert!(super::glob(b"+49*", b"+4930123"));
        assert!(super::glob(b"a?c", b"abc"));
        assert!(super::glob(b"[0-9][!a]x", b"7bx"));
        assert!(!super::glob(b"[0-9]x", b"ax"));
        assert!(super::glob(b"*", b""));
    }

    /// The recursive matcher `glob` replaced (it overflowed the stack on
    /// long values and took exponential time on several `*`).
    #[allow(clippy::arithmetic_side_effects, reason = "test oracle: the old matcher verbatim; i + 2 < set.len() bounds every index")]
    fn glob_ref(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => glob_ref(&p[1..], s) || (!s.is_empty() && glob_ref(p, &s[1..])),
            (Some(b'?'), Some(_)) => glob_ref(&p[1..], &s[1..]),
            (Some(b'['), Some(&c)) => match p.iter().position(|&x| x == b']') {
                Some(e) => {
                    let set = &p[1..e];
                    let (neg, set) = if set.first() == Some(&b'!') { (true, &set[1..]) } else { (false, set) };
                    let mut hit = false;
                    let mut i = 0;
                    while i < set.len() {
                        if i + 2 < set.len() && set[i + 1] == b'-' {
                            hit |= (set[i]..=set[i + 2]).contains(&c);
                            i += 3;
                        } else {
                            hit |= set[i] == c;
                            i += 1;
                        }
                    }
                    hit != neg && glob_ref(&p[e + 1..], &s[1..])
                }
                None => false,
            },
            (Some(&a), Some(&b)) => a == b && glob_ref(&p[1..], &s[1..]),
            _ => false,
        }
    }

    #[test]
    fn glob_matches_reference() {
        // Every pattern and input up to length 4 / 5 over a small alphabet.
        let pat = b"*?[]!-ab";
        let txt = b"ab-]";
        let all = |alpha: &[u8], max: usize| {
            let mut out: Vec<Vec<u8>> = vec![Vec::new()];
            let mut last = vec![Vec::new()];
            for _ in 0..max {
                last = last.iter().flat_map(|w: &Vec<u8>| alpha.iter().map(move |&c| [w.as_slice(), &[c]].concat())).collect();
                out.extend(last.iter().cloned());
            }
            out
        };
        let (ps, ts) = (all(pat, 4), all(txt, 5));
        for p in &ps {
            for t in &ts {
                assert_eq!(super::glob(p, t), glob_ref(p, t), "{:?} vs {:?}", String::from_utf8_lossy(p), String::from_utf8_lossy(t));
            }
        }
    }

    #[test]
    fn glob_long_and_pathological_inputs() {
        // A 4 MB value: the recursive matcher needed one stack frame per byte.
        let long = vec![b'a'; 4 << 20];
        assert!(super::glob(b"*", &long));
        assert!(!super::glob(b"*b", &long));
        // Exponential for the recursive matcher; linear-ish here.
        let s = vec![b'a'; 200];
        assert!(!super::glob(b"*a*a*a*a*a*a*a*a*a*a*b", &s));
        assert!(super::glob(b"*a*a*a*a*a*a*a*a*a*a*", &s));
    }
}
