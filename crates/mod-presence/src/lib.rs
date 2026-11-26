//! SIP events, presence and related modules (Kamailio names, one
//! `loadmodule` each): `presence`, `presence_xml`, `presence_dialoginfo`,
//! `pua`, `pua_dialoginfo`, `sca`, `msilo`, `rls`.
//!
//! `notifier` holds what they share: SUBSCRIBE dialogs (RFC 6665) and
//! NOTIFY sending through tm's UAC API.

use sip_core::Module;
use std::sync::Arc;

mod msilo;
pub mod notifier;
mod presence;
mod pua;
mod rls;
mod sca;
#[cfg(test)]
mod testutil;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["presence", "presence_xml", "presence_dialoginfo", "pua", "pua_dialoginfo", "sca", "msilo", "rls"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "presence" => Arc::new(presence::Presence::default()),
        "presence_xml" => Arc::new(presence::PresenceXml::default()),
        "presence_dialoginfo" => Arc::new(presence::PresenceDialoginfo::default()),
        "pua" => Arc::new(pua::Pua::default()),
        "pua_dialoginfo" => Arc::new(pua::PuaDialoginfo::default()),
        "sca" => Arc::new(sca::Sca::default()),
        "msilo" => Arc::new(msilo::Msilo::default()),
        "rls" => Arc::new(rls::Rls::default()),
        _ => return None,
    })
}

/// `sip:user@host` (no port/params) of a URI — the presentity key.
pub(crate) fn aor(uri: &[u8]) -> Option<String> {
    let u = sip_parser::parse_uri(uri)?;
    let user = String::from_utf8_lossy(u.user?);
    Some(format!("sip:{user}@{}", String::from_utf8_lossy(u.host).to_ascii_lowercase()))
}

/// Value of a header by name (first one), from a parsed message.
pub(crate) fn header(ctx: &mut sip_core::Ctx<'_, '_>, name: &str) -> Option<String> {
    ctx.msg.parse_headers(sip_parser::HdrFlags::EOH).ok()?;
    ctx.msg.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name.as_bytes())).map(|h| String::from_utf8_lossy(h.body).trim().to_string())
}

/// Minimal XML helpers for the presence documents (no full parser: the
/// documents are generated or passed through, never transformed deeply).
pub(crate) mod xml {
    /// Inner content of the first `<tag …>…</tag>` (namespace prefixes allowed).
    pub fn inner<'a>(doc: &'a str, tag: &str) -> Option<&'a str> {
        let (s, e) = element(doc, tag, 0)?;
        let (open, rest) = doc.get(s..e)?.split_once('>')?;
        if open.ends_with('/') {
            return Some("");
        }
        rest.get(..rest.rfind("</")?)
    }

    /// (start, end) of the first element named `tag` at or after `from`.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "offsets are positions found inside doc (plus at most 2), so they stay below doc.len() + 2; depth counts tags of doc and is > 0 when decremented"
    )]
    pub fn element(doc: &str, tag: &str, from: usize) -> Option<(usize, usize)> {
        let mut i = from;
        while let Some(p) = doc.get(i..)?.find('<') {
            let s = i + p;
            let rest = doc.get(s + 1..)?;
            let name = rest.split(|c: char| c.is_whitespace() || c == '>' || c == '/').next().unwrap_or(rest);
            let local = name.rsplit(':').next().unwrap_or(name);
            if local == tag && !name.starts_with('/') {
                let open_end = s + 1 + rest.find('>')?;
                if doc.get(..open_end)?.ends_with('/') {
                    return Some((s, open_end + 1));
                }
                // Find the matching close tag (no nesting of the same name assumed beyond depth counting).
                let mut depth = 1usize;
                let mut j = open_end + 1;
                while depth > 0 {
                    let q = doc.get(j..)?.find('<')? + j;
                    let r = doc.get(q + 1..)?;
                    let (closing, r) = match r.strip_prefix('/') {
                        Some(x) => (true, x),
                        None => (false, r),
                    };
                    let n = r.split(|c: char| c.is_whitespace() || c == '>' || c == '/').next().unwrap_or(r);
                    let gt = q + 1 + usize::from(closing) + r.find('>')?;
                    if n.rsplit(':').next() == Some(tag) {
                        if closing {
                            depth -= 1;
                        } else if !doc.get(..gt)?.ends_with('/') {
                            depth += 1;
                        }
                    }
                    j = gt + 1;
                }
                return Some((s, j));
            }
            i = s + 1;
        }
        None
    }

    /// All elements named `tag` (whole text), in order.
    pub fn all(doc: &str, tag: &str) -> Vec<String> {
        let mut v = Vec::new();
        let mut i = 0;
        while let Some((s, e)) = element(doc, tag, i) {
            v.extend(doc.get(s..e).map(str::to_string));
            i = e;
        }
        v
    }

    /// Attribute value of the first `<tag …>`.
    pub fn attr(doc: &str, tag: &str, name: &str) -> Option<String> {
        let (s, _) = element(doc, tag, 0)?;
        let (open, _) = doc.get(s..)?.split_once('>')?;
        // `name=` right after whitespace: `id` is not the end of `call-id`.
        let pat = format!("{name}=");
        let mut rest = open;
        let value = loop {
            let (before, after) = rest.split_once(&pat)?;
            if before.ends_with(char::is_whitespace) {
                break after;
            }
            rest = after;
        };
        // The quote is whatever character follows `=`, which may be
        // non-ASCII when it comes from the wire.
        let mut chars = value.chars();
        let q = chars.next()?;
        let (v, _) = chars.as_str().split_once(q)?;
        Some(v.to_string())
    }

    /// The opening tag of the first `<tag …>` (without `>`), and whether it self-closes.
    pub fn open_tag(doc: &str, tag: &str) -> Option<String> {
        let (s, _) = element(doc, tag, 0)?;
        let (open, _) = doc.get(s..)?.split_once('>')?;
        Some(open.trim_end_matches('/').to_string())
    }

    pub fn escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn elements() {
            let d = r#"<?xml version="1.0"?><presence xmlns="urn:ietf:params:xml:ns:pidf" entity="sip:a@x"><tuple id="1"><status><basic>open</basic></status></tuple><tuple id="2"><status><basic>closed</basic></status></tuple><dm:person/></presence>"#;
            assert_eq!(all(d, "tuple").len(), 2);
            assert_eq!(inner(d, "basic"), Some("open"));
            assert_eq!(attr(d, "presence", "entity").as_deref(), Some("sip:a@x"));
            assert_eq!(all(d, "person"), vec!["<dm:person/>"]);
            assert!(inner(d, "presence").unwrap().starts_with("<tuple"));
        }

        #[test]
        fn attr_matches_the_whole_attribute_name() {
            let d = r#"<dialog call-id="c1" id="d1" local-tag="lt"><state>early</state></dialog>"#;
            assert_eq!(attr(d, "dialog", "id").as_deref(), Some("d1"));
            assert_eq!(attr(d, "dialog", "call-id").as_deref(), Some("c1"));
            assert_eq!(attr(d, "dialog", "tag"), None);
            assert_eq!(attr("<entry display-uri='x' uri='sip:b@x'/>", "entry", "uri").as_deref(), Some("sip:b@x"));
            // Only the opening tag counts.
            assert_eq!(attr("<tuple><note id=\"n\"/></tuple>", "tuple", "id"), None);
        }

        #[test]
        fn nested_and_prefixed_elements() {
            let d = "<a><b>1<b>2</b>3</b><b/><x:b k='v'>4</x:b></a>";
            assert_eq!(all(d, "b"), vec!["<b>1<b>2</b>3</b>", "<b/>", "<x:b k='v'>4</x:b>"]);
            assert_eq!(inner(d, "b"), Some("1<b>2</b>3"));
            assert_eq!(inner("<a><b/></a>", "b"), Some(""));
            assert_eq!(open_tag(d, "b").as_deref(), Some("<b"));
            assert_eq!(open_tag("<b k='v'/>", "b").as_deref(), Some("<b k='v'"));
            // Names that only start like the tag, closing tags, and unclosed elements.
            assert_eq!(all("<bb>1</bb><b>2</b>", "b"), vec!["<b>2</b>"]);
            assert_eq!(element("</b><b>x</b>", "b", 0), Some((4, 12)));
            assert_eq!(element("<b>never closed", "b", 0), None);
            assert_eq!(inner("<b", "b"), None);
            assert_eq!(element("<b>x</b>", "b", 100), None);
        }

        #[test]
        fn escape_covers_markup() {
            assert_eq!(escape(r#"<a href="x">&</a>"#), "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;");
        }

        #[test]
        fn non_ascii_does_not_panic() {
            // An unquoted attribute starting with a multi-byte character used
            // to panic (`&open[p + 1..]` inside the character).
            assert_eq!(attr("<tuple id=\u{e9}x\u{e9}></tuple>", "tuple", "id").as_deref(), Some("x"));
            assert_eq!(attr("<tuple id=\u{e9}x></tuple>", "tuple", "id"), None);
            let d = "<p><n\u{e9}>\u{e9}t\u{e9}</n\u{e9}><note xml:lang=\"fr\">\u{e9}t\u{e9}</note></p>";
            assert_eq!(inner(d, "note"), Some("\u{e9}t\u{e9}"));
            assert_eq!(attr(d, "note", "xml:lang").as_deref(), Some("fr"));
            assert_eq!(open_tag(d, "note").as_deref(), Some("<note xml:lang=\"fr\""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aor_is_user_at_lowercased_host() {
        let cases: &[(&str, Option<&str>)] = &[
            ("sip:Alice@EX.com:5070;transport=tcp", Some("sip:Alice@ex.com")),
            ("sips:bob@ex.com", Some("sip:bob@ex.com")),
            ("sip:ex.com", None),
            ("not a uri", None),
        ];
        for (uri, want) in cases {
            assert_eq!(aor(uri.as_bytes()).as_deref(), *want, "{uri}");
        }
    }

    #[test]
    fn every_name_is_a_module() {
        for n in NAMES {
            assert_eq!(module(n).map(|m| m.name()), Some(*n));
        }
        assert!(module("presence_reginfo").is_none());
    }
}
