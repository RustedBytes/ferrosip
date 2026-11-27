//! RFC 3891 `Replaces` and RFC 3515 `Refer-To` helpers.

use crate::ids::SipDialogId;
use crate::msg::uri_of;

/// A `Replaces` header: the dialog to replace, **from the point of view of
/// the UA that receives the INVITE** (its local tag is `to_tag`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replaces {
    pub call_id: String,
    pub to_tag: String,
    pub from_tag: String,
    /// Only replace an early dialog (RFC 3891 §3).
    pub early_only: bool,
}

impl Replaces {
    /// `call-id;to-tag=x;from-tag=y[;early-only]`.
    pub fn parse(v: &str) -> Option<Self> {
        let mut parts = v.split(';');
        let call_id = parts.next()?.trim().to_string();
        if call_id.is_empty() {
            return None;
        }
        let (mut to_tag, mut from_tag, mut early_only) = (None, None, false);
        for p in parts {
            let (k, val) = p.split_once('=').map_or((p.trim(), ""), |(k, v)| (k.trim(), v.trim()));
            if k.eq_ignore_ascii_case("to-tag") {
                to_tag = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("from-tag") {
                from_tag = Some(val.to_string());
            } else if k.eq_ignore_ascii_case("early-only") {
                early_only = true;
            }
        }
        Some(Self { call_id, to_tag: to_tag.filter(|t| !t.is_empty())?, from_tag: from_tag.filter(|t| !t.is_empty())?, early_only })
    }

    pub fn to_header(&self) -> String {
        let mut s = format!("{};to-tag={};from-tag={}", self.call_id, self.to_tag, self.from_tag);
        if self.early_only {
            s.push_str(";early-only");
        }
        s
    }

    /// What the *peer* of our dialog `d` must find in a Replaces naming it
    /// (attended transfer: the transferor names its consultation dialog for
    /// the transfer target, whose local tag is our remote tag).
    pub fn for_peer_of(d: &SipDialogId) -> Self {
        Self { call_id: d.call_id.clone(), to_tag: d.remote_tag.clone(), from_tag: d.local_tag.clone(), early_only: false }
    }
}

fn unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&c)
}

/// Percent-encode for a URI header value (RFC 3261 §19.1.1).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.bytes() {
        if unreserved(c) {
            out.push(char::from(c));
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

fn unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = s.get(i.checked_add(1)?..i.checked_add(3)?)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i = i.checked_add(3)?;
        } else {
            out.push(c);
            i = i.checked_add(1)?;
        }
    }
    String::from_utf8(out).ok()
}

/// `<target?Replaces=…>` for an attended transfer's REFER.
pub fn refer_to_with_replaces(target_uri: &str, r: &Replaces) -> String {
    format!("<{}?Replaces={}>", target_uri.trim().trim_start_matches('<').trim_end_matches('>'), escape(&r.to_header()))
}

/// A Refer-To value split into the target URI (without URI headers) and
/// the embedded `Replaces`, if any. None: not a usable SIP/SIPS/TEL URI.
pub fn split_refer_to(v: &str) -> Option<(String, Option<Replaces>)> {
    let uri = uri_of(v);
    let (target, headers) = uri.split_once('?').map_or((uri.as_str(), ""), |(t, h)| (t, h));
    let scheme = target.split(':').next().unwrap_or_default();
    if !["sip", "sips", "tel"].iter().any(|s| scheme.eq_ignore_ascii_case(s)) || target.len() <= scheme.len().saturating_add(1) {
        return None;
    }
    let mut replaces = None;
    for h in headers.split('&').filter(|h| !h.is_empty()) {
        if let Some((k, val)) = h.split_once('=')
            && k.eq_ignore_ascii_case("Replaces")
        {
            replaces = Some(Replaces::parse(&unescape(val)?)?);
        }
    }
    Some((target.to_string(), replaces))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_round_trip_through_refer_to() {
        let d = SipDialogId { call_id: "abc@10.0.0.1".into(), local_tag: "mine".into(), remote_tag: "theirs".into() };
        let r = Replaces::for_peer_of(&d);
        assert_eq!(r.to_header(), "abc@10.0.0.1;to-tag=theirs;from-tag=mine");
        let rt = refer_to_with_replaces("sip:carol@10.0.0.3", &r);
        assert_eq!(rt, "<sip:carol@10.0.0.3?Replaces=abc%4010.0.0.1%3Bto-tag%3Dtheirs%3Bfrom-tag%3Dmine>");
        let (target, back) = split_refer_to(&rt).unwrap();
        assert_eq!(target, "sip:carol@10.0.0.3");
        assert_eq!(back, Some(r));
        assert_eq!(split_refer_to("<sip:bob@x>"), Some(("sip:bob@x".into(), None)));
        assert_eq!(split_refer_to("<http://x>"), None);
        assert_eq!(split_refer_to("<sip:bob@x?Replaces=%ZZ>"), None);
        assert!(Replaces::parse("c;to-tag=a;from-tag=b;early-only").unwrap().early_only);
        assert_eq!(Replaces::parse("c;to-tag=a"), None);
    }
}
