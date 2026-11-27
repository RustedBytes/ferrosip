//! Client-side digest authentication (RFC 3261 §22, RFC 7616 / RFC 8760).
//!
//! Credentials belong to one leg: they are never shared between legs, never
//! logged (`Debug` redacts the password) and never sent to a realm other
//! than the one configured (when a realm is configured).

use crate::msg::SipMessage;
use md5::{Digest as _, Md5};
use std::fmt;

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    /// Only answer challenges from this realm (None: any realm).
    pub realm: Option<String>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials").field("username", &self.username).field("password", &"<redacted>").field("realm", &self.realm).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alg {
    Md5,
    Sha256,
    Sha512_256,
}

impl Alg {
    fn hex(self, parts: &[&str]) -> String {
        let joined = parts.join(":");
        let bytes: Vec<u8> = match self {
            Alg::Md5 => Md5::digest(joined.as_bytes()).to_vec(),
            Alg::Sha256 => ring::digest::digest(&ring::digest::SHA256, joined.as_bytes()).as_ref().to_vec(),
            Alg::Sha512_256 => ring::digest::digest(&ring::digest::SHA512_256, joined.as_bytes()).as_ref().to_vec(),
        };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn token(self, sess: bool) -> String {
        let t = match self {
            Alg::Md5 => "MD5",
            Alg::Sha256 => "SHA-256",
            Alg::Sha512_256 => "SHA-512-256",
        };
        if sess { format!("{t}-sess") } else { t.to_string() }
    }
}

/// A parameter of a challenge (`key="value"` or `key=value`).
fn chal_param(ch: &str, key: &str) -> Option<String> {
    let body = ch.trim_start().get(6..)?;
    crate::msg::split_values(body).into_iter().find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        k.trim().eq_ignore_ascii_case(key).then(|| v.trim().trim_matches('"').to_string())
    })
}

fn challenge_alg(ch: &str) -> Option<(Alg, bool)> {
    if !ch.trim_start().get(..6)?.eq_ignore_ascii_case("digest") {
        return None;
    }
    let a = chal_param(ch, "algorithm").unwrap_or_else(|| "MD5".into()).to_ascii_uppercase();
    let (base, sess) = a.strip_suffix("-SESS").map_or((a.as_str(), false), |b| (b, true));
    let alg = match base {
        "MD5" => Alg::Md5,
        "SHA-256" => Alg::Sha256,
        "SHA-512-256" => Alg::Sha512_256,
        _ => return None,
    };
    Some((alg, sess))
}

/// The realm of the challenge we would answer in `resp` (401/407).
pub fn challenge_realm(resp: &SipMessage, creds: &Credentials) -> Option<String> {
    pick(resp, creds).map(|(_, realm, _)| realm)
}

/// (challenge, realm, authorization header name)
fn pick(resp: &SipMessage, creds: &Credentials) -> Option<(String, String, &'static str)> {
    let (chal_hdr, auth_hdr) = match resp.status()? {
        401 => ("WWW-Authenticate", "Authorization"),
        407 => ("Proxy-Authenticate", "Proxy-Authorization"),
        _ => return None,
    };
    // Servers list challenges in order of preference (RFC 8760).
    resp.header_lines(chal_hdr).find_map(|ch| {
        challenge_alg(ch)?;
        chal_param(ch, "nonce")?;
        let realm = chal_param(ch, "realm")?;
        creds.realm.as_ref().is_none_or(|r| r == &realm).then(|| (ch.to_string(), realm, auth_hdr))
    })
}

/// The header (name, value) answering the challenge in `resp` for a request
/// `method uri`, or None when no challenge is acceptable.
pub fn authorize(resp: &SipMessage, creds: &Credentials, method: &str, uri: &str, cnonce: &str) -> Option<(&'static str, String)> {
    let (ch, realm, hdr) = pick(resp, creds)?;
    let (alg, sess) = challenge_alg(&ch)?;
    let nonce = chal_param(&ch, "nonce")?;
    let qop = chal_param(&ch, "qop").filter(|q| q.split(',').any(|x| x.trim() == "auth"));
    let opaque = chal_param(&ch, "opaque");
    let user = &creds.username;
    let mut ha1 = alg.hex(&[user, &realm, &creds.password]);
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
    Some((hdr, h))
}

/// The challenge says `stale=true`: the nonce expired, the password was fine.
pub fn is_stale(resp: &SipMessage) -> bool {
    resp.header_lines("WWW-Authenticate")
        .chain(resp.header_lines("Proxy-Authenticate"))
        .any(|c| chal_param(c, "stale").is_some_and(|s| s.eq_ignore_ascii_case("true")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials { username: "Mufasa".into(), password: "Circle Of Life".into(), realm: None }
    }

    #[test]
    fn rfc2617_example_without_qop() {
        let mut r = SipMessage::response(401, "Unauthorized");
        r.push_header(
            "WWW-Authenticate",
            "Digest realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        );
        let (h, v) = authorize(&r, &creds(), "GET", "/dir/index.html", "0a4f113b").unwrap();
        assert_eq!(h, "Authorization");
        // No qop (RFC 2069 compatibility): response = MD5(HA1:nonce:HA2), checked against Python hashlib.
        assert!(v.contains("response=\"670fd8c2df070c60b045671b8b24ff02\""), "{v}");
        assert!(v.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    }

    #[test]
    fn rfc2617_example_with_qop() {
        let mut r = SipMessage::response(407, "Proxy Authentication Required");
        r.push_header("Proxy-Authenticate", "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");
        let (h, v) = authorize(&r, &creds(), "GET", "/dir/index.html", "0a4f113b").unwrap();
        assert_eq!(h, "Proxy-Authorization");
        assert!(v.contains("response=\"6629fae49393a05397450978507c4ef1\""), "{v}");
    }

    #[test]
    fn realm_restriction_and_unknown_algorithms() {
        let mut r = SipMessage::response(401, "Unauthorized");
        r.push_header("WWW-Authenticate", "Digest realm=\"other\", nonce=\"n\", algorithm=SHA-256, stale=TRUE");
        let mut c = creds();
        c.realm = Some("mine".into());
        assert!(authorize(&r, &c, "INVITE", "sip:x", "c").is_none());
        c.realm = Some("other".into());
        assert!(authorize(&r, &c, "INVITE", "sip:x", "c").unwrap().1.contains("algorithm=SHA-256"));
        assert!(is_stale(&r));
        let mut r2 = SipMessage::response(401, "Unauthorized");
        r2.push_header("WWW-Authenticate", "Digest realm=\"x\", nonce=\"n\", algorithm=AKAv1-MD5");
        assert!(authorize(&r2, &creds(), "INVITE", "sip:x", "c").is_none());
        assert!(!format!("{:?}", creds()).contains("Circle"));
    }
}
