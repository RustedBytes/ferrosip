//! HTTP Basic authentication: one user, a salted SHA-256 password hash
//! (`sha256:<salt>:<hex of sha256(salt ‖ password)>`, made by
//! `ferroctl webui-hash`), compared in constant time; repeated failures
//! from one address are refused for a while.

use sip_core::sync::lock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures allowed per address within [`WINDOW`] before it is refused.
const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(60);

pub struct Credentials {
    user: String,
    salt: Vec<u8>,
    digest: [u8; 32],
}

impl Credentials {
    /// From the `user` and `password_hash` parameters.
    pub fn new(user: &str, hash: &str) -> Result<Self, String> {
        let bad = || "webui: password_hash must look like sha256:<salt>:<64 hex digits> (ferroctl webui-hash <password>)".to_string();
        let mut it = hash.splitn(3, ':');
        let (Some("sha256"), Some(salt), Some(hex)) = (it.next(), it.next(), it.next()) else { return Err(bad()) };
        let digest = from_hex(hex).ok_or_else(bad)?;
        if user.is_empty() || user.contains(':') {
            return Err("webui: user must be non-empty and contain no ':'".into());
        }
        Ok(Credentials { user: user.to_string(), salt: salt.as_bytes().to_vec(), digest })
    }

    /// Checks an `Authorization` header value.
    pub fn check(&self, header: Option<&str>) -> bool {
        // The scheme name is case-insensitive (RFC 9110 §11.1).
        let Some(b64) = header.and_then(|h| h.get(..6).filter(|s| s.eq_ignore_ascii_case("basic ")).and(h.get(6..))) else { return false };
        let Some(raw) = base64_decode(b64.trim()) else { return false };
        let mut parts = raw.splitn(2, |&b| b == b':');
        let (Some(user), Some(pass)) = (parts.next(), parts.next()) else { return false };
        // Both comparisons always run: the time doesn't say which one failed.
        let user_ok = ct_eq(user, self.user.as_bytes());
        let pass_ok = ct_eq(&hash_password(&self.salt, pass), &self.digest);
        user_ok & pass_ok
    }
}

/// sha256(salt ‖ password).
pub fn hash_password(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(salt);
    ctx.update(password);
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Constant-time equality (length is not secret).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    let (pairs, []) = s.as_bytes().as_chunks::<2>() else { return None };
    if pairs.len() != 32 {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16);
    let mut out = [0u8; 32];
    for (o, &[hi, lo]) in out.iter_mut().zip(pairs) {
        *o = u8::try_from(nib(hi)? << 4 | nib(lo)?).ok()?;
    }
    Some(out)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let val = |c: u8| ALPHABET.iter().position(|&a| a == c).and_then(|v| u32::try_from(v).ok());
    let s = s.trim_end_matches('=').as_bytes();
    if s.len() > 1024 {
        return None;
    }
    let mut out = Vec::with_capacity((s.len() / 4).saturating_mul(3));
    for chunk in s.chunks(4) {
        // One character carries 6 bits: not a whole byte.
        if chunk.len() == 1 {
            return None;
        }
        // Four 6-bit values make 24 bits; k characters carry k - 1 bytes.
        let mut sextets = [0u32; 4];
        for (v, &c) in sextets.iter_mut().zip(chunk) {
            *v = val(c)?;
        }
        let [a, b, c, d] = sextets;
        let [_, bytes @ ..] = (a << 18 | b << 12 | c << 6 | d).to_be_bytes();
        out.extend(bytes.into_iter().take(chunk.len().saturating_sub(1)));
    }
    Some(out)
}

/// Failed logins per address: after [`MAX_FAILURES`] within [`WINDOW`],
/// the address is refused until the window has passed.
#[derive(Default)]
pub struct Throttle {
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Throttle {
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let g = lock(&self.failures);
        g.get(&ip).is_some_and(|&(n, since)| n >= MAX_FAILURES && since.elapsed() < WINDOW)
    }

    pub fn failed(&self, ip: IpAddr) {
        let mut g = lock(&self.failures);
        if g.len() > 10_000 {
            g.retain(|_, (_, since)| since.elapsed() < WINDOW);
        }
        let e = g.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() >= WINDOW {
            *e = (0, Instant::now());
        }
        e.0 = e.0.saturating_add(1);
    }

    pub fn succeeded(&self, ip: IpAddr) {
        lock(&self.failures).remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn basic_auth() {
        let h = format!("sha256:s4lt:{}", hex(&hash_password(b"s4lt", b"secret")));
        let c = Credentials::new("admin", &h).unwrap();
        // "admin:secret", "admin:wrong", "root:secret"
        assert!(c.check(Some("Basic YWRtaW46c2VjcmV0")));
        assert!(!c.check(Some("Basic YWRtaW46d3Jvbmc=")));
        assert!(!c.check(Some("Basic cm9vdDpzZWNyZXQ=")));
        assert!(!c.check(None));
        assert!(!c.check(Some("Bearer x")));
        assert!(!c.check(Some("Basic !!!")));
        assert!(Credentials::new("admin", "md5:x:y").is_err());
        assert!(Credentials::new("a:b", &h).is_err());
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("YWRtaW46c2VjcmV0").unwrap(), b"admin:secret");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI").unwrap(), b"ab");
        assert!(base64_decode("Y!==").is_none());
        assert_eq!(from_hex(&"0f".repeat(32)), Some([15; 32]));
        assert!(from_hex(&"0g".repeat(32)).is_none() && from_hex("0f").is_none());
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
    }

    #[test]
    fn throttle() {
        let t = Throttle::default();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(!t.blocked(ip));
            t.failed(ip);
        }
        assert!(t.blocked(ip));
        t.succeeded(ip);
        assert!(!t.blocked(ip));
    }

    fn creds(user: &str, salt: &str, password: &str) -> Credentials {
        Credentials::new(user, &format!("sha256:{salt}:{}", hex(&hash_password(salt.as_bytes(), password.as_bytes())))).unwrap()
    }

    #[test]
    fn password_hash_is_sha256_of_salt_then_password() {
        // sha256("abc"), FIPS 180-2 test vector.
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hex(&hash_password(b"a", b"bc")), want);
        assert_eq!(hex(&hash_password(b"", b"abc")), want);
        assert_eq!(hex(&hash_password(b"abc", b"")), want);
        let c = Credentials::new("u", &format!("sha256:a:{}", want.to_uppercase())).unwrap();
        assert!(c.check(Some("Basic dTpiYw==")), "u:bc with salt a; upper-case hex is accepted");
    }

    #[test]
    fn password_hash_format_is_checked() {
        let good = "0f".repeat(32);
        let cases: &[(&str, &str, bool)] = &[
            ("admin", &format!("sha256:salt:{good}"), true),
            ("admin", &format!("sha256::{good}"), true),
            ("admin", &format!("sha256:salt:{}", "0f".repeat(31)), false),
            ("admin", &format!("sha256:salt:{good}0"), false),
            ("admin", &format!("sha256:salt:{good}00"), false),
            ("admin", &format!("sha256:sa:lt:{good}"), false),
            ("admin", &format!("SHA256:salt:{good}"), false),
            ("admin", &format!("sha512:salt:{good}"), false),
            ("admin", &format!("sha256:{good}"), false),
            ("admin", "", false),
            ("admin", &format!("sha256:salt: {}", "0f".repeat(32).trim_start_matches('0')), false),
            ("", &format!("sha256:salt:{good}"), false),
            ("ad:min", &format!("sha256:salt:{good}"), false),
        ];
        for &(user, hash, ok) in cases {
            assert_eq!(Credentials::new(user, hash).is_ok(), ok, "user {user:?} hash {hash:?}");
        }
    }

    #[test]
    fn authorization_header_forms() {
        let c = creds("admin", "9f0c", "pa:ss word");
        let b64 = |s: &str| {
            const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for ch in s.as_bytes().chunks(3) {
                let n = ch.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
                for i in 0..4 {
                    out.push(if i <= ch.len() { char::from(A[(n >> (18 - 6 * i) & 63) as usize]) } else { '=' });
                }
            }
            out
        };
        let good = b64("admin:pa:ss word");
        let cases: &[(String, bool)] = &[
            (format!("Basic {good}"), true),
            (format!("basic {good}"), true),
            (format!("BASIC {good}"), true),
            (format!("Basic   {good}  "), true),
            (format!("Basic{good}"), false),
            (format!("Bearer {good}"), false),
            (good.clone(), false),
            (format!("Basic {}", b64("admin:pa:ss wor")), false),
            (format!("Basic {}", b64("Admin:pa:ss word")), false),
            (format!("Basic {}", b64("admin")), false),
            (format!("Basic {}", b64(":pa:ss word")), false),
            (format!("Basic {}", b64("admin:pa:ss word\0")), false),
            ("Basic ".to_string(), false),
            ("".to_string(), false),
        ];
        for (h, ok) in cases {
            assert_eq!(c.check(Some(h)), *ok, "Authorization: {h}");
        }
    }

    #[test]
    fn base64_decoder_cases() {
        let cases: &[(&str, Option<&[u8]>)] = &[
            ("", Some(b"")),
            ("TQ==", Some(b"M")),
            ("TWE=", Some(b"Ma")),
            ("TWFu", Some(b"Man")),
            ("TWFuTQ", Some(b"ManM")),
            ("+/+/", Some(&[0xfb, 0xff, 0xbf])),
            ("AAAA", Some(&[0, 0, 0])),
            ("TWFuT", None),
            ("T", None),
            ("TQ=a", None),
            ("TW-u", None),
            ("TW_u", None),
            ("TW u", None),
            ("TQ==TQ==", None),
        ];
        for &(input, want) in cases {
            assert_eq!(base64_decode(input).as_deref(), want, "base64_decode({input:?})");
        }
        assert!(base64_decode(&"A".repeat(1025)).is_none(), "over 1 KiB is refused");
        assert_eq!(base64_decode(&"A".repeat(1024)).map(|v| v.len()), Some(768));
    }

    #[test]
    fn hex_decoder_cases() {
        let mut ab = [0u8; 32];
        ab[0] = 0xab;
        ab[31] = 0xcd;
        let cases: &[(String, Option<[u8; 32]>)] = &[
            ("00".repeat(32), Some([0; 32])),
            ("ff".repeat(32), Some([255; 32])),
            ("FF".repeat(32), Some([255; 32])),
            (format!("ab{}cd", "00".repeat(30)), Some(ab)),
            ("0".repeat(63), None),
            ("0".repeat(65), None),
            ("00".repeat(33), None),
            (String::new(), None),
            (format!("{}+1", "00".repeat(31)), None),
            (format!("{}é", "00".repeat(31)), None),
        ];
        for (input, want) in cases {
            assert_eq!(from_hex(input), *want, "from_hex({input:?})");
        }
    }

    #[test]
    fn constant_time_compare_matches_equality() {
        let cases: &[(&[u8], &[u8])] = &[(b"", b""), (b"a", b"a"), (b"a", b"b"), (b"ab", b"a"), (b"\x01", b"\x81")];
        for &(a, b) in cases {
            assert_eq!(ct_eq(a, b), a == b, "{a:?} vs {b:?}");
        }
    }

    #[test]
    fn throttle_counts_per_address() {
        let t = Throttle::default();
        let (a, b): (IpAddr, IpAddr) = ("10.0.0.1".parse().unwrap(), "::1".parse().unwrap());
        for _ in 0..MAX_FAILURES - 1 {
            t.failed(a);
        }
        assert!(!t.blocked(a), "one below the limit");
        t.failed(a);
        assert!(t.blocked(a));
        assert!(!t.blocked(b), "other addresses are not affected");
        t.failed(a);
        assert!(t.blocked(a));
    }
}
