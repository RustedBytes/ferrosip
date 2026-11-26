use memchr::{memchr, memrchr};

/// `s` without leading ASCII whitespace.
#[inline]
pub fn trim_start(s: &[u8]) -> &[u8] {
    s.trim_ascii_start()
}

/// `s` without leading and trailing ASCII whitespace.
#[inline]
pub fn trim(s: &[u8]) -> &[u8] {
    s.trim_ascii()
}

/// Splits `s` around the first `sep`: the bytes before and after it.
#[inline]
pub fn split_once(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let (head, tail) = s.split_at_checked(memchr(sep, s)?)?;
    Some((head, tail.get(1..)?))
}

/// Splits `s` around the last `sep`: the bytes before and after it.
#[inline]
pub fn rsplit_once(s: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let (head, tail) = s.split_at_checked(memrchr(sep, s)?)?;
    Some((head, tail.get(1..)?))
}

/// The first line of `s`, including its `\n`; `None` if `s` has no `\n`.
#[inline]
pub fn first_line(s: &[u8]) -> Option<&[u8]> {
    s.get(..=memchr(b'\n', s)?)
}

/// `host`, `host:port`, `[v6]`, `[v6]:port`
pub fn split_host_port(s: &[u8]) -> (&[u8], Option<u16>) {
    let (host, port) = if s.first() == Some(&b'[') {
        // The host runs up to and including the `]` (all of `s` without one).
        let host = s.split_inclusive(|&c| c == b']').next().unwrap_or(s);
        (host, s.get(host.len()..).and_then(|r| r.strip_prefix(b":")))
    } else {
        rsplit_once(s, b':').map_or((s, None), |(host, port)| (host, Some(port)))
    };
    (host, port.and_then(parse_u32).and_then(|p| u16::try_from(p).ok()))
}

/// A decimal of 1–9 digits (no sign, no spaces).
#[inline]
pub fn parse_u32(s: &[u8]) -> Option<u32> {
    // Up to 10 digits: all of u32 (Expires: 4294967295 is valid and is
    // capped later, as in Kamailio); checked arithmetic refuses the rest.
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    s.iter().try_fold(0u32, |acc, &c| {
        let digit = c.checked_sub(b'0').filter(|d| *d <= 9)?;
        acc.checked_mul(10)?.checked_add(u32::from(digit))
    })
}
