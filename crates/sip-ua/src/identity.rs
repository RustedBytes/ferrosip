//! Trusted identity (RFC 3325 P-Asserted-Identity) and privacy (RFC 3323)
//! by explicit policy.
//!
//! An asserted identity is only believed from, and only sent to, hosts in
//! the trust domain configured here. Nothing is forwarded blindly: the
//! engine never copies headers between legs, inbound P-Asserted-Identity
//! from an untrusted source is not surfaced as an identity, and an
//! outbound one is removed whenever the next hop is not trusted.

use std::net::IpAddr;

/// The trust domain: networks (CIDR) whose P-Asserted-Identity we accept
/// and to which we send ours.
#[derive(Clone, Debug, Default)]
pub struct TrustPolicy {
    networks: Vec<(IpAddr, u8)>,
}

impl TrustPolicy {
    /// `["10.0.0.0/8", "192.0.2.7", "2001:db8::/32"]`.
    pub fn new<I: IntoIterator<Item = S>, S: AsRef<str>>(cidrs: I) -> Result<Self, String> {
        let networks = cidrs.into_iter().map(|c| parse_cidr(c.as_ref())).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { networks })
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|&(net, len)| contains(net, len, ip))
    }
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    let (ip, len) = s.split_once('/').map_or((s, None), |(i, l)| (i, Some(l)));
    let ip: IpAddr = ip.trim().parse().map_err(|_| format!("bad address in {s:?}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(l) => l.trim().parse::<u8>().ok().filter(|l| *l <= max).ok_or_else(|| format!("bad prefix in {s:?}"))?,
        None => max,
    };
    Ok((ip, len))
}

fn contains(net: IpAddr, len: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = u32::MAX.checked_shl(u32::from(32u8.saturating_sub(len))).unwrap_or(0);
            u32::from(n) & mask == u32::from(i) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = u128::MAX.checked_shl(u32::from(128u8.saturating_sub(len))).unwrap_or(0);
            u128::from(n) & mask == u128::from(i) & mask
        }
        _ => false,
    }
}

/// RFC 3323 §4.2 priv-values (plus RFC 3325's `id`).
pub const PRIVACY_VALUES: &[&str] = &["header", "session", "user", "none", "critical", "id"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let p = TrustPolicy::new(["10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "0.0.0.0/0"]).unwrap();
        assert!(p.is_trusted("10.9.8.7".parse().unwrap()));
        assert!(p.is_trusted("2001:db8::1".parse().unwrap()));
        let q = TrustPolicy::new(["10.0.0.0/8", "192.0.2.7"]).unwrap();
        assert!(!q.is_trusted("11.0.0.1".parse().unwrap()));
        assert!(q.is_trusted("192.0.2.7".parse().unwrap()));
        assert!(!q.is_trusted("192.0.2.8".parse().unwrap()));
        assert!(TrustPolicy::new(["10.0.0.0/33"]).is_err());
        assert!(!TrustPolicy::default().is_trusted("127.0.0.1".parse().unwrap()));
    }
}
