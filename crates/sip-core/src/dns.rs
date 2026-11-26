//! DNS for SIP (RFC 3263): a minimal DNS-over-UDP client (A, AAAA, SRV,
//! NAPTR) with a TTL cache, and `resolve_uri`, which turns the host part of
//! a SIP URI into an ordered list of next hops: NAPTR → SRV → A/AAAA.
//! Kamailio: `resolve.c` + `dns_cache.c` + `srv` / `naptr` lookups in
//! `forward.c`.
//!
//! Names listed in `/etc/hosts` (e.g. `localhost`) and IP literals never
//! hit DNS. A/AAAA come from the SRV answer's additional section when
//! present, then from the configured nameserver, then from the system
//! resolver (`getaddrinfo`).

use crate::ShardedMap;
use crate::net::{Dest, Proto};
use crate::sync::{read, write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub const T_A: u16 = 1;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_NAPTR: u16 = 35;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Naptr {
    pub order: u16,
    pub pref: u16,
    pub flags: String,
    pub services: String,
    pub regexp: String,
    pub replacement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv {
    pub prio: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rdata {
    Addr(IpAddr),
    Srv(Srv),
    Naptr(Naptr),
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub ty: u16,
    pub ttl: u32,
    pub data: Rdata,
}

/// Answers and additional records of one response.
#[derive(Clone, Debug, Default)]
pub struct Response {
    pub rcode: u8,
    /// TC bit: the answer didn't fit in UDP (retry over TCP).
    pub truncated: bool,
    pub answers: Vec<Record>,
    pub additional: Vec<Record>,
}

pub fn qname(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        // A DNS label is at most 63 octets; longer ones are cut.
        let label = l.as_bytes().get(..63).unwrap_or(l.as_bytes());
        v.push(u8::try_from(label.len()).unwrap_or(63));
        v.extend_from_slice(label);
    }
    v.push(0);
    v
}

/// The bytes after the (possibly compressed) name at the start of `b`.
fn skip_name(mut b: &[u8]) -> Option<&[u8]> {
    loop {
        match *b {
            [0, ref rest @ ..] => return Some(rest),
            // A pointer ends the name.
            [l, _, ref rest @ ..] if l & 0xc0 == 0xc0 => return Some(rest),
            [l, ref rest @ ..] => b = rest.get(usize::from(l)..)?,
            [] => return None,
        }
    }
}

/// The name at offset `i` of the message `p`.
pub fn read_name(p: &[u8], i: usize) -> Option<String> {
    name_at(p, p.get(i..)?)
}

/// The name at the start of `b`, a tail of the message `p` (compression
/// pointers are offsets into `p`).
fn name_at<'p>(p: &'p [u8], mut b: &'p [u8]) -> Option<String> {
    let mut labels = Vec::new();
    for _ in 0..64 {
        match *b {
            [] => return None,
            [0, ..] => break,
            [l, lo, ..] if l & 0xc0 == 0xc0 => b = p.get(usize::from(u16::from_be_bytes([l & 0x3f, lo]))..)?,
            [l, ref rest @ ..] => {
                let (label, rest) = rest.split_at_checked(usize::from(l))?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                b = rest;
            }
        }
    }
    Some(labels.join("."))
}

/// A `<character-string>` at the start of `b`, and the bytes after it.
fn char_string(b: &[u8]) -> Option<(String, &[u8])> {
    let (&l, rest) = b.split_first()?;
    let (s, rest) = rest.split_at_checked(usize::from(l))?;
    Some((String::from_utf8_lossy(s).into_owned(), rest))
}

fn be16(b: &[u8]) -> Option<u16> {
    b.first_chunk().map(|c| u16::from_be_bytes(*c))
}

/// The resource record at the start of `b` (a tail of the message `p`),
/// and the bytes after it.
fn record<'p>(p: &'p [u8], b: &'p [u8]) -> Option<(Record, &'p [u8])> {
    let name = name_at(p, b)?;
    let (fixed, rd) = skip_name(b)?.split_first_chunk::<10>()?;
    let [t0, t1, _class0, _class1, l0, l1, l2, l3, r0, r1] = *fixed;
    let ty = u16::from_be_bytes([t0, t1]);
    let ttl = u32::from_be_bytes([l0, l1, l2, l3]);
    let (raw, after) = rd.split_at_checked(usize::from(u16::from_be_bytes([r0, r1])))?;
    // The fields of SRV and NAPTR are read from `rd` (the rdata and on).
    let field = |at: usize| be16(rd.get(at..)?);
    let data = match ty {
        T_A if let Ok(a) = <[u8; 4]>::try_from(raw) => Rdata::Addr(IpAddr::from(a)),
        T_AAAA if let Ok(a) = <[u8; 16]>::try_from(raw) => Rdata::Addr(IpAddr::from(a)),
        T_SRV => Rdata::Srv(Srv { prio: field(0)?, weight: field(2)?, port: field(4)?, target: name_at(p, rd.get(6..)?)? }),
        T_NAPTR => {
            let (flags, rest) = char_string(rd.get(4..)?)?;
            let (services, rest) = char_string(rest)?;
            let (regexp, rest) = char_string(rest)?;
            Rdata::Naptr(Naptr { order: field(0)?, pref: field(2)?, flags, services, regexp, replacement: name_at(p, rest)? })
        }
        _ => Rdata::Other,
    };
    Some((Record { name: name.to_ascii_lowercase(), ty, ttl, data }, after))
}

/// Parse a response to query `id`.
pub fn parse(p: &[u8], id: u16) -> Option<Response> {
    let [i0, i1, f0, f1, q0, q1, a0, a1, n0, n1, r0, r1, ref body @ ..] = *p else { return None };
    if u16::from_be_bytes([i0, i1]) != id || f0 & 0x80 == 0 {
        return None;
    }
    let count = |hi, lo| u16::from_be_bytes([hi, lo]);
    let mut b = body;
    for _ in 0..count(q0, q1) {
        // name, QTYPE, QCLASS
        b = skip_name(b)?.get(4..).unwrap_or_default();
    }
    let mut r = Response { rcode: f1 & 0x0f, truncated: f0 & 0x02 != 0, ..Default::default() };
    // Answer, authority (skipped) and additional sections, in that order.
    'records: for (n, mut keep) in [(count(a0, a1), Some(&mut r.answers)), (count(n0, n1), None), (count(r0, r1), Some(&mut r.additional))] {
        for _ in 0..n {
            let Some((rec, next)) = record(p, b) else { break 'records };
            b = next;
            if let Some(k) = keep.as_mut() {
                k.push(rec);
            }
        }
    }
    Some(r)
}

pub fn build_query(id: u16, name: &str, ty: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    q.extend_from_slice(&qname(name));
    q.extend_from_slice(&ty.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

/// One query over UDP (2 tries, `timeout` each).
pub fn query(server: SocketAddr, name: &str, ty: u16, id: u16, timeout: Duration) -> Option<Response> {
    let q = build_query(id, name, ty);
    let s = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    let mut buf = [0u8; 4096];
    for _ in 0..2 {
        s.send_to(&q, server).ok()?;
        // No deadline for a timeout beyond the clock: the read timeout still applies.
        let deadline = Instant::now().checked_add(timeout);
        while let Ok((n, from)) = s.recv_from(&mut buf) {
            if from == server
                && let Some(r) = buf.get(..n).and_then(|b| parse(b, id))
            {
                if r.truncated {
                    return query_tcp(server, &q, id, timeout).or(Some(r));
                }
                return Some(r);
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
        }
    }
    None
}

/// The same query over TCP (RFC 1035 §4.2.2: 2-byte length prefix).
fn query_tcp(server: SocketAddr, q: &[u8], id: u16, timeout: Duration) -> Option<Response> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(&server, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let mut out = u16::try_from(q.len()).ok()?.to_be_bytes().to_vec();
    out.extend_from_slice(q);
    s.write_all(&out).ok()?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).ok()?;
    parse(&buf, id)
}

pub fn system_nameserver() -> Option<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let ip: IpAddr = conf.lines().find_map(|l| l.trim().strip_prefix("nameserver"))?.trim().parse().ok()?;
    Some(SocketAddr::new(ip, 53))
}

fn etc_hosts() -> &'static Vec<String> {
    static H: OnceLock<Vec<String>> = OnceLock::new();
    H.get_or_init(|| {
        let t = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        t.lines().filter_map(|l| l.split('#').next()).flat_map(|l| l.split_whitespace().skip(1).map(str::to_ascii_lowercase).collect::<Vec<_>>()).collect()
    })
}

/// Records of (name, type) and when they expire.
type Cached = (Arc<Vec<Record>>, Instant);

/// A next hop from DNS, with how it was found (for failover decisions).
pub type Targets = Vec<Dest>;

/// The process-wide resolver (Kamailio's DNS cache).
pub struct Resolver {
    server: RwLock<Option<SocketAddr>>,
    explicit: AtomicBool,
    cache: ShardedMap<(Box<str>, u16), Cached>,
    /// Names come from received messages (and failures are cached too):
    /// without a bound, random host names grew the cache forever.
    bound: crate::shm::Bounded,
    id: AtomicU16,
    rnd: AtomicU64,
    /// Weighted random order among SRV records of the same priority
    /// (`dns_srv_lb`); else by weight, highest first.
    pub srv_lb: AtomicBool,
    /// Try NAPTR before SRV when the URI has neither port nor transport.
    pub try_naptr: AtomicBool,
    /// Do SRV lookups at all (`dns_srv_lookup`, default on).
    pub srv_lookup: AtomicBool,
    timeout_ms: AtomicU64,
    neg_ttl: AtomicU64,
}

pub fn resolver() -> &'static Resolver {
    static R: OnceLock<Resolver> = OnceLock::new();
    R.get_or_init(|| Resolver {
        server: RwLock::new(None),
        explicit: AtomicBool::new(false),
        cache: ShardedMap::new(64),
        bound: crate::shm::Bounded::new(65_536),
        id: AtomicU16::new(0x5151),
        rnd: AtomicU64::new(0x9E37_79B9_7F4A_7C15 ^ u64::from(std::process::id())),
        srv_lb: AtomicBool::new(false),
        try_naptr: AtomicBool::new(false),
        srv_lookup: AtomicBool::new(true),
        timeout_ms: AtomicU64::new(1000),
        neg_ttl: AtomicU64::new(60),
    })
}

/// A target without a port: 5061 over TLS (and WSS), else 5060, as
/// `pvcore::dest_from_uri` does (Kamailio's resolve.c: SIPS_PORT for TLS,
/// SIP_PORT otherwise).
fn default_port(p: Proto) -> u16 {
    if p.is_tls() { 5061 } else { 5060 }
}

impl Resolver {
    /// Nameserver to use (`ip[:port]`); `None` = the first one of resolv.conf.
    pub fn set_server(&self, s: Option<SocketAddr>) {
        self.explicit.store(s.is_some(), Ordering::Relaxed);
        *write(&self.server) = s;
    }

    pub fn set_timeout(&self, ms: u64) {
        self.timeout_ms.store(ms.max(50), Ordering::Relaxed);
    }

    pub fn set_negative_ttl(&self, s: u64) {
        self.neg_ttl.store(s, Ordering::Relaxed);
    }

    fn server(&self) -> Option<SocketAddr> {
        let s = *read(&self.server);
        s.or_else(system_nameserver)
    }

    fn next_id(&self) -> u16 {
        self.id.fetch_add(1, Ordering::Relaxed)
    }

    fn rand(&self) -> u64 {
        // xorshift64*; good enough for load balancing.
        let mut x = self.rnd.load(Ordering::Relaxed);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rnd.store(x, Ordering::Relaxed);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The negative-cache TTL in seconds (clamped to what a DNS TTL can hold).
    fn neg_ttl(&self) -> u32 {
        u32::try_from(self.neg_ttl.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    fn put(&self, name: &str, ty: u16, recs: Vec<Record>, ttl: u32) {
        let now = Instant::now();
        if let Some(exp) = now.checked_add(Duration::from_secs(u64::from(ttl)))
            && self.bound.admit(&self.cache, |(_, exp)| now >= *exp)
        {
            self.cache.insert((name.to_ascii_lowercase().into(), ty), (Arc::new(recs), exp));
        }
    }

    /// Clear the cache (RPC `dns.flush`).
    pub fn flush(&self) {
        self.cache.retain(|_, _| false);
    }

    /// Records of `name`/`ty` (cached by TTL; failures cached `neg_ttl`).
    pub fn lookup(&self, name: &str, ty: u16) -> Arc<Vec<Record>> {
        let key: (Box<str>, u16) = (name.trim_end_matches('.').to_ascii_lowercase().into(), ty);
        if let Some((r, exp)) = self.cache.get_cloned(&key)
            && Instant::now() < exp
        {
            return r;
        }
        let timeout = Duration::from_millis(self.timeout_ms.load(Ordering::Relaxed));
        let resp = self.server().and_then(|s| query(s, &key.0, ty, self.next_id(), timeout));
        let Some(resp) = resp else {
            self.put(&key.0, ty, Vec::new(), self.neg_ttl());
            return Arc::new(Vec::new());
        };
        // Glue: A/AAAA in the additional section saves the next queries.
        let mut glue: Vec<(String, u16, Vec<Record>)> = Vec::new();
        for r in resp.additional.iter().filter(|r| matches!(r.ty, T_A | T_AAAA)) {
            match glue.iter_mut().find(|g| g.0 == r.name && g.1 == r.ty) {
                Some(g) => g.2.push(r.clone()),
                None => glue.push((r.name.clone(), r.ty, vec![r.clone()])),
            }
        }
        for (n, t, recs) in glue {
            let ttl = recs.iter().map(|r| r.ttl).min().unwrap_or(60);
            self.put(&n, t, recs, ttl);
        }
        let recs: Vec<Record> = resp.answers.into_iter().filter(|r| r.ty == ty).collect();
        let ttl = if recs.is_empty() { self.neg_ttl() } else { recs.iter().map(|r| r.ttl).min().unwrap_or(60) };
        self.put(&key.0, ty, recs.clone(), ttl);
        Arc::new(recs)
    }

    /// Addresses of a host: IP literal, /etc/hosts, cache/DNS (A then AAAA),
    /// then the system resolver.
    pub fn host_addrs(&self, host: &str) -> Vec<IpAddr> {
        let h = host.trim_matches(|c| c == '[' || c == ']');
        if let Ok(ip) = h.parse::<IpAddr>() {
            return vec![ip];
        }
        let lower = h.trim_end_matches('.').to_ascii_lowercase();
        let in_hosts = etc_hosts().contains(&lower);
        if !in_hosts {
            let cached = |ty| self.cache.get_cloned(&(Box::<str>::from(lower.as_str()), ty)).filter(|(r, e)| Instant::now() < *e && !r.is_empty());
            let mut v: Vec<IpAddr> = Vec::new();
            for ty in [T_A, T_AAAA] {
                if let Some((r, _)) = cached(ty) {
                    v.extend(r.iter().filter_map(|r| if let Rdata::Addr(a) = r.data { Some(a) } else { None }));
                }
            }
            if v.is_empty() && self.explicit.load(Ordering::Relaxed) {
                v.extend(self.lookup(&lower, T_A).iter().filter_map(|r| if let Rdata::Addr(a) = r.data { Some(a) } else { None }));
                if v.is_empty() {
                    v.extend(self.lookup(&lower, T_AAAA).iter().filter_map(|r| if let Rdata::Addr(a) = r.data { Some(a) } else { None }));
                }
            }
            if !v.is_empty() {
                return v;
            }
        }
        let mut v: Vec<IpAddr> = (lower.as_str(), 0).to_socket_addrs().map(|it| it.map(|a| a.ip()).collect()).unwrap_or_default();
        v.sort_by_key(|a| !a.is_ipv4()); // listeners are usually v4
        v.dedup();
        v
    }

    /// SRV records ordered for use (RFC 2782).
    pub fn srv(&self, name: &str) -> Vec<Srv> {
        let mut recs: Vec<Srv> = self.lookup(name, T_SRV).iter().filter_map(|r| if let Rdata::Srv(s) = &r.data { Some(s.clone()) } else { None }).collect();
        recs.retain(|s| s.target != "." && !s.target.is_empty());
        recs.sort_by_key(|s| (s.prio, std::cmp::Reverse(s.weight)));
        if !self.srv_lb.load(Ordering::Relaxed) {
            return recs;
        }
        // Weighted random selection within each priority.
        let mut out = Vec::with_capacity(recs.len());
        // Weight 0 still gets a (small) chance: every record counts weight + 1.
        let weight = |s: &Srv| u64::from(s.weight).saturating_add(1);
        for same_prio in recs.chunk_by(|a, b| a.prio == b.prio) {
            let mut group = same_prio.to_vec();
            while !group.is_empty() {
                let total: u64 = group.iter().map(weight).sum();
                let mut r = self.rand().checked_rem(total).unwrap_or(0);
                // The first record whose weight covers what is left of r.
                let k = group
                    .iter()
                    .position(|s| match r.checked_sub(weight(s)) {
                        Some(left) => {
                            r = left;
                            false
                        }
                        None => true,
                    })
                    .unwrap_or(0);
                out.push(group.remove(k));
            }
        }
        out
    }

    fn srv_targets(&self, name: &str, proto: Proto, out: &mut Targets) {
        for s in self.srv(name) {
            for ip in self.host_addrs(&s.target) {
                let d = Dest::new(proto, SocketAddr::new(ip, s.port));
                if !out.contains(&d) {
                    out.push(d);
                }
            }
        }
    }

    /// RFC 3263 §4: next hops for a URI host. `proto` is the URI's
    /// `;transport=` (None = not given), `secure` a `sips:` URI.
    pub fn resolve_uri(&self, host: &str, port: Option<u16>, proto: Option<Proto>, secure: bool) -> Targets {
        let out = self.resolve_uri_x(host, port, proto, secure);
        let h = host.trim_matches(|c| c == '[' || c == ']');
        if h.parse::<IpAddr>().is_err() {
            for d in out.iter().filter(|d| d.proto.is_tls()) {
                crate::net::set_tls_name(d.addr, h.trim_end_matches('.'));
            }
        }
        out
    }

    fn resolve_uri_x(&self, host: &str, port: Option<u16>, proto: Option<Proto>, secure: bool) -> Targets {
        let h = host.trim_matches(|c| c == '[' || c == ']');
        let fixed = proto.unwrap_or(if secure { Proto::Tls } else { Proto::Udp });
        let numeric = h.parse::<IpAddr>().is_ok();
        let lower = h.trim_end_matches('.').to_ascii_lowercase();
        let plain =
            |p: Proto| -> Targets { self.host_addrs(h).into_iter().map(|ip| Dest::new(p, SocketAddr::new(ip, port.unwrap_or(default_port(p))))).collect() };
        if numeric || port.is_some() || !self.srv_lookup.load(Ordering::Relaxed) || etc_hosts().contains(&lower) {
            return plain(fixed);
        }
        let mut out = Targets::new();
        // §4.1: NAPTR only when no transport was given.
        if proto.is_none() && self.try_naptr.load(Ordering::Relaxed) {
            let mut n: Vec<Naptr> =
                self.lookup(&lower, T_NAPTR).iter().filter_map(|r| if let Rdata::Naptr(n) = &r.data { Some(n.clone()) } else { None }).collect();
            n.sort_by_key(|n| (n.order, n.pref));
            for r in n.iter().filter(|r| r.flags.eq_ignore_ascii_case("s")) {
                let p = match r.services.to_ascii_uppercase().as_str() {
                    "SIPS+D2T" => Proto::Tls,
                    "SIP+D2T" if !secure => Proto::Tcp,
                    "SIP+D2U" if !secure => Proto::Udp,
                    "SIP+D2W" if !secure => Proto::Ws,
                    "SIPS+D2W" => Proto::Wss,
                    _ => continue,
                };
                self.srv_targets(&r.replacement, p, &mut out);
            }
            if !out.is_empty() {
                return out;
            }
        }
        // §4.1: SRV for the given transport, or each one we support.
        let protos: Vec<Proto> = match proto {
            Some(p) => vec![p],
            None if secure => vec![Proto::Tls],
            None => vec![Proto::Udp, Proto::Tcp, Proto::Tls],
        };
        for p in protos {
            let prefix = match p {
                Proto::Tls => "_sips._tcp",
                Proto::Tcp => "_sip._tcp",
                Proto::Ws | Proto::Wss => continue,
                Proto::Udp => "_sip._udp",
            };
            self.srv_targets(&format!("{prefix}.{lower}"), p, &mut out);
            if !out.is_empty() {
                return out;
            }
        }
        plain(fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(name: &str, ty: u16, rd: &[u8]) -> Vec<u8> {
        let mut v = qname(name);
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        v.extend_from_slice(&u16::try_from(rd.len()).unwrap().to_be_bytes());
        v.extend_from_slice(rd);
        v
    }

    #[test]
    fn parse_srv_with_glue() {
        let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 1];
        p.extend_from_slice(&qname("_sip._udp.example.test"));
        p.extend_from_slice(&[0, 33, 0, 1]);
        let mut srv = vec![0, 10, 0, 5, 0x13, 0xc4];
        srv.extend_from_slice(&qname("gw1.example.test"));
        p.extend_from_slice(&rr("_sip._udp.example.test", T_SRV, &srv));
        p.extend_from_slice(&rr("gw1.example.test", T_A, &[10, 0, 0, 1]));
        let r = parse(&p, 0x1234).unwrap();
        assert_eq!(r.answers[0].data, Rdata::Srv(Srv { prio: 10, weight: 5, port: 5060, target: "gw1.example.test".into() }));
        assert_eq!(r.additional[0].data, Rdata::Addr("10.0.0.1".parse().unwrap()));
        assert!(parse(&p, 0x9999).is_none());
    }

    #[test]
    fn parse_naptr_with_compressed_names() {
        let mut p = vec![0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(&qname("example.test")); // at offset 12
        p.extend_from_slice(&[0, 35, 0, 1]);
        let mut naptr = vec![0, 50, 0, 51, 1, b's', 7];
        naptr.extend_from_slice(b"SIP+D2U");
        naptr.extend_from_slice(&[0, 4]);
        naptr.extend_from_slice(b"_sip");
        naptr.extend_from_slice(&[4, b'_', b'u', b'd', b'p', 0xc0, 12]); // _sip._udp.<pointer>
        p.extend_from_slice(&[0xc0, 12, 0, 35, 0, 1, 0, 0, 0, 60]);
        p.extend_from_slice(&u16::try_from(naptr.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&naptr);
        let r = parse(&p, 7).unwrap();
        assert_eq!(r.answers[0].name, "example.test");
        let Rdata::Naptr(n) = &r.answers[0].data else { panic!("{:?}", r.answers[0].data) };
        assert_eq!((n.order, n.pref, n.flags.as_str(), n.services.as_str(), n.regexp.as_str()), (50, 51, "s", "SIP+D2U", ""));
        assert_eq!(n.replacement, "_sip._udp.example.test");
        // Cut anywhere: no panic, at most fewer records.
        for end in 0..p.len() {
            if let Some(r) = parse(&p[..end], 7) {
                assert!(r.answers.is_empty());
            }
        }
        // A pointer loop ends after 64 steps.
        assert_eq!(read_name(&[0xc0, 0], 0), Some(String::new()));
    }

    #[test]
    fn literal_and_hosts_skip_dns() {
        let r = resolver();
        assert_eq!(r.resolve_uri("10.1.2.3", None, None, false), vec![Dest::new(Proto::Udp, "10.1.2.3:5060".parse().unwrap())]);
        assert_eq!(r.resolve_uri("10.1.2.3", None, None, true), vec![Dest::new(Proto::Tls, "10.1.2.3:5061".parse().unwrap())]);
        assert_eq!(r.resolve_uri("localhost", Some(7000), Some(Proto::Tcp), false)[0], Dest::new(Proto::Tcp, "127.0.0.1:7000".parse().unwrap()));
    }

    fn header(id: u16, flags: [u8; 2], counts: [u16; 4]) -> Vec<u8> {
        let mut p = id.to_be_bytes().to_vec();
        p.extend_from_slice(&flags);
        for c in counts {
            p.extend_from_slice(&c.to_be_bytes());
        }
        p
    }

    #[test]
    fn qname_encoding() {
        let cases: &[(&str, &[u8])] =
            &[("", &[0]), (".", &[0]), ("a", &[1, b'a', 0]), ("ab.c.", &[2, b'a', b'b', 1, b'c', 0]), ("a..b", &[1, b'a', 1, b'b', 0])];
        for (name, want) in cases {
            assert_eq!(qname(name), *want, "{name:?}");
        }
        let long = "x".repeat(70);
        let q = qname(&long);
        assert_eq!((q[0], q.len()), (63, 65), "a label is cut at 63 octets");
    }

    #[test]
    fn query_layout() {
        let q = build_query(0xbeef, "a.b", T_SRV);
        assert_eq!(q, [0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 1, b'b', 0, 0, 33, 0, 1]);
        // A query is not a response: parse refuses it.
        assert!(parse(&q, 0xbeef).is_none());
    }

    #[test]
    fn response_header_flags() {
        let p = header(1, [0x83, 0x83], [0, 0, 0, 0]);
        let r = parse(&p, 1).unwrap();
        assert_eq!((r.rcode, r.truncated), (3, true), "NXDOMAIN, TC");
        let r = parse(&header(1, [0x81, 0x80], [0, 0, 0, 0]), 1).unwrap();
        assert_eq!((r.rcode, r.truncated, r.answers.len()), (0, false, 0));
        assert!(parse(&p[..11], 1).is_none(), "shorter than a header");
    }

    #[test]
    fn records_of_each_type_and_sections() {
        let mut p = header(9, [0x81, 0x80], [1, 3, 1, 1]);
        p.extend_from_slice(&qname("Host.Test"));
        p.extend_from_slice(&[0, 1, 0, 1]);
        p.extend_from_slice(&rr("Host.Test", T_A, &[192, 0, 2, 1]));
        p.extend_from_slice(&rr("host.test", T_AAAA, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        p.extend_from_slice(&rr("host.test", T_A, &[1, 2, 3])); // bad A length
        p.extend_from_slice(&rr("test", 2, &qname("ns.test"))); // authority NS: skipped
        p.extend_from_slice(&rr("ns.test", T_A, &[192, 0, 2, 53]));
        let r = parse(&p, 9).unwrap();
        let data: Vec<_> = r.answers.iter().map(|a| (a.name.as_str(), a.ty, a.ttl, a.data.clone())).collect();
        assert_eq!(
            data,
            [
                ("host.test", T_A, 60, Rdata::Addr("192.0.2.1".parse().unwrap())),
                ("host.test", T_AAAA, 60, Rdata::Addr("2001:db8::1".parse().unwrap())),
                ("host.test", T_A, 60, Rdata::Other),
            ]
        );
        assert_eq!(r.additional.len(), 1);
        assert_eq!(r.additional[0].data, Rdata::Addr("192.0.2.53".parse().unwrap()));
        // Counts larger than the records present: parse what is there.
        let mut short = header(9, [0x81, 0x80], [0, 5, 0, 0]);
        short.extend_from_slice(&rr("a", T_A, &[1, 1, 1, 1]));
        assert_eq!(parse(&short, 9).unwrap().answers.len(), 1);
    }

    fn test_resolver() -> Resolver {
        Resolver {
            server: RwLock::new(None),
            explicit: AtomicBool::new(false),
            cache: ShardedMap::new(4),
            bound: crate::shm::Bounded::new(1000),
            id: AtomicU16::new(1),
            rnd: AtomicU64::new(0x1234_5678_9abc_def1),
            srv_lb: AtomicBool::new(false),
            try_naptr: AtomicBool::new(false),
            srv_lookup: AtomicBool::new(true),
            timeout_ms: AtomicU64::new(50),
            neg_ttl: AtomicU64::new(60),
        }
    }

    fn srv_rec(prio: u16, weight: u16, port: u16, target: &str) -> Record {
        Record { name: String::new(), ty: T_SRV, ttl: 60, data: Rdata::Srv(Srv { prio, weight, port, target: target.into() }) }
    }

    fn naptr_rec(order: u16, pref: u16, flags: &str, services: &str, replacement: &str) -> Record {
        let n = Naptr { order, pref, flags: flags.into(), services: services.into(), regexp: String::new(), replacement: replacement.into() };
        Record { name: String::new(), ty: T_NAPTR, ttl: 60, data: Rdata::Naptr(n) }
    }

    #[test]
    fn srv_order_by_priority_then_weight() {
        let r = test_resolver();
        r.put(
            "_sip._udp.x.test",
            T_SRV,
            vec![srv_rec(20, 0, 1, "c"), srv_rec(10, 5, 2, "b"), srv_rec(10, 50, 3, "a"), srv_rec(5, 0, 4, "."), srv_rec(30, 1, 5, "d")],
            60,
        );
        let got: Vec<_> = r.srv("_SIP._udp.X.test.").into_iter().map(|s| (s.prio, s.target)).collect();
        assert_eq!(got, [(10, "a".to_string()), (10, "b".to_string()), (20, "c".to_string()), (30, "d".to_string())], "'.' means no service");
    }

    #[test]
    fn srv_load_balancing_keeps_priorities_and_favours_weight() {
        let r = test_resolver();
        r.srv_lb.store(true, Ordering::Relaxed);
        r.put("_sip._tcp.x.test", T_SRV, vec![srv_rec(10, 0, 1, "light"), srv_rec(10, 1000, 2, "heavy"), srv_rec(20, 7, 3, "backup")], 60);
        let mut heavy_first = 0;
        for _ in 0..200 {
            let got: Vec<String> = r.srv("_sip._tcp.x.test").into_iter().map(|s| s.target).collect();
            assert_eq!(got.len(), 3);
            assert_eq!(got[2], "backup", "a lower priority always comes last");
            assert!(got[..2].contains(&"light".to_string()) && got[..2].contains(&"heavy".to_string()));
            heavy_first += usize::from(got[0] == "heavy");
        }
        assert!(heavy_first > 180, "weight 1000 vs 0 should nearly always win: {heavy_first}/200");
    }

    #[test]
    fn resolve_uri_uses_srv_in_transport_order() {
        let r = test_resolver();
        r.put("_sip._udp.x.test", T_SRV, vec![], 60);
        r.put("_sip._tcp.x.test", T_SRV, vec![srv_rec(1, 0, 5070, "192.0.2.1"), srv_rec(2, 0, 5071, "192.0.2.2")], 60);
        r.put("_sips._tcp.x.test", T_SRV, vec![srv_rec(1, 0, 5061, "192.0.2.3")], 60);
        let d = |p, a: &str| Dest::new(p, a.parse().unwrap());
        assert_eq!(r.resolve_uri_x("x.test", None, None, false), [d(Proto::Tcp, "192.0.2.1:5070"), d(Proto::Tcp, "192.0.2.2:5071")], "UDP has none: TCP next");
        assert_eq!(r.resolve_uri_x("x.test", None, None, true), [d(Proto::Tls, "192.0.2.3:5061")], "sips: only TLS");
        assert_eq!(r.resolve_uri_x("X.TEST.", None, Some(Proto::Tls), false), [d(Proto::Tls, "192.0.2.3:5061")], "the given transport only");
        assert_eq!(r.resolve_uri_x("192.0.2.9", None, Some(Proto::Ws), false), [d(Proto::Ws, "192.0.2.9:5060")], "WS: SIP_PORT, as Kamailio");
        assert_eq!(r.resolve_uri_x("[2001:db8::2]", Some(7), None, true), [d(Proto::Tls, "[2001:db8::2]:7")]);
    }

    #[test]
    fn resolve_uri_follows_naptr_order_and_security() {
        let r = test_resolver();
        r.try_naptr.store(true, Ordering::Relaxed);
        r.put(
            "n.test",
            T_NAPTR,
            vec![
                naptr_rec(20, 10, "s", "SIP+D2U", "_sip._udp.n.test"),
                naptr_rec(10, 20, "S", "sip+d2t", "_sip._tcp.n.test"),
                naptr_rec(10, 10, "s", "SIPS+D2T", "_sips._tcp.n.test"),
                naptr_rec(5, 10, "u", "SIP+D2U", "ignored.n.test"),
                naptr_rec(5, 10, "s", "SIP+D2X", "ignored.n.test"),
            ],
            60,
        );
        r.put("_sip._udp.n.test", T_SRV, vec![srv_rec(1, 0, 5060, "192.0.2.10")], 60);
        r.put("_sip._tcp.n.test", T_SRV, vec![srv_rec(1, 0, 5060, "192.0.2.11")], 60);
        r.put("_sips._tcp.n.test", T_SRV, vec![srv_rec(1, 0, 5061, "192.0.2.12")], 60);
        let got: Vec<_> = r.resolve_uri_x("n.test", None, None, false).into_iter().map(|d| (d.proto, d.addr.to_string())).collect();
        assert_eq!(
            got,
            [(Proto::Tls, "192.0.2.12:5061".to_string()), (Proto::Tcp, "192.0.2.11:5060".to_string()), (Proto::Udp, "192.0.2.10:5060".to_string())],
            "order, then preference"
        );
        let got: Vec<_> = r.resolve_uri_x("n.test", None, None, true).into_iter().map(|d| d.proto).collect();
        assert_eq!(got, [Proto::Tls], "sips: only the SIPS services");
        let got: Vec<_> = r.resolve_uri_x("n.test", None, Some(Proto::Udp), false).into_iter().map(|d| d.addr.to_string()).collect();
        assert_eq!(got, ["192.0.2.10:5060"], "a transport given: no NAPTR, straight to SRV");
    }

    #[test]
    fn default_ports() {
        let cases = [(Proto::Udp, 5060), (Proto::Tcp, 5060), (Proto::Tls, 5061), (Proto::Ws, 5060), (Proto::Wss, 5061)];
        for (p, port) in cases {
            assert_eq!(default_port(p), port, "{p:?}");
        }
    }
}
