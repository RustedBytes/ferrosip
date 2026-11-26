//! Destination blocklist (Kamailio core `dst_blocklist`): next hops that
//! failed recently are skipped for `dst_blocklist_expire` seconds. tm adds
//! a destination when sending to it fails, when it never answered (local
//! 408 with no reply at all) and, with `blst_503`, on a 503; scripts add and
//! check entries with the `blst` module. Checking costs one atomic load
//! while the list is empty.

use crate::ShardedMap;
use crate::net::{Dest, Proto};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct Blocklist {
    map: ShardedMap<(Proto, SocketAddr), Instant>,
    /// Sweeps drop expired entries (not only when that destination is
    /// checked again), and the size is capped.
    bound: crate::shm::Bounded,
    any: AtomicBool,
    /// `use_dst_blocklist`: tm adds failing destinations automatically.
    pub enabled: AtomicBool,
    /// Also on 503 replies (`blst_503`), for `blst_503_def_timeout` s
    /// unless the reply has Retry-After.
    pub on_503: AtomicBool,
    pub def_503: AtomicU64,
    expire: AtomicU64,
}

pub fn blocklist() -> &'static Blocklist {
    static B: OnceLock<Blocklist> = OnceLock::new();
    B.get_or_init(|| Blocklist {
        map: ShardedMap::new(64),
        bound: crate::shm::Bounded::new(65_536),
        any: AtomicBool::new(false),
        enabled: AtomicBool::new(false),
        on_503: AtomicBool::new(false),
        def_503: AtomicU64::new(0),
        expire: AtomicU64::new(60),
    })
}

impl Blocklist {
    pub fn set_expire(&self, secs: u64) {
        self.expire.store(secs.max(1), Ordering::Relaxed);
    }

    /// Block `d` for `secs` (default `dst_blocklist_expire`).
    pub fn add(&self, d: &Dest, secs: Option<u64>) {
        let secs = secs.unwrap_or_else(|| self.expire.load(Ordering::Relaxed));
        if secs == 0 {
            return;
        }
        let now = Instant::now();
        let key = (d.proto, d.addr);
        // Re-blocking a listed destination is always allowed; new entries only
        // while under the cap.
        let until = crate::time::deadline(now, Duration::from_secs(secs));
        if self.map.with(&key, |u| *u = until).is_none() {
            if !self.bound.admit(&self.map, |u| *u <= now) {
                return;
            }
            self.map.insert(key, until);
        }
        self.any.store(true, Ordering::Relaxed);
    }

    pub fn del(&self, d: &Dest) -> bool {
        self.map.remove(&(d.proto, d.addr)).is_some()
    }

    #[inline]
    pub fn is_blocked(&self, d: &Dest) -> bool {
        if !self.any.load(Ordering::Relaxed) {
            return false;
        }
        match self.map.get_cloned(&(d.proto, d.addr)) {
            Some(until) if until > Instant::now() => true,
            Some(_) => {
                self.map.remove(&(d.proto, d.addr));
                // Back to the one-atomic-load fast path once nothing is listed
                // (rare: only when an expired entry is found).
                if self.map.is_empty() {
                    self.any.store(false, Ordering::Relaxed);
                }
                false
            }
            None => false,
        }
    }

    /// Unexpired entries: (proto, address, seconds left).
    pub fn list(&self) -> Vec<(Proto, SocketAddr, u64)> {
        let now = Instant::now();
        let mut v = Vec::new();
        self.map.retain(|k, until| {
            if *until <= now {
                return false;
            }
            v.push((k.0, k.1, until.duration_since(now).as_secs()));
            true
        });
        if v.is_empty() {
            self.any.store(false, Ordering::Relaxed);
        }
        v
    }

    pub fn flush(&self) {
        self.map.retain(|_, _| false);
        self.any.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_check_expire() {
        let b = Blocklist {
            map: ShardedMap::new(4),
            bound: crate::shm::Bounded::new(1000),
            any: AtomicBool::new(false),
            enabled: AtomicBool::new(true),
            on_503: AtomicBool::new(false),
            def_503: AtomicU64::new(0),
            expire: AtomicU64::new(60),
        };
        let d = Dest::new(Proto::Udp, "10.0.0.1:5060".parse().unwrap());
        assert!(!b.is_blocked(&d));
        b.add(&d, None);
        assert!(b.is_blocked(&d));
        assert!(!b.is_blocked(&Dest::new(Proto::Tcp, d.addr)), "per transport");
        assert_eq!(b.list().len(), 1);
        assert!(b.del(&d) && !b.is_blocked(&d));
        // blst_add($var): a script-supplied duration beyond the clock must not
        // overflow Instant::now() + d.
        b.add(&d, Some(u64::MAX));
        assert!(b.is_blocked(&d));
        b.add(&d, Some(i64::MAX.unsigned_abs()));
        assert!(b.is_blocked(&d));
    }

    fn fresh() -> Blocklist {
        Blocklist {
            map: ShardedMap::new(4),
            bound: crate::shm::Bounded::new(1000),
            any: AtomicBool::new(false),
            enabled: AtomicBool::new(true),
            on_503: AtomicBool::new(false),
            def_503: AtomicU64::new(0),
            expire: AtomicU64::new(60),
        }
    }

    #[test]
    fn keyed_by_transport_address_and_port() {
        let b = fresh();
        let d = |p, a: &str| Dest::new(p, a.parse().unwrap());
        let mut with_conn = d(Proto::Tcp, "192.0.2.1:5060");
        with_conn.conn = Some(7);
        b.add(&with_conn, None);
        assert!(b.is_blocked(&d(Proto::Tcp, "192.0.2.1:5060")), "the connection id is not part of the key");
        assert!(!b.is_blocked(&d(Proto::Tcp, "192.0.2.1:5061")), "other port");
        assert!(!b.is_blocked(&d(Proto::Tcp, "192.0.2.2:5060")), "other address");
        assert!(!b.is_blocked(&d(Proto::Tls, "192.0.2.1:5060")), "other transport");
        b.add(&d(Proto::Udp, "[2001:db8::1]:5060"), Some(5));
        assert!(b.is_blocked(&d(Proto::Udp, "[2001:db8::1]:5060")));
        assert!(!b.del(&d(Proto::Udp, "192.0.2.99:1")), "deleting an unknown entry");
    }

    #[test]
    fn zero_seconds_adds_nothing_and_list_reports_time_left() {
        let b = fresh();
        let d = Dest::new(Proto::Udp, "192.0.2.1:5060".parse().unwrap());
        b.add(&d, Some(0));
        assert!(!b.is_blocked(&d) && b.list().is_empty());
        b.set_expire(0);
        assert_eq!(b.expire.load(Ordering::Relaxed), 1, "the default expiry is at least 1 s");
        b.add(&d, Some(120));
        let l = b.list();
        assert_eq!(l.len(), 1);
        assert!((119..=120).contains(&l[0].2), "{l:?}");
        b.add(&d, Some(30));
        assert!(b.list()[0].2 <= 30, "adding again sets the new expiry");
        b.flush();
        assert!(!b.is_blocked(&d) && b.list().is_empty());
        assert!(!b.any.load(Ordering::Relaxed), "back on the fast path");
    }
}
