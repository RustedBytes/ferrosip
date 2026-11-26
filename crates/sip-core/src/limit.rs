//! Admission limits shared by threads: a counted budget ([`Limiter`], e.g.
//! `tcp_max_connections`) and a budget per key ([`KeyedLimiter`], e.g.
//! connections per source IP, Kamailio `tcp_accept_iplimit`).
//!
//! Acquiring is atomic: concurrent callers can never take more than the
//! limit (a separate check-then-increment could). A [`Permit`] gives its
//! unit back when dropped, unless [`Permit::keep`] hands it to a long-lived
//! owner, which then calls `release` when it ends.
//!
//! Built on `std::sync` normally and on `loom::sync` under `--cfg loom`, so
//! the loom models at the bottom check every interleaving:
//! `RUSTFLAGS="--cfg loom" cargo test -p sip-core --release loom`.

use std::collections::HashMap;
use std::hash::Hash;

#[cfg(loom)]
use loom::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
#[cfg(not(loom))]
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

/// At most `max` units in use at once.
pub struct Limiter {
    used: AtomicUsize,
    max: usize,
}

impl Limiter {
    pub fn new(max: usize) -> Self {
        Self { used: AtomicUsize::new(0), max }
    }

    /// One unit, or `None` when all `max` are in use.
    pub fn try_acquire(&self) -> Option<Permit<'_>> {
        let mut n = self.used.load(Ordering::Relaxed);
        loop {
            let next = n.checked_add(1).filter(|&next| next <= self.max)?;
            match self.used.compare_exchange_weak(n, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some(Permit(self)),
                Err(cur) => n = cur,
            }
        }
    }

    /// Give back a unit whose permit was [`Permit::keep`]-ed.
    pub fn release(&self) {
        self.used.fetch_sub(1, Ordering::AcqRel);
    }

    pub fn in_use(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

/// One unit of a [`Limiter`]; given back on drop.
#[must_use = "dropping the permit gives the unit back at once"]
pub struct Permit<'a>(&'a Limiter);

impl Permit<'_> {
    /// The unit now belongs to a long-lived owner (a connection) that calls
    /// [`Limiter::release`] when it ends.
    pub fn keep(self) {
        // Skip `Drop` (which would give the unit back); the permit only
        // borrows the limiter, so nothing leaks.
        let _kept = std::mem::ManuallyDrop::new(self);
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// At most `max` units per key (0 = unlimited). Keys with nothing in use
/// are removed, so the map only holds keys that currently hold units.
pub struct KeyedLimiter<K> {
    used: Mutex<HashMap<K, usize>>,
    max: usize,
}

impl<K: Hash + Eq + Clone> KeyedLimiter<K> {
    pub fn new(max: usize) -> Self {
        Self { used: Mutex::new(HashMap::new()), max }
    }

    /// Take one unit for `key`; false when the key is at its limit.
    pub fn try_acquire(&self, key: &K) -> bool {
        if self.max == 0 {
            return true;
        }
        let mut m = self.lock();
        let n = m.entry(key.clone()).or_insert(0);
        match n.checked_add(1).filter(|&next| next <= self.max) {
            Some(next) => {
                *n = next;
                true
            }
            None => false,
        }
    }

    /// Give back one unit of `key`.
    pub fn release(&self, key: &K) {
        if self.max == 0 {
            return;
        }
        let mut m = self.lock();
        if let Some(n) = m.get_mut(key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(key);
            }
        }
    }

    pub fn in_use(&self, key: &K) -> usize {
        self.lock().get(key).copied().unwrap_or(0)
    }

    /// Keys currently holding units.
    pub fn keys(&self) -> usize {
        self.lock().len()
    }

    #[cfg(not(loom))]
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<K, usize>> {
        crate::sync::lock(&self.used)
    }

    #[cfg(loom)]
    #[allow(clippy::unwrap_used, reason = "in a loom model a poisoned lock is a failed model")]
    fn lock(&self) -> loom::sync::MutexGuard<'_, HashMap<K, usize>> {
        self.used.lock().unwrap()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn limiter_counts_and_gives_back() {
        let l = Limiter::new(2);
        let a = l.try_acquire().expect("first");
        let b = l.try_acquire().expect("second");
        assert!(l.try_acquire().is_none());
        drop(a);
        assert_eq!(l.in_use(), 1);
        b.keep();
        assert_eq!(l.in_use(), 1);
        l.release();
        assert_eq!(l.in_use(), 0);
    }

    #[test]
    fn keyed_limits_each_key_and_forgets_idle_keys() {
        let l = KeyedLimiter::new(2);
        assert!(l.try_acquire(&"a") && l.try_acquire(&"a"));
        assert!(!l.try_acquire(&"a"), "a is at its limit");
        assert!(l.try_acquire(&"b"), "b has its own budget");
        l.release(&"a");
        assert!(l.try_acquire(&"a"));
        l.release(&"a");
        l.release(&"a");
        l.release(&"b");
        assert_eq!(l.keys(), 0, "no entries left for idle keys");
        assert!(KeyedLimiter::new(0).try_acquire(&"x"), "0 = unlimited");
    }

    #[test]
    fn never_overshoots_under_contention() {
        let l = Limiter::new(64);
        let got: usize = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        let mut n = 0;
                        for _ in 0..100 {
                            if let Some(p) = l.try_acquire() {
                                p.keep();
                                n += 1;
                            }
                        }
                        n
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!((got, l.in_use()), (64, 64));
    }

    #[test]
    fn zero_limit_admits_nothing() {
        let l = Limiter::new(0);
        assert!(l.try_acquire().is_none());
        assert_eq!(l.in_use(), 0);
    }

    #[test]
    fn keyed_release_of_an_unknown_key_is_harmless() {
        let l = KeyedLimiter::new(1);
        l.release(&"ghost");
        assert_eq!((l.keys(), l.in_use(&"ghost")), (0, 0));
        assert!(l.try_acquire(&"a"));
        assert!(!l.try_acquire(&"a"));
        assert_eq!(l.in_use(&"a"), 1);
        l.release(&"a");
        l.release(&"a");
        assert!(l.try_acquire(&"a"), "an extra release doesn't add budget beyond max");
        assert!(!l.try_acquire(&"a"));
        let u = KeyedLimiter::new(0);
        assert!(u.try_acquire(&1) && u.try_acquire(&1));
        assert_eq!((u.in_use(&1), u.keys()), (0, 0), "unlimited keeps no entries");
    }

    #[test]
    fn max_usize_limit_does_not_overflow() {
        let l = Limiter::new(usize::MAX);
        l.used.store(usize::MAX - 1, Ordering::Relaxed);
        l.try_acquire().unwrap().keep();
        assert!(l.try_acquire().is_none(), "full at usize::MAX");
    }
}

/// Exhaustive interleaving checks (`--cfg loom`).
#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;
    use loom::sync::Arc;
    use loom::thread;

    /// Three threads race for one unit: at most one ever holds it, and every
    /// unit is back afterwards.
    #[test]
    fn loom_limiter_never_exceeds_max() {
        // Three threads with CAS loops: bound preemptions (3 is ample for a
        // single CAS) to keep the model to seconds instead of minutes.
        let mut b = loom::model::Builder::new();
        b.preemption_bound = Some(3);
        b.check(|| {
            let l = Arc::new(Limiter::new(1));
            let holders = Arc::new(AtomicUsize::new(0));
            let hs: Vec<_> = (0..3)
                .map(|_| {
                    let (l, holders) = (l.clone(), holders.clone());
                    thread::spawn(move || {
                        if let Some(p) = l.try_acquire() {
                            let now = holders.fetch_add(1, Ordering::SeqCst) + 1;
                            assert!(now <= 1, "two holders at once");
                            holders.fetch_sub(1, Ordering::SeqCst);
                            drop(p);
                        }
                    })
                })
                .collect();
            for h in hs {
                h.join().unwrap();
            }
            assert_eq!(l.in_use(), 0);
        });
    }

    /// A kept permit released from another thread (a connection closed by its
    /// reader) frees exactly one unit.
    #[test]
    fn loom_kept_permit_released_elsewhere() {
        loom::model(|| {
            let l = Arc::new(Limiter::new(2));
            l.try_acquire().unwrap().keep();
            let l2 = l.clone();
            let t = thread::spawn(move || l2.release());
            let mine = l.try_acquire();
            t.join().unwrap();
            assert_eq!(l.in_use(), usize::from(mine.is_some()));
            drop(mine);
            assert_eq!(l.in_use(), 0);
        });
    }

    /// Two threads, same key, limit 1: exactly one wins per round, and the
    /// key's entry is gone once released (no leak per IP).
    #[test]
    fn loom_keyed_one_winner_and_cleanup() {
        loom::model(|| {
            let l = Arc::new(KeyedLimiter::new(1));
            let hs: Vec<_> = (0..2)
                .map(|_| {
                    let l = l.clone();
                    thread::spawn(move || {
                        let won = l.try_acquire(&7u8);
                        if won {
                            l.release(&7u8);
                        }
                        won
                    })
                })
                .collect();
            let wins: usize = hs.into_iter().map(|h| usize::from(h.join().unwrap())).sum();
            assert!(wins >= 1, "at least one acquires (the other may run after the release)");
            assert_eq!(l.keys(), 0);
        });
    }
}
