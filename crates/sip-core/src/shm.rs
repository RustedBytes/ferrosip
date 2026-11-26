//! Shared state ("shm" in Kamailio terms).
//!
//! Kamailio puts transactions, dialogs, registrations… into one shared memory
//! segment and protects each *hash bucket* with its own spinlock. The Rust
//! equivalent: a map split into many independently locked shards, so two
//! workers only contend if they hit the same shard at the same moment.
//! `std::sync::Mutex` on Linux is a futex: uncontended lock = one atomic op,
//! like Kamailio's fastlock.h / futexlock.h.

use crate::sync::lock;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::sync::{Mutex, MutexGuard};

/// Small, fast non-cryptographic hasher (FxHash). SipHash (std default) is
/// DoS-resistant but slower; keys here are mostly random branch/call-ids.
/// Kamailio does the same with its own hash functions (hash_func.c).
#[derive(Default, Clone, Copy)]
pub struct FxHasher(u64);

const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, r) = bytes.as_chunks::<8>();
        for c in chunks {
            self.add(u64::from_le_bytes(*c));
        }
        if !r.is_empty() {
            let mut w = [0u8; 8];
            w.iter_mut().zip(r).for_each(|(w, b)| *w = *b);
            self.add(u64::from_le_bytes(w));
        }
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i)
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64)
    }
    /// Raw Fx output has weak low bits (they only depend on the low bytes of
    /// each word) and hashbrown picks buckets from the low bits. SIP branch
    /// IDs differ mostly in their tail bytes, so without this finalizer keys
    /// collide and lookups degrade as the table grows. splitmix64 mixes all
    /// bits for ~3 extra instructions.
    #[inline]
    fn finish(&self) -> u64 {
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

pub type FxBuild = BuildHasherDefault<FxHasher>;

pub fn fx_hash<T: Hash + ?Sized>(t: &T) -> u64 {
    let mut h = FxHasher::default();
    t.hash(&mut h);
    h.finish()
}

pub struct ShardedMap<K, V> {
    shards: Box<[Mutex<HashMap<K, V, FxBuild>>]>,
    mask: usize,
}

impl<K: Hash + Eq, V> ShardedMap<K, V> {
    pub fn new(shards: usize) -> Self {
        let n = shards.next_power_of_two();
        Self { shards: (0..n).map(|_| Mutex::default()).collect(), mask: n.saturating_sub(1) }
    }

    #[inline]
    fn shard<Q: Hash + ?Sized>(&self, k: &Q) -> MutexGuard<'_, HashMap<K, V, FxBuild>> {
        let i = (fx_hash(k) >> 40) as usize & self.mask;
        // A panicking worker must not wedge everyone else: ignore poisoning.
        #[allow(clippy::indexing_slicing, reason = "i is masked by len - 1 and the length is a power of two")]
        lock(&self.shards[i])
    }

    pub fn insert(&self, k: K, v: V) -> Option<V> {
        self.shard(&k).insert(k, v)
    }

    /// Inserts only if absent; returns whether it was inserted.
    pub fn insert_if_absent(&self, k: K, v: V) -> bool {
        let mut s = self.shard(&k);
        if s.contains_key(&k) {
            return false;
        }
        s.insert(k, v);
        true
    }

    pub fn remove<Q>(&self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard(k).remove(k)
    }

    /// Run `f` on the entry while holding only that shard's lock.
    pub fn with<Q, R>(&self, k: &Q, f: impl FnOnce(&mut V) -> R) -> Option<R>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard(k).get_mut(k).map(f)
    }

    /// Remove only if the current value satisfies `pred`.
    pub fn remove_if<Q>(&self, k: &Q, pred: impl FnOnce(&V) -> bool) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut s = self.shard(k);
        if s.get(k).is_some_and(pred) { s.remove(k) } else { None }
    }

    pub fn get_cloned<Q>(&self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
        V: Clone,
    {
        self.shard(k).get(k).cloned()
    }

    /// Read-modify-write one key under its shard lock: `f` gets the current
    /// value (if any) and returns the new one (`None` deletes) plus a result.
    pub fn alter<R>(&self, k: K, f: impl FnOnce(Option<V>) -> (Option<V>, R)) -> R {
        let mut s = self.shard(&k);
        let (new, r) = f(s.remove(&k));
        if let Some(v) = new {
            s.insert(k, v);
        }
        r
    }

    /// Keep only entries for which `f` returns true (one shard at a time).
    pub fn retain(&self, mut f: impl FnMut(&K, &mut V) -> bool) {
        for s in self.shards.iter() {
            lock(s).retain(|k, v| f(k, v));
        }
    }

    /// Visit every entry, one shard lock at a time (rare, whole-table work).
    pub fn for_each_mut(&self, mut f: impl FnMut(&K, &mut V)) {
        for s in self.shards.iter() {
            for (k, v) in lock(s).iter_mut() {
                f(k, v);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Keeps a TTL cache keyed by peer-controlled data (host names from
/// R-URIs, addresses) bounded: every `SWEEP_EVERY` admissions it drops the
/// expired entries, and while `cap` live entries remain it admits no new
/// ones (callers then just don't cache). The insert path costs one atomic
/// add and one flag load. The map holds at most `cap + SWEEP_EVERY`
/// entries.
pub struct Bounded {
    cap: usize,
    admitted: std::sync::atomic::AtomicU64,
    full: std::sync::atomic::AtomicBool,
}

impl Bounded {
    const SWEEP_EVERY: u64 = 1024;

    pub const fn new(cap: usize) -> Self {
        Self { cap, admitted: std::sync::atomic::AtomicU64::new(0), full: std::sync::atomic::AtomicBool::new(false) }
    }

    /// May a new entry be inserted into `map`? `expired` says which entries
    /// a sweep may drop.
    pub fn admit<K: Hash + Eq, V>(&self, map: &ShardedMap<K, V>, mut expired: impl FnMut(&V) -> bool) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.admitted.fetch_add(1, Relaxed);
        if n.is_multiple_of(Self::SWEEP_EVERY) || (self.full.load(Relaxed) && n.is_multiple_of(64)) {
            map.retain(|_, v| !expired(v));
            self.full.store(map.len() >= self.cap, Relaxed);
        }
        !self.full.load(Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::{Bounded, ShardedMap, fx_hash};

    #[test]
    fn bounded_cache_stays_under_its_cap_and_recovers() {
        let m: ShardedMap<u64, u64> = ShardedMap::new(8);
        let b = Bounded::new(100);
        // A flood of distinct keys (all live): the map stops growing near the cap.
        for k in 0..100_000u64 {
            if b.admit(&m, |&exp| exp < 1) {
                m.insert(k, 10);
            }
        }
        assert!(m.len() <= 100 + usize::try_from(Bounded::SWEEP_EVERY).unwrap(), "len {}", m.len());
        // Once the entries expire, a sweep frees room and inserts resume.
        let mut admitted = false;
        for _ in 0..200 {
            admitted |= b.admit(&m, |_| true);
        }
        assert!(admitted);
        assert!(m.len() < 100);
    }

    #[test]
    fn low_bits_are_mixed_for_tail_varying_keys() {
        // Keys that differ only in their last bytes must spread over buckets.
        let mut seen = std::collections::HashSet::new();
        for i in 0..4096u32 {
            let k = format!("z9hG4bKfs.0.{i:04x}");
            seen.insert(fx_hash(k.as_bytes()) & 1023);
        }
        assert!(seen.len() > 900, "only {} of 1024 buckets used", seen.len());
    }
}
