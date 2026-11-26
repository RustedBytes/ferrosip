//! Statistics (Kamailio `counters` / `statistics` / kex stats): named
//! `group:name` counters that any module bumps lock-free, plus computed
//! gauges (e.g. current transactions). Exposed via RPC `stats.*`.

use crate::sync::{read, write};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

type Gauge = Arc<dyn Fn() -> i64 + Send + Sync>;

enum Kind {
    Counter(&'static AtomicI64),
    Gauge(Gauge),
}

struct Entry {
    group: String,
    name: String,
    kind: Kind,
}

fn reg() -> &'static RwLock<Vec<Entry>> {
    static R: OnceLock<RwLock<Vec<Entry>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// A counter, created on first use (same name → same counter).
pub fn counter(group: &str, name: &str) -> &'static AtomicI64 {
    let mut r = write(reg());
    if let Some(Entry { kind: Kind::Counter(c), .. }) = r.iter().find(|e| e.group == group && e.name == name) {
        return c;
    }
    let c: &'static AtomicI64 = Box::leak(Box::new(AtomicI64::new(0)));
    r.push(Entry { group: group.into(), name: name.into(), kind: Kind::Counter(c) });
    c
}

/// A computed value (read when the statistics are fetched).
pub fn gauge(group: &str, name: &str, f: impl Fn() -> i64 + Send + Sync + 'static) {
    let mut r = write(reg());
    r.retain(|e| !(e.group == group && e.name == name));
    r.push(Entry { group: group.into(), name: name.into(), kind: Kind::Gauge(Arc::new(f)) });
}

#[inline]
pub fn inc(c: &AtomicI64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// `(group, name, value)` matching `spec`: `all`, `group:` or `group:name`
/// (`name` alone matches in any group).
pub fn get(spec: &str) -> Vec<(String, String, i64)> {
    get_kinds(spec).into_iter().map(|(g, n, v, _)| (g, n, v)).collect()
}

/// Like `get`, plus whether each value is a monotonic counter (`true`) or a
/// computed gauge (`false`), for exporters that need the type.
pub fn get_kinds(spec: &str) -> Vec<(String, String, i64, bool)> {
    let r = read(reg());
    let (g, n) = match spec.split_once(':') {
        Some((g, n)) => (Some(g), (!n.is_empty()).then_some(n)),
        None if spec == "all" => (None, None),
        None => (None, Some(spec)),
    };
    let mut out: Vec<_> = r
        .iter()
        .filter(|e| g.is_none_or(|g| e.group == g) && n.is_none_or(|n| e.name == n))
        .map(|e| {
            let (v, counter) = match &e.kind {
                Kind::Counter(c) => (c.load(Ordering::Relaxed), true),
                Kind::Gauge(f) => (f(), false),
            };
            (e.group.clone(), e.name.clone(), v, counter)
        })
        .collect();
    out.sort();
    out
}

/// Reset matching counters (gauges are computed, not reset).
pub fn reset(spec: &str) -> usize {
    let r = read(reg());
    let mut n = 0usize;
    for e in r.iter() {
        if let Kind::Counter(c) = e.kind {
            let hit = spec == "all" || spec == format!("{}:", e.group) || spec == format!("{}:{}", e.group, e.name) || spec == e.name;
            if hit {
                c.store(0, Ordering::Relaxed);
                n = n.saturating_add(1);
            }
        }
    }
    n
}

// ------------------------------------------------------ Prometheus-native ---
//
// Histograms and labelled counters for exporters (the `prometheus`
// module). They live beside the Kamailio-style `group:name` statistics and
// are not part of `get`/`get_kinds`, so `stats.get_statistics` and
// xhttp_prom are unchanged.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

/// A latency histogram: fixed upper bounds (µs), lock-free observation.
pub struct Histogram {
    bounds: &'static [u64],
    /// Per bucket (not cumulative); the last one is `+Inf`.
    counts: Box<[AtomicU64]>,
    sum_us: AtomicU64,
}

/// A consistent-enough reading: cumulative counts per bound plus `+Inf`
/// (== count), and the sum in seconds.
#[derive(Clone, Debug, PartialEq)]
pub struct HistSnapshot {
    pub bounds: &'static [u64],
    pub cumulative: Vec<u64>,
    pub count: u64,
    pub sum_seconds: f64,
}

impl Histogram {
    fn new(bounds: &'static [u64]) -> Self {
        debug_assert!(bounds.is_sorted_by(|a, b| a < b), "bounds must increase");
        Histogram { bounds, counts: (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect(), sum_us: AtomicU64::new(0) }
    }

    #[inline]
    pub fn observe(&self, d: Duration) {
        self.observe_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    }

    #[inline]
    pub fn observe_us(&self, us: u64) {
        // The bucket of the first bound `us` is within, else the last (+Inf).
        let i = self.bounds.iter().position(|&b| us <= b).unwrap_or(self.bounds.len());
        if let Some(c) = self.counts.get(i).or(self.counts.last()) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HistSnapshot {
        let mut acc = 0;
        let cumulative: Vec<u64> = self
            .counts
            .iter()
            .map(|c| {
                acc = c.load(Ordering::Relaxed).saturating_add(acc);
                acc
            })
            .collect();
        // +Inf is the total: computed from the buckets so the two always agree.
        HistSnapshot { bounds: self.bounds, count: acc, cumulative, sum_seconds: self.sum_us.load(Ordering::Relaxed) as f64 / 1e6 }
    }
}

pub type Labels = Vec<(String, String)>;

struct Family<T: 'static> {
    name: String,
    help: String,
    labels: Labels,
    v: &'static T,
}

fn hists() -> &'static RwLock<Vec<Family<Histogram>>> {
    static R: OnceLock<RwLock<Vec<Family<Histogram>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn lcounters() -> &'static RwLock<Vec<Family<AtomicI64>>> {
    static R: OnceLock<RwLock<Vec<Family<AtomicI64>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn owned(labels: &[(&str, &str)]) -> Labels {
    labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn get_or_add<T: 'static>(r: &RwLock<Vec<Family<T>>>, name: &str, help: &str, labels: &[(&str, &str)], make: impl FnOnce() -> T) -> &'static T {
    let labels = owned(labels);
    if let Some(f) = read(r).iter().find(|f| f.name == name && f.labels == labels) {
        return f.v;
    }
    let mut w = write(r);
    if let Some(f) = w.iter().find(|f| f.name == name && f.labels == labels) {
        return f.v;
    }
    let v: &'static T = Box::leak(Box::new(make()));
    w.push(Family { name: name.into(), help: help.into(), labels, v });
    v
}

/// The histogram `name{labels}` (created on first use; same name and
/// labels → same histogram). Look it up once and keep the reference: this
/// takes a lock.
pub fn histogram(name: &str, help: &str, labels: &[(&str, &str)], bounds: &'static [u64]) -> &'static Histogram {
    get_or_add(hists(), name, help, labels, || Histogram::new(bounds))
}

/// A counter with labels, e.g. `sip_requests_received{method="INVITE"}`.
pub fn labeled_counter(name: &str, help: &str, labels: &[(&str, &str)]) -> &'static AtomicI64 {
    get_or_add(lcounters(), name, help, labels, || AtomicI64::new(0))
}

/// Every histogram: (name, help, labels, reading), sorted by name.
pub fn histograms() -> Vec<(String, String, Labels, HistSnapshot)> {
    let mut v: Vec<_> = read(hists()).iter().map(|f| (f.name.clone(), f.help.clone(), f.labels.clone(), f.v.snapshot())).collect();
    v.sort_by(|a, b| (&a.0, &a.2).cmp(&(&b.0, &b.2)));
    v
}

/// Every labelled counter: (name, help, labels, value), sorted by name.
pub fn labeled_counters() -> Vec<(String, String, Labels, i64)> {
    let mut v: Vec<_> = read(lcounters()).iter().map(|f| (f.name.clone(), f.help.clone(), f.labels.clone(), f.v.load(Ordering::Relaxed))).collect();
    v.sort_by(|a, b| (&a.0, &a.2).cmp(&(&b.0, &b.2)));
    v
}

/// Common bucket sets (µs).
pub mod buckets {
    /// Script/routing time: 10 µs … 100 ms.
    pub const ROUTE: &[u64] = &[10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000];
    /// Network round trips and transactions: 5 ms … 30 s.
    pub const TXN: &[u64] = &[5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 30_000_000];
    /// Calls: 10 s … 1 h.
    pub const CALL: &[u64] = &[10_000_000, 30_000_000, 60_000_000, 120_000_000, 300_000_000, 600_000_000, 1_800_000_000, 3_600_000_000];
}

#[cfg(test)]
mod tests {
    #[test]
    fn counters_and_gauges() {
        let c = super::counter("t", "hits");
        assert!(std::ptr::eq(c, super::counter("t", "hits")), "same counter");
        super::inc(c);
        super::inc(c);
        super::gauge("t", "now", || 42);
        assert_eq!(super::get("t:"), vec![("t".into(), "hits".into(), 2), ("t".into(), "now".into(), 42)]);
        assert_eq!(super::get("hits").len(), 1);
        assert_eq!(super::reset("t:hits"), 1);
        assert_eq!(super::get("t:hits")[0].2, 0);
    }

    #[test]
    fn histograms() {
        static B: &[u64] = &[10, 100, 1000];
        let h = super::histogram("t_seconds", "test", &[("m", "INVITE")], B);
        assert!(std::ptr::eq(h, super::histogram("t_seconds", "test", &[("m", "INVITE")], B)), "same histogram");
        assert!(!std::ptr::eq(h, super::histogram("t_seconds", "test", &[("m", "BYE")], B)), "other labels");
        for us in [5, 10, 11, 100, 999, 5000] {
            h.observe_us(us);
        }
        h.observe(std::time::Duration::from_micros(50));
        let s = h.snapshot();
        // <=10: 5, 10; <=100: + 11, 50, 100; <=1000: + 999; +Inf: + 5000.
        assert_eq!(s.cumulative, vec![2, 5, 6, 7]);
        assert_eq!(s.count, 7);
        assert!((s.sum_seconds - 6175e-6).abs() < 1e-12, "{}", s.sum_seconds);
        assert!(super::histograms().iter().any(|(n, _, l, s)| n == "t_seconds" && l == &vec![("m".to_string(), "INVITE".to_string())] && s.count == 7));
        // Concurrent observers lose nothing.
        let h2 = super::histogram("t2_seconds", "", &[], B);
        std::thread::scope(|sc| {
            for _ in 0..4 {
                sc.spawn(|| (0..10_000).for_each(|i| h2.observe_us(i % 2000)));
            }
        });
        assert_eq!(h2.snapshot().count, 40_000);
        let c = super::labeled_counter("t_total", "", &[("k", "v")]);
        super::inc(c);
        assert!(super::labeled_counters().iter().any(|(n, _, _, v)| n == "t_total" && *v == 1));
    }

    #[test]
    fn spec_forms_of_get_and_reset() {
        let a = super::counter("ut_grp_a", "x");
        let b = super::counter("ut_grp_b", "x");
        let c = super::counter("ut_grp_a", "y");
        for (ctr, n) in [(a, 1), (b, 2), (c, 3)] {
            ctr.store(n, std::sync::atomic::Ordering::Relaxed);
        }
        super::gauge("ut_grp_a", "g", || 7);
        super::gauge("ut_grp_a", "g", || 8); // replaces
        let names =
            |spec: &str| super::get(spec).into_iter().filter(|e| e.0.starts_with("ut_grp_")).map(|(g, n, v)| format!("{g}:{n}={v}")).collect::<Vec<_>>();
        assert_eq!(names("ut_grp_a:"), ["ut_grp_a:g=8", "ut_grp_a:x=1", "ut_grp_a:y=3"]);
        assert_eq!(names("ut_grp_a:x"), ["ut_grp_a:x=1"]);
        assert_eq!(names("x"), ["ut_grp_a:x=1", "ut_grp_b:x=2"], "a bare name matches in every group");
        assert_eq!(names("ut_grp_c:"), Vec::<String>::new());
        assert!(names("all").len() >= 4);
        let kinds: Vec<bool> = super::get_kinds("ut_grp_a:").into_iter().map(|k| k.3).collect();
        assert_eq!(kinds, [false, true, true], "gauge, counter, counter");
        assert_eq!(super::reset("ut_grp_a:g"), 0, "gauges are not reset");
        assert_eq!(super::reset("ut_grp_a:"), 2);
        assert_eq!(names("ut_grp_a:"), ["ut_grp_a:g=8", "ut_grp_a:x=0", "ut_grp_a:y=0"]);
        assert_eq!(names("ut_grp_b:"), ["ut_grp_b:x=2"]);
    }

    #[test]
    fn histogram_bucket_edges() {
        static B: &[u64] = &[1, 2];
        let h = super::histogram("ut_edges_seconds", "", &[], B);
        for us in [0, 1, 2, 3, u64::MAX / 2] {
            h.observe_us(us);
        }
        h.observe(std::time::Duration::MAX);
        let s = h.snapshot();
        assert_eq!(s.cumulative, [2, 3, 6], "a bound is inclusive; huge values land in +Inf");
        assert_eq!(s.count, 6);
    }
}
