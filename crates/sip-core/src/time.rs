//! Wall-clock helpers (Unix epoch). A clock before 1970 reads as 0.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// About a century: further than any timer here ever needs to reach.
const CENTURY: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

/// `from + d` without overflow: a deadline beyond what `Instant` can hold
/// (a configured or scripted timeout of ages) becomes one about a century
/// away, which in practice never comes.
#[inline]
pub fn deadline(from: Instant, d: Duration) -> Instant {
    from.checked_add(d).or_else(|| from.checked_add(CENTURY)).unwrap_or(from)
}

/// Whole seconds since the Unix epoch.
#[inline]
pub fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Milliseconds since the Unix epoch.
#[inline]
pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Fractional seconds since the Unix epoch.
#[inline]
pub fn unix_secs_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    #[test]
    fn units_agree() {
        let s = super::unix_secs();
        let ms = super::unix_ms();
        let f = super::unix_secs_f64();
        assert!(s > 1_600_000_000);
        assert!(ms / 1000 >= s && ms / 1000 <= s + 1);
        assert!((f - s as f64).abs() < 2.0);
    }

    #[test]
    fn deadlines_saturate() {
        let now = std::time::Instant::now();
        assert_eq!(super::deadline(now, std::time::Duration::from_secs(5)), now + std::time::Duration::from_secs(5));
        assert!(super::deadline(now, std::time::Duration::MAX) > now + std::time::Duration::from_secs(50 * 365 * 24 * 3600));
    }
}
