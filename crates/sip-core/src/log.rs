//! Logging with Kamailio's levels (`debug=` core parameter): a message is
//! printed when its level is <= the current level (default 2 = info).

use crate::sync::lock;
use std::io::Write;
use std::sync::atomic::{AtomicI32, Ordering};

pub const L_ALERT: i32 = -5;
pub const L_BUG: i32 = -4;
pub const L_CRIT: i32 = -3;
pub const L_ERR: i32 = -1;
pub const L_WARN: i32 = 0;
pub const L_NOTICE: i32 = 1;
pub const L_INFO: i32 = 2;
pub const L_DBG: i32 = 3;

static LEVEL: AtomicI32 = AtomicI32::new(L_INFO);

pub fn level() -> i32 {
    LEVEL.load(Ordering::Relaxed)
}

pub fn set_level(l: i32) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn name(l: i32) -> &'static str {
    match l {
        i32::MIN..=L_ALERT => "ALERT",
        L_BUG => "BUG",
        L_CRIT => "CRITICAL",
        -2 | L_ERR => "ERROR",
        L_WARN => "WARNING",
        L_NOTICE => "NOTICE",
        L_INFO => "INFO",
        _ => "DEBUG",
    }
}

/// `L_INFO`, `INFO`, `info`, `2` → level.
pub fn parse(s: &str) -> Option<i32> {
    let u = s.trim().trim_start_matches("L_").to_ascii_uppercase();
    Some(match u.as_str() {
        "ALERT" => L_ALERT,
        "BUG" => L_BUG,
        "CRIT" | "CRITICAL" => L_CRIT,
        "ERR" | "ERROR" => L_ERR,
        "WARN" | "WARNING" => L_WARN,
        "NOTICE" => L_NOTICE,
        "INFO" => L_INFO,
        "DBG" | "DEBUG" => L_DBG,
        n => return n.parse().ok(),
    })
}

pub fn log(l: i32, msg: &str) {
    if l <= level() {
        let msg = msg.trim_end_matches('\n');
        #[allow(clippy::let_underscore_must_use, reason = "nowhere left to report a failed stderr write")]
        let _ = writeln!(std::io::stderr().lock(), "{}: {}", name(l), msg);
        ring_push(l, msg);
    }
}

/// A line for stderr that isn't filtered by level (startup notes, transport
/// warnings, panics): printed as is, and kept in the ring (see [`elog!`]).
pub fn emit(text: &str) {
    let text = text.trim_end_matches('\n');
    #[allow(clippy::let_underscore_must_use, reason = "nowhere left to report a failed stderr write")]
    let _ = writeln!(std::io::stderr().lock(), "{text}");
    if RING.get().is_some() {
        ring_push(level_of(text), text);
    }
}

/// `eprintln!` for the proxy: the line also goes to the log ring that the
/// web UI shows. Use it instead of `eprintln!` outside tests and tools.
#[macro_export]
macro_rules! elog {
    ($($t:tt)*) => {
        $crate::log::emit(&format!($($t)*))
    };
}

/// Level of an unlevelled line, from its wording (for filtering only).
fn level_of(text: &str) -> i32 {
    let t = text.to_ascii_lowercase();
    if t.contains("panic") {
        L_CRIT
    } else if t.contains("error") || t.contains("failed") || t.contains("cannot") {
        L_ERR
    } else if t.contains("warning") || t.contains("refus") {
        L_WARN
    } else if t.contains("note:") {
        L_NOTICE
    } else {
        L_INFO
    }
}

// --------------------------------------------------------------- ring ---

/// One line kept in the ring.
#[derive(Clone, Debug)]
pub struct Line {
    /// Increasing sequence number (for "lines after N" polling).
    pub seq: u64,
    /// Unix time, milliseconds.
    pub ts_ms: u64,
    pub level: i32,
    pub text: String,
}

struct Ring {
    cap: usize,
    next: u64,
    lines: std::collections::VecDeque<Line>,
}

static RING: std::sync::OnceLock<std::sync::Mutex<Ring>> = std::sync::OnceLock::new();

/// Keep the last `cap` log lines in memory (the web UI's log view). Off
/// until called: without it, logging costs one atomic load more.
pub fn enable_ring(cap: usize) {
    #[allow(clippy::let_underscore_must_use, reason = "set once: a later call keeps the first value")]
    let _ = RING.set(std::sync::Mutex::new(Ring { cap: cap.max(1), next: 1, lines: std::collections::VecDeque::with_capacity(cap.clamp(1, 4096)) }));
}

fn ring_push(level: i32, text: &str) {
    let Some(r) = RING.get() else { return };
    let ts_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let mut g = lock(r);
    let seq = g.next;
    g.next = g.next.saturating_add(1);
    if g.lines.len() >= g.cap {
        g.lines.pop_front();
    }
    g.lines.push_back(Line { seq, ts_ms, level, text: text.to_string() });
}

/// Lines with a sequence number above `since` (oldest first, at most
/// `max`), and the sequence number of the newest line. `None` if the ring
/// is off.
pub fn tail(since: u64, max: usize) -> Option<(Vec<Line>, u64)> {
    let g = lock(RING.get()?);
    let newest = g.next.saturating_sub(1);
    let start = g.lines.partition_point(|l| l.seq <= since);
    // The last `max` of the lines after `since`.
    let skip = g.lines.len().saturating_sub(start).saturating_sub(max);
    Some((g.lines.iter().skip(start).skip(skip).cloned().collect(), newest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_the_newest_and_tails_by_sequence() {
        enable_ring(3);
        for i in 0..5 {
            log(L_ERR, &format!("line {i}"));
        }
        emit("warning: something");
        let (all, newest) = tail(0, 100).unwrap();
        assert_eq!(newest, 6);
        assert_eq!(all.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), ["line 3", "line 4", "warning: something"]);
        assert_eq!(all[2].level, L_WARN);
        let (after, _) = tail(5, 100).unwrap();
        assert_eq!(after.len(), 1, "only lines after seq 5");
        let (capped, _) = tail(0, 1).unwrap();
        assert_eq!(capped[0].text, "warning: something", "max keeps the newest");
    }
}
