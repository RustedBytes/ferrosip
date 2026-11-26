//! Standard `process_*` metrics from /proc (the names the Prometheus client
//! libraries use, so generic dashboards work).

use crate::expose::Ty;

/// `sysconf(_SC_CLK_TCK)`, which glibc and musl both take from the kernel's
/// AT_CLKTCK auxiliary vector entry: read here from /proc/self/auxv
/// instead of through FFI. 100 (USER_HZ on every Linux port) if it can't be read.
fn ticks_per_second() -> f64 {
    std::fs::read("/proc/self/auxv").ok().and_then(|auxv| clk_tck(&auxv)).map_or(100.0, |t| t as f64)
}

/// AT_CLKTCK from a raw auxv: (type, value) pairs of native-endian words,
/// ended by AT_NULL.
fn clk_tck(auxv: &[u8]) -> Option<u64> {
    const AT_NULL: usize = 0;
    const AT_CLKTCK: usize = 17;
    const W: usize = std::mem::size_of::<usize>();
    let word = |b: &[u8]| b.try_into().ok().map(usize::from_ne_bytes);
    for pair in auxv.as_chunks::<{ 2 * W }>().0 {
        let (ty, val) = pair.split_at(W);
        match word(ty)? {
            AT_NULL => return None,
            AT_CLKTCK => return word(val).filter(|&t| t > 0).and_then(|t| u64::try_from(t).ok()),
            _ => {}
        }
    }
    None
}

/// Fields of /proc/self/stat after the `(comm)` (field 3 is index 0).
fn stat_fields(stat: &str) -> Vec<&str> {
    stat.rsplit_once(')').map(|(_, rest)| rest.split_whitespace().collect()).unwrap_or_default()
}

fn boot_time() -> Option<f64> {
    std::fs::read_to_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime ")).and_then(|v| v.trim().parse().ok())
}

fn status_kb(status: &str, key: &str) -> Option<f64> {
    status.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.split_whitespace().next()?.parse::<f64>().ok()).map(|kb| kb * 1024.0)
}

fn max_fds() -> Option<f64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find_map(|l| l.strip_prefix("Max open files"))?;
    line.split_whitespace().next()?.parse().ok()
}

/// (name, type, help, value) for what this system provides.
pub fn metrics() -> Vec<(&'static str, Ty, &'static str, f64)> {
    let mut v = Vec::new();
    let tps = ticks_per_second();
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        let f = stat_fields(&stat);
        let num = |i: usize| f.get(i).and_then(|x| x.parse::<f64>().ok());
        // utime 14, stime 15, num_threads 20, starttime 22, vsize 23 (1-based).
        if let (Some(u), Some(s)) = (num(11), num(12)) {
            v.push(("process_cpu_seconds_total", Ty::Counter, "User and system CPU time spent, in seconds", (u + s) / tps));
        }
        if let Some(t) = num(17) {
            v.push(("process_threads", Ty::Gauge, "Number of OS threads", t));
        }
        if let (Some(st), Some(bt)) = (num(19), boot_time()) {
            v.push(("process_start_time_seconds", Ty::Gauge, "Start time of the process since the Unix epoch, in seconds", bt + st / tps));
        }
        if let Some(vs) = num(20) {
            v.push(("process_virtual_memory_bytes", Ty::Gauge, "Virtual memory size, in bytes", vs));
        }
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status")
        && let Some(rss) = status_kb(&status, "VmRSS:")
    {
        v.push(("process_resident_memory_bytes", Ty::Gauge, "Resident memory size, in bytes", rss));
    }
    if let Ok(d) = std::fs::read_dir("/proc/self/fd") {
        v.push(("process_open_fds", Ty::Gauge, "Open file descriptors", d.count() as f64));
    }
    if let Some(m) = max_fds() {
        v.push(("process_max_fds", Ty::Gauge, "Maximum number of open file descriptors", m));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let f = stat_fields("123 (a b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19");
        assert_eq!((f[0], f[11], f[12]), ("S", "11", "12"));
        assert_eq!(status_kb("Name:\tx\nVmRSS:\t   2048 kB\n", "VmRSS:"), Some(2048.0 * 1024.0));
        let m = metrics();
        let get = |n: &str| m.iter().find(|x| x.0 == n).map(|x| x.3);
        assert!(get("process_resident_memory_bytes").unwrap() > 1e5);
        assert!(get("process_threads").unwrap() >= 1.0);
        let start = get("process_start_time_seconds").unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
        assert!(start <= now + 1.0 && start > now - 86400.0 * 30.0, "start {start} now {now}");
        assert!(get("process_open_fds").unwrap() >= 3.0);
    }

    #[test]
    fn auxv_clock_ticks() {
        let aux = |pairs: &[(usize, usize)]| pairs.iter().flat_map(|&(t, v)| [t.to_ne_bytes(), v.to_ne_bytes()]).flatten().collect::<Vec<u8>>();
        assert_eq!(clk_tck(&aux(&[(6, 4096), (17, 250), (0, 0)])), Some(250));
        assert_eq!(clk_tck(&aux(&[(6, 4096), (0, 0), (17, 250)])), None, "nothing after AT_NULL");
        assert_eq!(clk_tck(&aux(&[(17, 0), (0, 0)])), None);
        assert_eq!(clk_tck(&aux(&[(6, 4096)])[..5]), None, "truncated");
        let real = std::fs::read("/proc/self/auxv").unwrap();
        assert!(clk_tck(&real).is_some_and(|t| t > 0), "this process has AT_CLKTCK");
    }

    #[test]
    fn stat_fields_start_after_the_last_parenthesis() {
        let cases: &[(&str, &[&str])] = &[
            ("1 (x) R 2 3", &["R", "2", "3"]),
            ("1 (a) b) (c) S 9", &["S", "9"]),
            ("1 () Z", &["Z"]),
            ("1 (x)", &[]),
            ("no parenthesis here", &[]),
            ("", &[]),
        ];
        for &(stat, want) in cases {
            assert_eq!(stat_fields(stat), want, "stat_fields({stat:?})");
        }
    }

    #[test]
    fn status_values_in_kb_become_bytes() {
        let status = "Name:\tferrosip\nVmPeak:\t  100 kB\nVmRSS:\t 3 kB\nVmSwap:\tbad kB\nVmHWM:\n";
        let cases: &[(&str, Option<f64>)] = &[("VmRSS:", Some(3072.0)), ("VmPeak:", Some(102_400.0)), ("VmSwap:", None), ("VmHWM:", None), ("VmData:", None)];
        for &(key, want) in cases {
            assert_eq!(status_kb(status, key), want, "{key}");
        }
    }
}
