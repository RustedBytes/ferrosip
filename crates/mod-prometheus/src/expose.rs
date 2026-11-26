//! The text exposition format (0.0.4) of everything in `sip_core::stats`:
//! - the Kamailio-style `group:name` statistics, mapped to labelled
//!   families where they form one (`tm:2xx` … → `tm_replies_total{class}`),
//!   the rest generically as `<group>_<name>[_total]`;
//! - labelled counters and histograms registered by modules;
//! - process metrics and build info.

use crate::process;
use sip_core::stats::{self, HistSnapshot};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Counter,
    Gauge,
    Histogram,
}

impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::Counter => "counter",
            Ty::Gauge => "gauge",
            Ty::Histogram => "histogram",
        }
    }
}

/// Where a Kamailio-style statistic goes: (family without prefix, type,
/// help, labels).
pub type Mapped = (&'static str, Ty, &'static str, Vec<(&'static str, String)>);

/// A Kamailio-style statistic that belongs to a labelled family.
pub fn map(group: &str, name: &str) -> Option<Mapped> {
    use Ty::*;
    let class = |n: &str| n.chars().next().filter(|c| ('1'..='6').contains(c)).map(|c| format!("{c}xx"));
    Some(match (group, name) {
        ("core", "rcv_requests") => ("sip_messages_received_total", Counter, "SIP messages received, by kind", vec![("kind", "request".into())]),
        ("core", "rcv_replies") => ("sip_messages_received_total", Counter, "SIP messages received, by kind", vec![("kind", "reply".into())]),
        ("core", "bad_msgs") => ("sip_messages_received_total", Counter, "SIP messages received, by kind", vec![("kind", "invalid".into())]),
        ("core", "panics") => ("panics_total", Counter, "Panics caught while handling a message (the message was dropped)", vec![]),
        ("core", "send_errors") => ("send_errors_total", Counter, "Messages a transport failed to send (logged at most once a second)", vec![]),
        ("tm", "total") => ("tm_transactions_total", Counter, "Transactions created", vec![]),
        ("tm", "total_local") => ("tm_local_transactions_total", Counter, "Transactions for requests ferrosip originated", vec![]),
        ("tm", "current") => ("tm_transactions", Gauge, "Transactions in memory", vec![]),
        ("tm", "rpl_received") => ("tm_replies_received_total", Counter, "Replies received for transactions", vec![]),
        ("tm", "rpl_sent") => ("tm_replies_sent_total", Counter, "Replies sent upstream", vec![]),
        ("tm", "rpl_generated") => ("tm_replies_generated_total", Counter, "Replies ferrosip generated itself (timeouts, errors)", vec![]),
        ("tm", "retransmissions") => ("tm_retransmissions_total", Counter, "Requests retransmitted", vec![]),
        ("tm", "timeouts") => ("tm_timeouts_total", Counter, "Branches that timed out", vec![]),
        ("tm", n) if n.len() == 3 && n.ends_with("xx") => ("tm_replies_total", Counter, "Final replies sent upstream, by class", vec![("class", class(n)?)]),
        ("sl", "sent_replies") => ("sl_replies_sent_total", Counter, "Stateless replies sent", vec![]),
        ("sl", n) if n.ends_with("xx_replies") => ("sl_replies_total", Counter, "Stateless replies sent, by class", vec![("class", class(n)?)]),
        ("tcp", "active_connections") => ("tcp_connections", Gauge, "Open TCP/TLS/WS connections", vec![]),
        ("tcp", "accepted") => ("tcp_connections_accepted_total", Counter, "TCP/TLS/WS connections accepted", vec![]),
        ("tcp", "rejected") => {
            ("tcp_connections_rejected_total", Counter, "TCP/TLS/WS connections refused, by reason", vec![("reason", "max_connections".into())])
        }
        ("tcp", "rejected_iplimit") => {
            ("tcp_connections_rejected_total", Counter, "TCP/TLS/WS connections refused, by reason", vec![("reason", "per_ip_limit".into())])
        }
        ("udp", "recv_errors") => ("udp_receive_errors_total", Counter, "UDP receive errors", vec![]),
        ("dialog", "active_dialogs") => ("dialogs", Gauge, "Dialogs, by state", vec![("state", "active".into())]),
        ("dialog", "early_dialogs") => ("dialogs", Gauge, "Dialogs, by state", vec![("state", "early".into())]),
        ("usrloc", "registered_users") => ("usrloc_registered_users", Gauge, "Registered AoRs", vec![]),
        ("usrloc", "location-contacts") => ("usrloc_contacts", Gauge, "Registered contacts", vec![]),
        ("ai", "active_calls") => ("ai_calls_active", Gauge, "AI calls in progress", vec![]),
        ("ai", "calls") => ("ai_calls_total", Counter, "AI calls answered (attempts that reached the provider stage)", vec![]),
        ("ai", "failed_calls") => ("ai_calls_failed_total", Counter, "AI calls whose provider session could not be opened", vec![]),
        _ => return None,
    })
}

/// `[a-zA-Z_:][a-zA-Z0-9_:]*`.
pub fn sanitize(name: &str) -> String {
    let mut s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == ':' { c } else { '_' }).collect();
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// A label name: like a metric name but without `:` ([a-zA-Z_][a-zA-Z0-9_]*).
fn label_name(name: &str) -> String {
    sanitize(name).replace(':', "_")
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn labels(l: &[(String, String)], extra: Option<(&str, &str)>) -> String {
    let mut parts: Vec<String> = l.iter().map(|(k, v)| format!("{}=\"{}\"", label_name(k), escape(v))).collect();
    if let Some((k, v)) = extra {
        parts.push(format!("{k}=\"{v}\""));
    }
    if parts.is_empty() { String::new() } else { format!("{{{}}}", parts.join(",")) }
}

enum Sample {
    Value(Vec<(String, String)>, f64),
    Hist(Vec<(String, String)>, HistSnapshot),
}

struct Family {
    ty: Ty,
    help: String,
    samples: Vec<Sample>,
}

fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else if v == v.trunc() && v.abs() < 1e15 {
        #[allow(clippy::cast_possible_truncation, reason = "a whole number below 1e15 fits i64 exactly")]
        let i = v as i64;
        format!("{i}")
    } else {
        format!("{v}")
    }
}

/// Seconds for a µs bound, shortest form ("0.00001", "2.5", "30").
fn le(us: u64) -> String {
    format!("{}", us as f64 / 1e6)
}

/// The whole page. `groups`: which Kamailio-style groups to include
/// (empty = all); `prefix`: put before every name but `process_*`.
pub fn render(prefix: &str, groups: &[String]) -> String {
    let mut fams: BTreeMap<String, Family> = BTreeMap::new();
    let mut add = |name: String, ty: Ty, help: &str, s: Sample| {
        let f = fams.entry(name).or_insert_with(|| Family { ty, help: help.to_string(), samples: Vec::new() });
        f.samples.push(s);
    };
    for (g, n, v, counter) in stats::get_kinds("all") {
        if !groups.is_empty() && !groups.iter().any(|x| x == &g) {
            continue;
        }
        match map(&g, &n) {
            Some((fam, ty, help, l)) => {
                let l = l.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
                add(format!("{prefix}{fam}"), ty, help, Sample::Value(l, v as f64));
            }
            None => {
                let base = sanitize(&format!("{prefix}{g}_{n}"));
                let (name, ty) = if counter { (format!("{base}_total"), Ty::Counter) } else { (base, Ty::Gauge) };
                add(name, ty, &format!("Statistic {g}:{n}"), Sample::Value(Vec::new(), v as f64));
            }
        }
    }
    for (n, help, l, v) in stats::labeled_counters() {
        add(sanitize(&format!("{prefix}{n}_total")), Ty::Counter, &help, Sample::Value(l, v as f64));
    }
    for (n, help, l, h) in stats::histograms() {
        add(sanitize(&format!("{prefix}{n}")), Ty::Histogram, &help, Sample::Hist(l, h));
    }
    add(
        format!("{prefix}build_info"),
        Ty::Gauge,
        "Always 1; the version is a label",
        Sample::Value(vec![("version".into(), env!("CARGO_PKG_VERSION").into())], 1.0),
    );
    for (n, ty, help, v) in process::metrics() {
        add(n.to_string(), ty, help, Sample::Value(Vec::new(), v));
    }

    let mut out = String::with_capacity(16 << 10);
    for (name, f) in &fams {
        let _ = writeln!(out, "# HELP {name} {}", f.help.replace('\\', "\\\\").replace('\n', "\\n"));
        let _ = writeln!(out, "# TYPE {name} {}", f.ty.name());
        for s in &f.samples {
            match s {
                Sample::Value(l, v) => {
                    let _ = writeln!(out, "{name}{} {}", labels(l, None), fmt_f64(*v));
                }
                Sample::Hist(l, h) => {
                    for (&b, c) in h.bounds.iter().zip(&h.cumulative) {
                        let _ = writeln!(out, "{name}_bucket{} {}", labels(l, Some(("le", &le(b)))), c);
                    }
                    let _ = writeln!(out, "{name}_bucket{} {}", labels(l, Some(("le", "+Inf"))), h.count);
                    let _ = writeln!(out, "{name}_sum{} {}", labels(l, None), fmt_f64(h.sum_seconds));
                    let _ = writeln!(out, "{name}_count{} {}", labels(l, None), h.count);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping() {
        assert_eq!(map("tm", "2xx").unwrap().3, vec![("class", "2xx".to_string())]);
        assert_eq!(map("sl", "4xx_replies").unwrap().0, "sl_replies_total");
        assert!(map("tm", "9xx").is_none());
        assert_eq!(map("tcp", "rejected_iplimit").unwrap().3[0].1, "per_ip_limit");
        assert!(map("htable", "items").is_none());
        // One family, one type, one help text, whatever the member.
        for (g, ns) in [("core", &["rcv_requests", "rcv_replies", "bad_msgs"][..]), ("dialog", &["active_dialogs", "early_dialogs"][..])] {
            let m: Vec<_> = ns.iter().map(|n| map(g, n).unwrap()).collect();
            assert!(m.windows(2).all(|w| w[0].0 == w[1].0 && w[0].1 == w[1].1 && w[0].2 == w[1].2));
        }
    }

    #[test]
    fn names_and_labels() {
        assert_eq!(sanitize("ferrosip_usrloc_location-contacts"), "ferrosip_usrloc_location_contacts");
        assert_eq!(sanitize("2x"), "_2x");
        assert_eq!(labels(&[("a".into(), "q\"u\\o\nte".into())], Some(("le", "+Inf"))), "{a=\"q\\\"u\\\\o\\nte\",le=\"+Inf\"}");
        assert_eq!(le(10), "0.00001");
        assert_eq!(le(2_500_000), "2.5");
        assert_eq!(le(30_000_000), "30");
        assert_eq!(fmt_f64(3.0), "3");
        assert_eq!(fmt_f64(0.25), "0.25");
    }

    #[test]
    fn page() {
        let c = stats::counter("tm", "2xx");
        stats::inc(c);
        stats::counter("exptest", "odd-name");
        stats::gauge("exptest", "level", || 7);
        static B: &[u64] = &[1_000, 10_000];
        let h = stats::histogram("exptest_seconds", "test", &[("method", "INVITE")], B);
        h.observe_us(500);
        h.observe_us(20_000);
        let p = render("ferrosip_", &[]);
        assert!(p.contains("# TYPE ferrosip_tm_replies_total counter\n"), "{p}");
        assert!(p.contains("ferrosip_tm_replies_total{class=\"2xx\"} "));
        assert!(p.contains("# TYPE ferrosip_exptest_odd_name_total counter\nferrosip_exptest_odd_name_total 0\n"));
        assert!(p.contains("# TYPE ferrosip_exptest_level gauge\nferrosip_exptest_level 7\n"));
        assert!(
            p.contains(
                "# TYPE ferrosip_exptest_seconds histogram\n\
             ferrosip_exptest_seconds_bucket{method=\"INVITE\",le=\"0.001\"} 1\n\
             ferrosip_exptest_seconds_bucket{method=\"INVITE\",le=\"0.01\"} 1\n\
             ferrosip_exptest_seconds_bucket{method=\"INVITE\",le=\"+Inf\"} 2\n\
             ferrosip_exptest_seconds_sum{method=\"INVITE\"} 0.0205\n\
             ferrosip_exptest_seconds_count{method=\"INVITE\"} 2\n"
            ),
            "{p}"
        );
        assert!(p.contains("ferrosip_build_info{version=\""));
        assert!(p.contains("# TYPE process_resident_memory_bytes gauge\n"));
        // Each family has exactly one HELP and TYPE.
        let types: Vec<&str> = p.lines().filter(|l| l.starts_with("# TYPE ")).collect();
        let mut dedup = types.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(types.len(), dedup.len());
        // Group filter: only the listed groups' statistics.
        let only = render("ferrosip_", &["exptest".into()]);
        assert!(only.contains("ferrosip_exptest_level") && !only.contains("ferrosip_tm_replies_total"));
    }

    #[test]
    fn sample_values_use_the_exposition_number_format() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-3.0, "-3"),
            (0.5, "0.5"),
            (0.0205, "0.0205"),
            (123_456_789.0, "123456789"),
            (1e15, "1000000000000000"),
            (f64::INFINITY, "+Inf"),
            (f64::NEG_INFINITY, "-Inf"),
            (f64::NAN, "NaN"),
        ];
        for &(v, want) in cases {
            assert_eq!(fmt_f64(v), want, "fmt_f64({v})");
        }
    }

    #[test]
    fn bucket_bounds_are_seconds_in_shortest_form() {
        let cases: &[(u64, &str)] = &[(0, "0"), (1, "0.000001"), (100, "0.0001"), (1_000, "0.001"), (250_000, "0.25"), (1_000_000, "1"), (60_000_000, "60")];
        for &(us, want) in cases {
            assert_eq!(le(us), want, "le({us})");
        }
    }

    #[test]
    fn metric_names_are_sanitized_to_the_prometheus_charset() {
        let cases: &[(&str, &str)] = &[
            ("ok_name", "ok_name"),
            ("with:colon", "with:colon"),
            ("dash-and.dot", "dash_and_dot"),
            ("sp ace", "sp_ace"),
            ("9lives", "_9lives"),
            ("ünï", "_n_"),
            ("", ""),
        ];
        for &(name, want) in cases {
            assert_eq!(sanitize(name), want, "sanitize({name:?})");
        }
    }

    #[test]
    fn label_sets_are_rendered_and_escaped_exactly() {
        let l = |pairs: &[(&str, &str)]| pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect::<Vec<_>>();
        assert_eq!(labels(&[], None), "");
        assert_eq!(labels(&[], Some(("le", "0.5"))), "{le=\"0.5\"}");
        assert_eq!(labels(&l(&[("a", "1"), ("b", "2")]), None), "{a=\"1\",b=\"2\"}");
        assert_eq!(labels(&l(&[("bad-name", "x")]), None), "{bad_name=\"x\"}");
        assert_eq!(labels(&l(&[("a:b", "x")]), None), "{a_b=\"x\"}", "metric names may have `:`, label names may not");
        assert_eq!(labels(&l(&[("v", "")]), None), "{v=\"\"}");
        assert_eq!(labels(&l(&[("v", "a\\nb")]), None), "{v=\"a\\\\nb\"}", "a literal backslash-n stays distinct from a newline");
        assert_eq!(labels(&l(&[("v", "tab\tand\rcr")]), None), "{v=\"tab\tand\rcr\"}", "only \\, \" and newline are escaped");
    }

    #[test]
    fn kamailio_statistics_map_to_their_documented_families() {
        // (group, name, family, type, labels)
        type Case = (&'static str, &'static str, &'static str, Ty, &'static [(&'static str, &'static str)]);
        let cases: &[Case] = &[
            ("core", "rcv_requests", "sip_messages_received_total", Ty::Counter, &[("kind", "request")]),
            ("core", "rcv_replies", "sip_messages_received_total", Ty::Counter, &[("kind", "reply")]),
            ("core", "bad_msgs", "sip_messages_received_total", Ty::Counter, &[("kind", "invalid")]),
            ("tm", "current", "tm_transactions", Ty::Gauge, &[]),
            ("tm", "1xx", "tm_replies_total", Ty::Counter, &[("class", "1xx")]),
            ("tm", "6xx", "tm_replies_total", Ty::Counter, &[("class", "6xx")]),
            ("sl", "2xx_replies", "sl_replies_total", Ty::Counter, &[("class", "2xx")]),
            ("sl", "sent_replies", "sl_replies_sent_total", Ty::Counter, &[]),
            ("tcp", "rejected", "tcp_connections_rejected_total", Ty::Counter, &[("reason", "max_connections")]),
            ("dialog", "early_dialogs", "dialogs", Ty::Gauge, &[("state", "early")]),
            ("usrloc", "location-contacts", "usrloc_contacts", Ty::Gauge, &[]),
            ("ai", "active_calls", "ai_calls_active", Ty::Gauge, &[]),
        ];
        for &(g, n, fam, ty, want) in cases {
            let (f, t, _, l) = map(g, n).unwrap_or_else(|| panic!("{g}:{n} is mapped"));
            let l: Vec<(&str, &str)> = l.iter().map(|(k, v)| (*k, v.as_str())).collect();
            assert_eq!((f, t, l.as_slice()), (fam, ty, want), "{g}:{n}");
        }
        for (g, n) in
            [("tm", "0xx"), ("tm", "7xx"), ("tm", "2x"), ("tm", "2xxx"), ("sl", "7xx_replies"), ("sl", "xx_replies"), ("core", "unknown"), ("nope", "total")]
        {
            assert!(map(g, n).is_none(), "{g}:{n} is not mapped");
        }
    }

    #[test]
    fn page_renders_an_empty_histogram_with_zero_buckets_and_escaped_help() {
        static B: &[u64] = &[5_000];
        let _ = stats::histogram("exptest_empty_seconds", "line1\nback\\slash", &[("q", "a\"b")], B);
        let p = render("pfx_", &["exptest_empty_group".into()]);
        let want = "# HELP pfx_exptest_empty_seconds line1\\nback\\\\slash\n\
                    # TYPE pfx_exptest_empty_seconds histogram\n\
                    pfx_exptest_empty_seconds_bucket{q=\"a\\\"b\",le=\"0.005\"} 0\n\
                    pfx_exptest_empty_seconds_bucket{q=\"a\\\"b\",le=\"+Inf\"} 0\n\
                    pfx_exptest_empty_seconds_sum{q=\"a\\\"b\"} 0\n\
                    pfx_exptest_empty_seconds_count{q=\"a\\\"b\"} 0\n";
        assert!(p.contains(want), "{p}");
        assert!(p.ends_with('\n'));
        // Process metrics never get the prefix; build_info does.
        assert!(p.contains("\npfx_build_info{version=\""), "{p}");
        assert!(!p.contains("pfx_process_"), "{p}");
    }
}
