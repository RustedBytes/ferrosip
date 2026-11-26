#!/usr/bin/env python3
"""Median table from bench/kamailio/run.sh or bench/ab.sh results (Markdown).

    summary.py RESULTS [A_LABEL B_LABEL]   (default: kamailio ferrosip)
"""
import re
import statistics as st
import sys

LINE = re.compile(
    r"(\w+) (\w+) (\d+) \S+ over \S+ in [\d.]+s → (\d+) req/s \| 200: (\d+), other: (\d+), lost: (\d+) "
    r"\| p50 ([\d.]+)(\S+) p99 ([\d.]+)(\S+) \| cpu_us_per_req ([\d.]+)")
UNIT = {"s": 1000.0, "ms": 1.0, "µs": 1e-3, "ns": 1e-6}
NAMES = {"sl": "stateless reply (UDP)", "udp": "t_relay UDP → UDP", "tcp": "t_relay TCP → TCP", "reg": "REGISTER → save()", "inv": "INVITE t_relay UDP (100 + 200)"}

runs, bad = {}, {}
for line in open(sys.argv[1]):
    m = LINE.match(line)
    if not m:
        continue
    sc, proxy, total, rps, ok, other, lost, p50, u50, p99, u99, cpu = m.groups()
    cpu = float(cpu)
    if int(other) + int(lost) > int(total) // 100:
        # A broken run (e.g. the connection failed at once): not a speed sample.
        bad[(sc, proxy)] = bad.get((sc, proxy), 0) + 1
        continue
    runs.setdefault((sc, proxy), []).append(
        (int(rps), int(other) + int(lost), float(p50) * UNIT[u50], float(p99) * UNIT[u99], cpu))

A, B = (sys.argv[2], sys.argv[3]) if len(sys.argv) > 3 else ("kamailio", "ferrosip")
print(f"| scenario | {A} req/s | {B} req/s | ratio | {A} p50 / p99 ms | {B} p50 / p99 ms | CPU µs/req {A} / {B} | errors {A} / {B} |")
print("|---|---|---|---|---|---|---|---|")
for sc, title in NAMES.items():
    k, f = runs.get((sc, A)), runs.get((sc, B))
    if not k or not f:
        continue
    med = lambda v, i: st.median(x[i] for x in v)  # noqa: E731
    print(f"| {title} | {med(k, 0):,.0f} | {med(f, 0):,.0f} | {med(f, 0) / med(k, 0):.2f}× "
          f"| {med(k, 2):.2f} / {med(k, 3):.2f} | {med(f, 2):.2f} / {med(f, 3):.2f} "
          f"| {med(k, 4):.1f} / {med(f, 4):.1f} | {sum(x[1] for x in k)} / {sum(x[1] for x in f)} |")

for (sc, proxy), n in sorted(bad.items()):
    print(f"\n{proxy} {NAMES[sc]}: {n} run(s) with more than 1% errors left out of the medians")
