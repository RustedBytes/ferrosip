# Performance measurements

All numbers come from the same 4-vCPU gVisor sandbox:
- the proxy is pinned to CPUs 0–1 with 2 UDP workers and 2 TCP readers;
- the `sipflood` client and UAS run on CPUs 2–3;
- the toolchain is Rust 1.100 with the release profile (fat LTO, 1 CGU).

## How to measure

| What | Command | Notes |
|---|---|---|
| Throughput, latency, CPU | `bench/ab.sh OLD_BIN NEW_BIN` | Old and new builds alternate, 7 rounds, medians |
| Allocations per request | `bench/allocs.sh [BIN]` | valgrind DHAT, difference of two run lengths, so startup cancels out |
| Allocation budget (CI) | `bench/allocs.sh --check` | Fails when a scenario allocates more per request than `bench/allocs-budget.txt` |
| Memory under sustained load | `python3 tests/soak.py 120` | RSS after warmup, drained state |
| Against Kamailio | `bench/kamailio/run.sh` | Same box, same load |

**Noise floor.** `bench/ab.sh` run with the same binary on both sides
(5 rounds) gave throughput ratios of 0.92×, 1.62×, 1.00× and 1.12×. This
sandbox's throughput is bimodal, so req/s alone can't show changes under
about 50%. CPU µs per request varies by 2–10% between runs, and the
allocation counts are exact. Those two are the primary metrics for a
change; req/s and p99 are reported as well.

## Allocations per request

From DHAT: one request plus its reply. `bench/allocs-budget.txt` holds
these values plus 0.3 of headroom (runs vary by about ±0.1; one more
allocation adds 1.0), and CI's `allocs` job fails a change that exceeds
them.

| scenario | allocations / request | bytes / request |
|---|---|---|
| stateless reply (UDP OPTIONS) | 1.0 | 2 |
| `t_relay` UDP → UDP (MESSAGE + 200) | 21.8 | 5,157 |
| `t_relay` TCP → TCP | 20.8 | 4,846 |
| REGISTER → `save()` | 19.3 | 1,936 |
| INVITE `t_relay` UDP (100 Trying + 200) | 24.9 | 6,170 |
| the UDP relay written in `.fsr` (`f_fsr.fsr`) | 21.9 | 5,190 |

The `.fsr` routing allocates exactly what the `.cfg` one does: it
compiles to the same route tree.

## CPU, throughput, latency

From `bench/ab.sh`, 7 rounds, all scenarios in one run. Medians:

| scenario | req/s | p50 / p99 ms | CPU µs / request |
|---|---|---|---|
| stateless reply (UDP) | 128k | 1.56 / 3.00 | 4.8 |
| `t_relay` UDP → UDP | see below | 3.74 / 6.09 | 20.6 |
| `t_relay` TCP → TCP | 56k | 3.52 / 6.11 | 27.8 |
| REGISTER → `save()` | 152k | 1.18 / 2.97 | 6.0 |
| INVITE `t_relay` UDP | see below | 6.27 / 10.47 | 35.2 |

For the two relays over UDP, the sandbox's throughput falls into two
clusters, and a median only reflects how many runs landed in the fast
one. Per run:

| scenario | fast cluster req/s (CPU µs/req) | slow cluster req/s (CPU µs/req) |
|---|---|---|
| UDP relay | 92–104k (16.6–18.4) | 47–53k (19.9–22.2) |
| INVITE | 43k (34.2–35.2) | 26–31k (33.8–40.4) |

These include all the hardening: atomic connection slots, bounded reads,
panic isolation, handshake deadlines, bounded caches, shutdown checks and
the counters.

## Memory under sustained load

`tests/soak.py 300`: 300 calls/s with dialogs, plus 20 REGISTER/s.

| RSS after warmup | peak | after drain |
|---|---|---|
| 17.5 MB | 17.9 MB | 17.9 MB, 0 transactions, 0 dialogs |

## Latency histograms for the Prometheus exporter

The SIP path does, per request:
- one labelled counter increment (requests by method);
- two `Instant::now()` around `request_route`, and one histogram observe.

Transactions add one observe at the final reply, and one more at the
INVITE's first reply.

**Cost in isolation** (one thread, the same calls in a loop): **76 ns per
request**. That is about 1.7% of the cheapest path (a stateless reply,
4.5 µs of CPU) and under 0.5% of a relayed transaction.

**`bench/ab.sh`** (5 rounds, without and with the instrumentation; medians):

| scenario | req/s without / with | CPU µs/req without / with |
|---|---|---|
| stateless reply (UDP) | 134,528 / 135,507 | 4.5 / 4.6 |
| t_relay UDP → UDP | noisy (bimodal runs on this box) | 18.6 / 17.4 |
| t_relay TCP → TCP | 60,024 / 60,882 | 25.9 / 26.3 |
| REGISTER → save() | 155,906 / 155,004 | 5.8 / 6.1 |

- Throughput is within noise everywhere.
- CPU per request moves by at most the 0.1 µs the micro-benchmark
  predicts, so there is no sampling knob.
- The counters are shared atomics: on many-core boxes at very high rates,
  per-worker sharding is the next step if contention ever shows up in a
  profile.

## Not done, and why

- **A level-checking `log!` macro.** All formatted log calls are at info
  level or more severe, so they are printed at the default level anyway
  and nothing would be saved.
- **Per-worker branch counter, cache-padded stats counters.** About one
  contended atomic add per 20–35 µs transaction, below the noise floor.
- **`ArcSwap` instead of `RwLock` for reply hooks, aliases and send taps.**
  Those locks are only taken when the matching feature is in use, so they
  aren't on the default hot path.
- **Integer branch keys.** Branch-id handling doesn't show up in the
  allocation profile.
