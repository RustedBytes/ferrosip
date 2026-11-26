# Benchmarks

ferrosip and Kamailio on the same machine, under the same load.

## Compared with Kamailio

`bench/kamailio/run.sh` runs Kamailio and ferrosip on the same machine.
Kamailio is built from its GitHub sources at a release tag by
`bench/kamailio/build.sh` (default 6.1.5, its own Makefile flags with
`MEMDBG=0`, as for production; the workflow takes the tag as an input and
caches the build). They take turns, and each gets the same CPU pinning, worker
counts (2 UDP workers/children, 2 TCP readers/tcp_children) and load
(`sipflood`, 200 requests in flight). Configs are minimal and equivalent
(`bench/kamailio/k_*.cfg` vs `f_*.cfg`). Kamailio uses its TLSF memory manager
(`-x tlsf -X tlsf`). The default allocator (`qm`) was 25–40% slower
here, and `fm` was erratic on the stateful path. The tables show medians of
alternating runs, plus the CPU time the proxy used per request, summed over
all its processes or threads.

### Kamailio 6.1.5

GitHub runner, AMD EPYC 9V74, 2 vCPU (proxy on one, load generator and UAS
on the other), 7 runs each, Kamailio built from the 6.1.5 tag:

| scenario | Kamailio req/s | ferrosip req/s | ratio | p50 / p99 ms (K) | p50 / p99 ms (F) | CPU µs/req K / F |
|---|---|---|---|---|---|---|
| stateless reply (UDP) | 36,911 | 93,580 | 2.5× | 5.41 / 6.82 | 2.11 / 2.29 | 26 / 9 |
| `t_relay` UDP → UDP | 13,611 | 35,462 | 2.6× | 14.16 / 18.19 | 5.42 / 7.78 | 73 / 27 |
| `t_relay` TCP → TCP | 10,268 | 30,558 | 3.0× | 20.14 / 23.38 | 6.61 / 8.69 | 97 / 32 |
| REGISTER → `save()` | 18,582 | 66,418 | 3.6× | 10.60 / 14.79 | 2.98 / 3.96 | 53 / 14 |

Neither proxy had errors. Kamailio's stateless replies were much slower on
this runner than in every other measurement, including the 5.7.4 runs below
and the same 6.1.5 build in the sandbox, where the two tie. ferrosip's
number matches the earlier runners. This run doesn't separate the CPU
model from the Kamailio version, so treat that row with care.

The 4-vCPU gVisor sandbox used for development (proxy on 2 CPUs, 3 runs),
same 6.1.5 build:

| scenario | Kamailio req/s | ferrosip req/s | ratio | CPU µs/req K / F |
|---|---|---|---|---|
| stateless reply (UDP) | 134,890 | 133,669 | 1.0× | 14 / 4 |
| `t_relay` UDP → UDP | 29,812 | 51,178 | 1.7× | 65 / 20 |
| `t_relay` TCP → TCP | 20,691 | 55,532 | 2.7× | 85 / 28 |
| REGISTER → `save()` | 42,183 | 166,523 | 3.9× | 46 / 5 |

Absolute numbers are lower in the sandbox, because syscalls are emulated.

### Kamailio 5.7.4

The tables below were measured with Kamailio 5.7.4 (the Ubuntu 24.04
package), before the switch to source builds.

GitHub runner, Intel Xeon Platinum 8573C, 2 vCPU (proxy on one, load
generator and UAS on the other), 7 runs each. This is a real kernel; run it
with the "Benchmark vs Kamailio" workflow:

| scenario | Kamailio req/s | ferrosip req/s | ratio | p50 / p99 ms (K) | p50 / p99 ms (F) | CPU µs/req K / F |
|---|---|---|---|---|---|---|
| stateless reply (UDP) | 125,483 | 126,600 | 1.0× | 1.57 / 1.96 | 1.57 / 1.74 | 7 / 6 |
| `t_relay` UDP → UDP | 28,849 | 56,048 | 1.9× | 7.09 / 9.97 | 3.29 / 6.19 | 34 / 17 |
| `t_relay` TCP → TCP | 23,078 | 49,456 | 2.1× | 8.68 / 10.61 | 3.92 / 5.93 | 43 / 19 |
| REGISTER → `save()` | 35,898 | 107,802 | 3.0× | 5.42 / 8.53 | 1.84 / 2.08 | 27 / 9 |

Rerun after the production-hardening and optimization work (graceful
shutdown, bounded reads, panic isolation, −25–46% allocations), on a slower
runner CPU, AMD EPYC 7763 with 2 vCPU, 7 runs:

| scenario | Kamailio req/s | ferrosip req/s | ratio | CPU µs/req K / F |
|---|---|---|---|---|
| stateless reply (UDP) | 74,977 | 93,043 | 1.24× | 13 / 10 |
| `t_relay` UDP → UDP | 17,597 | 34,895 | 1.98× | 56 / 28 |
| `t_relay` TCP → TCP | 12,089 | 27,506 | 2.28× | 82 / 36 |
| REGISTER → `save()` | 25,879 | 59,639 | 2.30× | 38 / 16 |

In that run, 2 of Kamailio's 7 TCP runs failed and were left out of its
median. ferrosip had no errors.

The sandbox (5 runs) gave 1.6× stateless, 3.4× UDP relay, 2.0× TCP relay
and 1.8× REGISTER with 5.7.4.

Reading the numbers:
- **Stateless replies are close to a tie** on most machines. Both do one
  receive, a lazy parse and one send, and the syscalls dominate. The 6.1.5
  runner above is the exception.
- **Stateful relaying** is where ferrosip uses about half the CPU per
  request. tm's transaction table is a sharded hash map with per-shard locks,
  and its timers are a wheel fed by per-worker inboxes. Kamailio uses a
  shared-memory hash table, global timer lists and a process-per-worker
  model.
- **REGISTER** gains the most: usrloc is an in-process sharded map, against
  Kamailio's shared-memory hash with per-slot locks.
- **Caveats.**
  - These are micro-benchmarks of minimal scripts. Real configs spend most of
    their time in script logic, database and DNS, where the gap is unknown.
  - ferrosip implements a subset of Kamailio's features and edge cases.
  - Kamailio is a stock build (its own Makefile, `MEMDBG=0`), not tuned
    beyond the allocator.
  - On the runner, the load generator shares a CPU with the UAS, so the
    fastest rows may be partly client-bound.
  - Kamailio lost 0.02–0.1% of requests in some UDP relay runs. In one of 7
    TCP runs it answered the first request with a non-200 and the connection
    dropped. Such runs are counted separately and left out of the medians.
    ferrosip lost none.
