# Design notes

What building ferrosip taught, and what was left out on purpose.

## Lessons from building it

1. **Hash quality matters for shared tables.** Plain FxHash leaves the low
   bits poorly mixed, and hashbrown picks buckets from them. SIP branch IDs
   differ only in their tail bytes, so lookups degraded as the table grew.
   Fixed with a splitmix finalizer (`shm.rs`, with a test).
2. **Don't wake anything per message.** The first version sent tm timers over
   an `mpsc` channel. Every transaction woke the timer thread three times
   (4 futex syscalls per transaction), capping throughput at ~27k txn/s.
   Switching to per-worker inboxes drained on the tick, as Kamailio does,
   raised it to ~97k.
3. **Publish shared state before the I/O that can trigger a response.** tm
   used to send the request before inserting the transaction. With TCP, the
   reply arrives on a different thread (a reader), which sometimes handled it
   before the insert and dropped it as unknown. The same race existed with
   UDP across `SO_REUSEPORT` workers, just less often.
4. **Index for the real topology, not the test topology.** usrloc's
   connection → AoR index was a `Vec` with `contains()`. That's fine when
   each phone has its own connection, but O(n²) when an edge proxy registers
   many users over one TCP connection: REGISTER over TCP ran at 3k/s instead
   of 109k/s until the index became a set.
5. **Measure refactors A/B on the same box.** After the forking rewrite a
   single-branch relay looked about 15% slower, but run-to-run noise here is
   ±2×. Alternating old and new builds showed a real gap. The cause was
   parsing *all* headers of every request to prepare CANCELs that only an
   INVITE can need, and copying each rendered request to send it outside the
   lock. Building CANCEL headers only for INVITE and sharing requests as
   `Arc<[u8]>` closed the gap to noise.

## Deliberately left out (next steps)

- DNSSEC validation.
- SCTP.
- `recvmmsg` batching and CPU pinning of UDP workers. Both were implemented
  and measured (A/B, alternating runs) and gave no reliable gain on the test
  box (a gVisor sandbox, where syscalls and scheduling are emulated), so
  they were dropped. `sendmmsg` would also need replies to be deferred.
