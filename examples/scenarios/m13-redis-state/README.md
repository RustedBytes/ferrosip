# m13-redis-state (medium)

This scenario models two proxies that share per-user state through Redis.
**proxy-a** and **proxy-b** have the same routing. Their state is a block
list and a call counter, kept in one Redis (`redis` namespace,
[Kamailio](../../../docs/glossary.md#kamailio) ndb_redis). What one proxy
writes, the other enforces. It proves that shared state works across
proxies, and it shows what happens when Redis stops, restarts or freezes.

```
alice ──MESSAGE sip:block@… (X-Block-User: carol, Expires: 3)──▶ proxy-a ──SET block:alice:carol 1 EX 3──┐
                                                                                                        ▼
carol ──INVITE alice──▶ proxy-b ──EXISTS block:alice:carol──────────────────────────────────────────▶ Redis
                          │  └─ INCR calls:carol (+ EXPIRE 30 on the first)                            ▲
                          │                                                                             │
                          └──▶ PBX (features.callee)        proxy-a: the same reads ───────────────────┘
```

**Shows**:
- `[modules.redis] server`, with the port from the environment
  (`REDIS_PORT`);
- `redis.exec_with` / `redis.exec_with2`. Their `%s` takes a value as one
  whole Redis argument, so a value can't add arguments;
- `redis.free`;
- reading a reply with `pv("$redis(b=>value)")`. This is the
  [escape hatch](../../../docs/glossary.md#escape-hatch), because `.fsr`
  has no typed way to read `$redis`. The `raw_kamailio` lint is pedantic,
  off by default;
- `txn.is_retransmission()`, so a
  [retransmitted](../../../docs/glossary.md#retransmission)
  [INVITE](../../../docs/glossary.md#invite) isn't counted twice;
- [`[feature]`](../../../docs/glossary.md#feature-switch) integers used in
  templates (`"{features.call_window}"`) and comparisons.

What the routing does:
- **Block list**: `MESSAGE sip:block@…` with `X-Block-User: <caller>`
  stores `block:<from user>:<caller>` with `EX <Expires>`. The default is
  `block_ttl`, 600 s. `sip:unblock@…` deletes it. An INVITE from a blocked
  caller gets 603.
- **Call counter**: every INVITE that isn't blocked does `INCR
  calls:<from user>`. The first of a window sets `EXPIRE call_window`
  (30 s). Above `call_limit` (3) the call gets 403.

**Redis down: the choice.**
- Reads **fail open**. When `EXISTS` or `INCR` fails, the call goes
  through unchecked and a warning is logged (`redis down: …`). A block
  list and a call counter are conveniences and fraud brakes. An outage of
  the state store shouldn't stop all calls.
- Writes **fail closed**. A block request gets 503, so the user knows the
  block wasn't stored.

A deployment that must never let a blocked caller through would reply 503
to the INVITE instead (`guard redis.exec_with(…) else reply(ServiceUnavailable, …)`).

What a Redis outage costs:
- A stopped server refuses the connection at once. So calls are answered
  without delay.
- A **frozen** one accepts connections but doesn't answer. Each command
  then costs its `cmd_timeout` (default 1 s). A timed-out command isn't
  retried. So a call's two commands cost about 2 s.
- `allowed_timeouts` and `disable_time` can skip a server that keeps
  timing out.

**Edge cases checked** (`tests/scenarios/m13_redis_state.py`):
- alice blocks carol via A for 3 s:
  - the key has an expiry of 1..3 s;
  - carol's calls to alice get 603 via B and via A, and never reach the
    PBX;
  - carol → bob and alice → carol still get 200.
- Redis expires the key, and carol reaches alice via B again.
- These get 400 and write nothing: `Expires: 0`, a non-numeric Expires, a
  space in `X-Block-User`, and a missing `X-Block-User`.
- A block without Expires gets the default 600 s. An unblock via B ends a
  block made via A.
- eve's calls alternate A, B, A (200 each). The 4th, via B, gets 403 and
  isn't relayed. The counter is 4 and expires within the 30 s window.
- Redis stopped:
  - a block request gets 503 in under 4 s;
  - frank (blocked) and eve (over her limit) get through (200) via B, and
    A answers too;
  - the warning is logged.
- Redis restarted (empty, no persistence):
  - both proxies reconnect;
  - a new block via A is enforced by B;
  - frank's old block and eve's counter are gone.
- Redis frozen (SIGSTOP):
  - a call still gets 200, within 5 s;
  - after it resumes, a block written via A is enforced via B, and an
    unblocked call goes through. So the replies aren't out of step with
    the commands after the timeouts.

**Run it by hand**: start `redis-server --port 6379`. Then start `proxy-a`
(`SIP_PORT` 5060) and `proxy-b` (`SIP_PORT` 5070), each from its own
directory, with `REDIS_PORT=6379` and `CALLEE=sip:127.0.0.1:5080`. Block
with `redis-cli SET block:alice:carol 1 EX 60`, or with a MESSAGE as
above.
