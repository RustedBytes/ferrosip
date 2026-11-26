# s10-routing-tests (small)

This scenario shows how to unit-test a routing without starting a server
or sending real packets. The routing is checked by its
[`test` blocks](../../../docs/glossary.md#test-block) alone.
`ferrosip test` runs them in-process with the real modules
([transactions](../../../docs/glossary.md#transaction), timers,
[`await`](../../../docs/glossary.md#await)). The network only records what
is sent. It proves that passing tests pass, a failing test is reported
with its line and value, and a test that doesn't compile is refused.

```
routes/main.fsr          the routing: OPTIONS · 483 · 405 · REGISTER (401, save)
                         INVITE (407) → registered user: voicemail on 486 / 20s no answer
                                     → +number from 10/8: gw1, gw2 (2s each), else 503
routes/main_test.fsr     20 tests that must pass
failing/                 expected_failure_test.fsr (must be reported failing)
                         does_not_compile_test.fsr (must be refused)
```

**Shows**:
- `test` blocks with `send()` (one line, or `"""…"""` with headers);
- `send(…, from: "ip:port")`, `answer()`, `wait()`;
- mocks (`auth.check = true`, `location.lookup = false`);
- `calls()`, `relays()`, `relay_uri(n)`, `relay_dest(n)`, `reply_code()`,
  `reply_reason()`;
- [shared tables](../../../docs/glossary.md#shared-table) inside tests;
- `--filter`.

The test files are passed explicitly. So the routing stays the same with
or without them. The failing ones live outside `routes/`, so nothing picks
them up by accident. `ferrosip test` without files reports that the
routing has no test blocks and exits 1.

**Edge cases checked** (`tests/scenarios/s10_routing_tests.py`, which runs
`ferrosip test` and reads its output):
- The 20 tests of `routes/main_test.fsr` pass and the run exits 0. Among
  them:
  - the await timeouts: `wait(21s)` → voicemail, `wait(3s)` → the second
    gateway;
  - a 603 forwarded instead of voicemail;
  - a gateway's 486 that ends the call without failover;
  - a refused source (`from:`);
  - counters in a shared table, and empty tables in each test;
  - `reply_code()` 0 while no [final](../../../docs/glossary.md#final-reply)
    was sent.
- `--filter gw1` runs exactly one test.
- `failing/expected_failure_test.fsr`:
  - exit code ≠ 0, and `0 passed, 1 failed`;
  - the FAIL line with name and `file:line`;
  - the assert with the value it saw (`reply_code() is "404"`);
  - with the green file and a filter, `1 passed, 1 failed`.
- `failing/does_not_compile_test.fsr` (a mock of `location.lokup`) is
  refused with its position and a did-you-mean. Nothing runs.

**Run it by hand**, from this directory:
`ferrosip test --config ferrosip.toml routes/main_test.fsr`. It takes
about 25 s, because `wait()` takes real time. Do the same with
`failing/expected_failure_test.fsr`.
