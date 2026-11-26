# mod-maxfwd

This module stops requests that loop between proxies. Every SIP request
carries a [Max-Forwards](../../docs/glossary.md#max-forwards) hop counter,
much like an IP TTL. Each [proxy](../../docs/glossary.md#proxy) must lower it
by one and refuse the request with 483 when it reaches 0 (RFC 3261 §16.3
step 3, §16.6 step 3). Load this module on any proxy that forwards requests.

It is a port of [Kamailio's](../../docs/glossary.md#kamailio) `maxfwd`
[module](../../docs/glossary.md#module). It does three things:
- it decrements the request's Max-Forwards header, or adds one when it is
  missing;
- it tells the script when the hop limit is exhausted, so the script can
  answer 483;
- it tests the value against a limit.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `sip` | `maxfwd` | `mf_process(max)`: decrement or insert Max-Forwards; `is_maxfwd_lt(n)` |

## Quick start

```rust
import sip

route main(msg: Request) {
    guard sip.process(70) else reply(TooManyHops, "Too Many Hops")
    …
}
```

The builtin `guard msg.max_forwards > 0 else reply(TooManyHops)` does the same with
max 70 (`mf_process_maxfwd_header(70)`). It needs no import.

## Parameters

| Name | Default | Description |
|---|---|---|
| `max_limit` | 70 | 0..255. An existing Max-Forwards that `mf_process()` decrements never leaves higher than this: a larger decremented value is lowered to it. A missing header is inserted with `max`, whatever this is. |

## Functions

| Function | Description |
|---|---|
| `mf_process(max)` (`.fsr`: `sip.process(max)`) | `max` is an integer 0..255, checked at startup. If the request has a Max-Forwards header with a value ≥ 1, the value is replaced by `min(value - 1, max_limit)` and the function returns 1 (Kamailio's `process_maxfwd_header()`: `max` is only for a missing header). If it has none, `Max-Forwards: max` is inserted after the request line and it returns 2. It returns -1 when the value is 0 (answer 483), and -2 when the value is not a number or the headers can't be parsed. Both are false. |
| `is_maxfwd_lt(n)` (`.fsr`: `sip.max_forwards_below(n)`), also `mf_lowlimit(n)` and `maxfwd_at_least(n)` | `n` is an integer 0..255. 1 if the request's Max-Forwards value is lower than `n`; -1 if it isn't, -2 if there is no Max-Forwards header, -3 if it is malformed. Changes nothing. |

The [return codes](../../docs/glossary.md#return-code-convention) follow
Kamailio's convention: a negative value counts as false.

The edit goes through the [lump](../../docs/glossary.md#lumps) list. So it
is applied when the request is forwarded (`t_relay()`).

## Differences from Kamailio

- Besides Kamailio's names (`mf_process_maxfwd_header`, `maxfwd_process`,
  `process_maxfwd`), the function is also registered as `mf_process(max)`.
- The arguments must be literal integers, checked at startup. Kamailio
  also takes variables.

## Testing

- `tests/e2e_stream.py` loads `maxfwd` and calls `mf_process(70)` on every
  request. `tests/interop_sipp.py` and `tests/soak.py` use `mf_process(10)`.
- The script parser tests (`crates/sip-script`) parse a `mf_process(70)`
  condition.
- `tests/e2e_maxfwd.py` covers:
  - decrement, insert, and 483 for 0;
  - the malformed case (`if (!mf_process_maxfwd_header(10))` still refuses
    it);
  - `max_limit` and `is_maxfwd_lt()`.
- Unit tests in `src/lib.rs` cover the return codes of both functions, the
  `max_limit` cap, and `max` for a missing header only.
