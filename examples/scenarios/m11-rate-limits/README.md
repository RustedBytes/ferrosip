# m11-rate-limits (medium)

This scenario models rate limits in front of an upstream. There is a limit
per source and a global cap on new calls. Both answer with 503 and
Retry-After. It proves that the limits hold under bursts, recover after
the window, and never block a caller from ending or cancelling a call.

```
UA (ip:port) ──▶ ferrosip ────────────────────────────────────────▶ upstream
                 │ in-dialog, CANCEL: never limited
                 │ pipe "src:<ip>:<port>"  5 / 2s ── over: 503 Server Unavailable, Retry-After: 2
                 │ INVITE: ratelimit "calls" 4 / 2s ── over: 503 Too many calls, Retry-After: 2
```

**Shows**:
- `pipe_limits.check_or_create(name, "TAILDROP", 5)`, with a pipe per
  source created on first use;
- `pipe_limits.reject(2s)`;
- ratelimit's static pipe and queue in `[modules.limits]` (`pipe`,
  `queue`), with `limits.check_rate()`;
- `text.append_to_reply("Retry-After: …")` before `reply(ServiceUnavailable, …)`;
- [in-dialog requests](../../../docs/glossary.md#in-dialog-request) and
  [CANCEL](../../../docs/glossary.md#cancel) handled ahead of the limits.

The per-source key is `ip:port`, not the IP. Phones behind one
[NAT](../../../docs/glossary.md#nat) share the address, and so does every
UA of the test, all on 127.0.0.1. That is also why pike
(`limits.check_flood()`, per IP) is not used here.

The limits are fixed windows (`timer_interval`, 2s). So a burst that
straddles a window boundary may pass up to twice the limit. Pipes created
per source are never removed, because pipelimit has no `clean_unused`.

**Edge cases checked** (`tests/scenarios/m11_rate_limits.py`):
- 15 [MESSAGEs](../../../docs/glossary.md#message) in a burst from one
  source: 5 to 10 are relayed. The rest get 503 with `Retry-After: 2` and
  pipelimit's reason. The upstream saw only the relayed ones.
- Another port on the same IP, in the same window, has its own pipe. All
  its requests are relayed.
- After the window the limited source is served again.
- 9 [INVITEs](../../../docs/glossary.md#invite) from 3 sources, each under
  its own limit: 4 to 8 are set up. The rest get `503 Too many calls` with
  Retry-After. `rl.stats` counts the drops.
- A source over its limit can still end its call
  ([BYE](../../../docs/glossary.md#bye) in the
  [dialog](../../../docs/glossary.md#dialog)) and cancel a ringing one
  (CANCEL → 487).
- `pl.stats` lists one pipe per source ip:port.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060
and `UPSTREAM` is `sip:127.0.0.1:5080`.
