# m14-lua-routing (medium)

This scenario models a proxy whose routing decision is made in Lua
([Kamailio](../../../docs/glossary.md#kamailio) app_lua). Use this pattern
when part of the logic is easier to write in a general-purpose language.
It proves that Lua can route or reject calls, that Lua errors fail safely,
that headers can't call arbitrary Lua, and how reloads and per-worker
state behave.

```
caller ──▶ ferrosip (.fsr)                         routes/route.lua (one Lua state per worker)
             │ Max-Forwards, source check           ┌──────────────────────────────────────────┐
             │ tenant = X-Tenant or "default"  ───▶ │ route_<tenant>(<From display name>)      │
             │ route_set.record()                   │  reads $rU, $fU, $hdr(X-Note)  (KSR.pv)  │
             │ lua.run("route_{tenant}", …)         │  stamps X-Lua-* headers       (KSR.hdr)  │
             │                                      │  sets $du  ─or─  sl_send_reply + exit    │
             │◀─────────────────────────────────────┴──────────────────────────────────────────┘
             ├─▶ PBX       sales, support; every call of tenant acme
             ├─▶ GATEWAY   numbers (+4930…)
             ├─▶ 403 / 404 answered from Lua (blocked caller, no route)
             └─▶ 500 "Lua routing failed": a Lua error, a missing function, false
```

**Shows**:
- `[modules.lua] load` with a path relative to the config directory. It
  comes from `${LUA_SCRIPT:-routes/route.lua}`, so the test can run an
  editable copy.
- `lua.run(name, arg)`, with the function name templated from a header
  and checked first (`^[a-z]+$`). So a header can't call `os.exit` or any
  other Lua global.
- From Lua, with the [KSR](../../../docs/glossary.md#kemi) API:
  - `KSR.pv.get/gete/sets` (see
    [pseudo-variable](../../../docs/glossary.md#pseudo-variable-pv));
  - `KSR.hdr.append`;
  - `KSR.sl.sl_send_reply` + `KSR.x.exit()`;
  - `os.getenv` for the targets (`PBX`, `GATEWAY`).
- `ferroctl app_lua.reload`.

`KSR.hdr.*` needs textops loaded. Here the `.fsr`'s
`msg.headers.has("X-Tenant")` loads it implicitly. A routing whose only
header edits are in Lua needs `[modules.text]` in ferrosip.toml.

Lua state is **per [worker](../../../docs/glossary.md#worker) thread**:
- Globals (here the `calls` counter) are never shared between workers.
- A reload gives every worker a new state, and the counters start again
  at 0.
- UDP workers share the port with SO_REUSEPORT. So one source address
  always meets the same worker, and so the same Lua state.

Keep shared data in a [`shared table`](../../../docs/glossary.md#shared-table),
not in Lua.

**Edge cases checked** (`tests/scenarios/m14_lua_routing.py`):
- Lua sends `sales` to the PBX and `+4930123456` to the gateway. Each has
  its `X-Lua-Route` header and the
  [Record-Route](../../../docs/glossary.md#record-route) added before
  `lua.run`.
- An unknown user gets 404 and a blocked caller (`$fU`) 403, both
  answered from Lua. Tenant `acme` goes to its own function.
- These get 500, nothing relayed, and the error logged:
  - a Lua runtime error (`error()`, indexing nil, an unknown `KSR`
    function);
  - a function that doesn't exist (`X-Tenant: ghost`);
  - a function returning `false`.

  The next call is routed as usual.
- `X-Tenant: os.exit` is refused (400) before any Lua runs.
- UTF-8 comes back intact in the From display name (a `lua.run`
  argument) and in a header read with `KSR.pv.get`. Lua's `#s` counts its
  bytes. Content-Length stays right.
- 24 calls from 12 sources: two Lua states (one per worker), each
  counting only its own calls. One source is always on one state.
- `app_lua.reload` of a new version: every call runs it, in fresh states.
  A reload of a script with a syntax error is refused, and the running
  version stays.
- Editing the file on disk *without* a reload changes nothing: the
  script is read once at startup and again only on `app_lua.reload`.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`PBX` is `sip:127.0.0.1:5070`, and `GATEWAY` is `sip:127.0.0.1:5080`.
After editing `routes/route.lua`, run
`ferroctl -s /tmp/ferrosip-m14.sock app_lua.reload`.
