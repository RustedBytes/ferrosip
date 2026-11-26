# mod-lua

The `app_lua` [module](../../docs/glossary.md#module) lets you write part of
your routing logic in Lua. Use it when some decision is easier to express in
a general-purpose language than in the routing script. The routing calls a
Lua function with `lua_run()` (`lua.run()` in [`.fsr`](../../docs/glossary.md#fsr)).

The module embeds Lua 5.4, vendored and built from source through `mlua`.
It gives Lua code a [KEMI](../../docs/glossary.md#kemi)-style `KSR` API.
From Lua, `KSR.<module>.<function>(...)` reaches every function exported by
the loaded modules. Each [worker thread](../../docs/glossary.md#worker) has
its own Lua state.

| Module | [Kamailio](../../docs/glossary.md#kamailio) module (`loadmodule`) | Purpose |
|---|---|---|
| `lua` | `app_lua` | Run Lua functions and code from the script, with the `KSR` API |

## lua (app_lua)

ferrosip reads and checks the file named by `load` once, at startup. A
script that fails to load stops ferrosip from starting. Every worker's Lua
state runs that copy. So editing the file changes nothing until
`app_lua.reload`.

The reload re-reads and checks the file. A broken file is refused, and the
old script stays. Otherwise each worker builds a fresh state before its
next Lua call. Lua globals are per worker, and they start over then.

The `KSR` API available to Lua:

| Lua | Description |
|---|---|
| `KSR.<module>.<function>(...)` | Calls the exported script function `<function>` with the given arguments and returns its return code. The module part is not checked: the function is looked up by name. Strings containing `$` are parsed as templates with variables. Arguments are fixed up once per distinct call and cached |
| `KSR.hdr.append/remove/insert/is_present(...)` | Aliases of `append_hf`, `remove_hf`, `insert_hf`, `is_present_hf` (textops must be loaded) |
| `KSR.pv.get(name)` | Value of a pseudo-variable (`"$rU"`), `nil` if null |
| `KSR.pv.gete(name)` | Same, `""` instead of `nil` |
| `KSR.pv.sets(name, v)` / `KSR.pv.seti(name, v)` | Set as string / integer; 1 or -1 |
| `KSR.pv.unset(name)` | Set to null |
| `KSR.pv.is_null(name)` | `true` if the value is null |
| `KSR.err/warn/notice/info/dbg/crit(msg)` | Log at that level |
| `KSR.x.exit()` / `KSR.x.drop()` | Stop the Lua code and the script (like `exit`) |

The glossary explains the
[return code](../../docs/glossary.md#return-code-convention),
[fixup](../../docs/glossary.md#fixup) and
[pseudo-variable](../../docs/glossary.md#pseudo-variable-pv) ideas used in
this table.

A called function that returns 0 also stops the Lua code and the script.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `load` | none | Lua file loaded into every worker's state |

`reload` and `log_mode` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `lua_run(func[, p1[, p2[, p3]]])` | Calls the global Lua function `func` with up to three string arguments. Returns the Lua function's number (0 becomes -1), -1 for `false`, 1 for anything else; 0 (script stops) after `KSR.x.exit()`/`KSR.x.drop()`; -1 on a Lua error (logged) |
| `lua_runstring(code)` | Runs a Lua chunk; return codes as for `lua_run` |
| `lua_dofile(path)` | Reads and runs a Lua file (not cached); -1 if it can't be read; otherwise as for `lua_run` |

**[RPC](../../docs/glossary.md#rpc) commands**

| Command | Description |
|---|---|
| `app_lua.reload` | Checks that the `load` file still loads, then makes every worker reload it before its next call; returns the new generation number |

**Example**

```toml
[modules.lua]
load = "/etc/ferrosip/route.lua"
```

```rust
import lua

route main(msg: Request) {
    lua.run("route_lua", msg.from.user)
    reply(ServerInternalError, "lua did not exit")
}
```

```lua
function route_lua(user)
  if KSR.pv.get("$rm") == "OPTIONS" then
    KSR.sl.sl_send_reply(200, "lua " .. user .. " " .. KSR.pv.get("$rU"))
    KSR.x.exit()
  end
  return 1
end
```

**Differences from Kamailio**

- Lua cannot be the routing engine (`cfgengine "lua"`). Call Lua from the
  routing with `lua_run()` (`lua.run()` in `.fsr`).
- The `KSR` table is a generic bridge to exported functions. It is not
  Kamailio's per-module KEMI exports. Functions keep their native script
  names and argument rules. Only the `KSR.pv`, `KSR.hdr`, `KSR.x` and
  logging helpers listed above are special.

## Testing

- `tests/e2e_extra.py` runs `lua_run` with `KSR.pv.get`,
  `KSR.sl.sl_send_reply` and `KSR.x.exit`. It also runs `lua_runstring`
  with `KSR.pv.sets`.
- No unit tests or fuzz targets.
