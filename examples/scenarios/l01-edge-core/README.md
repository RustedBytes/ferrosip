# l01-edge-core (large)

This scenario models a common two-tier deployment. An **edge** proxy
faces the phones and blocks floods. A **core** proxy behind it
authenticates users and acts as the
[registrar](../../../docs/glossary.md#registrar). It proves that
registrations and calls cross both tiers in both directions, and that the
edge stops a flooding source on its own.

```
alice ─┐                     ┌──────────────── core ────────────────┐
       ├──UDP──▶ edge ──────▶│ auth.check / challenge (users file)  │
bob ◀──┘    flood ban        │ location.save / lookup (with Path)   │
            Path, Record-Route└──────────────────────────────────────┘
            options_reply          │ lookup → Route: <edge> (the Path)
                 ▲─────────────────┘
```

**Shows**:
- **Edge:**
  - [`shared table`](../../../docs/glossary.md#shared-table) counters with
    a ttl and a ban table, keyed by `ip:port`;
  - `path.add()` on [REGISTER](../../../docs/glossary.md#register) (see
    [Path](../../../docs/glossary.md#path));
  - `route_set.follow()` for
    [in-dialog requests](../../../docs/glossary.md#in-dialog-request), and
    for requests the core sends back along the Path;
  - `route_set.record()` (see
    [Record-Route](../../../docs/glossary.md#record-route));
  - a route-level `// lint: allow(open_relay)`, since the edge only
    forwards to the core.
- **Core:**
  - `auth.check` / `auth.challenge` with a users file;
  - `auth.consume_credentials()`;
  - `location.save()` and `location.lookup()`.

  The registrar follows the Path, so calls to a phone go back through the
  edge it registered from. This needs `use_path = true`. Like
  [Kamailio](../../../docs/glossary.md#kamailio), the registrar ignores
  Path by default. Without it, calls go to the REGISTER's source, which is
  the edge. The edge has no [Route](../../../docs/glossary.md#route) to
  follow and sends them back to the core. The core's challenge then ends
  the call with a 407, because the credentials were already consumed.

**Edge cases checked** (`tests/scenarios/l01_edge_core.py`):
- REGISTER is [challenged](../../../docs/glossary.md#challenge) by the
  core through the edge (401, then 200). Wrong credentials are refused.
- alice → bob crosses edge, core and edge again. Bob sees three
  Record-Routes and no credentials. Bob's [BYE](../../../docs/glossary.md#bye)
  goes back through all three hops.
- An unregistered callee gets 404. An
  [INVITE](../../../docs/glossary.md#invite) without credentials gets 407.
- [OPTIONS](../../../docs/glossary.md#options) is answered at the edge.
- A burst of 40 requests from one source: about 20 are answered. Then the
  source is dropped and stays banned. Other sources are still served.

**Run it by hand**: start `core` (`CORE_PORT`, default 5070) and `edge`
(`EDGE_PORT` 5060, `CORE`), each from its own directory, because
`users_file` is relative.
