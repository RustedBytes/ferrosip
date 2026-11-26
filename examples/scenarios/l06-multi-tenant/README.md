# l06-multi-tenant (large)

This scenario models one proxy serving two tenants (customers), told
apart by the request's domain. Each tenant has its own users, call limit
and routes, in its own `.fsr` file. It proves that tenants are fully
isolated: same-named users stay separate, one tenant can't reach
another's users, and each tenant's limits count only its own calls.

```
                     ┌─ a.example.com ─▶ tenant_a.handle: users of A, 2 calls, +number → gw-a
UA ──▶ proxy: match msg.ruri.host ─┤
                     ├─ b.example.com ─▶ tenant_b.handle: users of B, 1 call, no PSTN
                     └─ anything else ─▶ 404 Unknown domain
        subscriber table (username, domain, password) · location with use_domain
```

**Shows**:
- `import "./tenant_a.fsr" as tenant_a`. Each tenant file has a
  `fn handle(msg) -> Action`, called as `tenant_a.handle(msg)`. Its routes
  lower to `route[tenant_a__handle]` (see
  [lowering](../../../docs/glossary.md#lowering) and
  [route block](../../../docs/glossary.md#route-block)). A tenant file
  imports the modules and
  [`[feature]`](../../../docs/glossary.md#feature-switch) values it uses
  itself.
- `match msg.ruri.host` with string patterns (see
  [R-URI](../../../docs/glossary.md#r-uri)).
- Per-tenant users: auth_db on an SQLite `subscriber` table
  (`[modules.auth] db_url`, `calculate_ha1`, `use_domain`). So `alice@a`
  and `alice@b` are two users with two passwords. Location `use_domain`
  keeps their registrations apart.
- Per-tenant limits: one [dialog profile](../../../docs/glossary.md#dialog-profile)
  with a value per tenant (`dialog.set_profile_value("calls", "a")`,
  `dialog.profile_value_size("calls", "a", active)` into a `let`).
- Per-tenant routes: A sends `+` numbers to its gateway
  (`features.gw_a`). B refuses them.
- Each tenant refuses a From in another tenant before the
  [challenge](../../../docs/glossary.md#challenge) (`403 Wrong tenant`).

**Edge cases checked** (`tests/scenarios/l06_multi_tenant.py`):
- Four users register, two of them named alice. alice@b with alice@a's
  password is refused.
- bob@a → alice@a rings A's alice only. carol@b → alice@b rings B's alice
  only.
- bob@a → carol@b: 403 Wrong tenant, and carol sees nothing.
- bob with a From in B (no account there) can't authenticate.
- An unknown domain gets 404 Unknown domain. An unregistered user of A
  gets 404 Not registered.
- A's `+4930…` reaches A's gateway. B's gets 403 No PSTN for this tenant.
- A failed call (404) after the profile was set doesn't keep B's only
  slot. Twice in a row: never 486.
- alice@a registering at B's domain → 403.
- B has one call up, and a second → 486 Tenant B call limit. Meanwhile A
  has two up at once, and a third gets 486 Tenant A call limit. After the
  hangups B can call again.

**Run it by hand**: create the `subscriber` table (`username`, `domain`,
`password`). The test does it with sqlite3. Then start
`ferrosip --config ferrosip.toml` from `proxy/` with
`SUBSCRIBER_DB=sqlite:///path/tenants.db`. `SIP_PORT` is 5060 and `GW_A`
is `sip:127.0.0.1:5081`.
