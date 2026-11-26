# s05-acl-allowlist (small)

This scenario models trunk ingress: the entry point where carriers send
calls to a company's PBX. Only the carriers may send, and what they send
goes to the PBX. It proves that two layers of source checks keep everyone
else out, and that the allowlist can be reloaded at run time.

```
trunk ──UDP──▶ ferrosip ──▶ PBX (features.pbx)
               │ 1. msg.src.ip in [features.trunk_a, features.trunk_b] else 403 "Not a trunk IP"
               │ 2. acl.source_allowed(1): ip/mask/port in the address table, group 1,
               │    else 403 "Not a trunk"
```

**Shows**:
- `msg.src.ip in [a, b]` over [`[feature]`](../../../docs/glossary.md#feature-switch)
  values. A feature is a scalar, so the list is written in the routing.
- The `acl` module ([Kamailio](../../../docs/glossary.md#kamailio)
  permissions) with a db_text `address` table and
  `permissions.addressReload`.

Both layers satisfy the `open_relay` [lint](../../../docs/glossary.md#lint).
So `ferrosip lint` is clean without an `allow`.

Every test UA is 127.0.0.1, so the address table tells them apart by
port. The test writes its own table into its temp directory (`ACL_DB`).
`db/` here is the table for running by hand. The acl module loads the
`trusted` table along with `address`, and it refuses to start without it.
So `db/trusted` is there, empty.

**Edge cases checked** (`tests/scenarios/s05_acl_allowlist.py`):
- The trunk (its port in group 1) calls the PBX,
  [BYE](../../../docs/glossary.md#bye) included.
- The same IP from a port the table doesn't list gets `403 Not a trunk`,
  for [OPTIONS](../../../docs/glossary.md#options) and
  [INVITE](../../../docs/glossary.md#invite). Nothing is relayed.
- An address in group 2 is refused: only group 1 may send.
- An [ACK](../../../docs/glossary.md#ack) from a stranger is dropped
  without a reply, because an ACK is never answered. It is not relayed.
- A row is added to the table and `permissions.addressReload` runs
  (→ 3 rows). The new trunk is relayed at once.
- A reload of a broken table keeps the rules that were running.
- A second proxy's trunk IPs don't include 127.0.0.1. It refuses even a
  listed ip:port with `403 Not a trunk IP` (the first layer).

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory.
The table is `db/`. It listens on port 5060, with PBX
`sip:127.0.0.1:5080` and trunk 127.0.0.1:5070. Set `SIP_PORT`, `PBX`,
`TRUNK_A`, `TRUNK_B`, `ACL_DB`.
