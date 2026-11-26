# mod-location

This crate handles registration and the location table. Phones send a
[REGISTER](../../docs/glossary.md#register) to say where they can be
reached. This crate stores those addresses and finds them again when a call
comes in. See [location service](../../docs/glossary.md#location-service).

It ports two [Kamailio](../../docs/glossary.md#kamailio) modules,
[`registrar`](../../docs/glossary.md#registrar) and
[`usrloc`](../../docs/glossary.md#usrloc). ferrosip calls them `location`
together: `[modules.location]`, and `location.save()` and
`location.lookup()` in [`.fsr`](../../docs/glossary.md#fsr).

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `location` | `registrar` | `save()`, `lookup()`, `registered()`, `lookup_branches()`, `unregister()`, `reg_fetch_contacts()` and `$ulc` on the `location` table |
| `location` | `usrloc` | Table of AoR → contacts, expiry, `handle_lost_tcp`, database persistence, `ul.*` RPCs |

The registrar is the crate's root (`mod_location`). The table is
`mod_location::store`. Other modules use it through
`Registry::api::<Usrloc>()`.

## Registration (registrar)

This part processes REGISTERs and looks up locations. It is a port of
Kamailio's `registrar` module.

- `save()` implements RFC 3261 §10.3 and answers the REGISTER itself.
- `lookup()` takes an [AoR](../../docs/glossary.md#aor) in the
  [Request-URI](../../docs/glossary.md#r-uri). It returns the registered
  contact or contacts, and the next hop to reach them.

Supported extensions:

- [Path](../../docs/glossary.md#path) (RFC 3327);
- outbound flows ([RFC 5626](../../docs/glossary.md#sip-outbound));
- [GRUU](../../docs/glossary.md#gruu) (RFC 5627).

Bindings are stored in the location table
([below](#the-location-table-usrloc)), so `usrloc` loads first.


### Quick start

In [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) and `.fsr`,
usrloc and registrar are one module, `location`
([docs/fsr.md](../../docs/fsr.md)). It loads when the routing calls one of
its functions.

```toml
[modules.location]                     # usrloc + registrar
handle_lost_tcp = true
max_contacts = 3
```

```rust
import location

route main(msg: Request) {
    match msg.method {
        REGISTER => location.save()
        OPTIONS => {
            if location.is_registered() {
                reply(OK, "Registered")
            }
            reply(NotFound, "Not Registered")
        }
        _ => {
            guard location.lookup() else reply(NotFound, "Not Found")
            relay(msg)
        }
    }
}
```

`relay(msg)` (`t_relay()`) without a destination sends to
[`$du`](../../docs/glossary.md#destination-uri) (`msg.dst_uri`).
`location.lookup()` set `$du` to the address and connection the client
registered from.

### Parameters

| Name | Default | Description |
|---|---|---|
| `default_expires` | 3600 | Expiry (s) when neither the Contact nor the request has one. |
| `min_expires` | 60 | Shorter non-zero intervals get `423 Interval Too Brief` with `Min-Expires`. |
| `max_expires` | 86400 | Longer intervals are reduced to this. |
| `max_contacts` | 0 | Maximum bindings per AoR. 0 = unlimited. Above it: `503 Too many registered contacts`. |
| `use_received` | 1 | 1: send to the source of the REGISTER. This is safe behind [NAT](../../docs/glossary.md#nat). 0: send UDP contacts to the Contact URI, when its host is an IP literal. TCP/TLS/WS contacts always reuse the source connection. |
| `append_branches` | 1 | `lookup()` adds every other contact as a fork [branch](../../docs/glossary.md#branch) for `t_relay()`, while the destination set has room (`max_branches - 1` entries, as in Kamailio). A contact that doesn't fit is dropped and logged; `lookup()` still succeeds. |
| `use_path` | 0 | Store the REGISTER's Path headers with its contacts. |
| `path_mode` | `lazy` (2) | Applies with `use_path`. 0: store Path without echoing it. 1: Path is required and always echoed. Without one, the reply is `420 Bad Extension` + `Unsupported: path`. 2: echo Path in the 200 when the client sent `Supported: path`. |
| `gruu_enabled` | 1 | Return `pub-gruu` / `temp-gruu` to clients with `+sip.instance` and `Supported: gruu`. |
| `outbound_mode` | `off` (0) | 1 or 2: add `Require: outbound` to the 200. This happens when the client supports outbound and has a binding with `reg-id` + instance. |
| `xavp_cfg` | none | [xavp](../../docs/glossary.md#xavp) with the fields `match_callid`, `match_contact` and `match_received`. `registered()`'s `match_option` compares against them. This is Kamailio's `xavp_cfg`. |
| `xavp_rcd` | none | xavp that `registered()`'s `match_action` 1 fills with the matched contact: `ruid`, `contact`, `received`, `path`, `expires`. |

At startup the module checks `min_expires <= default_expires <= max_expires`.
An unknown parameter is a config error that names the line. So is loading
`registrar` before `usrloc`.

### Functions

All functions except `reg_free_contacts()` take the table name first. It
must be `"location"`, which is checked at startup. In `.fsr` they are
`location.save()`, `location.save_and_continue()`, `location.lookup()`,
`location.lookup_branches()`, `location.is_registered()`,
`location.unregister()`, `location.fetch_contacts()` and
`location.free_contacts()`, without the table name. URI and flags
arguments may contain variables.

| Function | Description |
|---|---|
| `save("location"[, flags[, uri]])` | Processes a REGISTER and sends the reply itself. Returns Kamailio's codes (registrar `save.c`), listed below. Called for a non-REGISTER, it sends nothing and returns -1. `sl_reply_error()` then sends 500. `flags` is an integer, decimal or `"0x…"`, or a variable. A value above 0x1f is a config error. The flags are listed below. `uri` is the AoR to save under instead of the To URI. |
| `reg_send_reply()` | Sends the reply that a `save()` with flag 0x02 skipped: the 200 with the bindings, or the error. 1 when sent, -1 if no such `save()` came before it. |
| `lookup("location"[, uri])` | Looks up the AoR of the R-URI, or of `uri`. Rewrites the R-URI to the best contact and sets `$du` to its next hop. With `append_branches`, every other contact becomes a branch. Returns 1 if a contact was found. Returns -1 if not, or if the URI has no user. |
| `lookup_branches("location")` | Runs `lookup()` for the R-URI. Then it runs it for every branch that has no destination (`$du`) or Path of its own. A branch whose AoR has contacts becomes the best of them. With `append_branches`, the others are added at the end. A branch without contacts stays as it is. This follows Kamailio's `lookup.c`. 1 if any lookup found contacts, else -1. |
| `registered("location"[, uri[, match_option[, match_action]]])` | 1 if the AoR of the R-URI (or `uri`) has at least one unexpired binding, else -1. `match_option` bits restrict which bindings count, as in Kamailio's `registered4()`: 1 Call-ID, 2 received address (`sip:ip:port;transport=…`), 4 contact URI. Each must equal the `match_callid` / `match_received` / `match_contact` field of the `xavp_cfg` xavp. Without `xavp_cfg` they are ignored. The matched binding's `ruid`, `received`, `contact`, `expires` (seconds left) and `path` go into the `xavp_rcd` xavp, unless `match_action` has bit 2. Bit 1 (copy the contact's stored xavp) has no effect, because bindings are stored without one. |
| `unregister("location", uri[, ruid])` | Removes every binding of `uri`'s AoR and returns 1, also when there were none. With a `ruid`, removes only that binding, and returns -3 if there is none. An empty `uri` means the To URI, or any AoR when a `ruid` is given. -1 if no AoR can be taken from the URI. |
| `reg_fetch_contacts("location", uri, profile)` | Copies the bindings of `uri`'s AoR into `profile` for `$ulc`. They are ordered best first, as `lookup()` orders them. 1 if there are any. -1 if not, and the profile then has `count` 0. |
| `reg_free_contacts(profile)` | Drops the profile. Returns 1. |

`save()` return codes:

| Code | Meaning |
|---|---|
| 1 | contacts inserted, or a new AoR |
| 2 | contacts updated |
| 3 | contacts deleted, also by `Contact: *` |
| 4 | a query: the REGISTER had no Contact |
| -2 | too many contacts (503) |
| -1 | any other error (400, 420, 423, 500) |

With several contacts, the last change decides the code.

`save()` flags are bits with Kamailio's values:

| Flag | Meaning |
|---|---|
| `0x01` | Memory only. These bindings are never written to the database (`db_mode` > 0). `$ulc(…=>flags)` shows 1. |
| `0x02` | No reply. `save()` only returns the result, and the script answers. `reg_send_reply()` sends the reply `save()` would have sent. `sl_reply_error()` sends an error, with `Min-Expires` / `Unsupported` where it applies. In `.fsr`: `location.save_and_continue(2)`, then `location.send_reply()` or `reply(…)`. |
| `0x04` | One contact per AoR. When the REGISTER adds or refreshes a binding, the bindings it doesn't add or refresh are removed. |
| `0x08` | Accepted, no effect. In Kamailio it means "don't apply `expires_range`", which ferrosip doesn't have. |
| `0x10` | With 0x02: prepare the reply, like Kamailio's `reg_prepare_reply()`. The 200's header lines are added to the next stateless reply the script sends (`sl_send_reply()`, or `t_reply()` without a transaction), like `append_to_reply()`. These lines are Contact for every binding, GRUUs, Path and `Require: outbound`. |

`$ulc(profile=>attr)` reads the first fetched binding. It is a
[pseudo-variable](../../docs/glossary.md#pseudo-variable-pv).
`$(ulc(profile=>attr)[i])` reads binding `i`. A negative index counts as 0,
as in Kamailio's `regpv.c`. Every attribute is `$null` when there is no
binding at that index, the per-AoR ones too. So `count` is `$null` for an
AoR without bindings.

Per-AoR attributes: `aor`, `domain` (`location`), `aorhash`, `count`.

Per-binding attributes:

- `addr`: the Contact URI;
- `path`;
- `received`: the REGISTER's source, as `sip:ip:port;transport=…`;
- `expires` and `modified`: Unix seconds;
- `callid`, `cseq`;
- `q`: in thousandths, -1 when not given (see
  [q-value](../../docs/glossary.md#q-value));
- `flags`, `cflags`;
- `user_agent`;
- `socket`: the `proto:ip:port` it was received on;
- `methods`: the Allow header as Kamailio's method bits, 4294967295 without
  one;
- `ruid`;
- `instance`: `$null` without one;
- `regid`: 0 without one;
- `conid`: the connection id, `$null` for UDP;
- `server_id`: 0.

`path` and `user_agent` are empty strings when not set. An unknown attribute
is a config error. This includes `reg-id` and `keepalive`, which Kamailio
doesn't have.

### Behaviour notes

- **AoR**: the user part of the To URI (for REGISTER) or of the R-URI (for
  lookup). With usrloc `use_domain=1`, `@domain` is added.
- **`save()` follows RFC 3261 §10.3** and Kamailio's `save.c`:
  - A REGISTER without Contact is a query. The 200 lists the current
    bindings.
  - `Contact: *` is only valid alone and with `Expires: 0`. Otherwise the
    answer is 400. It removes all bindings, except ones from the same
    [Call-ID](../../docs/glossary.md#call-id) with a higher
    [CSeq](../../docs/glossary.md#cseq).
  - The expiry of each contact is its `expires` parameter, else the Expires
    header, else `default_expires`. 0 removes the binding.
  - Bindings match on `+sip.instance` + `reg-id` when both sides have an
    instance. Otherwise they match on the Contact URI.
  - A contact matched by URI from the same Call-ID with a lower CSeq gets
    `400 Invalid CSeq number`, and the binding is kept.
  - The same CSeq within usrloc's `cseq_delay` (20 s) is a
    [retransmission](../../docs/glossary.md#retransmission). That contact
    is left as it is (usrloc `get_ucontact()`).
  - A contact matched by `+sip.instance` is not checked.
  - All contacts of a REGISTER are applied together or not at all.
  - The 200 lists every current binding with its remaining `expires`. It
    adds `+sip.instance`, `reg-id` and GRUUs where present.
  - A malformed request gets a 400 whose reason names the problem. Examples
    are a missing To/Call-ID/CSeq, or a bad Expires or Contact URI.
- **What is stored per binding**:
  - the transport, address and connection id the REGISTER came from;
  - User-Agent;
  - Path, with `use_path`;
  - the [branch flags](../../docs/glossary.md#branch-flags) set before
    `save()` (`setbflag`), shown as `cflags` in `ul.dump`.
- **`lookup()`**:
  - Fills the `xavp_rcd` xavp, when set, with the chosen contact, as
    `registered()` does.
  - Picks the contact with the highest q, then the most recently refreshed.
  - When the contact has a Path, the next hop is the first Path hop. The
    stored Path then becomes the [Route](../../docs/glossary.md#route) set,
    also for each forked branch. Without Path, the next hop is the
    registration source (see `use_received`).
  - Restores the stored branch flags. nathelper uses them for NAT
    keep-alives.
  - Passes the contact's instance and reg-id to
    [tm](../../docs/glossary.md#tm), for `t_load_contacts()` /
    `t_next_contact_flow()`.
- **GRUU (RFC 5627)**:
  - `pub-gruu` is `<aor>;gr=<instance>`.
  - `temp-gruu` is `sip:tgruu.<hex>@<domain>;gr`. The hex part encodes the
    AoR, the instance and a Call-ID hash, so it can be decoded without
    state.
  - A GRUU in the R-URI makes `lookup()` return only that instance's
    contact.

### Differences from Kamailio

- `Contact: *` keeps a binding of the same Call-ID with a higher CSeq
  (RFC 3261 §10.3 step 6). Kamailio's `star()` removes every binding.
- `save()` flag 0x08 has no effect, because there is no `expires_range`.
  With 0x04, every contact the REGISTER adds or refreshes is kept. Clients
  normally send one.
- `reg_fetch_contacts()` profiles live for the message being processed,
  like `$dbr`. In Kamailio they live for the worker process. So a later
  message does not see a profile.
- `$ulc(…=>received)` is always set to the source of the REGISTER, because
  ferrosip always routes to it.
- `methods` comes from the Allow header only. A Contact's `methods`
  parameter is ignored.
- `$ulc` lists only unexpired bindings, best first. Kamailio copies the
  record's list in the order usrloc keeps it.
- `save()` doesn't fill `xavp_rcd`.
- The REGISTER's source, including the connection, is always stored with
  each binding. So Kamailio's `received_avp` / `received_param` setup is
  not needed, and those parameters are not accepted.

### Testing

- `tests/e2e_registrar.py` covers:
  - 200 with bindings, query REGISTER, `registered()`;
  - 423 and clamping, 500 out of order;
  - parallel [forking](../../docs/glossary.md#forking) over two bindings;
  - 503 above `max_contacts`, `Contact: *`, expiry;
  - instance/reg-id replacement;
  - delivery over a client's TCP and
    [WebSocket](../../docs/glossary.md#websocket) connection;
  - `handle_lost_tcp`.

  A second proxy covers:
  - `save()` flags 0x01 (with a db_text table), 0x02 (alone: no bindings
    in the script's reply; `reg_send_reply()`), 0x12 (script reply with the
    bindings, `sl_reply_error()` with 423), 0x04 and flags from a variable;
  - `save()`'s return codes 1–4 and -1;
  - 400 for a lower CSeq and the `cseq_delay` retransmission;
  - the `save()` / `lookup()` URI argument;
  - `lookup_branches()`;
  - `registered()` with `match_option` / `match_action` (Call-ID and
    received matches, `xavp_rcd` and its bit 2);
  - `unregister()` by AoR and by ruid (-3);
  - `reg_fetch_contacts()` with `$ulc` attributes and indexes (negative,
    past the end, `conid`, `regid`).
- `tests/e2e_fsr.py`: the typed forms (`save_and_continue(2, aor)`,
  `fetch_contacts`, `unregister`, `is_registered(uri)`, `lookup(uri)`).
- `tests/e2e_routing.py`: `use_path` (Path echoed in the 200), NAT
  branch flags.
- `tests/e2e_extra.py`: `pub-gruu` / `temp-gruu` and lookups of both,
  `outbound_mode`.
- `tests/e2e_auth.py`, `tests/e2e_state.py`, `tests/e2e_sqldb.py`,
  `tests/interop_sipp.py`: authenticated REGISTERs ending in `save()`.
- Unit tests in `src/lib.rs`: `save()` flags parsing and
  [fixup](../../docs/glossary.md#fixup), Allow method bits, `$ulc`
  attribute names.

## The location table (usrloc)

This is the user location table, a port of Kamailio's `usrloc` module. It
maps an address-of-record (AoR) to its contacts and expires them. It can
also keep them in the `location` database table.

It has almost no script functions. `registrar` (`save()` / `lookup()`) and
other modules use it through a typed API: `Registry::api::<Usrloc>()`, the
equivalent of Kamailio's `load_ul_api()`.

The table is a `ShardedMap` with 1024 shards, each with its own lock. tm
uses the same structure. So REGISTERs and lookups for different users don't
contend.


### Quick start

In `ferrosip.toml` and `.fsr`, usrloc and registrar are one module,
`location` ([docs/fsr.md](../../docs/fsr.md)). It loads when the routing
calls one of its functions, usrloc before registrar.

```toml
[modules.location]                     # usrloc + registrar
handle_lost_tcp = true
db_url = "sqlite:///var/lib/ferrosip/location.db"
db_mode = "write-back"                 # db_mode 2
```

```rust
import location

route main(msg: Request) {
    if msg.method == REGISTER {
        location.save()
    }
    guard location.lookup() else reply(NotFound, "Not Found")
    relay(msg)
}
```

### Parameters

| Name | Default | Description |
|---|---|---|
| `use_domain` | 0 | 1: the AoR is `user@domain`, with the domain lower-cased. 0: just `user`. Only 0 or 1 is accepted. |
| `handle_lost_tcp` | 0 | 1: when a TCP, TLS or WebSocket connection closes, remove the contacts registered over it. Only 0 or 1 is accepted. |
| `timer_interval` | 10 | Seconds between sweeps of expired contacts (minimum 1). In `db_mode` 2 this is also the flush interval. |
| `db_url` | none | Database for the `location` table. Any sip-db URL works (`text:///dir`, `sqlite:///file`, `mysql://…`, `postgres://…`). Required when `db_mode` > 0. |
| `db_mode` | `off` (0) | 0 memory only, 1 write-through, 2 write-back, 3 same as 1. See below. In `ferrosip.toml`: `"off"`, `"write-through"`, `"write-back"`, `"db-only"`. |
| `cseq_delay` | 20 | Seconds. A REGISTER with the Call-ID and CSeq of a binding refreshed less than this ago is a retransmission. It leaves the binding as it is. Otherwise it gets 400. |

`nat_bflag`, `desc_time_order`, `matching_mode`,
`user_column`, `domain_column` and `contact_column` are accepted for
compatibility with Kamailio configs and ignored. Any other name is a
config error.

### Functions

| Function | Description |
|---|---|
| `ul_dump()` (`.fsr`: `location.dump()`) | Prints every unexpired contact to stderr: AoR, URI, remaining seconds, q, source. Returns 1. |

### RPC commands

| Command | Description |
|---|---|
| `ul.dump` | All AoRs with their unexpired contacts: `contact`, `expires` (remaining seconds), `q`, `callid`, `cseq`, `received`, `user_agent`, `path`, `cflags`, `ruid`. |
| `ul.lookup location <aor>` | Contacts of one AoR. The table name may be omitted. Error `AoR not found` if it has none. |
| `ul.rm location <aor>` | Removes all contacts of an AoR and returns how many were removed. |

See [RPC](../../docs/glossary.md#rpc). Example:
`ferroctl ul.lookup location alice`.

### Statistics

| Name | Kind | Meaning |
|---|---|---|
| `usrloc:registered_users` | [gauge](../../docs/glossary.md#gauge) | AoRs in the table |
| `usrloc:location-contacts` | gauge | Contacts in the table |

Both are computed when read. They include expired contacts that are not
swept yet.

### Behaviour notes

- **What a contact stores**:
  - URI, expiry, q, Call-ID, CSeq;
  - the source of the REGISTER: transport, address and connection id;
  - User-Agent and the Allow methods;
  - a record id (`ruid`). It is kept on refresh but not stored in the
    database. A new one is made at load;
  - flags: `FL_MEM` marks memory-only contacts, which are never written to
    the database;
  - `+sip.instance` and `reg-id` (RFC 5626);
  - the Path route set (RFC 3327);
  - the branch flags at save time (`cflags`);
  - the last-modified time.
- **Expiry**: lookups never return expired contacts, whatever the timer
  does. The `usrloc-timer` thread removes them every `timer_interval`
  seconds. An AoR is deleted with its last contact. Expiry uses a
  monotonic clock.
- **`handle_lost_tcp`**: usrloc keeps an index from each connection to its
  AoRs. The index holds a set, because an edge proxy may register thousands
  of AoRs over one connection. When the transport reports a closed
  connection, that connection's contacts are dropped. This makes calls to a
  closed browser tab fail fast instead of timing out.
- **Database (`db_mode`)**: rows are written per contact. On a change, the
  module deletes the rows of the contacts this process wrote or loaded for
  the AoR. It then inserts the AoR's current contacts. Rows that another
  registrar wrote to the same table are left alone, as with Kamailio's
  per-contact writes.
  - 1 and 3: written on every change.
  - 2: changed AoRs are collected. The timer flushes them every
    `timer_interval`.
  - With `db_mode` > 0, the unexpired rows are loaded at startup.
  - `expires` and `last_modified` are stored as Unix seconds. `received` is
    stored as a SIP URI, because connection ids don't survive a restart.
  - `etc/schema/postgres.sql` and `etc/schema/mysql.sql` create the table.

### Differences from Kamailio

- There is one table, `location`. `registrar` rejects any other name.
- `db_mode` 3 behaves like 1: the in-memory table stays the cache.
- The `ul.*` RPCs are a subset of Kamailio's: `ul.dump`, `ul.lookup` and
  `ul.rm`. There is no `ul.add`, `ul.rm_contact`, `ul.flush` or
  `ul.db_*`.
- Several Kamailio parameters are accepted and ignored. They are listed
  above. Column names can't be changed.

### Testing

- `tests/e2e_registrar.py`: registration, expiry (`timer_interval` 1) and
  `handle_lost_tcp` over TCP and WebSocket.
- `tests/e2e_script.py`: `ul.dump`, `ul.lookup`, `ul.rm` and the
  `usrloc:registered_users` gauge.
- `tests/e2e_state.py`: `db_mode` 1 with a db_text table, contacts reloaded
  after a restart.
- `tests/e2e_sqldb.py`: `db_mode` 1 on PostgreSQL and MariaDB.
- Unit tests in `src/lib.rs`: update, lookup, expiry and lost connection,
  and AoR keys with and without `use_domain`.
