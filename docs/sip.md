# Registrar, authentication and forking

The core SIP features: registration and the location table, digest authentication, and forking with RFC 3263 resolution.

## Registrar and usrloc

> Full reference: [`mod-location`](../crates/mod-location/README.md).

```toml
[modules.location]            # usrloc + registrar
handle_lost_tcp = true
```

```rust
import location

route main(msg: Request) {
    if msg.method == REGISTER {
        location.save(msg)            // save("location"): answers the REGISTER
    }
    guard location.lookup() else reply(NotFound)
    relay(msg)
}
```

- **`save("location")`** (`location.save()`) implements RFC 3261 §10.3. It binds the REGISTER's
  Contacts to the To AoR and answers the REGISTER itself: 200 listing every
  current binding with its remaining `expires`. Other answers:
  - 423 + `Min-Expires` when the interval is too short;
  - 400 for a misused `Contact: *` or missing headers;
  - 500 for an out-of-order CSeq on the same Call-ID;
  - 503 above `max_contacts`.
  A REGISTER without Contact is a query. Updates are all-or-nothing.
  Bindings are matched by `+sip.instance` + `reg-id` (RFC 5626) when
  present, otherwise by URI.
- **Every binding remembers where the REGISTER came from**: transport,
  address and connection id. `lookup("location")` picks the best contact
  (highest q, then most recent), rewrites the R-URI to it (`$ru`) and sets
  the next hop (`$du`) to that source. `t_relay()` without arguments then
  reaches UDP clients behind NAT and reuses the client's TCP, TLS or
  WebSocket connection, which is the only way to reach a browser.
  `use_received = false` (`[modules.location]`) routes UDP to the Contact
  address instead.
- **`handle_lost_tcp`**: when a client's connection closes, its bindings are
  dropped, so calls to a closed browser tab fail with 404 instead of
  timing out.
- **Path (RFC 3327)**: with `use_path = true` (`[modules.location]`) the
  Path headers of a REGISTER are stored with its contacts. `lookup()` then
  sends to the first Path hop, with the whole Path as Route set (also per
  forked branch). `path_mode` 0 stores Path silently; 1 requires it (420)
  and echoes it; 2 (the default) echoes it in the 200 OK when the client
  sent `Supported: path`.
- **Branch flags** set before `save()` (`setbflag`) are stored with each
  contact (`cflags`, shown by `ul.dump`) and restored by `lookup()`.
  nathelper uses them to pick contacts to keep alive.
- **Parameters**: usrloc `use_domain`, `handle_lost_tcp`, `timer_interval`;
  registrar `default_expires`, `min_expires`, `max_expires`, `max_contacts`,
  `use_received`, `use_path`, `path_mode`. Config errors name the line, e.g. registrar loaded before
  usrloc, or an unknown parameter.
- **`t_relay()` without arguments** uses `$du`, otherwise the R-URI: its
  `;transport=`, `sips:` → TLS, default ports, IP literals directly, and
  host names resolved per RFC 3263 (NAPTR → SRV → A, see below), with
  tm caching the result for 30 s.

## Digest authentication (auth)

> Full reference: [`mod-auth`](../crates/mod-auth/README.md).

```toml
[modules.auth]
users_file = "/etc/ferrosip/users"   # user password | user md5:HA1 | user sha256:HA1
algorithm = "SHA-256,MD5"            # default "MD5"
```

```rust
import auth, location

route main(msg: Request) {
    if msg.method == REGISTER {
        // flags 1 (the default): the auth user must be the To user
        if !auth.check(msg.to.host) {
            auth.www_challenge(msg.to.host, qop: 1)    // sends the 401
        }
        auth.consume_credentials()
        location.save(msg)
    }
    if !auth.proxy_authorize(msg.from.host) {
        auth.proxy_challenge(msg.from.host, qop: 1)    // sends the 407
    }
    auth.consume_credentials()
    relay(msg)
}
```

In `.fsr` the checks are true/false. To tell Kamailio's negative return
codes apart (`-8`: the user isn't the To user → 403), use the `.cfg`
form: `if (!auth_check("$td", "subscriber", 1)) { if ($rc == -8) … }`.

- **Functions and return codes are Kamailio's** (auth + auth_db):
  `www_authorize`, `proxy_authorize`, `auth_check`, `www_challenge`,
  `proxy_challenge`, `auth_challenge`, `consume_credentials`. They return 1
  ok, -1 error, -2 wrong password, -3 unknown user, -4 stale nonce, -5 no
  credentials, -6 nonce reused (replayed nc), -8 user mismatch. The script reads them via the new `rc == N`
  condition (`$rc`). Realms can be literals or `$td` / `$fd` / `$rd`.
- **Stateless nonces**: expiry (ms) + index + an HMAC-SHA256 tag bound to
  the realm, so any worker can verify any nonce and nothing is stored per
  challenge. Expired nonces get `stale=true`, so clients retry without
  asking the user. Forged nonces are rejected.
- **Replay protection**: with `qop=auth`, each nonce's highest
  nonce-count is tracked in a shared array of atomics (Kamailio
  `nc_enabled`). A repeated or lower `nc` returns -6 and the next
  challenge has `stale=true`.
- **Algorithms**: MD5 and SHA-256 (RFC 8760), plain or `-sess` (RFC 7616),
  with one challenge header per configured algorithm, preferred first. Passwords can be stored in plain
  text or as an HA1 hash. The digest `uri` must match the Request-URI, and
  responses are compared in constant time.
- **qop**: `qop=auth` and `qop=auth-int`; with auth-int the body is hashed
  into HA2. Challenge flags: 1 offers auth, 2 offers auth-int, 3 both. RPC
  `auth.reload` re-reads `users_file`. A database backend is the `auth_db`
  module.
- Also `has_credentials(realm)`, `pv_www_authorize(realm)` /
  `pv_proxy_authorize(realm)` (password or HA1 from the `username_spec` /
  `password_spec` variables), `auth_get_www_authenticate(realm, flags,
  pvdest)`, and the `qop`, `nonce_count`, `one_time_nonce`,
  `realm_prefix` and `add_authinfo_hdr` parameters.

## Forking (tm)

> Full reference: [`mod-txn`](../crates/mod-txn/README.md).

`t_relay()` sends one branch to the R-URI (`$ru`/`$du`) plus one per entry
in the destination set: `append_branch("sip:…"[, "q"])`, or every contact of
a user via `lookup()` (registrar `append_branches`, default 1 as in
Kamailio). A transaction has at most `max_branches` branches (default 12),
failure routes included. As in Kamailio (core `dset.c`), the destination
set holds at most `max_branches - 1` entries, the R-URI being the first
branch: past that `append_branch()` fails (-1, logged "max nr of branches
exceeded", `sl_reply_error()` answers `500 Forking capacity exceeded
(12/SL)`), and `lookup()` drops the contacts that don't fit and still
succeeds. `max_branches` is the core parameter (`max_branches=N` in a
`.cfg`, 1..30) or tm's `max_branches`.

One final per request, as in Kamailio:
- A `t_relay()` that fails in `request_route` (`478 Unresolvable
  destination (478/TM)`, `477 … (477/TM)`) is answered by tm when the
  script ends (tm's `delayed_reply`), after `100 Trying` for an INVITE.
  `t_reply()` / `send_reply()` / `t_reply_error()` before that replace it;
  `sl_reply_error()` and `send_reply_error()` send nothing. The stock
  `if (!t_relay()) { sl_reply_error(); }` sends tm's reply only.
- In a failure route, `t_reply()`, `send_reply()`, `send_reply_error()`
  and `t_reply_error()` answer through the transaction: that is its final,
  and the best reply is not relayed after the route. `sl_send_reply()` /
  `sl_reply_error()` are request_route functions (a config error in a
  failure_route block, stateless from a `route[…]` it calls).

```toml
[modules.txn]           # tm
fork_by_q = true        # serial: groups of descending q, equal q in parallel
fr_timer = "30s"        # without a provisional
fr_inv_timer = "120s"   # of ringing
```

```rust
route main(msg: Request) {
    if location.lookup() {
        txn.set_timeout(20s, 5s)    // per-call timers (t_set_fr)
        relay(msg)
    }
    reply(NotFound)
}
```

- **One transaction with N branches** under one shard lock. A
  branch → transaction index routes replies and timers. Everything a reply
  or timer triggers (forwarding, CANCELs, next q-group, timers) is decided
  under the lock and sent after releasing it.
- **Response aggregation follows RFC 3261 §16.7**:
  - 1xx (except 100) and every 2xx are forwarded at once (each 2xx to an
    INVITE can be a separate dialog).
  - The first 2xx or any 6xx CANCELs the other branches.
  - Otherwise, once every branch has a final response, the best one is sent
    upstream: 6xx, else the lowest class. Within 4xx, 401/407/415/420/484 are
    preferred, and a real response beats our own timeout of the same class.
  - A chosen 503 is not forwarded: tm answers with its own
    `500 Service Unavailable` built from the request, as Kamailio does.
  - The challenges of all 401/407 branches are merged into the response
    (so a caller can authenticate to every branch at once).
- **INVITE** gets `100 Trying` at once. Non-2xx finals are ACKed per branch.
  An upstream CANCEL is answered 200 and fanned out. A branch that hasn't
  sent a provisional yet gets its CANCEL as soon as one arrives (§9.1).
  Request retransmissions are answered with the last reply and not
  forwarded again.
- **Timers per branch**: UDP retransmission, `fr_timer` until the first
  provisional, then `fr_inv_timer`. On expiry a ringing branch is CANCELed and
  the branch counts as a local 408. Serial forking moves to the next q-group
  when the current one has failed. A 6xx, a 2xx or an upstream CANCEL stops it.
- **CANCEL** is a client transaction of its own (§9.1):
  - retransmitted over UDP (T1 doubling, capped at T2) until it is
    answered;
  - the branch is abandoned after 64·T1, and a canceled INVITE then gets
    487 rather than our 408;
  - replies to our CANCEL (same Via branch, CSeq CANCEL) are absorbed, not
    taken for the INVITE's final;
  - the hop-by-hop ACK for a non-2xx is built once and resent unchanged
    for every retransmitted final;
  - `retr_timer1` / `retr_timer2` set T1 / T2.
- **RFC 5626 flows**: `t_load_contacts()` keeps one flow (reg-id) per
  `+sip.instance` as a contact. `t_next_contact_flow()` in a failure_route
  (e.g. after 430 Flow Failed) tries the next flow.
- **Serial forking from the script**, Kamailio style:
  - `t_load_contacts()` sorts the R-URI and the destination set by q into
    the `contacts_avp` XAVP (default `tm_contacts`).
  - `t_next_contacts()` makes the next q-group the R-URI and destination
    set. It returns -2 when nothing is left.
  - Call it in `request_route` and again in a `failure_route` before
    `t_relay()`.

### R-URI resolution (RFC 3263)

A host name in the R-URI (or in a branch) is resolved like Kamailio's
core DNS:
- **NAPTR** (`dns_try_naptr`, used only when the URI has neither a port nor
  a transport): `SIP+D2U`, `SIP+D2T`, `SIPS+D2T`, `SIP+D2W` → SRV name.
- **SRV** (`_sip._udp`, `_sip._tcp`, `_sips._tcp`), unless the URI has a
  port: ordered by priority. Within a priority, `dns_srv_lb` gives a weighted
  random order; otherwise the heaviest goes first.
- **A/AAAA**: from the SRV answer's additional section when present, then
  from `dns_server`, then the system resolver. IP literals and names in
  `/etc/hosts` never hit DNS.
- A small DNS client caches records for their TTL; failures are cached for
  `dns_cache_negative_ttl` seconds. A truncated answer (TC bit) is retried
  over TCP.
- **Destination blocklist** (Kamailio `dst_blocklist`):
  - With `use_dst_blocklist`, tm blocks a next hop for
    `dst_blocklist_expire` seconds when sending fails or it never answers.
    With `blst_503`, a 503 blocks it for its Retry-After, or
    `blst_503_def_timeout`.
  - Blocked hops are skipped when forking and in DNS failover. With nothing
    left, `t_relay()` fails with 477 (E_SEND, as in Kamailio, where the
    blocked branches are not sent).
  - The `blst` module: `blst_add([s])`, `blst_add_retry_after(min, max)`,
    `blst_del()`, `blst_is_blocklisted()` for `$du` or the R-URI.
  - RPC `dst_blocklist.list/add/del/flush`.
  - The check costs one atomic load while the list is empty.
- `use_dns_failover`: a 503, a timeout or a send failure on a branch moves
  it to the next address of the same name. The failed attempt is ACKed and
  dropped from aggregation, and the new attempt gets a new Via branch.
- TLS targets verify the certificate against the URI's domain (RFC 5922).
- RPC `dns.lookup <uri>` and `dns.flush`.

```toml
[modules.txn]
dns_server = "10.0.0.53"   # default: /etc/resolv.conf
use_dns_failover = true
dns_srv_lb = true
dns_try_naptr = true
```

These are core parameters in Kamailio. Here they are tm (`txn`)
parameters, because tm does the resolving.

## Via: `received`, `rport` and where replies go

Every request's top Via is stamped on arrival, before routing:
- `;received=<source IP>` when the sent-by host isn't the source IP
  (RFC 3261 §18.2.1), replacing any `received` the sender put there;
- `;rport=<source port>` (plus `received`) when the sender asked with a
  bare `;rport` (RFC 3581 §4).

The relayed request, every local reply and the transaction's copy carry
the stamped Via, so a phone behind NAT learns its public address and a
stateless next hop can route replies. `$ml`, `$mb`, `$msg(len|buf)`,
sipdump and siptrace still see the bytes as received.

Replies go back to the request's source address and port by default,
also without `;rport`: as if `force_rport()` were always on, which keeps
clients behind NAT working. `[core] force_rport = false` (or the `.cfg`
global `force_rport=no`) gives Kamailio's and RFC 3261 §18.2.2's
behaviour: a UDP reply to a request whose top Via has no `;rport` goes to
the source IP and the Via sent-by port (5060 when absent); the script's
`force_rport()` then turns symmetric replies on for that request.
`add_rport()` is accepted and does nothing.

A UDP upstream whose port is closed isn't detected (send errors aren't
reported back): the branch times out after `fr_timer` with a 408, as in
Kamailio.
