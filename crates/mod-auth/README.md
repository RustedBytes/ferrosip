# mod-auth

Password checks for SIP requests. Use it to make phones prove who they are
before they can [register](../../docs/glossary.md#register) or place calls
through the proxy. It implements SIP
[digest authentication](../../docs/glossary.md#digest-authentication):
RFC 2617, RFC 3261 §22, and RFC 7616 / RFC 8760 for SHA-256 and `-sess`.

The crate contains three modules:

- `auth` checks credentials and sends
  [challenges](../../docs/glossary.md#challenge).
- `auth_db` reads credentials from a database table.
- `auth_ephemeral` checks time-limited credentials shared with a web
  service.

Function names and return codes are
[Kamailio](../../docs/glossary.md#kamailio)'s.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `auth` | `auth` (+ the `auth_db` functions) | `www_authorize`, `proxy_authorize`, `auth_check`, challenges, `consume_credentials`; credentials from a users file |
| `auth` | `auth_db` | Credentials from a table (`subscriber`) through sip-db; `load_credentials` |
| `auth_ephemeral` | `auth_ephemeral` | TURN-REST-style ephemeral credentials (an HMAC of the username) |

`auth_db` and `auth_ephemeral` must be loaded after `auth`.

## Quick start

In [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) and
[`.fsr`](../../docs/glossary.md#fsr) ([docs/fsr.md](../../docs/fsr.md)),
`auth` and `auth_db` are one module, `auth`. It loads when the routing calls
one of its functions. `auth_db` loads with it when `[modules.auth]` has
`auth_db` parameters.

```toml
[modules.auth]
users_file = "/etc/ferrosip/users"     # user password | user md5:HA1 | user sha256:HA1
algorithm = "SHA-256,MD5"              # default "MD5"
```

```rust
import auth, location

route main(msg: Request) {
    if msg.method == REGISTER {
        // flags 1: the auth user must be the To user; challenge 1: qop=auth
        guard auth.check(msg.to.host, "subscriber", 1) else auth.www_challenge(msg.to.host, 1)
        auth.consume_credentials()
        location.save()
    }
    guard auth.proxy_authorize(msg.from.host, "subscriber") else auth.proxy_challenge(msg.from.host, 1)
    auth.consume_credentials()
    guard location.lookup() else reply(NotFound)
    relay(msg)
}
```

In `.fsr` the check functions return a `Bool`. To tell apart the return
codes listed below, read the last return code with `pv("$rc")` right after
the check. A user mismatch (-8) can then get a 403 instead of a new
challenge:

```
if !auth.check(features.realm, "subscriber", 1) {
    if pv("$rc") == -8 {
        reply(403, "Forbidden")
    }
    auth.challenge(features.realm, 1)
}
```

With a database instead of a users file (the `auth_db` parameters also go in
`[modules.auth]`):

```toml
[modules.auth]                         # auth + auth_db
db_url = "postgres://ferrosip:pw@db/ferrosip"
calculate_ha1 = true                   # password column holds plain text
load_credentials = "rpid"              # → $avp(rpid) after a successful check
```

## Parameters

### auth

| Name | Default | Description |
|---|---|---|
| `users_file` | none | File with one user per line: `user password`, `user md5:<HA1 hex>` or `user sha256:<HA1 hex>`. `#` starts a comment line. Read at startup and by `auth.reload`. See [HA1](../../docs/glossary.md#ha1). |
| `algorithm` | `"MD5"` | Comma-separated list of `MD5`, `SHA-256`, `SHA-512` and `SHA-512-256`, each also as `-sess`, preferred first. One challenge header is sent per algorithm. Credentials are accepted for any hash in the list, with or without `-sess`. MD5-sess credentials are accepted when `MD5` is listed, as in Kamailio. Other algorithms are rejected (-1). Credentials without `algorithm=` are MD5 when MD5 is listed, else the first algorithm's (Kamailio: its one configured algorithm). `auth_algorithm()` replaces the list at run time. |
| `use_domain` | 0 | For `pv_auth_check()` with `checks & 1`: also compare the From and To hosts (and the R-URI host for PUBLISH), as Kamailio's `auth` `use_domain`. It is a `.cfg` `modparam("auth", "use_domain", …)`. In `ferrosip.toml`, `use_domain` is the `auth_db` one, so this one is set under `[modules.auth.kamailio]`. |
| `nonce_expire` | 300 | [Nonce](../../docs/glossary.md#nonce) lifetime in seconds (minimum 1). |
| `secret` | random | Key of the nonce HMAC. When unset, 32 random bytes are generated at startup, so nonces don't survive a restart. |
| `qop` | `""` | `auth`, `auth-int` (or both, comma-separated) is accepted and checked. As in Kamailio, it does not change `www_challenge()` & co.: their flags choose the [qop](../../docs/glossary.md#qop). Kamailio uses it only in the challenge API for other modules. |
| `nonce_count` | 1 | Track the highest [`nc`](../../docs/glossary.md#nc) of each nonce, for credentials with `qop`. A repeated or lower `nc` makes the nonce [stale](../../docs/glossary.md#stale) (-4, as in Kamailio's `check_nonce()`), and the next challenge has `stale=true`. 0: any `nc` is accepted until the nonce expires. Kamailio's default is 0. |
| `one_time_nonce` | 0 | Each nonce is accepted once, with or without `qop`. A second use returns -6, and the next challenge has `stale=true`. Every request then needs its own challenge. Takes precedence over `nonce_count`. |
| `realm_prefix` | `""` | Stripped from the start of every [realm](../../docs/glossary.md#realm) the functions check credentials or send challenges for (Kamailio's `strip_realm()`). This applies whether the realm is given as an argument or taken from the To/From URI (realm `""`). For example, `sip.` makes `sip.example.com` the realm `example.com`. Case-sensitive, as in Kamailio. |
| `add_authinfo_hdr` | 0 | After a successful check of credentials with `qop`, add `Authentication-Info: qop=…, rspauth="…", cnonce="…", nc=…` to the next reply sent from the script (as `append_to_reply`). For `auth-int`, `rspauth` assumes an empty reply body. |
| `username_spec` | none | Variable with the user name for the one-argument `pv_www_authorize(realm)` / `pv_proxy_authorize(realm)`, e.g. `$avp(user)` or `$var(user)`. This is the API of older Kamailio versions. Current Kamailio has no such parameter. |
| `password_spec` | none | Variable with that user's password (`calculate_ha1=1`) or HA1 (MD5, or SHA-256 when 64 hex digits). |
| `calculate_ha1` | 0 | For the one-argument `pv_*_authorize` functions: 1 when `password_spec` holds the plain password, 0 when it holds the HA1. It is a `.cfg` `modparam("auth", "calculate_ha1", …)`. In `ferrosip.toml`, `calculate_ha1` is the `auth_db` one, so this one is set under `[modules.auth.kamailio]`. |

`force_stateless_reply` and `use_next_nonce` are accepted with no effect,
and a note is logged. Challenges are always sent statelessly, and no
`nextnonce` is sent.

### auth (auth_db)

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Any sip-db URL: `text:///dir`, `sqlite:///file`, `mysql://…`, `postgres://…`. |
| `calculate_ha1` | 0 | 0: read the HA1 from the HA1 column. 1: read the plain password from the password column and compute HA1. |
| `use_domain` | 0 | Also match the domain column against the realm. |
| `user_column` | `username` | |
| `domain_column` | `domain` | |
| `password_column` | `password` | Plain-text password column (used with `calculate_ha1=1`). |
| `password_column_2` | `ha1` | HA1 column (used with `calculate_ha1=0`): an MD5 HA1, or a SHA-256 one (64 hex digits). |
| `load_credentials` | none | `"col1;col2"`: after a successful check, each column's value is added to `$avp(col)`. See [AVP](../../docs/glossary.md#avp). |

`version_table` and `force_default_realm` are accepted and ignored.

### auth_ephemeral

| Name | Default | Description |
|---|---|---|
| `secret` | none (required) | Shared secret. Can be repeated. A password made with any of them is accepted. |
| `username_format` | `timestamp-username` (1) | 1: the username is `<expiry>:<user>`. 0: `<user>:<expiry>`. The expiry is a Unix timestamp. |
| `sha_algorithm` | `sha1` (0) | HMAC for the password: 0 SHA-1, 1 SHA-256, 2 SHA-384, 3 SHA-512. |
| `username_delimiter` | `":"` | Only `":"` is accepted. |

## Functions

`realm` can be a literal or a template such as `$td`, `$fd` or `$rd` (the
To, From or R-URI domain). Template realms are lower-cased, so the challenge
and the check always agree. `table` is the credentials table. It is only
used with `auth_db`.

In `.fsr` they are `auth.www_authorize`, `auth.proxy_authorize`,
`auth.check`, `auth.www_challenge`, `auth.proxy_challenge`,
`auth.challenge`, `auth.consume_credentials`, `auth.has_credentials`,
`auth.pv_www_authorize`, `auth.pv_proxy_authorize`,
`auth.pv_www_authenticate`, `auth.pv_proxy_authenticate`,
`auth.pv_check(realm, passwd, flags, checks)`,
`auth.set_algorithm(alg)` and
`auth.get_www_authenticate(realm, flags, out)`. The `auth_ephemeral` ones
are `auth_ephemeral.check`, `check_www`, `check_proxy` and `authenticate`
(see [docs/functions-reference.md](../../docs/functions-reference.md)).
A realm is then a string or a field: `msg.to.host` (`$td`),
`msg.from.host` (`$fd`), `msg.ruri.host` (`$rd`).

An empty realm `""` means the host of a URI, lower-cased and without
`realm_prefix`. For a REGISTER's Authorization (and `www_challenge`) it is
the To URI's host. Otherwise it is the From URI's host.

| Function | Description |
|---|---|
| `www_authorize(realm, table)` | Checks the `Authorization` header for `realm`. |
| `proxy_authorize(realm, table)` | Checks the `Proxy-Authorization` header for `realm`. |
| `auth_check(realm, table, flags)` | `www_authorize` for REGISTER, `proxy_authorize` otherwise. With `flags & 1`, the authenticated user must also be the user of the To URI (REGISTER) or of the From URI (other requests), else -8. |
| `www_challenge(realm, flags)` | Replies `401 Unauthorized` with `WWW-Authenticate`. |
| `proxy_challenge(realm, flags)` | Replies `407 Proxy Authentication Required` with `Proxy-Authenticate`. |
| `auth_challenge(realm, flags)` | 401 for REGISTER, 407 otherwise. |
| `consume_credentials()` | Removes the credentials header that the last check used, so it isn't forwarded. Returns -1 if no credentials were checked for this message. |
| `has_credentials(realm)` | 1 when the request has an `Authorization` or `Proxy-Authorization` header with digest credentials for `realm`, else -1. Nothing is checked. |
| `pv_www_authenticate(realm, passwd, flags[, method])` / `pv_proxy_authenticate(realm, passwd, flags)` | As in Kamailio: like `www_authorize` / `proxy_authorize`, but the script gives the credentials user's password, e.g. from a database query. With `flags & 1` it gives the HA1 instead: 32 or 64 hex digits, else -1. `method` replaces the request's method in HA2. On failure, flags 2, 4 and 8 add a challenge (no qop, `qop="auth"`, `qop="auth-int"`) to `$avp(digest_challenge)`. Kamailio's flag 32 (keep the nonce-count on failure) is accepted. |
| `pv_www_authorize(realm, passwd, flags)` / `pv_proxy_authorize(realm, passwd, flags)` | The same functions, under the names Kamailio keeps for them. |
| `pv_auth_check(realm, passwd, flags, checks)` | As in Kamailio: ACK and CANCEL return 1. Otherwise it runs `pv_www_authenticate` for REGISTER and `pv_proxy_authenticate` for other requests, with the request's method (`flags` as there). An empty realm or password is -1. With `checks & 1`, after a successful check, the credentials' user (before an `@`) must match, else -8. It must be the From user. For REGISTER and PUBLISH it must be the To user, with From user = To user (the hosts too with `use_domain`). For PUBLISH it must also be the R-URI user (and host). |
| `auth_algorithm(alg)` | As in Kamailio: from now on challenges offer `alg`, and credentials without `algorithm=` use it. `alg` is `MD5` (also `""`), `SHA-256`, `SHA-512` or `SHA-512-256`, case-sensitive as in Kamailio. Anything else is -1 and changes nothing. In Kamailio the setting belongs to the worker process that runs the call. In ferrosip it is shared by all workers, like the `algorithm` parameter it replaces. |
| `pv_www_authorize(realm)` / `pv_proxy_authorize(realm)` | Older Kamailio API: the secret comes from variables. The credentials' user must equal the value of `username_spec` (ignoring case), else -3. `password_spec` holds the password or HA1 (see `calculate_ha1`). An empty password variable is -3. |
| `auth_get_www_authenticate(realm, flags, pvdest)` | Writes a `WWW-Authenticate` challenge into the variable `pvdest`. It writes the complete header lines, `WWW-Authenticate: Digest …`, each ending in CRLF, one per algorithm, as Kamailio does. They are ready for `append_to_reply` or an HTTP reply. `flags` as for the challenges (`stale=true` only with 16). Returns 1, or -1 if the variable can't be set. |
| `autheph_check(realm)` | (`auth_ephemeral`) Digest check with the ephemeral password: www for REGISTER, proxy otherwise. |
| `autheph_www(realm)` / `autheph_proxy(realm)` | (`auth_ephemeral`) Same, for a fixed header. |
| `autheph_authenticate(username, password)` | (`auth_ephemeral`) Checks a plain username/password pair. Both may be templates. 1 ok, -1 expired or unparsable username, -2 wrong password. |

Challenge `flags` follow Kamailio's `auth_challenge_helper()`:

- 1 offers `qop="auth"`;
- 2 offers `qop="auth-int"`. With 1 too, only `auth-int` is offered;
- 0 offers no qop;
- 16 adds `stale=true`;
- 32 leaves out `algorithm=MD5`, for old clients;
- 4 is accepted. No 500 is sent anyway.

A challenge after a check that found a stale nonce has `stale=true`, even
without flag 16. The challenge functions return 1 when the reply was sent.

Return codes of the check functions. A `.cfg` script reads them as `rc`. In
`.fsr` the result is true for 1 and false otherwise. See the
[return code convention](../../docs/glossary.md#return-code-convention).

| Code | Meaning |
|---|---|
| 1 | Authenticated |
| -1 | Error: malformed credentials, algorithm not allowed, digest `uri` differs from the Request-URI, invalid or forged nonce, bad `qop`, missing `nc`/`cnonce`, no credential source, or a database error. For `auth_ephemeral` also an expired username |
| -2 | Wrong password, or a stored HA1 for a different algorithm |
| -3 | Unknown user. For `pv_*_authorize`: the user isn't `username_spec`'s, or `password_spec` is empty |
| -4 | Stale nonce: expired, or a repeated or lower nonce-count (`nonce_count`) |
| -5 | No credentials for this realm |
| -6 | Nonce reused (`one_time_nonce`) |
| -8 | User mismatch (`auth_check` with flag 1, `pv_auth_check` with checks 1) |

## Variables

These give the digest credentials of a request. In Kamailio they come from
the `pv` module. Here they are core variables that need no module. They
read the first `Proxy-Authorization` header, else the first
`Authorization`. They are null for ACK and CANCEL, or without credentials.

| Variable | Value |
|---|---|
| `$au` | User name (before an `@` in `username`) |
| `$ad` | Domain (after the `@`; empty without one) |
| `$aU` | The whole `username` |
| `$ar` | `realm` |
| `$adu` | `uri` (null when empty) |
| `$aa` | `algorithm` (empty when absent) |
| `$adn`, `$adc`, `$adr`, `$ado` | `nonce`, `cnonce`, `response`, `opaque` |

## RPC commands

| Command | Description |
|---|---|
| `auth.reload` | Re-reads `users_file` and returns the number of users. Only registered when `users_file` is set. |

## Behaviour notes

- **Stateless nonces**: a nonce is the hex of expiry (ms) ‖ index ‖ the
  first 16 bytes of HMAC-SHA256(secret, expiry ‖ index ‖ realm).
  - Any worker can verify any nonce, and nothing is stored per challenge.
  - A nonce for another realm or with a wrong MAC is invalid (-1).
  - An expired one is stale (-4). A challenge sent for the same request then
    carries `stale=true`, so clients retry without asking the user.
  - Nonce indices start at a random value at startup.
- **Replay protection**: when the credentials have a `qop`, the highest
  `nc` of each nonce is kept in a shared array of 65536 atomic slots
  (Kamailio's `nc_enabled`). A repeated or lower `nc` makes the nonce stale
  (-4, as in Kamailio), and the next challenge has `stale=true`. When a slot
  is reused by a newer nonce, the old nonce becomes stale.
- **Credential selection**: when a request has several credentials headers,
  the one whose `realm` matches is used.
- **Algorithms**: MD5 and SHA-256, plain or `-sess`. There is one challenge
  per configured algorithm, preferred first (RFC 8760 §2.4). Credentials
  without `algorithm=` are MD5. For `-sess`, HA1 is
  H(H(user:realm:password):nonce:cnonce) (RFC 7616 §3.4.2), from the
  password or a stored HA1. `-sess` credentials without
  [`cnonce`](../../docs/glossary.md#cnonce) are an error (-1). So offer
  `-sess` together with `qop`.
- **qop**: none (RFC 2069 style), `auth`, or `auth-int`. With `auth-int`
  the body hash is part of HA2.
- **Checks**: the digest `uri` must equal the Request-URI. The response is
  compared in constant time.
- **auth_db**: an HA1 of 64 hex digits in the table is SHA-256. Any other
  is MD5. A user has one HA1, so one hash. With plain passwords and
  `calculate_ha1=1`, every algorithm works. A database connection is opened
  for each check.
- **auth_ephemeral**: the password is base64(HMAC(secret, username)). A
  username whose timestamp is in the past is rejected with -1.

## Differences from Kamailio

- Without `auth_db`, credentials come from `users_file`, which has no
  Kamailio equivalent. The `table` argument is then ignored.
- `auth_db`: `password_column` defaults to `password` (plain text). The HA1
  column is set with `password_column_2` (default `ha1`). In Kamailio,
  `password_column` holds the HA1 by default. `password_column_2` is not
  Kamailio's `ha1b` (user@domain) column, and its HA1 may be SHA-256.
- `algorithm` is a list, and a challenge is sent per entry. Kamailio takes
  one algorithm. Credentials are accepted only for a hash in the list, with
  or without `-sess`. Kamailio checks any algorithm it knows, whatever
  `algorithm` says. ferrosip keeps the stricter rule so that an operator who
  lists only SHA-256 does not accept MD5 (no downgrade).
- `-sess` credentials are also checked against a stored HA1 (RFC 7616
  §3.4.2). Kamailio (`auth_db`, `pv_*_authenticate`) returns -1 there.
- A challenge sent after a check found a stale nonce has `stale=true`
  without flag 16. RFC 2617 §3.2.1 says the client then retries without
  asking the user. Kamailio adds it only with flag 16.
- `nonce_count` is on by default, for replay protection. Kamailio has it
  off.
- `pv_www_authorize(realm)` / `pv_proxy_authorize(realm)` with
  `username_spec`, `password_spec` and `calculate_ha1` are the older auth
  module's API. They are kept next to Kamailio's three-argument forms.
- Not implemented: `nonce_auth_max_drift`, `protect_contents`, the
  `auth_checks_*` extra nonce checks (accepted with no effect), the
  `nextnonce` of `use_next_nonce`, and stateful challenges. It works as if
  `force_stateless_reply` were always set.

## Testing

- `tests/e2e_auth.py`:
  - 401 with one challenge per algorithm;
  - MD5 and SHA-256 credentials, stored MD5/SHA-256 HA1;
  - wrong password, unknown user, nc replay, expired and forged nonces,
    digest `uri` mismatch;
  - RFC 2069 credentials;
  - `auth_check` identity (-8), `proxy_authorize` + `consume_credentials`,
    `qop=auth-int`, `auth.reload`;
  - MD5-sess and SHA-256-sess (password and stored HA1, missing cnonce);
  - `has_credentials`;
  - `pv_proxy_authorize` / `pv_www_authorize` (HA1 and `calculate_ha1`, -2,
    -3, -5, -4 for a repeated nc);
  - `pv_proxy_authenticate(realm, passwd,
    flags)` (password, HA1, `$avp(digest_challenge)` with flag 4);
  - `auth_get_www_authenticate`;
  - challenge flags 3, 16 and 32;
  - the `qop`, `one_time_nonce`, `realm_prefix` (also for a realm argument)
    and `add_authinfo_hdr` (rspauth checked) parameters.
- `tests/e2e_state.py` (db_text) and `tests/e2e_sqldb.py` (PostgreSQL,
  MariaDB): `auth_db` with `calculate_ha1` and `load_credentials`.
- `tests/e2e_extra.py`: `auth_ephemeral`.
- `tests/interop_sipp.py`: digest-authenticated REGISTERs from
  [SIPp](../../docs/glossary.md#sipp).
- Unit tests in `src/lib.rs`: the RFC 2617 and RFC 7616 (MD5, SHA-256) test
  vectors, MD5-sess and SHA-256-sess known answers, the nonce lifecycle
  (realm binding, forgery, nc replay, expiry), credentials parsing, the
  `qop` parameter, challenge flags.
