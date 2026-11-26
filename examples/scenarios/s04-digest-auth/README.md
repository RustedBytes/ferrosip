# s04-digest-auth (small)

This scenario models a proxy that only serves users who know their
password. It uses [digest authentication](../../../docs/glossary.md#digest-authentication)
from a users file. [REGISTERs](../../../docs/glossary.md#register) are
[challenged](../../../docs/glossary.md#challenge) with 401 and saved.
Everything else is challenged with 407 and relayed to an upstream. It
proves that wrong, stale, replayed and borrowed credentials are refused,
with both SHA-256 and MD5.

```
UA ──▶ ferrosip ── auth.check(realm, "subscriber", 1)
        │ no / wrong / stale credentials: 401 (REGISTER) · 407 (others)
        │ valid credentials of another user (-8): 403 User mismatch
        │ REGISTER: location.save() · else: Record-Route, relay ──▶ upstream
        │ in-dialog: follows the Record-Route · CANCEL: never challenged
```

**Shows**:
- `[modules.auth]` with `users_file`. It holds a plain password, a
  `sha256:` [HA1](../../../docs/glossary.md#ha1) and an `md5:` HA1.
- `algorithm = "SHA-256,MD5"` and a short `nonce_expire`.
- `auth.check` with flags 1. The authenticated user must be the To user
  of a REGISTER, and the From user otherwise.
- `auth.challenge`.
- `auth.consume_credentials()`.

`.fsr` checks return a Bool. So the mismatch (-8) is read from
[Kamailio's](../../../docs/glossary.md#kamailio) `$rc` through the
[escape hatch](../../../docs/glossary.md#escape-hatch): `pv("$rc") == -8`
(see [return code convention](../../../docs/glossary.md#return-code-convention)).
That triggers the `raw_kamailio` lint. That lint is pedantic and off by
default, so `lint -D warnings` stays clean.

A second check with flags 0 instead does not work. The second check sees
the credentials' nonce-count ([nc](../../../docs/glossary.md#nc)) again
and calls it a replay ([stale](../../../docs/glossary.md#stale)).

**Edge cases checked** (`tests/scenarios/s04_digest_auth.py`):
- REGISTER without credentials gets 401 with two WWW-Authenticate
  headers: SHA-256 first, then MD5. The [realm](../../../docs/glossary.md#realm)
  is `example.com`, with `qop="auth"` (see [qop](../../../docs/glossary.md#qop)).
- SHA-256 and MD5 credentials are accepted. So are credentials without
  `algorithm=` (MD5).
- A stored SHA-256 HA1 refuses MD5 credentials. A stored MD5 HA1 accepts
  them.
- These get a new 401: a wrong password, an unknown user, and a digest
  `uri` that isn't the [R-URI](../../../docs/glossary.md#r-uri).
- [INVITE](../../../docs/glossary.md#invite):
  - it gets 407 with Proxy-Authenticate, and nothing is relayed;
  - with credentials it is relayed without Proxy-Authorization;
  - the [BYE](../../../docs/glossary.md#bye) follows the
    [Record-Route](../../../docs/glossary.md#record-route) unchallenged;
  - a wrong password gets a new 407.
- Valid credentials of alice in a REGISTER for bob, or in an INVITE From
  bob, get 403. Nothing is relayed.
- A [nonce](../../../docs/glossary.md#nonce) older than `nonce_expire`
  (2s in the test) gets 401 with `stale=true`, and the fresh nonce works.
  The same nonce and nc again (a replay) get 401.
- A [CANCEL](../../../docs/glossary.md#cancel) of an authenticated,
  ringing INVITE is not challenged (200, then 487).
- A second proxy with `AUTH_ALG=SHA-256` sends one challenge, and refuses
  MD5 credentials.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory,
because `users_file` is relative. It listens on port 5060, with upstream
`sip:127.0.0.1:5080`. Set `SIP_PORT`, `UPSTREAM`, `AUTH_ALG`,
`NONCE_EXPIRE`.
