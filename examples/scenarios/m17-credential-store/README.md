# m17-credential-store (medium)

This scenario models a [registrar](../../../docs/glossary.md#registrar)
and proxy whose subscribers' credentials live in Redis. A provisioning
system writes them there as [HA1s](../../../docs/glossary.md#ha1)
(`HSET subscriber:<user> ha1 <md5(user:realm:password)>`). ferrosip has
no users file and no subscriber table. The route reads the HA1 of the
user the credentials name, and checks the
[digest](../../../docs/glossary.md#digest-authentication) against it. It
proves that password changes apply at once, that cached users survive a
Redis outage, and that each user keeps only one phone.

```
provisioning ──HSET subscriber:alice ha1 …──▶ Redis
                                                ▲ HGET subscriber:$au ha1 (on a cache miss
phone ──REGISTER / INVITE──▶ ferrosip ──────────┘  or when the cached HA1 no longer matches)
                              │ shared table ha1_cache (ttl 10m)
                              │ auth.pv_check(realm, ha1, 1, 1) · location.save(4)
                              └──▶ callee (X-Authenticated-User: $au@$ar)
HTTP GET /phone?alice ──▶ location.fetch_contacts → $ulc(p=>count/addr/received/user_agent)
```

**Shows**:
- `auth.has_credentials()` / `auth.challenge()` for the 401 / 407 (see
  [challenge](../../../docs/glossary.md#challenge)). Then
  `auth.pv_check(realm, ha1, 1, 1)`, which is
  [Kamailio's](../../../docs/glossary.md#kamailio) `pv_auth_check`:
  - flags 1: the value is an HA1;
  - checks 1: the credentials' user must be the From user (To for
    REGISTER).
- The credentials variables:
  - `$au` is the user the credentials name. It picks the Redis key, after
    a check that it is a plain user name;
  - `$au@$ar` goes to the callee as `X-Authenticated-User`.

  `.fsr` has no typed form of them. So they are read with `pv("$au")`
  inside a template (`"{pv("$au")}"`, a `Str`), as `$redis(r=>value)` is
  (see [pseudo-variable](../../../docs/glossary.md#pseudo-variable-pv)).
  The pedantic `raw_kamailio` lint lists them.
- A cache in front of Redis: `shared table ha1_cache` (Kamailio's
  [htable](../../../docs/glossary.md#htable)) holds the HA1s every worker
  uses.
  - A cached HA1 that doesn't match is read again from Redis. So a
    password change applies at once.
  - Cached users keep working while Redis is down. The others get 503.
- `redis.exec_with("creds", "HGET %s ha1", …)` with short
  `connect_timeout` / `cmd_timeout`.
- One phone per user: `location.save(4)` (Kamailio's save flag 0x04)
  drops the bindings a REGISTER doesn't add or refresh.
- `GET /phone?<user>` (`on http`): `location.fetch_contacts()`
  (Kamailio's `reg_fetch_contacts`) and `$ulc(p=>count)`, `addr`,
  `received`, `user_agent`, then `location.free_contacts()`.

**Edge cases checked** (`tests/scenarios/m17_credential_store.py`). It
needs `redis-server`, and is skipped without it.
- [REGISTER](../../../docs/glossary.md#register):
  - without credentials → 401 for the [realm](../../../docs/glossary.md#realm);
  - alice and bob register with the passwords whose HA1s are in Redis;
  - carol (not in Redis) and a wrong password are challenged again (401);
  - a user name that can't be a key → 403 Bad user name.
- `GET /phone?alice`: count 1, her [Contact](../../../docs/glossary.md#contact),
  the source address and her User-Agent.
- alice calls bob: 407, then 200. bob's
  [INVITE](../../../docs/glossary.md#invite) has
  `X-Authenticated-User: alice@voip.example.com` and no credentials.
- bob's valid credentials on an INVITE From alice → 403 Credentials of
  another user.
- alice's password is changed in Redis. The new one works at once,
  because the cached HA1 fails and Redis is read again. The old one gets
  401.
- One phone per user:
  - the phone that registered with the new password replaced the first
    one;
  - a second phone's 200 lists only its own contact;
  - `GET /phone` shows it with its User-Agent;
  - a call rings only it;
  - `GET /phone?carol` → 404, and a bad user name → 400.
- Redis stopped: alice (cached) re-registers (200). dave (provisioned but
  never seen) gets 503 Credential store unavailable. Once Redis is back
  (and provisioned again), dave registers.

**Run it by hand**: start Redis and provision a user
(`redis-cli HSET subscriber:alice ha1 $(printf alice:voip.example.com:secret | md5sum | cut -d' ' -f1)`).
Then run `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`HTTP_PORT` 8080, and `REDIS_PORT` 6379. Then run
`curl 'http://127.0.0.1:8080/phone?alice'`.
