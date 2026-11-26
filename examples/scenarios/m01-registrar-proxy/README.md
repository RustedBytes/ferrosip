# m01-registrar-proxy (medium)

This scenario models the classic single-box SIP service. One
[registrar](../../../docs/glossary.md#registrar) authenticates every
request and routes calls to every registered
[contact](../../../docs/glossary.md#contact) of the callee. It proves that
the proxy tells unknown users from offline ones, refuses forged
identities, and rings several devices at once with exactly one winner.

```
                       ┌──────────── ferrosip ─────────────┐
alice ──UDP──▶ INVITE ▶│ auth.check / challenge (users)     │──▶ bob (desk phone)  ─ 200 wins
                       │ users list? no → 404               │──▶ bob (softphone)   ─ CANCEL
                       │ location.lookup? no → 480          │
                       │ Record-Route, fork to all contacts │
                       └────────────────────────────────────┘
```

**How 404 and 480 are told apart**: the registrar only knows who is
*registered*, not who *exists*. So the users of the domain are listed in
`[feature] users` as a regex alternation (`alice|bob|carol`, `${USERS}` to
override). The routing checks the [R-URI](../../../docs/glossary.md#r-uri)
user against it with `=~ "^(…)$"`. The regex is anchored so that
`caroline` is not `carol`.
- A listed user without a contact gets `480 Temporarily Unavailable`.
  They exist, but are offline.
- Anybody else gets `404 Not Found`.

The list has to be kept in step with the `users` file, which holds the
passwords. No `.fsr` function asks the auth module whether a user exists.

**Shows**:
- `auth.check` / `auth.challenge` with a users file: 401 for
  [REGISTER](../../../docs/glossary.md#register), 407 for the rest (see
  [challenge](../../../docs/glossary.md#challenge));
- `auth.consume_credentials()`;
- `location.save()`;
- `location.lookup()` with `append_branches`. That is the default:
  parallel [forking](../../../docs/glossary.md#forking) to every contact;
- a [`[feature]`](../../../docs/glossary.md#feature-switch) interpolated
  into a regex;
- `route_set.record()` / `follow()` (see
  [Record-Route](../../../docs/glossary.md#record-route));
- a helper `fn` for [in-dialog requests](../../../docs/glossary.md#in-dialog-request);
- `max_expires`.

**Edge cases checked** (`tests/scenarios/m01_registrar_proxy.py`):
- REGISTER:
  - 401 then 200;
  - without credentials, 401 with WWW-Authenticate;
  - a wrong password is refused;
  - two contacts of one [AoR](../../../docs/glossary.md#aor) are both
    listed;
  - `Expires: 7200` is clamped to `max_expires` (3600);
  - `Expires: 0` removes a contact.
- A call to an unknown user → 404. A call to a known but unregistered
  user → 480. `caroline` is not mistaken for `carol`.
- An [INVITE](../../../docs/glossary.md#invite) without credentials → 407,
  and it is not relayed. alice's credentials with `From: carol` are
  refused. That is auth.check's flag 1: the From user must be the
  authenticated user.
- Parallel forking:
  - both contacts get one INVITE each;
  - the one that answers wins, and the 200 carries one Record-Route;
  - the other [branch](../../../docs/glossary.md#branch) gets a
    [CANCEL](../../../docs/glossary.md#cancel) on its own INVITE branch.
    The proxy [ACKs](../../../docs/glossary.md#ack) its 487 hop by hop;
  - the winner gets the ACK and the [BYE](../../../docs/glossary.md#bye),
    the loser neither.
- A CANCEL from the caller while both contacts ring: 200 for the CANCEL,
  487 for the INVITE, CANCEL on both branches, and only one
  [final reply](../../../docs/glossary.md#final-reply) to the caller.
- After one contact unregisters, only the other is tried. With none left,
  the call gets 480.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory,
because `users_file` is relative. Set `SIP_PORT` (default 5060), `USERS`,
`USERS_FILE`.
