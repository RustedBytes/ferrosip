# m03-voicemail (medium)

This scenario models a voicemail service in front of registered users.
Calls go to the callee first. They are retargeted to a voicemail server
when the callee is busy, doesn't answer or isn't registered. It proves
that each of those cases reaches voicemail with the right reason, and that
redirects, declines and hang-ups are passed back to the caller instead.

```
                    ┌─ 2xx ─────────────────▶ forwarded (already, by tm)
caller ─▶ ferrosip ─┼─ 486 Busy ─────────┐
  lookup(bob)       ├─ no answer (5s) ───┼──▶ voicemail (features.voicemail)
  └─ none ──────────┼────────────────────┘     R-URI sip:bob@voicemail.example.com
                    │                          Diversion: <sip:bob@example.com>;reason=…
                    └─ 3xx / 603 / 600 / 487 (CANCEL) ─▶ forwarded to the caller
```

**Shows**:
- `await txn.relay(msg, timeout: 5s)` as the ring timer (see
  [await](../../../docs/glossary.md#await));
- a `match` on `Final(r)` / `Timeout` with guards;
- `txn.is_canceled()` after the await;
- retargeting on the same [transaction](../../../docs/glossary.md#transaction):
  `msg.ruri`, `msg.dst_uri`, then `relay(msg)` from a helper `fn`. That
  helper is called both before and after the await;
- `text.append_header` for a [Diversion header](../../../docs/glossary.md#diversion-header) (RFC 5806) with the reason
  (`user-busy`, `no-answer`, `unavailable`);
- auth only for [REGISTER](../../../docs/glossary.md#register), and a
  source check (`ip.in_subnet`) for calls.

**Decisions**:
- **3xx from the callee is forwarded, not followed.** The proxy doesn't
  recurse on redirects. The callee's device chooses the
  [Contact](../../../docs/glossary.md#contact) of a 3xx. Following it would
  let any registered phone send calls (at our cost) to any address, past
  this proxy's checks. The caller's UA decides whether to follow it.
  RFC 3261 §16.7 step 4 lets the proxy do either. A 3xx is not a reason
  for voicemail either: the callee said where it is.
- **6xx doesn't go to voicemail.** A 6xx is global (RFC 3261 §16.7: no
  other location is tried). So the first arm forwards it, like a final
  after the caller's [CANCEL](../../../docs/glossary.md#cancel)
  (`txn.is_canceled()`). `603 Decline` is the callee's choice and is
  passed on.
- **`txn.drop_replies()` before retargeting.** This is
  [Kamailio's](../../../docs/glossary.md#kamailio) `t_drop_replies()`.
  Without it, bob's 486 stays the best
  [final reply](../../../docs/glossary.md#final-reply) of the transaction.
  A caller who hangs up while the mailbox rings would then get 486 instead
  of 487.
- **Ring time.** The `timeout: 5s` of the await decides when an unanswered
  call goes to voicemail, not `fr_inv_timer` (60s). tm then CANCELs the
  ringing [branch](../../../docs/glossary.md#branch).

**Edge cases checked** (`tests/scenarios/m03_voicemail.py`):
- bob answers: 200, voicemail is never called, and the
  [BYE](../../../docs/glossary.md#bye) goes through the
  [Record-Route](../../../docs/glossary.md#record-route).
- 486 → voicemail:
  - one [INVITE](../../../docs/glossary.md#invite) with the mailbox
    [R-URI](../../../docs/glossary.md#r-uri), the Diversion header, the
    caller's [SDP](../../../docs/glossary.md#sdp), the proxy's Record-Route
    and Max-Forwards 69;
  - the caller sees voicemail's 200, never the 486;
  - the BYE goes to voicemail.
- 600 and 603 are forwarded, and voicemail is not called.
- No answer: bob's branch is CANCELed after about 5s (not 60s). Voicemail
  answers with `reason=no-answer`.
- An unregistered user goes to voicemail at once (`reason=unavailable`).
- A 302 from bob is forwarded with its Contact. Voicemail is not called.
- CANCEL while bob rings: 487, bob is CANCELed, no voicemail.
- CANCEL while voicemail rings: voicemail gets the CANCEL on its own
  branch. bob gets none, because it had already answered 486. The caller
  gets 487.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory.
Set `SIP_PORT` (5060), `VOICEMAIL` (`sip:127.0.0.1:5090`), `TRUSTED`,
`USERS_FILE`.
