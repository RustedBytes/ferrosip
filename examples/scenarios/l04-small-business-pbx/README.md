# l04-small-business-pbx (large)

This scenario models one proxy acting as a small office PBX. Extensions
100–199 register and call each other. Unanswered calls fall back to a
voicemail server. Users can forward their calls over HTTP and see each
other's line state ([BLF](../../../docs/glossary.md#blf)). It proves that
ringing, voicemail, forwarding, BLF and call records work together in one
configuration.

```
100 ──INVITE 101──▶ pbx ── forward table? (101 → 102) ── lookup ──▶ 101 (rings 4s)
                     │  486 / 480 / 408 / no answer / offline ──────▶ voicemail (R-URI sip:<ext>@pbx)
HTTP /forward?101 ──▶│  shared table `forward`
102 ──SUBSCRIBE dialog (sip:101@pbx)──▶ presence ◀── PUBLISH ── pua_dialoginfo (dialog.manage)
                     └ on dialog.ended / failed: "CDR …" log line
```

**Shows**:
- `auth.check` / `auth.challenge` for
  [REGISTER](../../../docs/glossary.md#register),
  [INVITE](../../../docs/glossary.md#invite) and
  [SUBSCRIBE](../../../docs/glossary.md#subscribe); `location.save` /
  `lookup`.
- `await txn.relay(msg, timeout: 4s)`: the ring time. Then a `match`
  sends these to voicemail: busy (486), unavailable (480), request
  timeout (408) and no answer (`Timeout`). It forwards anything else, a
  [CANCEL's](../../../docs/glossary.md#cancel) 487 included.
- A helper `fn voicemail(msg, ext) -> Action`, used before the `await`
  (offline extension) and after it.
- Call forwarding in a `shared table forward: Map<Str, Str>` (see
  [shared table](../../../docs/glossary.md#shared-table)). `on http`
  manages it (`GET`/`POST`/`DELETE /forward?<ext>`). Bad input gets 400.
  The call gets a `Diversion` header.
- BLF:
  - `[modules.pua_dialoginfo]` publishes every managed
    [dialog's](../../../docs/glossary.md#dialog) state to the PBX itself
    (`presence_server`);
  - `presence.handle_publish()` accepts those
    [PUBLISHes](../../../docs/glossary.md#publish) without auth only when
    they come from the PBX's own address
    (`"{msg.src.port}" == features.self_port`);
  - watchers subscribe to `Event: dialog` with credentials.
- [Dialog variables](../../../docs/glossary.md#dialog-variable) and
  [CDR](../../../docs/glossary.md#cdr) lines from `on dialog.ended` /
  `dialog.failed`.

**Edge cases checked** (`tests/scenarios/l04_small_business_pbx.py`):
- Registration of four extensions (401, then 200).
- BLF: 102 subscribes to 101 and gets an initial
  [NOTIFY](../../../docs/glossary.md#notify). A call 100 → 101 that rings
  for 1s is shown `confirmed`, and after its
  [BYE](../../../docs/glossary.md#bye) `terminated`.
- BLF for a call 101 answers right after its 180 shows `confirmed` too.
  The "confirmed" PUBLISH is queued while the "early" one is in flight.
  It still goes to `presence_server`, not to the
  [R-URI](../../../docs/glossary.md#r-uri).
- The CDR line has caller, callee and `caller_bye`.
- 103 busy → voicemail answers. Voicemail gets one INVITE for
  `sip:103@pbx.example.com`, and 103 exactly one. The CDR names 103.
- 103 rings and never answers. After the 4s ring time its
  [branch](../../../docs/glossary.md#branch) is canceled and voicemail
  answers.
- 104 (not registered) goes straight to voicemail. 555 (not an
  extension) gets `404 No such extension`.
- The caller cancels while 101 rings (BLF shows `early`): 487, and
  voicemail is not tried.
- Forwarding:
  - POST 101 → 102, then GET;
  - a SIP URI as the target is refused (400) and changes nothing;
  - a call to 101 rings 102 with `Diversion: <sip:101@pbx.example.com>`,
    and 101 never sees it.
- 101 → 103 and 103 → 102: only one hop is followed. 103 is busy → 103's
  voicemail. 102 never rings.
- DELETE (204), then GET gives 404, and 101 answers itself again.
  `/forward?abc` → 400.

**Run it by hand**: `ferrosip --config ferrosip.toml` from `pbx/`.
`SIP_PORT` is 5060, `HTTP_PORT` 8080, and `VOICEMAIL`
`sip:127.0.0.1:5090`. Then run
`curl -d 102 'http://127.0.0.1:8080/forward?101'`.
