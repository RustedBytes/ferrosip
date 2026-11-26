# m09-presence (medium)

This scenario models the [presence](../../../docs/glossary.md#presence)
server of `example.com`: the service that tells users whether their
contacts are online or on a call. The proxy takes publications, serves
subscriptions (presence and dialog events) and resource lists, and
publishes the state of the calls it routes. It proves that the
publication and subscription rules of the presence RFCs hold, including
expiry, refresh and buddy lists.

```
bob's devices ── PUBLISH (presence) ──▶ ┌──────────── ferrosip ────────────┐
watcher ──── SUBSCRIBE presence/dialog ▶│ presence (+ presence_xml,         │── NOTIFY ──▶ watcher
        ──── SUBSCRIBE friends (list) ─▶│   presence_dialoginfo), rls       │
alice ── INVITE ─▶ dialog.manage() ────▶│ pua_dialoginfo: PUBLISH to itself │── INVITE ──▶ bob
                                        └───────────────────────────────────┘
```

The flow uses [PUBLISH](../../../docs/glossary.md#publish),
[SUBSCRIBE](../../../docs/glossary.md#subscribe) and
[NOTIFY](../../../docs/glossary.md#notify).

**Shows**:
- `presence.handle_publish()`, `presence.handle_subscribe()`;
- `resource_lists.handle_subscribe()`, falling back to presence. It
  returns true when the request is for a list, which it answers;
- the [event packages](../../../docs/glossary.md#event-package), loaded
  by their sections (`[modules.presence_xml]`,
  `[modules.presence_dialoginfo]`) with `force_dummy_*`;
- `[modules.pua_dialoginfo] presence_server` pointing at the proxy
  itself. So routed calls (`dialog.manage()`) show up as dialog-info (see
  [BLF](../../../docs/glossary.md#blf));
- the rls lists from a db_text `xcap` table (`db/xcap`). It holds one
  rls-services document: `sip:friends@example.com` = alice, carol.

[In-dialog](../../../docs/glossary.md#in-dialog-request) SUBSCRIBEs
(refresh, unsubscribe) are sent to the server's
[Contact](../../../docs/glossary.md#contact). So the domain check applies
to initial ones only. They go to rls first as well: rls refreshes a list
subscription, not presence.

**Edge cases checked** (`tests/scenarios/m09_presence.py`):
- SUBSCRIBE before any publication: an initial NOTIFY with a dummy
  `closed` [PIDF](../../../docs/glossary.md#pidf).
- PUBLISH:
  - [SIP-ETag](../../../docs/glossary.md#entity-tag), and Expires 7200 cut to `max_expires` (1800);
  - a second device's tuple is aggregated;
  - its 3s publication expires, and the [watcher](../../../docs/glossary.md#watcher) is told;
  - refresh with `SIP-If-Match` and no body (new entity tag);
  - modify with a body;
  - unknown entity tag → 412;
  - new publication without body → 400;
  - unknown event → 489 with Allow-Events;
  - another domain → 404;
  - removal with Expires 0 → back to the dummy state.
- SUBSCRIBE:
  - below `min_expires` → 423 with Min-Expires;
  - above `max_expires_subscribe` → cut to 600;
  - unknown event → 489;
  - Expires 0 as a fetch (one terminated NOTIFY);
  - in-dialog refresh and unsubscribe: a terminated NOTIFY, gone from
    `presence.watcher_list`, 481 afterwards.
- Dialog event: an empty dialog-info first. Then a call alice → bob
  through the proxy shows early → confirmed → terminated, with increasing
  `version`. bob is the recipient, with the call's
  [Call-ID](../../../docs/glossary.md#call-id).
- Resource list:
  - 421 without `Supported: eventlist`;
  - a multipart/related [RLMI](../../../docs/glossary.md#resource-list) NOTIFY listing both members, with
    `Require: eventlist`;
  - a member's PUBLISH re-notifies, a non-member's doesn't;
  - a non-list URI falls through to presence;
  - refresh and unsubscribe of the list subscription in its
    [dialog](../../../docs/glossary.md#dialog).
- A [MESSAGE](../../../docs/glossary.md#message) gets 405.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory.
`SIP_PORT` is 5060 and `CALLEE` is `sip:127.0.0.1:5080`. `RLS_DB`
defaults to `text://db`, relative to the working directory.
