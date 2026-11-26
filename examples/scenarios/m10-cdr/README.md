# m10-cdr (medium)

This scenario models billing records for calls. Every call is tracked as
a [dialog](../../../docs/glossary.md#dialog). When it ends, or fails, a
JSON [CDR](../../../docs/glossary.md#cdr) is POSTed to a collector. It
proves that each call gives exactly one correct record, whoever hangs up,
and that prepaid limits and admin hang-ups are recorded with their reason.

```
caller ──▶ ferrosip ──────────────▶ PBX (features.callee)
           dialog.manage()            │
           dialog vars caller, plan   │ BYE either way / 3s prepaid limit / dlg.end_dlg
             │
             └─ on dialog.ended / on dialog.failed ── POST /cdr (JSON) ──▶ collector
```

**Shows**:
- `dialog.manage()`;
- `dialog var`s set in the route and read as `d.caller` / `d.plan` in the
  handlers (see [dialog variable](../../../docs/glossary.md#dialog-variable));
- `d.duration`, `d.end_reason`, `d.started_at`, `d.code`;
- a per-call limit for prepaid callers (From user `pp…`), with
  `dialog.set_timeout(3s)` and `dialog.set_property("timeout-bye")`;
- a helper `fn` without a message, called from both handlers.

The [BYEs](../../../docs/glossary.md#bye) the proxy sends itself (the
prepaid limit, `dlg.end_dlg`) get a
`Reason: SIP;cause=200;text="Call ended by the proxy"` header. It comes
from `on kamailio.event_route(name: "tm:local-request")` (see
[event route](../../../docs/glossary.md#event-route)). tm runs that route
before it sends each request of its own (BYEs, keep-alives, NOTIFYs…). It
does not run it for relayed ones. `.fsr` has no typed form of that route.
So it is written with the [Kamailio](../../../docs/glossary.md#kamailio)
[escape hatch](../../../docs/glossary.md#escape-hatch) (`pv("$rm")`,
`kamailio.call("append_hdr", …)`). The pedantic `raw_kamailio` lint lists
them.

[Event handlers](../../../docs/glossary.md#event-handler) can't `await`.
`http.post` is allowed in routes only. So the CDR goes out with the
blocking `http_client`. It holds the [worker](../../../docs/glossary.md#worker)
for up to `connection_timeout` (1s here) when the collector is slow or
down. `http_client.query` with a `Content-Type: application/json` header
is used instead of `http_client.post`, which sends no Content-Type. JSON
braces are written `\{` `\}` in `.fsr` strings.

**Edge cases checked** (`tests/scenarios/m10_cdr.py`):
- The caller hangs up:
  - its relayed BYE reaches the PBX without a `Reason`;
  - there is one CDR, valid JSON, with `caller_bye`;
  - it has the dialog variables, the From/To URIs, and a start time near
    the call's;
  - its duration is between 1s and the time the call was held.
- The callee hangs up, with a BYE from the PBX through the
  [Record-Route](../../../docs/glossary.md#record-route): `callee_bye`.
- A prepaid caller is cut after 3s:
  - a BYE goes to both sides, each with the `Reason` header;
  - the CDR says `timeout`, with a duration of 3 to 5s;
  - the caller's late BYE makes no second CDR.
- `dlg.list` shows the variables. `dlg.end_dlg` gives `admin`, and its BYE
  has the `Reason` too.
- A 486: `on dialog.failed` posts code 486, and `on dialog.ended` doesn't
  run.
- The collector is down: the BYE still gets its 200 within about
  `connection_timeout`, and the next call works.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`CALLEE` is `sip:127.0.0.1:5080`, and `COLLECTOR` is
`http://127.0.0.1:8090`.
