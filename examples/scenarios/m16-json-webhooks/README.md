# m16-json-webhooks (medium)

This scenario models call routing by a webhook. Every new call is POSTed
to a webhook as a JSON event. The webhook's JSON answer routes the call.
Use this pattern to plug ferrosip into a web application. It proves that
the event is always valid JSON, and that any bad, hostile or slow answer
falls back safely without injecting headers.

```
caller ──▶ ferrosip ── POST {webhook}  {"event":"call.new","call_id":…,"from":{"user","display"},
             │          2s timeout      "to":…,"cseq":7,"subject":…,"sdp":…}  ──────────▶ webhook
             │◀──────── 200 {"action":"route","route":{"uri":"sip:ip:port","account":…}}
             │              {"action":"reject","code":486,"reason":…}
             ├─▶ route.uri  (+ X-Account: route.account)
             ├─▶ 403 / 404 / 480 / 486 / 603 with the webhook's reason
             └─▶ features.fallback + X-Webhook-Fallback: <why>
                   error / status / no action / unknown action / no route.uri /
                   bad route.uri / bad route.account / no code / bad code / bad reason
```

**Shows**:
- building a JSON document with `json_doc.set`: string and integer
  values, and nested paths (`from.user`);
- `await http.post(url, doc, timeout: 2s)`, with Content-Type
  `application/json` by default (see [await](../../../docs/glossary.md#await));
- reading the answer with `json_doc.get` and nested paths (`route.uri`);
- helper `fn`s returning `Action` after the `await`;
- an `Int` local as `json_doc.get`'s result (`let code: Int = 0`), so it
  can be matched against codes.

Design notes:
- The rejection codes the webhook may use are a `match` allowlist. Any
  other code takes the fallback.
- Every value from the answer that goes into a
  [header](../../../docs/glossary.md#header-field) or a reason phrase is
  checked for control characters (`[[:cntrl:]]`). A JSON string can carry
  `\r\n`, and `msg.headers[…] = v` writes it as is. A regex `"[\r\n]"`
  would also do. But `ferrosip fmt` turns a string containing `\n` into a
  `"""…"""` over two lines.
- `json_doc.get` puts JSON numbers and booleans into the variable as
  integers (`true` → 1), and arrays/objects as JSON text. So a regex or a
  `match` after it is the type check.

**Edge cases checked** (`tests/scenarios/m16_json_webhooks.py`):
- One POST per call, and none for the [BYE](../../../docs/glossary.md#bye).
  The event is valid JSON (Python's strict `json.loads`):
  - `cseq` is a JSON integer;
  - the UTF-8 `Subject` is as is;
  - there is no `subject` key when there is no Subject header;
  - the [SDP](../../../docs/glossary.md#sdp) is byte for byte.

  The call reaches `route.uri` with the
  [Record-Route](../../../docs/glossary.md#record-route).
- `route.account` with `\"`, `\\` and UTF-8 escapes arrives decoded in
  `X-Account`.
- From display names: with `\"` and `\\` escapes, one ending in an
  escaped quote, UTF-8, a tab, and an unquoted name. The event stays valid
  JSON, and `from.display` holds the name (as written, or unescaped).
- Reject 486 with a UTF-8 reason, and 603 without a reason.
- Each of these goes to the fallback with its reason:
  - cut-off JSON, HTML, an empty body;
  - no `action`, an unknown action, `action: 1`;
  - no `route.uri`, `route.uri` a number or a list, `route` a string;
  - no `code`, `code` `"abc"`, `true` or 200;
  - `\r\n` in `route.account` (no header injected) or in the reason;
  - status 500, a webhook slower than the timeout, the webhook down.
- A 300 KB answer with the fields after the padding. A 20 KB SDP full of
  quotes, backslashes and UTF-8 in the event.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`WEBHOOK_URL` is `http://127.0.0.1:8090/call`, and `FALLBACK` is
`sip:127.0.0.1:5090`.
