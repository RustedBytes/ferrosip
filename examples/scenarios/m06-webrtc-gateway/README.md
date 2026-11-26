# m06-webrtc-gateway (medium)

This scenario models a gateway between browsers and ordinary phones.
Browsers speak SIP over [WebSocket](../../../docs/glossary.md#websocket)
(RFC 7118), as [WebRTC](../../../docs/glossary.md#webrtc) apps do. UDP
phones use plain SIP. Both meet at one proxy. It proves that calls work in
both directions and that a closed browser tab is noticed at once.

```
browser alice ──WS──▶ ┌───────── ferrosip ──────────┐ ──UDP──▶ bob (phone)
 Contact x.invalid    │ :WS_PORT          :SIP_PORT │
 Via WSS x.invalid    │ Record-Route twice (WS, UDP)│
                      │ ;alias=127.0.0.1~port~ws on │
                      │ the browser's Contact       │
                      └─────────────────────────────┘
```

A browser can't be reached by its [Contact](../../../docs/glossary.md#contact).
JsSIP and SIP.js put a random `.invalid` host in it, and in the
[Via](../../../docs/glossary.md#via). Only its WebSocket connection
reaches it. So:
- For calls *to* the browser, the
  [registrar's](../../../docs/glossary.md#registrar) binding holds the
  connection. `location.lookup()` sends there.
- For [in-dialog requests](../../../docs/glossary.md#in-dialog-request),
  the proxy adds `;alias=ip~port~transport` to the browser's Contact. It
  does this in the browser's [INVITE](../../../docs/glossary.md#invite)
  (`nat.add_contact_alias()`) and in its answers
  (`on reply where r.src.transport == WS`). `nat.handle_ruri_alias()`
  turns the alias of an in-dialog [R-URI](../../../docs/glossary.md#r-uri)
  back into the destination.
- `route_set.record()` adds two
  [Record-Routes](../../../docs/glossary.md#record-route) when the call
  changes transport (`enable_double_rr`, on by default). One is for the
  UDP side to reach. The other has `transport=ws` for the browser side.
- `handle_lost_tcp = true`: a closed tab's binding is removed with its
  connection. So calls to it fail at once instead of timing out.

**Shows**:
- `[[listen]] proto = "ws"` next to UDP;
- `msg.src.transport` / `r.src.transport` compared with `WS` / `WSS`;
- `nat.add_contact_alias()`, `nat.handle_ruri_alias()`;
- double Record-Route;
- `handle_lost_tcp`.

**Edge cases checked** (`tests/scenarios/m06_webrtc_gateway.py`). A local
`Browser` UA uses the `.invalid` Contact and Via.
- [REGISTER](../../../docs/glossary.md#register) over WS: 401, then 200,
  with the `.invalid` Contact listed.
- Browser → phone:
  - two Record-Routes (UDP first, then `transport=ws`) in the INVITE and
    the 200;
  - the alias on the browser's Contact, and its Via kept;
  - [ACK](../../../docs/glossary.md#ack) and
    [BYE](../../../docs/glossary.md#bye) from the browser reach the phone;
  - in a second call, the phone's BYE reaches the browser.
- Phone → browser:
  - the INVITE goes over the WebSocket, with the registered Contact as
    R-URI;
  - the alias is on the browser's 200;
  - ACK and BYE from the phone reach the browser;
  - the browser's BYE reaches the phone.
- A [CANCEL](../../../docs/glossary.md#cancel) from the phone while the
  browser rings: 487, and CANCEL over WS.
- A closed WebSocket: the binding leaves `ul.dump`, and a call to that
  user gets 404 at once.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this
directory. Set `SIP_PORT` (5060), `WS_PORT` (8080), `USERS_FILE`.
