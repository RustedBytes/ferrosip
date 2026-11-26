# s06-message-edits (small)

This scenario models a proxy that rewrites messages on the way through.
It edits [header fields](../../../docs/glossary.md#header-field), bodies
and the [R-URI](../../../docs/glossary.md#r-uri) user on requests, and
headers on replies. Use it when you need to add, remove or mask data
between two networks. It proves that every edit leaves a correct
Content-Length, even with large headers and multi-byte text.

```
UA ──▶ ferrosip ──────────────────────────────────────────────▶ upstream
       │ − X-Secret   + X-Proxy: s06   X-Tenant := acme   X-Echo := X-Long
       │ R-URI user 0… → +49… · support → alice
       │ text/plain body: card numbers masked · SDP: c= → features.media_ip
       │ X-Set-Body: set_body() · X-Drop-Body: remove_body()
   ◀── │ replies: − X-Internal   + X-Replied-Via: s06
```

**Shows**:
- `text.remove_header`, `text.append_header`;
- `msg.headers["X"] = …` (remove + append) and `.has`;
- `text.subst_user`, `msg.ruri.user = …`;
- `text.has_body`, `text.replace_body_all`, `text.set_body`,
  `text.remove_body`;
- `msg.has_sdp` (see [SDP](../../../docs/glossary.md#sdp));
- the same text functions in `on reply`.

Note: `{…}` in an [`.fsr`](../../../docs/glossary.md#fsr) string is an
interpolation, also in a regex. A repetition is written `\{4\}`.
`"[0-9]{4}"` compiles to `[0-9]4` without a warning.

**Edge cases checked** (`tests/scenarios/s06_message_edits.py`). After
every edit the relayed message must have exactly one Content-Length (long
or compact form) equal to its body's bytes.
- Two X-Secret headers are both removed. X-Tenant is replaced, not added.
  Header names match case-insensitively (`x-SECRET`, `X-TENANT`).
- The R-URI user is rewritten (`0301234567` → `+49301234567`,
  `support` → `alice`). The To header is left alone.
- The body is masked. This also works after UTF-8 text (Content-Length in
  bytes) and in a request written with compact headers (`l:`, `c:`, `i:`,
  `v:`).
- An SDP with a session and a media `c=` line: both are rewritten, and the
  SDP gets longer. The 200's SDP is not touched.
- `set_body` on a bodiless [OPTIONS](../../../docs/glossary.md#options)
  adds Content-Type and Content-Length 22. After `replace_body_all` on the
  same body, the last edit wins. `remove_body` leaves Content-Length 0.
- An 8 KB header is relayed intact. The routing copies it whole into
  X-Echo, with a body edit in the same message. An 8 KB header in a reply
  survives the reply edits.
- Replies lose X-Internal and gain X-Replied-Via.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on port
5060, with upstream `sip:127.0.0.1:5080`. Set `SIP_PORT`, `UPSTREAM`,
`TRUSTED`.
