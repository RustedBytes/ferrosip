# s09-transports (small)

This scenario models one proxy that speaks UDP, TCP, TLS and
[WebSocket](../../../docs/glossary.md#websocket) at once. Phones register
over any of them. Each phone is reached over the transport, and the
connection, it registered with. It proves that calls cross between
transports correctly, and that stream transports frame messages right.

```
alice ─UDP─┐                      ┌─UDP─▶ carol
erin ──TLS─┤                      ├─TCP─▶ bob   (its own connection)
           ├──▶ ferrosip ─────────┼─WS──▶ dave  (its own connection)
bob ───TCP─┤   Record-Route ×2    └─TCP─▶ sip:+4930555@host:port;transport=tcp
dave ──WS──┘   when the transport changes        (the proxy connects out)
```

**Shows**:
- four `[[listen]]` sections;
- `[tls.default]` with the test certificate from `etc/tls/`.
  `etc/tls/gen-certs.sh` writes it, and the test runs it when it's
  missing;
- `location.save()` / `location.lookup()` over connection-oriented
  transports (see [location service](../../../docs/glossary.md#location-service));
- `route_set.record()`: double
  [Record-Route](../../../docs/glossary.md#record-route) with `r2=on`.
  `enable_double_rr` defaults to on;
- `route_set.follow()`.

**Edge cases checked** (`tests/scenarios/s09_transports.py`):
- [REGISTER](../../../docs/glossary.md#register) over UDP, TCP, TLS and
  WS.
- UDP → TCP, TLS → UDP and UDP → WS calls:
  - the callee gets the [INVITE](../../../docs/glossary.md#invite) with
    the proxy's [Via](../../../docs/glossary.md#via) on its transport;
  - it has two Record-Routes, both `r2=on`. The callee's side is on top,
    with its `;transport=`. The caller's side is below, with none for UDP;
  - the 200 carries the same route set, and the
    [ACK](../../../docs/glossary.md#ack) arrives;
  - the callee's [BYE](../../../docs/glossary.md#bye) goes back over the
    caller's transport. For TLS, it uses the caller's own connection.
- UDP → UDP: a single Record-Route.
- An [R-URI](../../../docs/glossary.md#r-uri) with `;transport=tcp` to an
  unregistered TCP listener: the proxy opens the connection and
  Record-Routes twice. The BYE uses that connection.
- A 4.3 KB [MESSAGE](../../../docs/glossary.md#message) TCP → UDP and
  UDP → TCP, and 8.6 KB TCP → TCP, are delivered whole with the right
  Content-Length.
- TCP framing: two requests in one write, and one request split over
  three writes (inside the headers and the body).
- A missing TLS certificate stops the proxy at startup, naming the file.
  `ferrosip check` doesn't open the certificate files, so it passes.

The test's TCP callee is a small listening-socket UA written in the test
module. The kit's UAs only connect out.

**Run it by hand**: `ferrosip --config ferrosip.toml`. It listens on UDP
and TCP 5060, TLS 5061 and WS 8088. Set `SIP_PORT`, `TLS_PORT`, `WS_PORT`,
`TLS_DIR`, `TRUSTED`.
