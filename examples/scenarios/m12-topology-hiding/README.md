# m12-topology-hiding (medium)

This scenario models a border proxy between the internal network and a
carrier, with [topology hiding](../../../docs/glossary.md#topology-hiding)
([Kamailio](../../../docs/glossary.md#kamailio) topoh). The carrier must
not learn internal addresses. It proves that no internal address leaks in
any header, and that calls still route both ways, including
[ACK](../../../docs/glossary.md#ack), [BYE](../../../docs/glossary.md#bye)
and [re-INVITE](../../../docs/glossary.md#re-invite).

```
alice ── internal proxy (10.0.0.7) ──▶ ferrosip ─────────────────────────▶ carrier
  Via: alice, 10.0.0.7                 │ Via: ferrosip;th=<hidden Vias>
  Contact: alice@127.0.0.1:…           │ Contact: sip:198.51.100.10:<port>;line=<hidden contact>
  Record-Route: internal proxy         │ Record-Route: ferrosip, sip:198.51.100.10:<port>;lr;line=<hidden>
        ◀── replies: Vias restored ────┘◀── in-dialog: R-URI = masked Contact → the real one
```

**Shows**:
- `[modules.topology]` (topoh) with `mask_ip` and `mask_key` from the
  environment.
- Nothing in the routing: the module rewrites what the proxy sends and
  decodes what it gets.
- The routing is a plain border proxy:
  - `route_set.record()` (see [Record-Route](../../../docs/glossary.md#record-route));
  - `route_set.follow()` for
    [in-dialog requests](../../../docs/glossary.md#in-dialog-request).
    After it, the [R-URI](../../../docs/glossary.md#r-uri) is the decoded
    real [Contact](../../../docs/glossary.md#contact);
  - a source check for new calls.

The test's caller also plays an internal proxy in front of her. Her
[INVITE](../../../docs/glossary.md#invite) has a second
[Via](../../../docs/glossary.md#via) (`10.0.0.7`) and a Record-Route with
her own address. Her in-dialog requests carry only the border proxy's
[Route](../../../docs/glossary.md#route).

**Edge cases checked** (`tests/scenarios/m12_topology_hiding.py`):
- The carrier's INVITE has one Via (with `;th=`) and a Contact
  `sip:198.51.100.10:<port>;line=…`. It has no internal address in Via or
  Contact.
- The internal proxy's Record-Route doesn't reach the carrier either. It
  is masked like a Contact. It is unmasked again in the carrier's 200 and
  in the Route of the carrier's in-dialog requests.
- The 200 to the caller has both of her Vias back, in order, and the
  internal Record-Route. The carrier's Contact is masked too.
- The caller's ACK and BYE, sent to the masked Contact, reach the
  carrier's real Contact with nothing internal in them. The BYE's 200
  comes back.
- The carrier's re-INVITE, sent to the caller's masked Contact, reaches
  her real Contact with one Via. Its 200 goes back with only the carrier's
  Via, and with the caller's Contact masked. The ACK follows.
- A request with a forged `;line=` token is routed to no one inside.

**Run it by hand**: `ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060,
`CARRIER` is `sip:127.0.0.1:5080`, and `MASK_IP` is `198.51.100.10`.
