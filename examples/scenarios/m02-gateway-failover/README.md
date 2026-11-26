# m02-gateway-failover (medium)

This scenario models outbound calls to the
[PSTN](../../../docs/glossary.md#pstn) through three gateways, tried in
turn. If one gateway fails or stays silent, the next one gets the call. It
proves that failover happens only on server errors and timeouts, never on
a busy or declined call, and never after the caller hangs up.

```
            ┌─▶ gw1 ─ 5xx / no answer ─┐
caller ──▶ ferrosip                      ├─▶ gw2 ─ … ─▶ gw3 ─ … ─▶ 503 "All gateways failed"
            └── 2xx/3xx/4xx/6xx: the outcome ◀┘
```

**Shows**:
- `await txn.relay` inside a `for` loop over
  [`[feature]`](../../../docs/glossary.md#feature-switch) values (see
  [await](../../../docs/glossary.md#await));
- `match` on the result, and `forward(r)`;
- a helper `fn` returning `Action`;
- `route_set.record()` / `follow()` for the
  [in-dialog requests](../../../docs/glossary.md#in-dialog-request);
- the trunk ACL with `ip.in_subnet(msg.src.ip, …)`.

**Edge cases checked** (`tests/scenarios/m02_gateway_failover.py`):
- The first gateway answers: the others are never tried.
- 503 → the next gateway. Three 503s → `503 All gateways failed`.
- 486 Busy and 603 Decline end the call. A 6xx is global, so there is no
  failover.
- A gateway that sends nothing at all is given up on after the await's
  `timeout: 3s`, and the next one is tried. That timeout replaces
  `fr_timer` and `fr_inv_timer` for that relay (docs/fsr.md; see
  [final response timer](../../../docs/glossary.md#final-response-timer)).
- A [CANCEL](../../../docs/glossary.md#cancel) while a gateway rings: 487
  to the caller, and no failover.

**Run it by hand**: set `SIP_PORT`, `GW1`…`GW3` (default
`sip:127.0.0.1:5071`…`5073`).
