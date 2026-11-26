# l03-carrier-interconnect (large)

This scenario models an [SBC](../../../docs/glossary.md#sbc) between
customers and two carriers. Customers authenticate, their numbers are
normalised, and calls go to carrier 1 with failover to carrier 2. The
carriers never see customer addresses, and every call produces a billing
record. It proves the failover rules, the per-customer limit, topology
hiding, and that each [CDR](../../../docs/glossary.md#cdr) names the
carrier that actually answered.

```
cust-a … cust-e ──UDP──▶ sbc ──────────────────────────▶ carrier 1 ─ 5xx / silent ─┐
   digest auth           │ per-customer pipe (5 / 5s)                               ├─▶ carrier 2
   (customers file)      │ 0301234 → +49301234, 00… → +…    topology hiding ◀───────┘
                         │ dialog.ended / dialog.failed ──HTTP POST──▶ CDR collector
```

**Shows**:
- `auth.check` / `auth.challenge` with a users file of customers (see
  [digest authentication](../../../docs/glossary.md#digest-authentication)).
  The customer is the authenticated From user.
- A per-customer rate limit:
  `pipe_limits.check_or_create("cust-{who}", "TAILDROP", …)` and
  `pipe_limits.reject(5s)` (503 with Retry-After).
- Number normalisation with `text.subst_user` and a regex `=~`, then
  `sip.is_e164` (484 otherwise). The [R-URI](../../../docs/glossary.md#r-uri)
  read after `subst_user` sees the new number.
- Carrier failover with `await txn.relay` in a `for` loop, and
  `txn.set_timeout(30s, 1s)`. That allows 30s of ringing, but a carrier
  that sends nothing at all is down after 1s.
  `await txn.relay(…, timeout: 5s)` would set both timers to 5s. The timeout is for the whole
  wait, so `fr_timer` stops mattering (see
  [final response timer](../../../docs/glossary.md#final-response-timer)).
- [Topology hiding](../../../docs/glossary.md#topology-hiding)
  (`[modules.topology]`, topoh). The carriers see only the SBC: one
  [Via](../../../docs/glossary.md#via) and a masked
  [Contact](../../../docs/glossary.md#contact). Their
  [in-dialog requests](../../../docs/glossary.md#in-dialog-request) come
  back through it.
- [Dialog variables](../../../docs/glossary.md#dialog-variable)
  (`dialog var`) and CDRs from `on dialog.ended` / `on dialog.failed`,
  posted with `http_client.post`. The body is a plain `key=value&…`
  string. It is not URL-encoded: a `+` stays a `+`.

The in-dialog branch relays whatever has a To
[tag](../../../docs/glossary.md#tag). Topology hiding sends it on to the
real contact it decoded from the masked R-URI.

**Edge cases checked** (`tests/scenarios/l03_carrier_interconnect.py`):
- `030123456` → `+4930123456`, `00442071234567` → `+442071234567`, and
  `+4930999` unchanged. `123` → 484, and no carrier is tried.
- The carrier's [INVITE](../../../docs/glossary.md#invite) has one Via
  (the SBC's), no customer address anywhere, a masked Contact pointing at
  the SBC, and no credentials.
- The carrier hangs up. Its [BYE](../../../docs/glossary.md#bye) to the
  masked Contact reaches the customer. The CDR has the customer, the
  normalised number, carrier 1 and `callee_bye`.
- Carrier 1 503 → carrier 2 answers. The CDR names carrier 2:
  `dialog.carrier = gw` after an `await` sets the dialog's variable.
- Carrier 1 silent → carrier 2, after about `fr_timer`, not the 30s.
- 486 from carrier 1 is forwarded with no failover.
- Both carriers 503 → `503 No carrier available`. There is a
  `dialog.failed` CDR with code 503, but no `end` CDR.
- [CANCEL](../../../docs/glossary.md#cancel) while carrier 1 rings → 487,
  no failover.
- A burst of 12 calls from one customer: at least 5 go through, and at
  most two windows' worth. The rest get 503 with `Retry-After: 5`.
  Another customer is still served.

**Run it by hand**: `ferrosip --config sbc/ferrosip.toml` from `sbc/`.
`SIP_PORT` is 5060. `CARRIER1`/`CARRIER2` default to
`sip:127.0.0.1:5081`/`5082`. `CDR_URL` defaults to
`http://127.0.0.1:8080/cdr`.
