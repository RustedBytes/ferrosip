# m05-nat-edge (medium)

This scenario models a [registrar](../../../docs/glossary.md#registrar)
and proxy for phones behind [NAT](../../../docs/glossary.md#nat). A phone
advertises its private address: [Contact](../../../docs/glossary.md#contact)
and [Via](../../../docs/glossary.md#via) say `10.0.0.5:5060`. Its packets
come from the NAT's public address. It proves that registrations, calls
and hang-ups reach the real public address in both directions.

Everything runs on 127.0.0.1 in the test. So the "public" address is
`127.0.0.1:<port>`, and the private one is only written in the headers.

```
carol (thinks 10.0.0.5:5060) ──▶ NAT ──▶ 127.0.0.1:P ──▶ ferrosip
   REGISTER  Contact 10.0.0.5     stored as is, received = 127.0.0.1:P, NAT bflag 6
   INVITE    Contact 10.0.0.5  ─▶ nat.fix_contact()  → 127.0.0.1:P
bob ──▶ INVITE carol ──▶ lookup: R-URI sip:carol@10.0.0.5:5060, sent to 127.0.0.1:P
            200 Contact 10.0.0.5 ─▶ on reply: nat.fix_contact() → bob's ACK/BYE reach P
```

**Shows**:
- `nat.is_behind(19)` into a named `flag`. It tests for a private
  Contact, or a Via address or port that is not the source.
- `nat.fix_contact()`:
  - on [initial](../../../docs/glossary.md#initial-request) and
    [in-dialog](../../../docs/glossary.md#in-dialog-request) requests;
  - in `on reply … where nat.is_behind(1)`, on a NATed callee's answer.
- The NAT [branch flag](../../../docs/glossary.md#branch-flags) stored
  with the binding (`[modules.nat] nat_bflag`). It is set with
  `kamailio.call("setbflag", …)` before `location.save()`.
- The registrar's `use_received` (default on). Calls go to the address the
  REGISTER came from, while the [R-URI](../../../docs/glossary.md#r-uri)
  stays the registered Contact.

Why `kamailio.call`: `.fsr` has no branch flags (see the nat section of
crates/mod-routing/README.md). `setbflag` is the
[escape hatch](../../../docs/glossary.md#escape-hatch). The flag number is
a [`[feature]`](../../../docs/glossary.md#feature-switch), so the routing
and `[modules.nat] nat_bflag` are visibly the same value. `raw_kamailio`
is a pedantic lint (off by default), so no `allow` is needed.

The [REGISTER's](../../../docs/glossary.md#register) Contact is not
rewritten. The 200 must list the binding the phone sent. Otherwise the
phone thinks it is not registered and retries. The registrar keeps the
source address anyway.

**Edge cases checked** (`tests/scenarios/m05_nat_edge.py`). A local
`NatUA` advertises the private address.
- The 401 and 200 of a REGISTER from a private Via reach the real port.
  This works with `;rport`, and also without it: ferrosip always answers
  to the source port.
- The 200 lists the private Contact. The reply's Via has
  [`received`](../../../docs/glossary.md#received) and
  [`rport`](../../../docs/glossary.md#rport) (RFC 3581).
- `ul.dump`: the NATed binding has `received` = the real address and the
  NAT flag (cflags bit 6). A public phone's binding hasn't.
- Public → NATed:
  - the [INVITE](../../../docs/glossary.md#invite) reaches the real
    socket, with the private Contact as R-URI;
  - the callee's private Contact in the 200 is rewritten, so
    [ACK](../../../docs/glossary.md#ack) and
    [BYE](../../../docs/glossary.md#bye) reach it.
- NATed → public:
  - the callee sees the caller's Contact rewritten and its Via stamped
    `received=…;rport=…`;
  - the callee's BYE reaches the caller.
- NATed (no rport) → NATed: both Contacts are rewritten, and the BYE is
  delivered.
- A public caller's Contact is left alone. After unregistering, 404.

The Via checks cover `received`/`rport` on the relayed request and in
the replies (RFC 3261 §18.2.1, RFC 3581). See docs/sip.md.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this
directory. Set `SIP_PORT` (5060), `USERS_FILE`.
