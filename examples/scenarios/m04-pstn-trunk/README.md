# m04-pstn-trunk (medium)

This scenario models [PSTN](../../../docs/glossary.md#pstn) access for a
SIP domain. Users dial numbers the way people write them. The proxy
normalises them to [E.164](../../../docs/glossary.md#e164) and picks a carrier by prefix. It proves that
valid numbers reach the right trunk, invalid ones are refused, emergency
calls always work, and callers can't fake their identity.

```
                              normalise                  route
alice ─▶ ferrosip ─ auth ─▶ 030-1234-567 → +49301234567 ─▶ +49…   ─▶ trunk_de   (trusted, 127.0.0.2)
                            0044… → +44…                ─▶ other  ─▶ trunk_intl (untrusted, 127.0.0.3)
anyone ─▶ 110 / 112 (no auth) ─────────────────────────────────────▶ emergency gateway
                            116xxx, 115, 118 (short codes) ─────────▶ trunk_de
                            anything else ─▶ 484
trunk IPs ─▶ ferrosip ─▶ PBX          (other sources must authenticate: 407)
```

**Number plan** (`normalise` and `to_trunk` in `routes/main.fsr`):
- Visual separators `- . ( )` and spaces are removed (`text.subst_user`).
- `00…` → `+…` (international). `0…` → `+49…` (national,
  `features.country_code`). A `+…` number stays.
- An E.164 number must pass `sip.is_e164` and have at least 7 digits.
  `+49` alone isn't a subscriber.
- `+49…` goes to the domestic trunk. Every other country goes to the
  international trunk.
- Short codes (`1` plus 2 to 5 digits) are matched by value, with a range.
  `116000..116999` (EU harmonised services), `115` and `118` go to the
  domestic trunk as dialled. Other short codes get 484.
- `110` / `112` go to the emergency gateway before authentication.
  Emergency calls must work without an account.
- Everything else gets `484 Address Incomplete`. That covers letters,
  `0`, `00`, a long number without a prefix, and so on.

**Identity (RFC 3325)**:
- A `P-Asserted-Identity` (PAI) is only believed from a trusted trunk
  (`features.trusted_ips`). From anybody else it is removed on the way in.
  So a phone can't assert its own identity, and the emergency centre
  can't be sent a false one. `P-Preferred-Identity` is always removed.
- For an authenticated caller the proxy adds
  `P-Asserted-Identity: <sip:user@example.com>`. The From user is the
  credentials' user (auth.check's flag 1).
- With `Privacy: id` (also in a list: `header;id`) the PAI still goes to
  the trusted trunk, which withholds it from the far end. It does not go
  to the untrusted one. `Privacy: none` / `user` don't hide the PAI.

**Shows**:
- `text.subst_user` with a
  [`[feature]`](../../../docs/glossary.md#feature-switch) in the
  replacement;
- `=~` regexes (`\{7,\}` escapes the interpolation braces);
- `text.starts_with`, `sip.is_e164`, `text.search_header`;
- `match` with an integer range and `|`;
- `msg.headers[…] = …` / `.remove(…)`;
- functions with `Str` and `Bool` parameters;
- `ip.in_subnet` as the trunk ACL;
- `sip.options_reply()`.

`pv("$(rU\{s.int\})")` is the one escape to
[Kamailio](../../../docs/glossary.md#kamailio) (see
[escape hatch](../../../docs/glossary.md#escape-hatch)). `.fsr` has no
typed way to turn the [R-URI](../../../docs/glossary.md#r-uri) user into an
Int for the `match`. The `raw_kamailio` lint is pedantic (off by default),
so no `allow` is needed.

**Edge cases checked** (`tests/scenarios/m04_pstn_trunk.py`). The trunks
are fake UAs bound to 127.0.0.2 and 127.0.0.3, so the ACL can tell them
apart by source IP.
- E.164, national, international, separators and short codes. `0049…` is
  the international form of a domestic number and goes to the domestic
  trunk.
- 110 and 112 work, also without any credentials and with a spoofed PAI,
  which is removed. A normal call without credentials → 407.
- Nine invalid numbers → 484, none relayed (`+49`, `0049`, 16 digits…).
- PAI:
  - there is one, the proxy's, replacing the caller's;
  - credentials are not passed on;
  - all Privacy combinations are checked for both trunks;
  - P-Preferred-Identity is removed.
- Calls from the trunks go to the PBX without a
  [challenge](../../../docs/glossary.md#challenge). The trusted trunk's PAI
  is kept, and the untrusted one's is removed. The same call from
  127.0.0.5 is challenged. The [BYE](../../../docs/glossary.md#bye) goes
  back through the proxy.
- [OPTIONS](../../../docs/glossary.md#options) keepalives are answered.
  [MESSAGE](../../../docs/glossary.md#message) → 405.

**Run it by hand**: `ferrosip --config ferrosip.toml` from this directory.
Set `SIP_PORT`, `TRUNK_DE`, `TRUNK_INTL`, `EMERGENCY`, `PBX`, `TRUNK_IPS`,
`TRUSTED_IPS`, `USERS_FILE`.
