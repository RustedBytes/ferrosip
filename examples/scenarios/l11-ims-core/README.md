# l11-ims-core (large)

This scenario models an [IMS](../../../docs/glossary.md#ims) core, the SIP
network design mobile operators use for voice over LTE and 5G. It runs
three ferrosip processes, a [P-CSCF](../../../docs/glossary.md#p-cscf), an
[I-CSCF](../../../docs/glossary.md#i-cscf) and an
[S-CSCF](../../../docs/glossary.md#s-cscf). They talk to an
[HSS](../../../docs/glossary.md#hss), the subscriber database, which speaks
[Diameter](../../../docs/glossary.md#diameter)
[Cx](../../../docs/glossary.md#cx) over TLS. The test uses a fake HSS. The
S-CSCF keeps its registrations and [reg-event](../../../docs/glossary.md#reg-event)
subscriptions in a database.

It proves that registration and calls cross all three nodes as the 3GPP
specifications describe, that identities can't be forged, that a silent
or missing HSS is handled, and that an S-CSCF restart loses neither
registrations nor subscriptions.

```
                          ┌──── REGISTER (+Path) ───▶ icscf ── UAR ──┐
alice ─┐                  │                          ▲  │      LIR ──┤
       ├──UDP──▶ pcscf ───┤                    orig  │  │ term       │   Cx (TLS)
bob  ◀─┘   PAI, keeps the │                          │  ▼            ▼
           registration   └─ INVITE, Route: ──────▶ scscf ── MAR, SAR ──▶ HSS
                  ▲          <sip:orig@scscf;lr>     │ lookup
                  └──── Route: bob's Path ◀──────────┘
                                                     │ impu, contact, subscriber_scscf
                                                     ▼
                                                  SQLite
```

A registration goes:
1. [UE](../../../docs/glossary.md#ue) → P-CSCF (`path.add()`, see
   [Path](../../../docs/glossary.md#path));
2. → I-CSCF ([UAR](../../../docs/glossary.md#uar): which S-CSCF?);
3. → S-CSCF ([MAR](../../../docs/glossary.md#mar) → 401; with credentials,
   [SAR](../../../docs/glossary.md#sar) → 200 with
   [Service-Route](../../../docs/glossary.md#service-route),
   [P-Associated-URI](../../../docs/glossary.md#p-associated-uri) and the Path).

A call goes:
1. UE → P-CSCF ([P-Asserted-Identity](../../../docs/glossary.md#p-asserted-identity), the Service-Route as
   [Route](../../../docs/glossary.md#route));
2. → S-CSCF, originating leg (the Route's user part is `orig`);
3. → I-CSCF ([LIR](../../../docs/glossary.md#lir): where is the callee?);
4. → S-CSCF, terminating leg (`lookup()`, which follows the callee's
   Path);
5. → the callee's P-CSCF → the callee.

**Shows**:
- **P-CSCF:**
  - `ims_registrar_pcscf.save_pending()` on the
    [REGISTER](../../../docs/glossary.md#register), and `save()` in
    `on reply(r) where r.method == REGISTER && r.code == OK`. This is the
    form crates/mod-ims/README.md shows;
  - `is_registered()` (by source address);
  - `assert_identity(msg.from.uri)`;
  - a P-Asserted-Identity set by the proxy. Any the UE sent, and
    P-Preferred-Identity, are removed;
  - `force_service_routes()`;
  - terminating requests are accepted only from the S-CSCF's address
    (`[feature] scscf_addr`), and follow the Path with
    `route_set.follow()`;
  - no Diameter (no Rx).
- **I-CSCF:**
  - `let uar = await ims_icscf.authorize()` and
    `let lir = await ims_icscf.locate()` (see
    [await](../../../docs/glossary.md#await));
  - `uar.code` mapped to replies: -2 user unknown → 403 for REGISTER, 404
    for a call; -1, the HSS not answering → 500;
  - `ims_icscf.select_scscf()`;
  - `scscf_entry` from the environment, for answers with capabilities
    only;
  - not in any route set.
- **S-CSCF:**
  - `ims_auth.www_authenticate` / `www_challenge`: SIP
    [Digest](../../../docs/glossary.md#digest-authentication) or
    [AKA](../../../docs/glossary.md#aka), as the HSS says;
  - `ims_registrar_scscf.save()`, `orig_registered()`,
    `term_registered()`, `lookup()`;
  - `route_set.record("orig")`, so
    [in-dialog requests](../../../docs/glossary.md#in-dialog-request) show
    the leg;
  - reg-event subscriptions (RFC 3680), for example a UE's subscription
    to its own registration along its Service-Route.
    `ims_registrar_scscf.can_subscribe()` checks that the subscriber's
    P-Asserted-Identity is in the watched
    [implicit set](../../../docs/glossary.md#implicit-registration-set),
    else 403. Then `ims_registrar_scscf.subscribe()`. Another `Event` gets
    489;
  - `[modules.ims_usrloc_scscf] db_mode = "write-through"` with an SQLite
    `db_url` (in `STATE_DIR`). Records, contacts and subscriptions are
    written through and loaded at startup. So a restart loses neither
    the registrations nor the subscriptions'
    [dialogs](../../../docs/glossary.md#dialog).
- `[modules.diameter]`:
  - the HSS [peer](../../../docs/glossary.md#diameter-peer) from
    `HSS_HOST` / `HSS_PORT`, with `proto=tls` (RFC 6733 §13: TLS from the
    first byte);
  - the HSS's certificate must name its FQDN, `hss.ims.test`, and be
    signed by `tls_ca_list`;
  - `tls_certificate` is the CSCF's client certificate. The files come
    from `TLS_DIR`, by default the repository's `etc/tls`, made by
    `etc/tls/gen-certs.sh`;
  - a 2s `transaction_timeout`, so a silent HSS costs 2s per request, not
    5s;
  - a 1s `tc`.

Everything is typed `.fsr`. No `kamailio.*`
[escape hatch](../../../docs/glossary.md#escape-hatch) is needed.

**Lint**: no allows. The `open_relay` [lint](../../../docs/glossary.md#lint)
counts these as each node's check:
- the I-CSCF's user authorization request (UAR);
- the P-CSCF's source-address check;
- the S-CSCF's `ims_auth`.

**Edge cases checked** (`tests/scenarios/l11_ims_core.py`):
- S-CSCF and I-CSCF connect to the HSS over TLS (`cdp.list_peers`: open,
  `tls`). The HSS gets both [CERs](../../../docs/glossary.md#cer) inside
  TLS. It verifies each CSCF's client certificate, and it requires one.
- Registration through all three:
  - 401 with SIP Digest (alice), or Digest-AKAv1-MD5 with
    nonce = base64(RAND‖AUTN) (bob);
  - the HSS sees a UAR per REGISTER, one MAR, and SAR REGISTRATION;
  - the 200 has the Service-Route `<sip:orig@scscf;lr>`, the P-CSCF's
    Path, and the implicit set in P-Associated-URI;
  - the S-CSCF resolves the `tel:` [IMPU](../../../docs/glossary.md#impu)
    to alice's record;
  - the P-CSCF keeps alice as registered, with her Service-Route and
    associated URIs.
- The core alone: a [MESSAGE](../../../docs/glossary.md#message) on
  alice's Service-Route goes S-CSCF → I-CSCF (LIR) → S-CSCF → bob's
  P-CSCF → bob, with all five [Vias](../../../docs/glossary.md#via).
- A call alice → bob through P-CSCF, S-CSCF (orig), I-CSCF, S-CSCF
  (term), P-CSCF:
  - four [Record-Routes](../../../docs/glossary.md#record-route), one of
    them `;orig`;
  - P-Asserted-Identity from the P-CSCF;
  - no Route left;
  - the [BYE](../../../docs/glossary.md#bye) goes back along the route
    set.
- Identity checks:
  - a forged P-Asserted-Identity is replaced;
  - a From that isn't one of the UE's identities → 403. One from its
    implicit set (`tel:`) → 200;
  - an unregistered UE → 403, even with a Route to the P-CSCF preloaded;
  - an originating request from an unregistered user straight to the
    S-CSCF → 403.
- Calls to a user the HSS knows but who isn't registered → 480 (S-CSCF).
  Calls to an unknown one (LIR 5001) → 404 (I-CSCF).
- HSS problems:
  - REGISTER of an unknown user (UAR 5001) → 403, and no MAR;
  - the HSS not answering the UAR → 500 after 2s, and only one UAR for
    it;
  - the HSS not answering the MAR → the S-CSCF's own 500 "MAR failed".
    That is what [Kamailio's](../../../docs/glossary.md#kamailio) ims_auth
    and its sample S-CSCF config send on an MAA timeout;
  - the HSS down → a 5xx at once.
- Re-registration → SAR RE_REGISTRATION. There is still one contact at
  the S-CSCF and at the P-CSCF, with the expiry pushed out.
- The S-CSCF's database has alice's and bob's `impu` rows, and alice's
  `contact` with the Path.
- Reg event:
  - alice subscribes to her reg event through the P-CSCF: 200, then a
    [NOTIFY](../../../docs/glossary.md#notify) through the P-CSCF with the
    full reginfo (both IMPUs of her implicit set, and her contact);
  - bob subscribing to alice's → 403;
  - `Event: presence` → 489;
  - alice re-registers → a partial NOTIFY (`refreshed`, version 1) in the
    same dialog. The subscription's row in `subscriber_scscf` has that
    version and [CSeq](../../../docs/glossary.md#cseq).
- The S-CSCF restarts:
  - it reconnects over TLS and loads the 2 records;
  - alice is registered (implicit set, Path) without a REGISTER;
  - a call alice → bob works at once (no SAR);
  - alice's next REGISTER is a SAR RE_REGISTRATION;
  - her subscription continues: a partial NOTIFY in the same dialog (same
    [tags](../../../docs/glossary.md#tag)), CSeq + 1, version 2;
  - de-registration (Expires 0) → UAR de-registration and SAR
    USER_DEREGISTRATION. The contact is gone from both. Then calls to
    bob → 480, and bob's own requests → 403.
- A P-CSCF restart: the REGISTER it sends next still reaches the S-CSCF,
  with a new Via [branch](../../../docs/glossary.md#branch-parameter).

**Not covered**:
- [IPsec](../../../docs/glossary.md#ipsec-security-association)
  (`ims_ipsec_pcscf`), [Rx](../../../docs/glossary.md#rx) (`ims_qos`),
  [Ro](../../../docs/glossary.md#ro) (`ims_charging`) and
  [iFCs](../../../docs/glossary.md#ifc) / application servers
  (`ims_isc`). tests/e2e_ims.py covers them with `.cfg` routing.
- Also not here: registration expiry (SAR TIMEOUT_DEREGISTRATION needs a
  wait), several S-CSCFs, [CANCEL](../../../docs/glossary.md#cancel)
  through the core, TCP.

**Run it by hand**:
1. Run `etc/tls/gen-certs.sh`.
2. Start an HSS on `HSS_PORT` (5658). It must speak Diameter Cx over TLS
   with `etc/tls/hss.ims.test.pem`, realm `ims.test`, host
   `hss.ims.test`.
3. Create the `impu`, `contact` and `subscriber_scscf` tables (as in
   `etc/schema/*.sql`) in `$STATE_DIR/scscf.db`.
4. Start `scscf` (`SCSCF_PORT` 5080, `ICSCF`, `STATE_DIR`), `icscf`
   (`ICSCF_PORT` 5070, `SCSCF`) and `pcscf` (`PCSCF_PORT` 5060, `ICSCF`,
   `SCSCF_ADDR`), each from its own directory.

The HSS must name `sip:127.0.0.1:5080` as Server-Name.
