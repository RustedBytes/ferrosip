# mod-ims

This crate turns ferrosip into the SIP servers of an
[IMS](../../docs/glossary.md#ims) core network, the architecture mobile
operators use for VoLTE, VoWiFi and fixed-line voice. Use it when ferrosip
must work as one of the three [CSCF](../../docs/glossary.md#cscf) roles and
talk to the operator's back-end servers over
[Diameter](../../docs/glossary.md#diameter). The modules keep
[Kamailio](../../docs/glossary.md#kamailio)'s
[module](../../docs/glossary.md#module) names, function names and return
codes, so a Kamailio IMS config reads the same way here.

## The three CSCF roles

- **[P-CSCF](../../docs/glossary.md#p-cscf)**: the first hop of the
  [UE](../../docs/glossary.md#ue), the user's phone.
  - `ims_usrloc_pcscf` and `ims_registrar_pcscf` keep the UE's
    registration. They learn it from the 200 that answers its
    [REGISTER](../../docs/glossary.md#register). They check asserted
    identities and enforce
    [Service-Routes](../../docs/glossary.md#service-route).
  - `ims_qos` reserves media resources at the
    [PCRF](../../docs/glossary.md#pcrf) over the Diameter
    **[Rx](../../docs/glossary.md#rx)** interface.
  - `ims_ipsec_pcscf` negotiates the RFC 3329
    [security agreement](../../docs/glossary.md#security-client) (IPsec,
    TS 33.203). It can also install the kernel [ESP](../../docs/glossary.md#esp)
    [SAs](../../docs/glossary.md#ipsec-security-association).
- **[I-CSCF](../../docs/glossary.md#i-cscf)**: the network's entry point.
  `ims_icscf` asks the [HSS](../../docs/glossary.md#hss) over
  **[Cx](../../docs/glossary.md#cx)** which
  [S-CSCF](../../docs/glossary.md#s-cscf) serves a user. It uses
  [UAR](../../docs/glossary.md#uar) and [LIR](../../docs/glossary.md#lir)
  for this. Then it forwards the request there.
- **S-CSCF**: the [registrar](../../docs/glossary.md#registrar) and service
  node.
  - `ims_auth` challenges and authenticates users with vectors from the HSS
    (Cx [MAR](../../docs/glossary.md#mar)). It supports
    [SIP Digest](../../docs/glossary.md#digest-authentication) and
    [Digest-AKAv1-MD5](../../docs/glossary.md#aka).
  - `ims_registrar_scscf` / `ims_usrloc_scscf` register users. They send a
    Cx [SAR](../../docs/glossary.md#sar) and read the
    [implicit registration set](../../docs/glossary.md#implicit-registration-set)
    and the [initial filter criteria](../../docs/glossary.md#ifc) from the
    User-Data in the answer. They also serve RFC 3680
    [reg-event](../../docs/glossary.md#reg-event) subscriptions.
  - `ims_isc` routes requests through
    [application servers](../../docs/glossary.md#as) by iFC.
  - `ims_charging` does online charging over Diameter
    **[Ro](../../docs/glossary.md#ro)**.

## Diameter and state

Diameter comes from the `sip-diameter` crate. It provides the
[AVP](../../docs/glossary.md#diameter-avp) and message codec, and peers
over TCP, TLS or SCTP. It handles [CER](../../docs/glossary.md#cer)/CEA and
[DWR](../../docs/glossary.md#dwr)/DWA, reconnects, incoming peers and
[realm](../../docs/glossary.md#diameter-realm) routing tables.

The `cdp` module owns the peer manager. The other Diameter modules load
after it. With [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) this
happens by itself. In a [`.cfg`](../../docs/glossary.md#cfg) with
`loadmodule`, put `cdp` first.

S-CSCF registrations can be kept in a database (`ims_usrloc_scscf`
`db_mode`). The rest of the state is in memory.

## Asynchronous Diameter requests

The Cx exchanges are asynchronous, as in Kamailio. These requests
[suspend](../../docs/glossary.md#suspend-and-resume) the
[transaction](../../docs/glossary.md#transaction):

- UAR and LIR (the I-CSCF requests);
- MAR (`ims_www_challenge` / `ims_proxy_challenge`);
- SAR (`save`).

The transaction stays suspended until the HSS answers or the cdp
transaction timeout runs out. Meanwhile [tm](../../docs/glossary.md#tm)
absorbs the request's
[retransmissions](../../docs/glossary.md#retransmission), and the
[worker](../../docs/glossary.md#worker) goes on with other messages. Then:

- In a `.cfg`, the script continues in the
  [reply route](../../docs/glossary.md#reply-route) named in the call
  (`I_perform_user_authorization_request("REG_UAR_REPLY", "0")`) when the
  script has that route. Otherwise it continues right after the call.
- MAR and SAR send their reply themselves: 401/407, 200, or an error. They
  set `$avp(maa_return_code)` / `$avp(saa_return_code)` to one of:
  - 1;
  - -1;
  - -2 (Kamailio's `CSCF_RETURN_ERROR`), when the HSS didn't answer in
    time. For SAR, also when the request couldn't be sent.

  On an MAA timeout, the S-CSCF answers 500 "MAR failed". Kamailio's
  ims_auth leaves that reply to the script, and its sample S-CSCF config
  sends exactly this. An MAR that can't be sent gets 480. A SAR that can't
  be sent or times out gets 500 "SAR failed", as in Kamailio's
  ims_registrar_scscf.

  Timeouts are counted in `ims_auth:mar_timeouts`,
  `ims_registrar_scscf:sar_timeouts` and `ims_icscf:uar_timeouts` /
  `lir_timeouts` (Kamailio's names). UAR and LIR set
  `$avp(uaa_return_code)` / `$avp(lia_return_code)`.
- In [`.fsr`](../../docs/glossary.md#fsr) the route argument is left out.
  You write `let r = await ims_icscf.authorize()` and then read `r.code`.
  `ims_auth.www_challenge` and `ims_registrar_scscf.save` are actions.

In a [failure route](../../docs/glossary.md#failure-route), a transaction
can't be suspended. There these requests run synchronously.

Rx (`Rx_AAR`) and Ro CCR-Initial (`Ro_CCR`) suspend the transaction too,
when the script waits for them:

- In `.fsr`, with [`await`](../../docs/glossary.md#await):
  `let r = await ims_qos.authorize_media("orig")`, then `r.code`.
- In a `.cfg`, when the script has the reply route named in the call. That
  route reads `$avp(aar_return_code)` / `$avp(cca_return_code)` (1 granted,
  -1 not).

A `.cfg` without that route uses them as checks
(`if (!Rx_AAR("RX_REPLY", "orig")) …`). So they stay synchronous there,
bounded by the cdp timeout. Calls from a reply route are synchronous too.

## Configuration

Module parameters go in `ferrosip.toml` (`[modules.diameter]`,
`[modules.ims_auth]`…). `ferrosip schema <module>` lists them. The examples
below use `.fsr`. The `.fsr` names are in
[docs/functions-reference.md](../../docs/functions-reference.md).

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `diameter` | `cdp` | Diameter peer manager |
| `diameter` | `cdp_avp` | Placeholder for configs (the codec is in `sip-diameter`) |
| `ims_auth` | `ims_auth` | S-CSCF authentication (Cx MAR) |
| `ims_usrloc_scscf` | `ims_usrloc_scscf` | S-CSCF [IMPU](../../docs/glossary.md#impu) records |
| `ims_registrar_scscf` | `ims_registrar_scscf` | S-CSCF registrar (Cx SAR), lookup, reg event |
| `ims_isc` | `ims_isc` | iFC evaluation, routing to application servers |
| `ims_icscf` | `ims_icscf` | I-CSCF: UAR/LIR, S-CSCF selection |
| `ims_usrloc_pcscf` | `ims_usrloc_pcscf` | P-CSCF UE contacts |
| `ims_registrar_pcscf` | `ims_registrar_pcscf` | P-CSCF registration, identity and Service-Route checks |
| `ims_qos` | `ims_qos` | Rx towards the PCRF |
| `ims_charging` | `ims_charging` | Ro online charging |
| `ims_ipsec_pcscf` | `ims_ipsec_pcscf` | IPsec security agreement at the P-CSCF |
| `ims_diameter_server` | `ims_diameter_server` | Diameter requests that the script answers (`event_route[diameter:request]`) and sends (`diameter_request`, `diameter_request_async`) |

## diameter (cdp)

The Diameter node. You configure it in one of two ways: with Kamailio's
DiameterPeer XML file (`config_file`), or with ferrosip parameters. Peers
are connected at startup and reconnected every `tc` seconds, over TCP, TLS
or SCTP.

Requests are routed as cdp does. The node tries these in order:

1. The Destination-Host peer, when it is open.
2. The destination realm's route table (`<Realm name><Route FQDN metric/></Realm>`,
   `realm_route`), lowest metric first, skipping peers that are not open.
3. For a realm without a table, a peer of that realm.
4. The default routes (`<DefaultRoute>`, `default_route`), lowest metric
   first.
5. The first open peer.

**Transports.**

- `proto="tls"` on a `<Peer>` / `<Acceptor>` runs Diameter over TLS from
  the first byte (RFC 6733 §13; default port 5658). In the parameters this
  is `proto=tls` in `peer` and `tls:` in `listen`.
  - Outgoing, the peer's certificate is verified against `ca_list`, with
    the peer's FQDN as the name. Our certificate is presented as client
    certificate when one is set.
  - Incoming, the acceptor presents `certificate`. With
    `require_certificate`, it requires a client certificate signed by
    `ca_list`.
  - The certificates are loaded like SIP TLS's: PEM files, rustls with
    ring.
- `proto="sctp"` uses a one-to-one SCTP socket (`SOCK_STREAM`,
  `IPPROTO_SCTP`). It needs the kernel's SCTP support (`modprobe sctp`).
  Without it, the connection or the acceptor fails with "SCTP is not
  supported by this kernel".

```xml
<DiameterPeer FQDN="scscf.ims.test" Realm="ims.test">
  <Peer FQDN="hss1.ims.test" Realm="ims.test" port="5658" proto="tls"/>
  <Peer FQDN="hss2.ims.test" Realm="ims.test" proto="sctp"/>
  <Acceptor port="5658" bind="0.0.0.0" proto="tls"/>
  <TLS certificate="/etc/ferrosip/scscf.pem" private_key="/etc/ferrosip/scscf.key"
       ca_list="/etc/ferrosip/ca.pem" require_certificate="1"/>
  <Realm name="ims.test">
    <Route FQDN="hss1.ims.test" metric="10"/>
    <Route FQDN="hss2.ims.test" metric="20"/>
  </Realm>
  <DefaultRoute FQDN="hss1.ims.test" metric="10"/>
</DiameterPeer>
```

**Parameters**

| Name | Default | Description |
|---|---|---|
| `config_file` | none | Kamailio cdp XML config (replaces the parameters below) |
| `identity` | `ferrosip.localdomain` | Origin-Host |
| `realm` | `localdomain` | Origin-Realm, and the default destination realm of the other modules |
| `peer` | none | `fqdn=...;realm=...;host=...;port=...;proto=tcp\|tls\|sctp` (repeatable). Port 3868, or 5658 for TLS. host = fqdn by default |
| `listen` | none | `[tls:\|sctp:]ip:port` to accept incoming peers (repeatable) |
| `auth_app` | Cx, Rx ([3GPP](../../docs/glossary.md#3gpp)) and CC (4) | `vendor:app` advertised in CER (repeatable) |
| `default_route` | none | `fqdn[;metric=N]`: peer for realms without a route table (repeatable) |
| `realm_route` | none | `realm=...;fqdn=...[;metric=N]`: a route of a realm's table (repeatable) |
| `tls_certificate` | none | Our certificate (PEM), for TLS acceptors and as client certificate towards TLS peers |
| `tls_private_key` | none | Its private key (PEM) |
| `tls_ca_list` | none | CAs (PEM) that verify TLS peers (required when there is one), and clients with `tls_require_certificate` |
| `tls_require_certificate` | false | TLS acceptors require a verified client certificate |
| `transaction_timeout` | 5 | Seconds to wait for an answer |
| `tc` | 30 | Reconnect interval (s) |

`workers`, `debug` and `latency_threshold` are accepted and ignored.

**[RPC](../../docs/glossary.md#rpc) commands**

| Command | Description |
|---|---|
| `cdp.list_peers` | FQDN, Realm, State, Origin-Host and Proto of each peer |

**Example**

```toml
[modules.diameter]
identity = "scscf.ims.test"
realm = "ims.test"
peer = ["fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port=3868",
        "fqdn=hss2.ims.test;realm=ims.test;host=10.0.0.2;port=5658;proto=tls"]
listen = ["tls:0.0.0.0:5658"]
realm_route = ["realm=ims.test;fqdn=hss.ims.test;metric=10", "realm=ims.test;fqdn=hss2.ims.test;metric=20"]
tls_certificate = "/etc/ferrosip/scscf.pem"
tls_private_key = "/etc/ferrosip/scscf.key"
tls_ca_list = "/etc/ferrosip/ca.pem"
```

**Differences from Kamailio**:

- TLS is TLS from the start of the connection (RFC 6733 §13). It is not the
  RFC 3588 in-band upgrade after a CER with Inband-Security-Id.
- The TLS files go in a `<TLS>` element, a ferrosip addition to the XML.
- SCTP uses one stream and payload protocol id 0, and no multi-homing.
- A peer's supported applications are not considered when routing.

`cdp_avp` takes any parameter and does nothing. It is not needed with
`ferrosip.toml`.

## ims_auth

S-CSCF authentication. A [challenge](../../docs/glossary.md#challenge)
sends a Cx MAR for one vector and answers 401/407 itself. There are two
schemes:

- SIP Digest: the [HA1](../../docs/glossary.md#ha1) comes from the HSS,
  the [nonce](../../docs/glossary.md#nonce) is random, and the challenge
  has `algorithm=MD5`.
- Digest-AKAv1-MD5: nonce = base64(RAND || AUTN), and XRES is the password.
  `ck`/`ik` are added to the challenge for the P-CSCF.

Each vector can be used once.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `name` (alias `scscf_name`) | empty | Server-Name sent to the HSS |
| `cxdx_dest_realm` | cdp `realm` | Destination-Realm of Cx requests |
| `cxdx_forced_peer` (alias `cxdx_dest_host`) | none | Send Cx requests to this peer |
| `registration_default_algorithm` | `AKAv1-MD5` | Scheme when the challenge names none (anything else = SIP Digest) |
| `registration_qop` | empty (no qop) | [`qop`](../../docs/glossary.md#qop) offered in the challenge |
| `auth_vector_timeout` | 60 | Seconds a vector stays valid |

These are accepted and ignored: `auth_data_hash_size`,
`auth_used_vector_timeout`, `auth_data_timeout`, `max_nonce_reuse`,
`add_authinfo_hdr`, `av_request_at_once`, `av_request_at_sync`, `av_mode`,
`invite_qop`, `ignore_failed_auth` and `av_check_only_impu`.

**Functions**

| Signature | Description |
|---|---|
| `ims_www_challenge(route, realm[, algorithm])` | MAR, then 401 with WWW-Authenticate. 1 when sent. -1 when an error reply was already sent: 400 (no identities), 480 (MAR not sent: no peer) or 403 (HSS refused / bad vector). -2 with 500 "MAR failed" sent when the HSS doesn't answer in time |
| `ims_proxy_challenge(route, realm[, algorithm])` | Same with 407 / Proxy-Authenticate |
| `ims_www_authenticate(realm)` | Check Authorization against the stored vector. 1 ok. -2 wrong response. -3 unknown or expired nonce. -4 no credentials for the [realm](../../docs/glossary.md#realm). -5 incomplete credentials. -1 other errors |
| `ims_proxy_authenticate(realm)` | Same with Proxy-Authorization |

The [IMPI](../../docs/glossary.md#impi) is the credentials' `username`.
By default it is the IMPU without `sip:`. The IMPU is the To URI for
REGISTER, and the From URI otherwise.

In `.fsr`:

- `ims_auth.www_challenge(realm[, algorithm])` and `proxy_challenge` are
  actions: they answer, and the route ends.
- `www_authenticate(realm)` and `proxy_authenticate` are checks.

**Example**: an S-CSCF registrar.

```toml
[modules.diameter]
identity = "scscf.ims.test"
realm = "ims.test"
peer = ["fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1;port=3868"]

[modules.ims_auth]
name = "sip:scscf.ims.test:5060"

[modules.ims_registrar_scscf]
name = "sip:scscf.ims.test:5060"
```

```rust
import ims_auth, ims_registrar_scscf

route main(msg: Request) {
    if msg.method == REGISTER {
        guard ims_auth.www_authenticate("ims.test") else ims_auth.www_challenge("ims.test")
        ims_registrar_scscf.save()
    }
    guard ims_registrar_scscf.lookup() else reply(NotFound, "Not Found")
    relay(msg)
}
```

The Kamailio form is `ims_www_challenge("REG_MAR_REPLY", "ims.test")`
then `save("REG_SAR_REPLY", "location")`.

## ims_usrloc_scscf

The S-CSCF's store of IMPU records. A record holds:

- the registered [contacts](../../docs/glossary.md#contact), with
  [Path](../../docs/glossary.md#path), received address,
  [Call-ID](../../docs/glossary.md#call-id) and
  [CSeq](../../docs/glossary.md#cseq);
- the IMPI;
- the registration state;
- the subscription: the implicit registration set and iFCs, from the HSS's
  User-Data.

Every IMPU of the implicit set resolves to the same record.

**Database storage.** With `db_mode` > 0, every change is written through
to the database at `db_url`. It takes the same URLs as usrloc:
`text:///dir`, `sqlite:///file`, `mysql://…`, `postgres://…`. The records
are loaded at startup. So registrations survive a restart, with their
contacts, Paths and iFCs, and the next REGISTER is a re-registration.
Records whose contacts expired meanwhile are dropped when loaded.

The reg-event subscriptions of `ims_registrar_scscf` are stored too. After
a restart, their [NOTIFYs](../../docs/glossary.md#notify) continue in the
same [dialog](../../docs/glossary.md#dialog) with the next CSeq and
version. This matches Kamailio's `subscriber_scscf`, which its
`preload_udomain()` reads back. There are three tables (in
`etc/schema/*.sql`):

| Table | Columns |
|---|---|
| `impu` | `impu` (the record's IMPU), `impi`, `reg_state` (1 registered), `ims_subscription_data` (the User-Data XML) |
| `contact` | `impu`, `contact`, `received` (a SIP URI), `path`, `expires` (Unix seconds), `callid`, `cseq` |
| `subscriber_scscf` | Kamailio's columns: `watcher_uri` (the [SUBSCRIBE](../../docs/glossary.md#subscribe)'s From URI), `watcher_contact` (its Contact, where NOTIFYs go), `presentity_uri` (the IMPU watched), `event` (1, reg), `expires` (Unix seconds), `version` (of the last reginfo document), `local_cseq` (of the last NOTIFY), `call_id`, `from_tag` (the watcher's [tag](../../docs/glossary.md#tag)), `to_tag` (ours), `record_route` (comma-separated), `sockinfo_str` (the SUBSCRIBE's source as a SIP URI, where the NOTIFYs are sent) |

For `text://`, the files start with these header lines:

```
impu(string) impi(string) reg_state(int) ims_subscription_data(string,null)
impu(string) contact(string) received(string) path(string,null) expires(int) callid(string) cseq(int)
watcher_uri(string) watcher_contact(string) presentity_uri(string) event(int) expires(int) version(int) local_cseq(int) call_id(string) from_tag(string) to_tag(string) record_route(string,null) sockinfo_str(string,null)
```

A subscription's row is written when the subscription is accepted or
refreshed. It is also written before each NOTIFY, with the new CSeq and
version. It is deleted when the subscription is ended (`Expires: 0`) or
found expired. Expired rows are dropped at startup.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_mode` | 0 (`off`) | 0: memory only. 1 (`write-through`), 2, 3: written through, loaded at startup |
| `db_url` | Kamailio's default | Database for `db_mode` |

The other Kamailio parameters (hash sizes, timers, …) are accepted and
ignored.

**Differences from Kamailio**:

- The schema is simpler. Kamailio's `impu_contact` join table is folded
  into `contact.impu`. Its `impu_subscriber` join is folded into
  `subscriber_scscf.presentity_uri`.
- A subscription's row is replaced by its dialog (Call-ID and the
  watcher's tag). Kamailio's insert-update relies on a unique (event,
  watcher_contact, presentity_uri) key instead.
- `sockinfo_str` holds the watcher's address rather than our socket.
- Every `db_mode` but 0 writes through. There is no write-back timer and
  no database-only mode.
- `expires` holds Unix seconds.

**RPC commands**

| Command | Description |
|---|---|
| `ulscscf.showimpu <impu>` | One record: state, public identities, iFC count, contacts |
| `ulscscf.status` | All records |

## ims_registrar_scscf

The S-CSCF registrar. Load `cdp` and `ims_usrloc_scscf` first, and `tm`
for reg-event NOTIFYs.

**Registration.** `save()` sends a SAR (REGISTRATION, RE_REGISTRATION or
USER_DEREGISTRATION). It parses the User-Data subscription and answers the
REGISTER itself. The answer is a 200 with:

- the Contacts;
- `Service-Route: <sip:orig@<our address>;lr>`;
- [P-Associated-URI](../../docs/glossary.md#p-associated-uri) (the implicit set);
- the Path.

When a record's last contact expires, a SAR TIMEOUT_DEREGISTRATION is
sent.

**Reg event.** Reg-event subscribers (RFC 3680) first get a full
`application/reginfo+xml` document. It comes in the NOTIFY that answers
their SUBSCRIBE, and again on each refresh. After that they get partial
documents (`state="partial"`) on registration, re-registration,
de-registration and expiry. A partial document lists only the contacts
that changed. Each comes with its event (`registered`, `refreshed`,
`shortened`, `unregistered`, `expired`) and the registration's state. The
`version` counts up across the whole subscription, refreshes included.
Element ids stay the same from one document to the next.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `name` (alias `scscf_name`) | empty | Server-Name in SAR |
| `cxdx_dest_realm` | cdp `realm` | Destination-Realm of Cx requests |
| `cxdx_forced_peer` (alias `cxdx_dest_host`) | none | Send Cx requests to this peer |
| `default_expires` | 3600 | Expiry when the REGISTER gives none |
| `min_expires` | 10 | Lower bound |
| `max_expires` | 3600 | Upper bound |

These are accepted and ignored: `user_data_dtd`, `user_data_xsd`,
`support_wildcardPSI`, `store_profile_dereg`,
`subscription_default_expires`, `notification_list_size_threshold`,
`append_branches`, `method_filtering`, `ue_unsubscribe_on_dereg` and
`contact_expires_buffer`.

**Functions** (the arguments are `[route,] "location"`; 1 = true/ok, -1 = false/error)

| Signature | Description |
|---|---|
| `save([route,] "location")` | SAR and the reply (see above). -2 with 500 "SAR failed" sent when the HSS refuses (any result but success), or when the SAR couldn't be sent or got no answer in time, as in Kamailio. `.fsr`: `ims_registrar_scscf.save()` |
| `lookup("location")` | Maps the [R-URI](../../docs/glossary.md#r-uri) IMPU to its contacts. The one with the latest expiry becomes the R-URI, the others become [branches](../../docs/glossary.md#branch). Path is honored |
| `impu_registered("location")` | The originating user ([P-Asserted-Identity](../../docs/glossary.md#p-asserted-identity), else From) is registered |
| `term_impu_registered("location")` | The R-URI IMPU is registered |
| `subscribe_to_reg("location")` | Answer a SUBSCRIBE for `Event: reg` (489 for other events) and send the first NOTIFY |
| `can_subscribe_to_reg("location")` | The subscriber (P-Asserted-Identity, else From) is in the target's implicit set |

**Example**

```rust
import ims_registrar_scscf

route main(msg: Request) {
    if msg.method == SUBSCRIBE {
        guard ims_registrar_scscf.can_subscribe() else reply(Forbidden, "Forbidden")
        ims_registrar_scscf.subscribe()
    }
    if ims_registrar_scscf.lookup() {
        relay(msg)
    }
}
```

## ims_isc

The [ISC](../../docs/glossary.md#isc) interface: it sends requests through
the application servers the user subscribes to. Load `ims_usrloc_scscf`
first.

The iFCs from the user's subscription are evaluated in priority order.
Their [trigger points](../../docs/glossary.md#trigger-point) can test:

- the [method](../../docs/glossary.md#method);
- the Request-URI;
- a SIP header (name and content regex);
- the session case;
- an [SDP](../../docs/glossary.md#sdp) line.

Trigger points combine in CNF or DNF, with negation. The first matching iFC
gets the request, with `Route: <AS;lr>, <sip:us;lr;s=N;d=direction>` and
`$du` = the AS (the
[destination URI](../../docs/glossary.md#destination-uri)). When the
request comes back with that [Route](../../docs/glossary.md#route),
evaluation continues after iFC N. Any parameter is accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `isc_match_filter(direction[, "location"])` | `orig` (served user = P-Asserted-Identity or From) or `term` (R-URI). 1 when routed to an AS (then `t_relay()`), -1 when no (further) iFC matches |
| `isc_from_as(direction)` | 1 when the request returns from an AS for that direction |

**Example**

```rust
import ims_registrar_scscf, ims_isc

// in a route
if ims_registrar_scscf.orig_registered() && ims_isc.match_filter("orig") {
    relay(msg)
}
```

**Differences from Kamailio**: the iFC DefaultHandling is parsed but not
applied. DefaultHandling says whether the session continues or ends when
the AS does not answer.

## ims_icscf

The I-CSCF sends Cx UAR/LIR to the HSS and selects the S-CSCF. The
candidate list is the Server-Name from the answer. Without one, it is the
`scscf_entry` URIs that hold every mandatory capability, ordered by how
many optional capabilities they match.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `cxdx_dest_realm` | cdp `realm` | Destination-Realm |
| `cxdx_forced_peer` (alias `cxdx_dest_host`) | none | Send Cx requests to this peer |
| `scscf_entry` | none | `uri` or `uri;caps=1,2` (repeatable) |

These are accepted and ignored: `db_url`, `route_lir_user_unknown`,
`route_uar_user_unknown`, `scscf_entry_expiry`, `use_preferred_scscf_uri`
and `preferred_scscf_uri`.

**Functions**

| Signature | Description |
|---|---|
| `I_perform_user_authorization_request(route, capabilities)` | UAR for a REGISTER: registration, de-registration when it expires 0, or registration-and-capabilities when `capabilities` is "1". Sets `$avp(uaa_return_code)`. 1 ok, -2 user unknown, -3 identities don't match, -4 roaming not allowed, -1 error |
| `I_perform_location_information_request(route, orig)` | LIR for the R-URI (or for the P-Asserted-Identity / From when `orig` is "1"). Sets `$avp(lia_return_code)`. 1 ok (also for unregistered service), -2 user unknown, -3 not registered, -1 error |
| `I_scscf_select(initial)` | `$du` = the next candidate. 1, or -1 when none is left |
| `I_scscf_drop()` | Drop the candidate list. Returns 1 |

In `.fsr`:
- `let r = await ims_icscf.authorize([capabilities: true])` is the UAR.
  `r.code` is the return code above.
- `let r = await ims_icscf.locate([originating: true])` is the LIR.
- `ims_icscf.select_scscf()` and `ims_icscf.drop_scscfs()`.

**Example**

```toml
[modules.ims_icscf]
scscf_entry = ["sip:scscf.ims.test:5060;caps=1,2"]
```

```rust
import ims_icscf

route main(msg: Request) {
    if msg.method == REGISTER {
        let uar = await ims_icscf.authorize()
        guard uar.code == 1 else reply(Forbidden, "UAR {uar.code}")
        guard ims_icscf.select_scscf() else reply(ServerInternalError, "No S-CSCF")
        relay(msg)
    }
    let lir = await ims_icscf.locate()
    guard lir.code == 1 else reply(NotFound, "LIR {lir.code}")
    guard ims_icscf.select_scscf() else reply(ServerInternalError, "No S-CSCF")
    relay(msg)
}
```

**Differences from Kamailio**: no `s_cscf` database tables. Use
`scscf_entry` instead.

## ims_usrloc_pcscf

The P-CSCF's in-memory store of UE contacts. Each entry holds the
[AoR](../../docs/glossary.md#aor), contact, received address, expiry,
Service-Route, associated URIs and a pending/registered state. Expired
entries are removed every 5 s. Any parameter is accepted and ignored.

**RPC commands**

| Command | Description |
|---|---|
| `ulpcscf.showcontacts` | All UE contacts |

## ims_registrar_pcscf

The P-CSCF's registration handling. Load `ims_usrloc_pcscf` first. Any
parameter is accepted and ignored. The UE of a request is found by its
source address.

**Functions** (1 = true/ok, -1 = false/error)

| Signature | Description |
|---|---|
| `pcscf_save_pending("location")` | On the UE's REGISTER: remember its contacts and source address (pending for 120 s) |
| `save("location")` | In the [onreply_route](../../docs/glossary.md#onreply-route) of the 200: store expiry, Service-Route and P-Associated-URI. Contacts with expires 0, or no longer listed, are removed |
| `pcscf_is_registered("location")` | The request comes from a registered UE |
| `pcscf_assert_identity("location", identity)` | `identity` is one of the UE's associated URIs |
| `pcscf_follows_service_routes("location")` | The request's Route set (minus our own) equals the stored Service-Route |
| `pcscf_force_service_routes("location")` | Replace the Route headers with the Service-Route and set `$du` to its first hop |

**Example**. The `.cfg` version arms an `onreply_route` with `t_on_reply`.
Here `on reply` picks the replies to REGISTERs.

```rust
import ims_registrar_pcscf, ims_ipsec_pcscf, path

route main(msg: Request) {
    if msg.method == REGISTER {
        ims_registrar_pcscf.save_pending()
        path.add()
        txn.relay(to: "udp:10.0.0.2:5060")
    }
    guard ims_registrar_pcscf.is_registered() else reply(Forbidden, "Not registered")
    guard ims_registrar_pcscf.assert_identity(msg.from.uri) else reply(Forbidden, "Bad identity")
    ims_registrar_pcscf.force_service_routes()
    relay(msg)
}

on reply(r: Reply) where r.method == REGISTER {
    if r.code == Unauthorized {
        ims_ipsec_pcscf.create()
    }
    if r.code == OK {
        ims_registrar_pcscf.save()
    }
}
```

**Differences from Kamailio**: the P-CSCF does not subscribe to reg
events itself.

## ims_qos

The Rx interface towards the PCRF. It asks the network to reserve media
resources for a call.

An [AAR](../../docs/glossary.md#aar) carries one
Media-Component-Description per SDP `m=` line. The flow descriptions come
from the `c=` address and port. Further calls for the same Call-ID reuse
the Rx session. With `dialog` loaded, the session is closed with an
[STR](../../docs/glossary.md#str) when the call ends. An
[Abort-Session-Request](../../docs/glossary.md#asr) from the PCRF ends the call.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `rx_dest_realm` | cdp `realm` | Destination-Realm |

These are accepted and ignored: `af_signaling_ip`, `af_signaling_ip6`,
`rx_forced_peer`, `rx_auth_expiry`, `cdp_event_latency`,
`authorize_video_flow`, `include_rtcp_fd`,
`terminate_dialog_on_rx_failure`, `delete_contact_on_rx_failure`,
`regex_sdp_ip_prefix_to_maintain_in_fd`, `early_qosrelease_reason`,
`confirmed_qosrelease_headers`, `trust_bottom_via`, `recv_mode` and
`dialog_direction`.

**Functions**

| Signature | Description |
|---|---|
| `Rx_AAR(route, direction[, subscription_id[, subscription_id_type]])` | Send the AAR. Subscription-Id defaults to the From URI, type 2. With an existing `route`, the transaction is suspended, and `route[route]` runs on the AAA with `$avp(aar_return_code)`. Otherwise it waits: 1 on DIAMETER_SUCCESS. -1 if there is no SDP media, the PCRF refuses, or there is no answer |
| `Rx_STR()` | Close the Rx session of this Call-ID. 1 if there was one |

In `.fsr`:

- `await ims_qos.authorize_media("orig"|"term"[, subscription_id[, type]])`
  returns an `AarResult`: `code` 1 granted, -1 not.
- `ims_qos.terminate_session()`.

**Example**

```rust
import dialog, ims_qos

route main(msg: Request) {
    if msg.method == INVITE {
        dialog.manage()
        let qos = await ims_qos.authorize_media("orig")
        guard qos.code == 1 else reply(ServiceUnavailable, "QoS refused")
    }
    relay(msg)
}
```

**Differences from Kamailio**: no Rx registration sessions (signalling
path status). The `direction` argument is not used.

## ims_charging

Online charging over Ro (Diameter Credit-Control, RFC 4006 / TS 32.299).
It checks that the caller has credit before a call and during it. It
works on calls tracked by `dialog`: load it first and call `dlg_manage()`.

- `Ro_CCR` sends a [CCR-Initial](../../docs/glossary.md#ccr) for the
  requested seconds.
- While the call is answered, a CCR-Update reports the used time. It asks
  for `interim_update_credits` more just before the grant runs out. A
  refusal ends the call with [BYEs](../../docs/glossary.md#bye) to both
  sides.
- CCR-Termination reports the final usage when the call ends. When it gets
  no answer, the usage is not reported. That is logged and counted in the
  `ims_charging:ccr_t_failed` [statistic](../../docs/glossary.md#statistics).

**Parameters**

| Name | Default | Description |
|---|---|---|
| `destination_realm` | cdp `realm` | Destination-Realm |
| `service_context_id_root` | `32260@3gpp.org` | Service-Context-Id |
| `interim_update_credits` | 30 | Seconds requested per CCR-Update |

These are accepted and ignored: `origin_host`, `origin_realm`,
`destination_host`, the other `service_context_id_*` parameters, the
voice/video service and rating group parameters, `timer_buffer`,
`ro_forced_peer`, `ro_auth_expiry`, `cdp_event_latency`,
`single_ro_session_per_dialog`, `strip_plus_from_e164`,
`use_pani_from_term_invite`, `node_func`, `custom_user_avp`,
`app_provided_party_avp`, `vendor_specific_chargeinfo`,
`vendor_specific_id`, `db_url` and `db_mode`.

**Functions**

| Signature | Description |
|---|---|
| `Ro_CCR(route, direction, reservation_units[, incoming_trunk_id, outgoing_trunk_id])` | CCR-Initial for the subscriber. For `term` that is the R-URI. Otherwise it is the P-Asserted-Identity, else From. With an existing `route`, the transaction is suspended, and `route[route]` runs on the CCA with `$avp(cca_return_code)`. Otherwise it waits: 1 when granted (then `t_relay()`), -1 when refused or no answer |

**RPC commands**

| Command | Description |
|---|---|
| `ro.sessions` | callid, session_id, granted, answered, requests |

In `.fsr`:
`await ims_charging.reserve("orig"|"term", units[, incoming_trunk[, outgoing_trunk]])`
returns a `CcaResult`: `code` 1 granted, -1 not.

**Example**

```rust
import dialog, ims_charging

route main(msg: Request) {
    if msg.method == INVITE {
        let credit = await ims_charging.reserve("orig", 30)
        guard credit.code == 1 else reply(PaymentRequired, "Payment Required")
        dialog.manage()
    }
    relay(msg)
}
```

**Differences from Kamailio**: time-based units only. The trunk IDs are
not sent. No database.

## ims_ipsec_pcscf

RFC 3329 security agreement at the P-CSCF (TS 33.203). It protects the
SIP traffic between the UE and the P-CSCF with IPsec. Load `tm` first.

`ipsec_create` runs in the onreply route of the 401 to a REGISTER. It:

1. reads the UE's Security-Client from the request;
2. allocates our [SPIs](../../docs/glossary.md#spi);
3. keeps the association with the CK/IK from the challenge;
4. adds Security-Server to the 401;
5. strips `ck`/`ik` from WWW-Authenticate.

With `ipsec_kernel` 1, the four ESP transport-mode SAs and their policies
are installed with `ip xfrm`. IK maps to hmac-sha1-96 / hmac-md5-96. CK
maps to aes-cbc / des-ede3-cbc / null. `ipsec_destroy` removes them.
Kernel support is probed at startup. Without it, only the negotiation
runs.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `ipsec_client_port` | 5062 | Our protected client port |
| `ipsec_server_port` | 5063 | Our protected server port |
| `ipsec_spi_id_start` | 100 | First SPI to allocate |
| `ipsec_listen_addr` | advertised UDP address | Our IP for the SAs |
| `ipsec_kernel` | 0 | 1 = install the SAs in the kernel (needs CAP_NET_ADMIN and iproute2) |

These are accepted and ignored: `ipsec_listen_addr6`,
`ipsec_max_connections`, `ipsec_spi_id_range`, `ipsec_preferred_alg`,
`ipsec_preferred_ealg`, `ipsec_reuse_server_port` and
`ipsec_listen_name`.

**Functions** (argument `"location"[, flags]`; 1 = ok, -1 = error)

| Signature | Description |
|---|---|
| `ipsec_create("location")` | In the 401's onreply route: set up the association (see above) |
| `ipsec_forward("location")` | Send the request to the UE's protected server port (`port-s`). The UE is found by IP and port: its REGISTER's source, or one of its protected ports. False, with the destination unchanged, for a UE without an association |
| `ipsec_destroy("location")` | Remove the UE's association (and its kernel SAs) |

**RPC commands**

| Command | Description |
|---|---|
| `ipsec.list` | Associations (no keys): UE address (`ue`, `ue_port`), ports, SPIs, algorithms, `keys`, `kernel` (installed / not installed / unavailable / off) |

**Example**: see `ims_registrar_pcscf` above.

**Differences from Kamailio**: IPsec only. There is no TLS between UE and
P-CSCF. `ipsec_listen_addr6` is ignored.

## ims_diameter_server

This module lets the script answer and send Diameter requests itself. Use
it for [Sh](../../docs/glossary.md#sh) and any other application the IMS
modules don't handle.

- **Incoming requests** that no IMS module takes run
  `event_route[diameter:request]`, an
  [event route](../../docs/glossary.md#event-route). That means any
  application and command except those the `ims_*` modules answer.
  - The route runs on a thread of its own, so the script may send Diameter
    requests itself.
  - The route reads `$diameter_command`, `$diameter_application` and
    `$diameter_request` (the request's AVPs as JSON). It sets
    `$diameter_response` (AVPs as JSON).
  - The answer carries the request's Session-Id first, then the script's
    AVPs.
  - When the script sets no `$diameter_response`, or sets JSON that does
    not parse, the request is not answered, as in Kamailio
    (`callback_cdp_request()`).
- **`diameter_request([peer,] appid, commandcode, message)`** sends a
  request built from `message` and waits for the answer.
  - `message` is AVPs as JSON. A Session-Id is added first when missing.
  - The wait lasts up to the cdp transaction timeout.
  - `peer` names the Destination-Host peer. Without it (Kamailio's
    three-argument form), or with `""`, the request is routed through the
    cdp route tables by its Destination-Realm AVP. That defaults to the
    peer's realm, then ours.
  - Returns 1 with the answer's AVPs in `$diameter_response`. Returns -1
    when there is no answer or `message` does not parse.
- **`diameter_request_async([peer,] appid, commandcode, message)`** sends
  the request and returns 0, which ends the route (Kamailio's return
  code). The answer runs `event_route[diameter:response]` with its AVPs in
  `$diameter_response`. It returns -1 without that event route, or when
  `message` does not parse. With no answer (timeout, no peer), the route
  does not run.
- **In `.fsr`** the two event routes are typed
  [handlers](../../docs/glossary.md#event-handler)
  ([docs/fsr.md](../../docs/fsr.md)):
  - `on diameter.request(req: DiameterRequest)` with `req.command`,
    `req.application`, `req.avps` (the request's AVPs as JSON),
    `req.answer_avps` (the answer set so far) and `req.answer(avps)`;
  - `on diameter.response(ans: DiameterAnswer)` with `ans.avps`.

  The functions are `ims_diameter_server.request(…)` and
  `.request_async(…)`.

The JSON is Kamailio's (`avp_helper.c`): a list of AVPs. One object is
taken as a one-AVP list.

```json
[{"avpCode": 263, "vendorId": 0, "DataType": 1, "Flags": 64, "string": "scscf.ims.test;1;1"},
 {"avpCode": 268, "vendorId": 0, "DataType": 3, "Flags": 64, "int32": 2001},
 {"avpCode": 700, "vendorId": 10415, "DataType": 0, "Flags": 192, "data": "0000025...", "list": [
     {"avpCode": 601, "vendorId": 10415, "DataType": 0, "Flags": 192, "data": "7369703a...", "string": "sip:alice@ims.test"}]}]
```

**Received AVPs** are written as `avp2json()` does. `DataType` is cdp's
type. cdp knows it only for a few base AVPs, by code:

- `string` (1): User-Name, Class, Session-Id,
  Origin-/Destination-Host/-Realm, Proxy-State, Product-Name and
  Error-Message;
- `int32` (3): Session-Timeout, Auth-/Acct-Application-Id,
  Redirect-Max-Cache-Time, Supported-Vendor-Id, Vendor-Id, Result-Code,
  Session-Binding, Auth-Grace-Period, Origin-State-Id and
  Authorization-Lifetime;
- `address` (2): Host-IP-Address.

Every other AVP is octets (0). It gets `data` (hex), plus:

- `int32` for four octets;
- `string` for longer ones that do not start with a NUL: the text up to
  the first NUL;
- `list` (the AVPs inside) for a grouped AVP.

One addition: 64-bit credit-control counters (CC-Total-Octets and the
like) are also given as `int64`.

**Building AVPs** (`$diameter_response`, `diameter_request()`): each item
needs `avpCode` and a value. The value is the first of `list`, `int32`,
`int64` (ferrosip's), `string` and `hexdump` that is present. `data` is
taken as `hexdump` too. An item without them is skipped with a warning,
as in Kamailio. `vendorId` defaults to 0 (Kamailio requires it). `Flags`
defaults to none. The V flag follows `vendorId`, and the base AVPs that
cdp types get its M flag.

Differences from Kamailio:

- Answers get Origin-Host and Origin-Realm, and Result-Code 2001 unless
  the script gave a Result-Code or an Experimental-Result. This keeps the
  answer well formed (RFC 6733 §7.1).
- Without `event_route[diameter:request]`, ferrosip still starts and
  answers 3001 (DIAMETER_COMMAND_UNSUPPORTED). Kamailio refuses to load
  the module.
- `diameter_request()` does not add a second Session-Id when the script
  gives one.

**[Pseudo-variables](../../docs/glossary.md#pseudo-variable-pv)**

| Name | Description |
|---|---|
| `$diameter_command` | Command code of the request (event route) |
| `$diameter_application` | Application id of the request (event route) |
| `$diameter_request` | The request's AVPs as JSON (event route) |
| `$diameter_response` | Read/write: the answer's AVPs (event route), or the last `diameter_request` answer |

**Functions**

| Signature | Description |
|---|---|
| `diameter_request([peer,] appid, commandcode, message)` | Send a request and wait for its answer (1 / -1) |
| `diameter_request_async([peer,] appid, commandcode, message)` | Send a request. Its answer runs `event_route[diameter:response]` (0: the route ends / -1) |

**Example** (Kamailio script). In `.fsr` you would use
`ims_diameter_server.request(…)`, and
`on kamailio.event_route(name: "diameter:request") { … }` with
`pv("$diameter_response") = …` (the
[escape hatch](../../docs/glossary.md#escape-hatch)).

```
loadmodule "cdp"
loadmodule "ims_diameter_server"

event_route[diameter:request] {
    if ($diameter_command == 306 && $diameter_request =~ "sip:alice@ims.test") {
        $diameter_response = "[{\"avpCode\":702,\"vendorId\":10415,\"Flags\":192,\"string\":\"<Sh-Data/>\"}]";
    }
}

request_route {
    $var(udr) = "[{\"avpCode\":283,\"vendorId\":0,\"Flags\":64,\"string\":\"ims.test\"}]";
    if (diameter_request("", "16777217", "306", "$var(udr)")) {
        xlog("L_INFO", "UDA: $diameter_response\n");
    }
}
```

**Differences from Kamailio**:

- `async` is accepted and ignored. Requests are always synchronous: the
  worker waits up to the cdp transaction timeout.
- The AVP types come from a built-in list rather than cdp's dictionary.
- Answers always get a Result-Code 2001 when the script sets neither
  Result-Code nor Experimental-Result.

## Not implemented

- the P-CSCF subscribing to reg events itself;
- the `s_cscf` database tables of `ims_icscf` (use `scscf_entry`).

## Testing

- `tests/e2e_diameter.py` covers:
  - cdp over TLS to a Python peer (client certificate checked by the
    peer);
  - cdp over TLS from a Python client (CER/CEA, DWR/DWA, a client without
    a certificate refused);
  - the SCTP acceptor (skipped when the kernel has no SCTP);
  - realm routes and default routes (a peer going down);
  - `event_route[diameter:request]` answering Sh UDRs over TLS, and
    `diameter_request`, in a `.cfg` and in `.fsr` (the typed
    `on diameter.request` / `on diameter.response` handlers).
- `tests/e2e_ims.py` runs a UE behind a P-CSCF, an I-CSCF, an S-CSCF and
  an application server, with a scripted Diameter peer playing HSS, PCRF
  and [OCS](../../docs/glossary.md#ocs). It covers:
  - CER/CEA;
  - SIP Digest and AKA registration (MAR, SAR registration /
    re-registration / de-registration);
  - Service-Route, P-Associated-URI and Path;
  - UAR/LIR and S-CSCF selection;
  - iFC routing through the AS and back;
  - Rx AAR/STR;
  - Ro CCR-I/U/T, with a call cut off by the OCS;
  - reg-event SUBSCRIBE/NOTIFY: a full document, then a partial one, then
    a full one for a refresh;
  - IPsec negotiation and `ipsec_forward`;
  - the S-CSCF's registrations in db_text tables (`db_mode=1`), loaded
    after a restart;
  - the reg-event subscription in `subscriber_scscf`, whose NOTIFYs
    continue after the restart (same dialog, next CSeq and version).

  The kernel SA installation is checked only where `ip xfrm` works.
  Otherwise the test checks that it is reported as unavailable.

  Then it runs an I-CSCF and an S-CSCF written in `.fsr` (with
  `ferrosip.toml`). These cover `await ims_icscf.authorize()` / `locate()`
  (also their -2 codes and capability-based selection), `www_challenge`
  and `save()` for Digest and AKA, and `await ims_charging.reserve`.
- Unit tests: AVPs to JSON and back (`ims_diameter_server`), User-Data
  parsing and iFC matching, SDP to Media-Component-Description, `ip xfrm`
  command generation and header parsing for IPsec, digest credential
  parsing.
- Fuzzing: `fuzz/fuzz_targets/ims_xml.rs` (the User-Data subscription
  parser) and `fuzz/fuzz_targets/diameter.rs` (Diameter message and AVP
  decoding, the cdp XML config, in `sip-diameter`).
