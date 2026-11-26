# sip-diameter

This crate lets ferrosip's [IMS](../../docs/glossary.md#ims) modules talk
[Diameter](../../docs/glossary.md#diameter) to the operator's back-end
servers, such as the [HSS](../../docs/glossary.md#hss) (the subscriber
database), the [PCRF](../../docs/glossary.md#pcrf) (media policy) and the
[OCS](../../docs/glossary.md#ocs) (online charging). You use it through
`mod-ims`. You would only use it directly to write a new Diameter-based
module or a test peer.

It is a small Diameter base stack (RFC 6733). It has three parts:

- a codec for [Diameter AVPs](../../docs/glossary.md#diameter-avp) and
  messages;
- the command, application, AVP and result codes that the
  [CSCF](../../docs/glossary.md#cscf) modules need;
- a peer manager. It keeps TCP, TLS or SCTP connections to the configured
  [Diameter peers](../../docs/glossary.md#diameter-peer) open and accepts
  incoming peers. It routes requests by
  [realm](../../docs/glossary.md#diameter-realm) route tables. It sends
  requests and blocks until the answer arrives or a timer expires.

It is the equivalent of [Kamailio](../../docs/glossary.md#kamailio)'s `cdp`
and `cdp_avp` [modules](../../docs/glossary.md#module). It reads cdp's XML
configuration (`<DiameterPeer>`).

The crate is `#![forbid(unsafe_code)]`. It depends on `sip-core`,
`sip-transport`, `rustls` and `socket2`. The TLS loader in `sip-transport`
builds the rustls configurations. `socket2` provides the SCTP socket.
`mod-ims` uses the crate (cdp, ims_auth, the S-CSCF registrar, ims_icscf,
ims_qos, ims_charging, …). So does the `diameter` fuzz target.

## Contents

| File | Provides |
|---|---|
| `src/lib.rs` | `Avp`, `Msg`, `decode_avps`, `find`, header flag constants (`FLAG_V`, `FLAG_M`, `FLAG_R`, `FLAG_P`, `FLAG_E`) |
| `src/codes.rs` | Constants: vendor (`VENDOR_3GPP` = 10415); applications (`APP_COMMON`, `APP_CC`, `APP_CX`, `APP_RX`); commands (`CMD_CE`, `CMD_DW`, `CMD_DP`, `CMD_UAR`, `CMD_SAR`, `CMD_LIR`, `CMD_MAR`, `CMD_RTR`, `CMD_PPR`, `CMD_AA`, `CMD_RA`, `CMD_ST`, `CMD_AS`, `CMD_CC`); base, credit-control, Cx and Rx AVP codes; result codes (`DIAMETER_SUCCESS`, `DIAMETER_FIRST_REGISTRATION`, `DIAMETER_ERROR_USER_UNKNOWN`, …) |
| `src/peer.rs` | `Config`, `PeerCfg`, `Route`, `TlsCfg`, `Peers` (connector, acceptors, watchdog, request routing), `PeerInfo`, the request `Handler` type, `parse_xml_config` |
| `src/wire.rs` | `Proto` (tcp / tls / sctp). Connecting and listening on TCP or SCTP. The TLS handshakes. Splitting a connection into a reader and a shared writer |

## Key types and APIs

### Codec

The example builds a [MAR](../../docs/glossary.md#mar) for the
[Cx](../../docs/glossary.md#cx) interface, encodes it and decodes it again.

```rust
use sip_diameter::{codes::*, Avp, Msg};

let mut m = Msg::request(CMD_MAR, APP_CX);
m.add(Avp::str(SESSION_ID, None, "scscf.ims.test;1;1"))
    .add(Avp::str(PUBLIC_IDENTITY, Some(VENDOR_3GPP), "sip:alice@ims.test"))
    .add(Avp::u32(SIP_NUMBER_AUTH_ITEMS, Some(VENDOR_3GPP), 1))
    .add(Avp::group(SIP_AUTH_DATA_ITEM, Some(VENDOR_3GPP),
        vec![Avp::str(SIP_AUTHENTICATION_SCHEME, Some(VENDOR_3GPP), "SIP Digest")]));
let wire = m.encode();
let back = Msg::decode(&wire).unwrap();
let user = back.get(PUBLIC_IDENTITY, Some(VENDOR_3GPP)).map(Avp::as_str);
```

- Codes are typed. There are five types: `AvpCode`, `CmdCode`, `AppId`,
  `VendorId` and `ResultCode`. Each is a `#[repr(transparent)]` `u32`
  newtype with a public field. Each is `const`-constructible and implements
  `Display`/`Debug`. Every constant in `codes` has its kind. So passing an
  AVP code as a command code does not compile, and neither does passing a
  vendor as an application. To write an id or result code as an Unsigned32
  AVP value, call `.get()`. The wire format is unchanged.
- `Avp { code, flags, vendor, data }`. The constructors set the M flag.
  They also set the V flag when a vendor is given. Constructors: `Avp::new`,
  `str`, `u32`, `u64`, `group` (nested AVPs) and `addr` (Address type,
  IPv4/IPv6). `.optional()` clears M. Readers: `as_str`, `as_u32`, `as_u64`,
  `group_avps`. `encode` pads to 4 bytes.
- `Msg { flags, cmd, app, hbh, e2e, avps }`:
  - `Msg::request(cmd, app)` sets the R and P flags.
  - `answer()` keeps the same ids and application and clears R.
  - `add` chains by `&mut`. `with` chains by value.
  - `get` / `get_all` look up by (code, vendor). `str` reads a string AVP.
  - `result()` returns a `ResultCode`. That is the Result-Code, or the
    Experimental-Result-Code inside Experimental-Result.
- `Msg::frame_len(buf)` reads the length from the first 4 bytes. The
  version must be 1. `Msg::decode` returns `None` on any malformed input.
  `decode_avps(bytes)` decodes a run of AVPs. `find(avps, code, vendor)`
  finds one AVP in a list.

### Peers

The example connects to one HSS, answers the HSS's RTRs and sends a MAR.

```rust
use sip_diameter::{codes::*, Avp, Config, Msg, PeerCfg, Peers, Proto};
use std::sync::Arc;

let peers = Peers::new(Config {
    identity: "scscf.ims.test".into(),
    realm: "ims.test".into(),
    peers: vec![PeerCfg { fqdn: "hss.ims.test".into(), realm: "ims.test".into(),
                          host: "127.0.0.1".into(), port: 3868, proto: Proto::Tcp }],
    auth_apps: vec![(VENDOR_3GPP, APP_CX)],
    ..Default::default()
});
// Answer Cx RTRs from the HSS.
peers.add_handler(APP_CX, CMD_RTR, Arc::new(|req: &Msg| {
    Some(req.answer().with(Avp::u32(RESULT_CODE, None, DIAMETER_SUCCESS.get())))
}));
peers.start();
let mut mar = Msg::request(CMD_MAR, APP_CX);
mar.add(Avp::str(SESSION_ID, None, &peers.session_id("mar")));
let answer = peers.request(mar, "ims.test", None)?; // blocks until answer or timeout
```

- `Config` fields:
  - `identity` and `realm`: this node's own name and realm.
  - `vendor_id` and `product`.
  - `peers`: the peers to connect to,
    `PeerCfg { fqdn, realm, host, port, proto }`.
  - `listen`: the acceptors, as `(Proto, "ip:port")`.
  - `auth_apps` / `acct_apps`: pairs of (vendor or 0, application id).
  - `tc`: the reconnect interval, in seconds.
  - `tw`: the watchdog interval, in seconds.
  - `timeout`: the transaction timeout.
  - `realm_routes`: route tables, as `(realm, Vec<Route { fqdn, metric }>)`.
  - `default_routes`.
  - `tls`: `TlsCfg { certificate, private_key, ca_list, require_certificate }`.

  Defaults: identity `ferrosip.localdomain`, realm `localdomain`, vendor
  10415, product `ferrosip`, `tc` = `tw` = 30 s, timeout 5 s.
- `Peers::try_new(cfg)` loads the TLS certificates when a peer or an
  acceptor uses TLS. It returns an error when they are missing. TLS peers
  need `ca_list`. TLS acceptors need `certificate` and `private_key`. `new`
  panics instead of returning the error. `start()` spawns one connector
  thread per configured peer, one acceptor per `listen` entry, and a
  watchdog thread.
- `request(msg, dest_realm, dest_host)` sends a request and waits for its
  answer. It adds Origin-Host/-Realm and Destination-Realm/-Host when they
  are missing. It assigns the hop-by-hop and end-to-end ids. It then waits
  up to `cfg.timeout` for the answer with the same hop-by-hop id.
  - `send(msg, dest_realm)` sends without waiting.
  - `request_cb` is the non-blocking form. The callback gets the answer, or
    the error once the timeout has passed.
  - Failures are a `DiameterError`:
    - `NoRoute`: no open peer for the realm.
    - `Send`: the write failed.
    - `Timeout`: no answer in time.
    - `Encode`: a field is over its 24-bit limit.
    - `NoCdp`.

    `is_timeout()` picks out the timeout case, because the IMS modules
    answer it differently. `From<DiameterError> for String` keeps `?`
    working.
- `add_handler(app, cmd, Handler)` answers incoming requests for one
  (application, command) pair. A `Handler` is
  `Arc<dyn Fn(&Msg) -> Option<Msg>>`. Returning `None` sends nothing.
  `set_fallback_handler(Handler)` takes the requests that no handler takes.
  Without it they are answered with 3001.
- `session_id(tag)` builds `identity;state_id;counter;tag`.
- `peer_realm(fqdn)` returns the realm a peer announced. If it announced
  none, it returns the realm the peer was configured with.
- `peers()` lists `PeerInfo { fqdn, realm, state, origin_host, proto }`.
  The state is `I_Open` / `Closed` for configured peers and `R_Open` for
  accepted ones.

### Kamailio cdp XML

`parse_xml_config(xml) -> Result<Config, String>` reads the parts of
Kamailio's DiameterPeer file that ferrosip uses:

```xml
<DiameterPeer FQDN="scscf.ims.test" Realm="ims.test" Vendor_Id="10415" Tc="5">
  <Peer FQDN="hss.ims.test" Realm="ims.test" port="3869" host="127.0.0.1"/>
  <Peer FQDN="hss2.ims.test" Realm="ims.test" proto="tls"/>
  <Acceptor port="3870" bind="127.0.0.1"/>
  <Acceptor port="5658" bind="127.0.0.1" proto="tls"/>
  <TLS certificate="scscf.pem" private_key="scscf.key" ca_list="ca.pem" require_certificate="1"/>
  <Auth id="16777216" vendor="10415"/>
  <Realm name="ims.test">
    <Route FQDN="hss.ims.test" metric="10"/>
    <Route FQDN="hss2.ims.test" metric="20"/>
  </Realm>
  <DefaultRoute FQDN="hss.ims.test" metric="10"/>
</DiameterPeer>
```

The attributes it reads, per element:

| Element | Attributes |
|---|---|
| `DiameterPeer` | `FQDN`, `Realm`, `Vendor_Id`, `Product_Name`, `Tc`, `TransactionTimeout` |
| `Peer` | `FQDN`, `Realm`, `port` (default 3868, 5658 for TLS), `proto` (`tcp`, `tls` or `sctp`), `host` (where to connect, default the FQDN; a ferrosip addition) |
| `Acceptor` | `bind` (default `0.0.0.0`), `port`, `proto`. Several acceptors may be given |
| `Auth` / `Acct` | `id`, `vendor` |
| `Realm` | `name` |
| `Route` (inside `Realm`) and `DefaultRoute` | `FQDN`, `metric` (default 0) |
| `TLS` (ferrosip's element) | `certificate`, `private_key`, `ca_list`, `require_certificate` |

Attribute names are case-insensitive. XML comments are skipped.

## Design notes

- **Limits.** At most 64 inbound connections are served at once. Each one
  is a thread, and the [CER](../../docs/glossary.md#cer) is the only check
  on who connects. After the CER, a reader times out after 3 × `tw` of
  silence, when the watchdog (below) closes the connection anyway. A dead
  peer is dropped from the pick list (RFC 3539). It is not written to
  forever.
- **Panics.** A panic in a request handler answers 5012
  (DIAMETER_UNABLE_TO_COMPLY). It does not kill the peer's reader.

- **Reduced peer state machine.** The steps are:
  1. Connect.
  2. CER/CEA. A CEA without DIAMETER_SUCCESS, or with no application in
     common, fails the attempt.
  3. Open.
  4. DWR/DWA.
  5. A [DPR](../../docs/glossary.md#dpr) is answered with a DPA, and the connection is closed.
  6. Reconnect every `tc` seconds (at least 1).

  Incoming peers must start with a CER. It is answered with our
  capabilities: DIAMETER_SUCCESS when the peer supports one of our
  applications, else 5010 (DIAMETER_NO_COMMON_APPLICATION), and the
  connection is closed.
- **Capabilities.** CER/CEA carry these AVPs: Origin-Host/-Realm,
  Host-IP-Address (the local socket address), Vendor-Id, Product-Name,
  Origin-State-Id, Supported-Vendor-Id
  ([3GPP](../../docs/glossary.md#3gpp)), the configured Auth/Acct
  application ids and Firmware-Revision. The application ids are wrapped in
  Vendor-Specific-Application-Id when a vendor is set.
- **Common applications** (RFC 6733 §5.3). The peer's Auth- and
  Acct-Application-Ids, alone or inside Vendor-Specific-Application-Id,
  are compared with ours by kind and id; the Vendor-Id is informational.
  The Relay id (0xffffffff) on either side matches everything on the
  other.
- **Watchdog** (RFC 3539 §3.4.1, `src/watchdog.rs`). Each connection has
  a timer of `tw` seconds (at least 6), restarted by anything received.
  Once a second the watchdog thread checks it:
  1. OKAY: when it fires, a DWR is sent.
  2. Still nothing when it fires again: SUSPECT. The peer gets no new
     requests and `cdp.list_peers` shows it as `Suspect`. Any message from
     it makes it OKAY again.
  3. Still nothing a third time: down. It is dropped from the pick list,
     and its reader's timeout closes the socket.
- **Request routing.** The peer manager tries these in order:
  1. Destination-Host (a configured FQDN or Origin-Host), when that peer is
     open.
  2. The destination realm's route table, lowest metric first, skipping
     peers that are not open (SUSPECT peers count as not open). Open peers that share the lowest metric take
     turns, the least recently chosen first, as cdp does.
  3. For a realm without a table, a peer in that realm.
  4. The default routes, by metric.
  5. Any open peer.

  The last two fallbacks are ferrosip's own. cdp (`routing.c`
  `get_routing_peer()`) gives up when neither the realm's routes nor the
  `DefaultRoute`s have an open peer. ferrosip keeps them so that a module
  configured with just a peer list (no routing table) still reaches its
  HSS. Not done: cdp's per-session sticky peer, and its check that the
  chosen peer advertised the request's application.
- **TLS** (RFC 6733 §13). TLS starts from the first byte. There is no
  RFC 3588 in-band upgrade. Clients verify the server against `ca_list`,
  with the peer's FQDN as the name. They present `certificate` when it is
  set. Acceptors present `certificate`. With `require_certificate`, they
  also verify the client's certificate. The reader waits for ciphertext
  without holding the connection's lock. So writers (requests, DWRs) are
  never blocked behind a read. rustls's bounded plaintext buffer is flushed
  as large messages are written.
- **SCTP.** The stack opens a one-to-one `SOCK_STREAM` socket with
  `IPPROTO_SCTP` through socket2. It then uses it like a TCP stream: one
  stream, PPID 0, no multi-homing. Without kernel SCTP support, the connect
  or listen fails with "SCTP is not supported by this kernel".
- **Blocking requests.** Each request registers a channel under its
  hop-by-hop id. The connection's reader thread delivers the answer. The
  caller's thread waits for it (`recv_timeout`) without polling. Answers
  that arrive after the timeout are dropped.
- **Defensive decoding.** Messages over 1 MiB or under 20 bytes are refused
  on read. AVP lengths are checked against the buffer. Requests with no
  handler are answered with 3001 (DIAMETER_COMMAND_UNSUPPORTED).

## Testing

- Unit tests: `cargo test -p sip-diameter`. They cover:
  - an encode/decode round trip with vendor and grouped AVPs and
    Experimental-Result;
  - XML configuration parsing, with transports, `<TLS>`, `<Realm>` tables
    and default routes;
  - two `Peers` instances on 127.0.0.1 doing CER/CEA and a MAR, with an
    unhandled [SAR](../../docs/glossary.md#sar) answered 3001;
  - realm routes by metric with a peer down;
  - TLS with client certificates both ways and a 70 kB answer, and an
    anonymous client refused;
  - SCTP, skipped without kernel support.
- `tests/e2e_diameter.py`: TLS to a Python peer and from Python clients,
  and the SCTP acceptor (skipped without kernel support).
- CI's `sctp` job loads the kernel's `sctp` module. It runs both SCTP tests
  with `REQUIRE_SCTP=1`, which turns their skip into a failure.
- Fuzz target: `fuzz/fuzz_targets/diameter.rs`. It covers `frame_len`,
  `decode`, grouped AVPs, re-encoding, `decode_avps` and
  `parse_xml_config`. Run it with `cd fuzz && cargo +nightly fuzz run diameter`.
- End-to-end: `tests/e2e_ims.py` runs a
  [P-CSCF](../../docs/glossary.md#p-cscf),
  [S-CSCF](../../docs/glossary.md#s-cscf) and
  [application server](../../docs/glossary.md#as) against a scripted
  Diameter peer playing HSS, PCRF and OCS.
