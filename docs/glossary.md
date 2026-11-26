# Glossary

The words this project uses, in plain English. It is for developers who
know networking (IP, TCP, TLS, DNS, HTTP) but not SIP, Kamailio or IMS.
It has 213 entries.

Each entry gives a short meaning, an example where one helps, the
standard or Kamailio reference in brackets, and related terms.

Sections: [SIP basics](#sip-basics),
[SIP routing and transactions](#sip-routing-and-transactions),
[Authentication](#authentication), [NAT and media](#nat-and-media),
[Kamailio scripting concepts](#kamailio-scripting-concepts),
[IMS and Diameter](#ims-and-diameter),
[ferrosip-specific](#ferrosip-specific), [Operations](#operations).
Inside each section the terms are in alphabetical order.

## How to link here

The READMEs and docs link to an entry instead of explaining the term
again. Use the anchor from the index below:

- from a file in `docs/`: `[AoR](glossary.md#aor)`;
- from the root `README.md`: `[AoR](docs/glossary.md#aor)`;
- from `crates/*/README.md`, `tools/*/README.md` or `bin/*/README.md`:
  `[AoR](../../docs/glossary.md#aor)`;
- from `examples/scenarios/*/README.md`:
  `[AoR](../../../docs/glossary.md#aor)`.

The anchors follow fixed rules, so they stay stable:

- **An acronym or abbreviation is the heading on its own.** `### AoR`
  gives `#aor`, `### R-URI` gives `#r-uri`, `### P-CSCF` gives `#p-cscf`.
  The full name is the first words of the entry, and it has its own row in
  the index.
- **Any other term is its plain name in sentence case.** `### Loose routing`
  gives `#loose-routing`, `### Record-Route` gives `#record-route`. When
  Kamailio has a short name for it, that follows in brackets:
  `### Pseudo-variable (pv)` gives `#pseudo-variable-pv`.
- **Headings have no underscores, `$` or backticks.** Script names such as
  `request_route` get a plain heading (`### Request route`, `#request-route`)
  and appear in the index as other names. A dot is dropped from the anchor:
  `### .fsr` gives `#fsr`, and `### ferrosip.toml` gives `#ferrosiptoml`.
- **Every heading is unique.** Where a word means two things, the second
  one is qualified: `#realm` (digest) and `#diameter-realm`, `#avp`
  (script) and `#diameter-avp`.
- **Other names point to the same anchor.** The index lists abbreviations,
  long forms and Kamailio names (`CEA`, `Request-URI`, `failure_route`) as
  rows of their own. Never link to an anchor that is not in the index.

## Anchor index

| Term | Anchor | Section |
|---|---|---|
| 100 Trying → Provisional reply | [`glossary.md#provisional-reply`](#provisional-reply) | SIP basics |
| 1xx reply → Provisional reply | [`glossary.md#provisional-reply`](#provisional-reply) | SIP basics |
| 2xx reply → Final reply | [`glossary.md#final-reply`](#final-reply) | SIP basics |
| 3GPP | [`glossary.md#3gpp`](#3gpp) | IMS and Diameter |
| 401 and 407 → Challenge | [`glossary.md#challenge`](#challenge) | Authentication |
| AAA (Rx answer) → AAR | [`glossary.md#aar`](#aar) | IMS and Diameter |
| AAR | [`glossary.md#aar`](#aar) | IMS and Diameter |
| Abort-Session-Request → ASR | [`glossary.md#asr`](#asr) | IMS and Diameter |
| acc → CDR | [`glossary.md#cdr`](#cdr) | Operations |
| ACK | [`glossary.md#ack`](#ack) | SIP basics |
| Address of record → AoR | [`glossary.md#aor`](#aor) | SIP basics |
| AKA | [`glossary.md#aka`](#aka) | IMS and Diameter |
| AoR | [`glossary.md#aor`](#aor) | SIP basics |
| `app_lua` → KEMI | [`glossary.md#kemi`](#kemi) | Kamailio scripting concepts |
| Application server → AS | [`glossary.md#as`](#as) | IMS and Diameter |
| AS | [`glossary.md#as`](#as) | IMS and Diameter |
| ASA → ASR | [`glossary.md#asr`](#asr) | IMS and Diameter |
| ASR | [`glossary.md#asr`](#asr) | IMS and Diameter |
| Authentication and Key Agreement → AKA | [`glossary.md#aka`](#aka) | IMS and Diameter |
| Authorization header → Challenge | [`glossary.md#challenge`](#challenge) | Authentication |
| AVP | [`glossary.md#avp`](#avp) | Kamailio scripting concepts |
| `$avp` → AVP | [`glossary.md#avp`](#avp) | Kamailio scripting concepts |
| await | [`glossary.md#await`](#await) | ferrosip-specific |
| B2BUA | [`glossary.md#b2bua`](#b2bua) | SIP basics |
| Back-to-back user agent → B2BUA | [`glossary.md#b2bua`](#b2bua) | SIP basics |
| balancer → Dispatcher | [`glossary.md#dispatcher`](#dispatcher) | Kamailio scripting concepts |
| Binding → Location service | [`glossary.md#location-service`](#location-service) | SIP routing and transactions |
| BLF | [`glossary.md#blf`](#blf) | SIP basics |
| blst → Destination blocklist | [`glossary.md#destination-blocklist`](#destination-blocklist) | Kamailio scripting concepts |
| Branch | [`glossary.md#branch`](#branch) | SIP routing and transactions |
| Branch flags | [`glossary.md#branch-flags`](#branch-flags) | Kamailio scripting concepts |
| Branch parameter | [`glossary.md#branch-parameter`](#branch-parameter) | SIP routing and transactions |
| Branch route | [`glossary.md#branch-route`](#branch-route) | Kamailio scripting concepts |
| `branch_route` → Branch route | [`glossary.md#branch-route`](#branch-route) | Kamailio scripting concepts |
| Busy lamp field → BLF | [`glossary.md#blf`](#blf) | SIP basics |
| BYE | [`glossary.md#bye`](#bye) | SIP basics |
| Call detail record → CDR | [`glossary.md#cdr`](#cdr) | Operations |
| Call Session Control Function → CSCF | [`glossary.md#cscf`](#cscf) | IMS and Diameter |
| Call-ID | [`glossary.md#call-id`](#call-id) | SIP basics |
| CANCEL | [`glossary.md#cancel`](#cancel) | SIP basics |
| Capabilities exchange → CER | [`glossary.md#cer`](#cer) | IMS and Diameter |
| Capture server → HOMER | [`glossary.md#homer`](#homer) | Operations |
| carriers → LCR | [`glossary.md#lcr`](#lcr) | Kamailio scripting concepts |
| CCA → CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| CCR-Initial → CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| CCR-Termination → CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| CCR-Update → CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| cdp → Diameter | [`glossary.md#diameter`](#diameter) | IMS and Diameter |
| CDR | [`glossary.md#cdr`](#cdr) | Operations |
| CEA → CER | [`glossary.md#cer`](#cer) | IMS and Diameter |
| CER | [`glossary.md#cer`](#cer) | IMS and Diameter |
| .cfg | [`glossary.md#cfg`](#cfg) | Kamailio scripting concepts |
| cfg.reload → Live reload | [`glossary.md#live-reload`](#live-reload) | ferrosip-specific |
| Challenge | [`glossary.md#challenge`](#challenge) | Authentication |
| Check | [`glossary.md#check`](#check) | ferrosip-specific |
| children → Worker | [`glossary.md#worker`](#worker) | ferrosip-specific |
| cnonce | [`glossary.md#cnonce`](#cnonce) | Authentication |
| Contact | [`glossary.md#contact`](#contact) | SIP basics |
| Counter | [`glossary.md#counter`](#counter) | Operations |
| Credit-Control-Request → CCR | [`glossary.md#ccr`](#ccr) | IMS and Diameter |
| CSCF | [`glossary.md#cscf`](#cscf) | IMS and Diameter |
| CSeq | [`glossary.md#cseq`](#cseq) | SIP basics |
| Cx | [`glossary.md#cx`](#cx) | IMS and Diameter |
| `data_lump` → Lumps | [`glossary.md#lumps`](#lumps) | Kamailio scripting concepts |
| `#!define` → Preprocessor | [`glossary.md#preprocessor`](#preprocessor) | Kamailio scripting concepts |
| Destination blocklist | [`glossary.md#destination-blocklist`](#destination-blocklist) | Kamailio scripting concepts |
| Destination set | [`glossary.md#destination-set`](#destination-set) | SIP routing and transactions |
| Destination URI | [`glossary.md#destination-uri`](#destination-uri) | SIP routing and transactions |
| Destination-Realm → Diameter realm | [`glossary.md#diameter-realm`](#diameter-realm) | IMS and Diameter |
| Dialog | [`glossary.md#dialog`](#dialog) | SIP routing and transactions |
| Dialog profile | [`glossary.md#dialog-profile`](#dialog-profile) | Kamailio scripting concepts |
| dialog var → Dialog variable | [`glossary.md#dialog-variable`](#dialog-variable) | ferrosip-specific |
| Dialog variable | [`glossary.md#dialog-variable`](#dialog-variable) | ferrosip-specific |
| dialog-info → BLF | [`glossary.md#blf`](#blf) | SIP basics |
| Diameter | [`glossary.md#diameter`](#diameter) | IMS and Diameter |
| Diameter AVP | [`glossary.md#diameter-avp`](#diameter-avp) | IMS and Diameter |
| Diameter node → Diameter peer | [`glossary.md#diameter-peer`](#diameter-peer) | IMS and Diameter |
| Diameter peer | [`glossary.md#diameter-peer`](#diameter-peer) | IMS and Diameter |
| Diameter realm | [`glossary.md#diameter-realm`](#diameter-realm) | IMS and Diameter |
| Digest → Digest authentication | [`glossary.md#digest-authentication`](#digest-authentication) | Authentication |
| Digest authentication | [`glossary.md#digest-authentication`](#digest-authentication) | Authentication |
| Digest-AKAv1-MD5 → AKA | [`glossary.md#aka`](#aka) | IMS and Diameter |
| Dispatcher | [`glossary.md#dispatcher`](#dispatcher) | Kamailio scripting concepts |
| Diversion → Diversion header | [`glossary.md#diversion-header`](#diversion-header) | SIP basics |
| Diversion header | [`glossary.md#diversion-header`](#diversion-header) | SIP basics |
| DMQ | [`glossary.md#dmq`](#dmq) | Kamailio scripting concepts |
| DNS resolution | [`glossary.md#dns-resolution`](#dns-resolution) | SIP routing and transactions |
| DPA → DPR | [`glossary.md#dpr`](#dpr) | IMS and Diameter |
| DPR | [`glossary.md#dpr`](#dpr) | IMS and Diameter |
| `dst_blocklist` → Destination blocklist | [`glossary.md#destination-blocklist`](#destination-blocklist) | Kamailio scripting concepts |
| DTLS | [`glossary.md#dtls`](#dtls) | NAT and media |
| DTLS-SRTP → DTLS | [`glossary.md#dtls`](#dtls) | NAT and media |
| `$du` → Destination URI | [`glossary.md#destination-uri`](#destination-uri) | SIP routing and transactions |
| DWA → DWR | [`glossary.md#dwr`](#dwr) | IMS and Diameter |
| DWR | [`glossary.md#dwr`](#dwr) | IMS and Diameter |
| E.164 | [`glossary.md#e164`](#e164) | SIP basics |
| Encapsulating Security Payload → ESP | [`glossary.md#esp`](#esp) | IMS and Diameter |
| Entity tag | [`glossary.md#entity-tag`](#entity-tag) | SIP basics |
| ENUM | [`glossary.md#enum`](#enum) | SIP routing and transactions |
| Escape hatch | [`glossary.md#escape-hatch`](#escape-hatch) | ferrosip-specific |
| ESP | [`glossary.md#esp`](#esp) | IMS and Diameter |
| Event handler | [`glossary.md#event-handler`](#event-handler) | ferrosip-specific |
| Event header → Event package | [`glossary.md#event-package`](#event-package) | SIP basics |
| Event package | [`glossary.md#event-package`](#event-package) | SIP basics |
| Event route | [`glossary.md#event-route`](#event-route) | Kamailio scripting concepts |
| `event_route` → Event route | [`glossary.md#event-route`](#event-route) | Kamailio scripting concepts |
| Failure route | [`glossary.md#failure-route`](#failure-route) | Kamailio scripting concepts |
| `failure_route` → Failure route | [`glossary.md#failure-route`](#failure-route) | Kamailio scripting concepts |
| Feature switch | [`glossary.md#feature-switch`](#feature-switch) | ferrosip-specific |
| `[feature]` → Feature switch | [`glossary.md#feature-switch`](#feature-switch) | ferrosip-specific |
| ferroctl | [`glossary.md#ferroctl`](#ferroctl) | ferrosip-specific |
| ferrosip check → Check | [`glossary.md#check`](#check) | ferrosip-specific |
| ferrosip import → Import | [`glossary.md#import`](#import) | ferrosip-specific |
| ferrosip lint → Lint | [`glossary.md#lint`](#lint) | ferrosip-specific |
| ferrosip test → Test block | [`glossary.md#test-block`](#test-block) | ferrosip-specific |
| ferrosip.toml | [`glossary.md#ferrosiptoml`](#ferrosiptoml) | ferrosip-specific |
| Final reply | [`glossary.md#final-reply`](#final-reply) | SIP basics |
| Final response timer | [`glossary.md#final-response-timer`](#final-response-timer) | SIP routing and transactions |
| Fixup | [`glossary.md#fixup`](#fixup) | Kamailio scripting concepts |
| Flags | [`glossary.md#flags`](#flags) | Kamailio scripting concepts |
| Flow → SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| Fork → Forking | [`glossary.md#forking`](#forking) | SIP routing and transactions |
| Forking | [`glossary.md#forking`](#forking) | SIP routing and transactions |
| `fr_inv_timer` → Final response timer | [`glossary.md#final-response-timer`](#final-response-timer) | SIP routing and transactions |
| `fr_timer` → Final response timer | [`glossary.md#final-response-timer`](#final-response-timer) | SIP routing and transactions |
| From tag → Tag | [`glossary.md#tag`](#tag) | SIP basics |
| .fsr | [`glossary.md#fsr`](#fsr) | ferrosip-specific |
| Gateway | [`glossary.md#gateway`](#gateway) | SIP basics |
| Gauge | [`glossary.md#gauge`](#gauge) | Operations |
| Graceful shutdown | [`glossary.md#graceful-shutdown`](#graceful-shutdown) | Operations |
| Grafana | [`glossary.md#grafana`](#grafana) | Operations |
| GRUU | [`glossary.md#gruu`](#gruu) | SIP routing and transactions |
| HA1 | [`glossary.md#ha1`](#ha1) | Authentication |
| Header → Header field | [`glossary.md#header-field`](#header-field) | SIP basics |
| Header field | [`glossary.md#header-field`](#header-field) | SIP basics |
| HEP | [`glossary.md#hep`](#hep) | Operations |
| Histogram → Prometheus metric | [`glossary.md#prometheus-metric`](#prometheus-metric) | Operations |
| Home Subscriber Server → HSS | [`glossary.md#hss`](#hss) | IMS and Diameter |
| HOMER | [`glossary.md#homer`](#homer) | Operations |
| Homer Encapsulation Protocol → HEP | [`glossary.md#hep`](#hep) | Operations |
| HSS | [`glossary.md#hss`](#hss) | IMS and Diameter |
| htable | [`glossary.md#htable`](#htable) | Kamailio scripting concepts |
| I-CSCF | [`glossary.md#i-cscf`](#i-cscf) | IMS and Diameter |
| ICE | [`glossary.md#ice`](#ice) | NAT and media |
| iFC | [`glossary.md#ifc`](#ifc) | IMS and Diameter |
| IMPI | [`glossary.md#impi`](#impi) | IMS and Diameter |
| Implicit registration set | [`glossary.md#implicit-registration-set`](#implicit-registration-set) | IMS and Diameter |
| Import | [`glossary.md#import`](#import) | ferrosip-specific |
| IMPU | [`glossary.md#impu`](#impu) | IMS and Diameter |
| IMS | [`glossary.md#ims`](#ims) | IMS and Diameter |
| IMS Service Control → ISC | [`glossary.md#isc`](#isc) | IMS and Diameter |
| In-dialog request | [`glossary.md#in-dialog-request`](#in-dialog-request) | SIP routing and transactions |
| Initial filter criteria → iFC | [`glossary.md#ifc`](#ifc) | IMS and Diameter |
| Initial request | [`glossary.md#initial-request`](#initial-request) | SIP routing and transactions |
| Instance ID → SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| Interrogating-CSCF → I-CSCF | [`glossary.md#i-cscf`](#i-cscf) | IMS and Diameter |
| INVITE | [`glossary.md#invite`](#invite) | SIP basics |
| IP Multimedia Subsystem → IMS | [`glossary.md#ims`](#ims) | IMS and Diameter |
| IPsec → IPsec security association | [`glossary.md#ipsec-security-association`](#ipsec-security-association) | IMS and Diameter |
| IPsec security association | [`glossary.md#ipsec-security-association`](#ipsec-security-association) | IMS and Diameter |
| ISC | [`glossary.md#isc`](#isc) | IMS and Diameter |
| JSON-RPC → RPC | [`glossary.md#rpc`](#rpc) | ferrosip-specific |
| Kamailio | [`glossary.md#kamailio`](#kamailio) | Kamailio scripting concepts |
| Kamailio script → .cfg | [`glossary.md#cfg`](#cfg) | Kamailio scripting concepts |
| kamailio.call → Escape hatch | [`glossary.md#escape-hatch`](#escape-hatch) | ferrosip-specific |
| kamailio.cfg → .cfg | [`glossary.md#cfg`](#cfg) | Kamailio scripting concepts |
| kamcmd | [`glossary.md#kamcmd`](#kamcmd) | Kamailio scripting concepts |
| Keepalive | [`glossary.md#keepalive`](#keepalive) | NAT and media |
| KEMI | [`glossary.md#kemi`](#kemi) | Kamailio scripting concepts |
| KSR → KEMI | [`glossary.md#kemi`](#kemi) | Kamailio scripting concepts |
| LCR | [`glossary.md#lcr`](#lcr) | Kamailio scripting concepts |
| Least cost routing → LCR | [`glossary.md#lcr`](#lcr) | Kamailio scripting concepts |
| LIA → LIR | [`glossary.md#lir`](#lir) | IMS and Diameter |
| Lint | [`glossary.md#lint`](#lint) | ferrosip-specific |
| LIR | [`glossary.md#lir`](#lir) | IMS and Diameter |
| Live reload | [`glossary.md#live-reload`](#live-reload) | ferrosip-specific |
| loadmodule → Module | [`glossary.md#module`](#module) | Kamailio scripting concepts |
| location (module) → usrloc | [`glossary.md#usrloc`](#usrloc) | Kamailio scripting concepts |
| Location service | [`glossary.md#location-service`](#location-service) | SIP routing and transactions |
| Location table → Location service | [`glossary.md#location-service`](#location-service) | SIP routing and transactions |
| Loose routing | [`glossary.md#loose-routing`](#loose-routing) | SIP routing and transactions |
| Lowering | [`glossary.md#lowering`](#lowering) | ferrosip-specific |
| lr parameter → Loose routing | [`glossary.md#loose-routing`](#loose-routing) | SIP routing and transactions |
| Lumps | [`glossary.md#lumps`](#lumps) | Kamailio scripting concepts |
| MAA → MAR | [`glossary.md#mar`](#mar) | IMS and Diameter |
| MAR | [`glossary.md#mar`](#mar) | IMS and Diameter |
| Max-Forwards | [`glossary.md#max-forwards`](#max-forwards) | SIP basics |
| Media relay | [`glossary.md#media-relay`](#media-relay) | NAT and media |
| MESSAGE | [`glossary.md#message`](#message) | SIP basics |
| Message flags → Flags | [`glossary.md#flags`](#flags) | Kamailio scripting concepts |
| Method | [`glossary.md#method`](#method) | SIP basics |
| Metric → Prometheus metric | [`glossary.md#prometheus-metric`](#prometheus-metric) | Operations |
| Mid-dialog request → In-dialog request | [`glossary.md#in-dialog-request`](#in-dialog-request) | SIP routing and transactions |
| modparam | [`glossary.md#modparam`](#modparam) | Kamailio scripting concepts |
| Module | [`glossary.md#module`](#module) | Kamailio scripting concepts |
| Module name | [`glossary.md#module-name`](#module-name) | ferrosip-specific |
| myself | [`glossary.md#myself`](#myself) | Kamailio scripting concepts |
| NAPTR → DNS resolution | [`glossary.md#dns-resolution`](#dns-resolution) | SIP routing and transactions |
| NAT | [`glossary.md#nat`](#nat) | NAT and media |
| nathelper → NAT | [`glossary.md#nat`](#nat) | NAT and media |
| nc | [`glossary.md#nc`](#nc) | Authentication |
| Network address translation → NAT | [`glossary.md#nat`](#nat) | NAT and media |
| Next hop → Destination URI | [`glossary.md#destination-uri`](#destination-uri) | SIP routing and transactions |
| ng protocol → Media relay | [`glossary.md#media-relay`](#media-relay) | NAT and media |
| Nonce | [`glossary.md#nonce`](#nonce) | Authentication |
| Nonce count → nc | [`glossary.md#nc`](#nc) | Authentication |
| NOTIFY | [`glossary.md#notify`](#notify) | SIP basics |
| OCS | [`glossary.md#ocs`](#ocs) | IMS and Diameter |
| Offer and answer | [`glossary.md#offer-and-answer`](#offer-and-answer) | NAT and media |
| on (event handler) → Event handler | [`glossary.md#event-handler`](#event-handler) | ferrosip-specific |
| Online charging → Ro | [`glossary.md#ro`](#ro) | IMS and Diameter |
| Online Charging System → OCS | [`glossary.md#ocs`](#ocs) | IMS and Diameter |
| Onreply route | [`glossary.md#onreply-route`](#onreply-route) | Kamailio scripting concepts |
| `onreply_route` → Onreply route | [`glossary.md#onreply-route`](#onreply-route) | Kamailio scripting concepts |
| OPTIONS | [`glossary.md#options`](#options) | SIP basics |
| Outbound proxy | [`glossary.md#outbound-proxy`](#outbound-proxy) | SIP routing and transactions |
| Overlay | [`glossary.md#overlay`](#overlay) | ferrosip-specific |
| `--overlay` → Overlay | [`glossary.md#overlay`](#overlay) | ferrosip-specific |
| P-Asserted-Identity | [`glossary.md#p-asserted-identity`](#p-asserted-identity) | SIP basics |
| P-Associated-URI | [`glossary.md#p-associated-uri`](#p-associated-uri) | IMS and Diameter |
| P-CSCF | [`glossary.md#p-cscf`](#p-cscf) | IMS and Diameter |
| PAI → P-Asserted-Identity | [`glossary.md#p-asserted-identity`](#p-asserted-identity) | SIP basics |
| Parallel forking → Forking | [`glossary.md#forking`](#forking) | SIP routing and transactions |
| Path | [`glossary.md#path`](#path) | SIP routing and transactions |
| pcap | [`glossary.md#pcap`](#pcap) | Operations |
| PCRF | [`glossary.md#pcrf`](#pcrf) | IMS and Diameter |
| PIDF | [`glossary.md#pidf`](#pidf) | SIP basics |
| Policy and Charging Rules Function → PCRF | [`glossary.md#pcrf`](#pcrf) | IMS and Diameter |
| Preprocessor | [`glossary.md#preprocessor`](#preprocessor) | Kamailio scripting concepts |
| Presence | [`glossary.md#presence`](#presence) | SIP basics |
| Presentity | [`glossary.md#presentity`](#presentity) | SIP basics |
| Private user identity → IMPI | [`glossary.md#impi`](#impi) | IMS and Diameter |
| Prometheus → Prometheus metric | [`glossary.md#prometheus-metric`](#prometheus-metric) | Operations |
| Prometheus metric | [`glossary.md#prometheus-metric`](#prometheus-metric) | Operations |
| Provisional reply | [`glossary.md#provisional-reply`](#provisional-reply) | SIP basics |
| Proxy | [`glossary.md#proxy`](#proxy) | SIP basics |
| Proxy-Authenticate → Challenge | [`glossary.md#challenge`](#challenge) | Authentication |
| Proxy-CSCF → P-CSCF | [`glossary.md#p-cscf`](#p-cscf) | IMS and Diameter |
| Pseudo-variable (pv) | [`glossary.md#pseudo-variable-pv`](#pseudo-variable-pv) | Kamailio scripting concepts |
| PSTN | [`glossary.md#pstn`](#pstn) | SIP basics |
| PSTN gateway → Gateway | [`glossary.md#gateway`](#gateway) | SIP basics |
| Public user identity → IMPU | [`glossary.md#impu`](#impu) | IMS and Diameter |
| PUBLISH | [`glossary.md#publish`](#publish) | SIP basics |
| pv → Pseudo-variable (pv) | [`glossary.md#pseudo-variable-pv`](#pseudo-variable-pv) | Kamailio scripting concepts |
| q-value | [`glossary.md#q-value`](#q-value) | SIP routing and transactions |
| qop | [`glossary.md#qop`](#qop) | Authentication |
| Quality of protection → qop | [`glossary.md#qop`](#qop) | Authentication |
| R-URI | [`glossary.md#r-uri`](#r-uri) | SIP basics |
| `raw_kamailio` → Escape hatch | [`glossary.md#escape-hatch`](#escape-hatch) | ferrosip-specific |
| `$rc` → Return code convention | [`glossary.md#return-code-convention`](#return-code-convention) | Kamailio scripting concepts |
| re-INVITE | [`glossary.md#re-invite`](#re-invite) | SIP basics |
| Real-time Transport Protocol → RTP | [`glossary.md#rtp`](#rtp) | NAT and media |
| Realm | [`glossary.md#realm`](#realm) | Authentication |
| received | [`glossary.md#received`](#received) | SIP routing and transactions |
| Record-Route | [`glossary.md#record-route`](#record-route) | SIP routing and transactions |
| Reg event | [`glossary.md#reg-event`](#reg-event) | SIP basics |
| reg-event → Reg event | [`glossary.md#reg-event`](#reg-event) | SIP basics |
| reg-id → SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| REGISTER | [`glossary.md#register`](#register) | SIP basics |
| Registrar | [`glossary.md#registrar`](#registrar) | SIP basics |
| registrar (module) → Registrar | [`glossary.md#registrar`](#registrar) | SIP basics |
| Reload → Live reload | [`glossary.md#live-reload`](#live-reload) | ferrosip-specific |
| Remote procedure call → RPC | [`glossary.md#rpc`](#rpc) | ferrosip-specific |
| Reply code → Status code | [`glossary.md#status-code`](#status-code) | SIP basics |
| Reply route | [`glossary.md#reply-route`](#reply-route) | Kamailio scripting concepts |
| `reply_route` → Reply route | [`glossary.md#reply-route`](#reply-route) | Kamailio scripting concepts |
| Request route | [`glossary.md#request-route`](#request-route) | Kamailio scripting concepts |
| Request-URI → R-URI | [`glossary.md#r-uri`](#r-uri) | SIP basics |
| `request_route` → Request route | [`glossary.md#request-route`](#request-route) | Kamailio scripting concepts |
| Resource list | [`glossary.md#resource-list`](#resource-list) | SIP basics |
| Response → Status code | [`glossary.md#status-code`](#status-code) | SIP basics |
| Resume → Suspend and resume | [`glossary.md#suspend-and-resume`](#suspend-and-resume) | ferrosip-specific |
| Retransmission | [`glossary.md#retransmission`](#retransmission) | SIP routing and transactions |
| Return code convention | [`glossary.md#return-code-convention`](#return-code-convention) | Kamailio scripting concepts |
| RFC 3263 → DNS resolution | [`glossary.md#dns-resolution`](#dns-resolution) | SIP routing and transactions |
| RFC 5626 → SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| RLMI → Resource list | [`glossary.md#resource-list`](#resource-list) | SIP basics |
| RLS → Resource list | [`glossary.md#resource-list`](#resource-list) | SIP basics |
| Ro | [`glossary.md#ro`](#ro) | IMS and Diameter |
| Route | [`glossary.md#route`](#route) | SIP routing and transactions |
| Route block | [`glossary.md#route-block`](#route-block) | Kamailio scripting concepts |
| Route set → Route | [`glossary.md#route`](#route) | SIP routing and transactions |
| `route[NAME]` → Route block | [`glossary.md#route-block`](#route-block) | Kamailio scripting concepts |
| Routing language → .fsr | [`glossary.md#fsr`](#fsr) | ferrosip-specific |
| RPC | [`glossary.md#rpc`](#rpc) | ferrosip-specific |
| rport | [`glossary.md#rport`](#rport) | SIP routing and transactions |
| RTA → RTR | [`glossary.md#rtr`](#rtr) | IMS and Diameter |
| RTP | [`glossary.md#rtp`](#rtp) | NAT and media |
| rtpengine → Media relay | [`glossary.md#media-relay`](#media-relay) | NAT and media |
| rtpflux → Media relay | [`glossary.md#media-relay`](#media-relay) | NAT and media |
| RTR | [`glossary.md#rtr`](#rtr) | IMS and Diameter |
| `$ru` → R-URI | [`glossary.md#r-uri`](#r-uri) | SIP basics |
| Rx | [`glossary.md#rx`](#rx) | IMS and Diameter |
| S-CSCF | [`glossary.md#s-cscf`](#s-cscf) | IMS and Diameter |
| SAA → SAR | [`glossary.md#sar`](#sar) | IMS and Diameter |
| SAR | [`glossary.md#sar`](#sar) | IMS and Diameter |
| SBC | [`glossary.md#sbc`](#sbc) | SIP basics |
| SCA | [`glossary.md#sca`](#sca) | SIP basics |
| Scenario suite | [`glossary.md#scenario-suite`](#scenario-suite) | ferrosip-specific |
| Scenarios → Scenario suite | [`glossary.md#scenario-suite`](#scenario-suite) | ferrosip-specific |
| Schema | [`glossary.md#schema`](#schema) | ferrosip-specific |
| SDP | [`glossary.md#sdp`](#sdp) | NAT and media |
| Secure RTP → SRTP | [`glossary.md#srtp`](#srtp) | NAT and media |
| Security agreement → Security-Client | [`glossary.md#security-client`](#security-client) | IMS and Diameter |
| Security association → IPsec security association | [`glossary.md#ipsec-security-association`](#ipsec-security-association) | IMS and Diameter |
| Security Parameter Index → SPI | [`glossary.md#spi`](#spi) | IMS and Diameter |
| Security-Client | [`glossary.md#security-client`](#security-client) | IMS and Diameter |
| Security-Server → Security-Client | [`glossary.md#security-client`](#security-client) | IMS and Diameter |
| Security-Verify → Security-Client | [`glossary.md#security-client`](#security-client) | IMS and Diameter |
| Serial forking → Forking | [`glossary.md#forking`](#forking) | SIP routing and transactions |
| Service-Route | [`glossary.md#service-route`](#service-route) | SIP routing and transactions |
| Serving-CSCF → S-CSCF | [`glossary.md#s-cscf`](#s-cscf) | IMS and Diameter |
| Session border controller → SBC | [`glossary.md#sbc`](#sbc) | SIP basics |
| Session case → Trigger point | [`glossary.md#trigger-point`](#trigger-point) | IMS and Diameter |
| Session Description Protocol → SDP | [`glossary.md#sdp`](#sdp) | NAT and media |
| `--set` → Overlay | [`glossary.md#overlay`](#overlay) | ferrosip-specific |
| setbflag → Branch flags | [`glossary.md#branch-flags`](#branch-flags) | Kamailio scripting concepts |
| setflag → Flags | [`glossary.md#flags`](#flags) | Kamailio scripting concepts |
| Sh | [`glossary.md#sh`](#sh) | IMS and Diameter |
| Shared Call Appearances → SCA | [`glossary.md#sca`](#sca) | SIP basics |
| Shared table | [`glossary.md#shared-table`](#shared-table) | ferrosip-specific |
| shared table → Shared table | [`glossary.md#shared-table`](#shared-table) | ferrosip-specific |
| `shared_tables` → htable | [`glossary.md#htable`](#htable) | Kamailio scripting concepts |
| `$sht` → htable | [`glossary.md#htable`](#htable) | Kamailio scripting concepts |
| Shutdown → Graceful shutdown | [`glossary.md#graceful-shutdown`](#graceful-shutdown) | Operations |
| SIP | [`glossary.md#sip`](#sip) | SIP basics |
| SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| SIP URI | [`glossary.md#sip-uri`](#sip-uri) | SIP basics |
| SIP-ETag → Entity tag | [`glossary.md#entity-tag`](#entity-tag) | SIP basics |
| SIP-If-Match → Entity tag | [`glossary.md#entity-tag`](#entity-tag) | SIP basics |
| `+sip.instance` → SIP Outbound | [`glossary.md#sip-outbound`](#sip-outbound) | SIP routing and transactions |
| `sip_dump` → sipdump | [`glossary.md#sipdump`](#sipdump) | Operations |
| sipdump | [`glossary.md#sipdump`](#sipdump) | Operations |
| sipflood | [`glossary.md#sipflood`](#sipflood) | ferrosip-specific |
| SIPp | [`glossary.md#sipp`](#sipp) | Operations |
| siptrace | [`glossary.md#siptrace`](#siptrace) | Operations |
| Sipwise | [`glossary.md#sipwise`](#sipwise) | Kamailio scripting concepts |
| sl | [`glossary.md#sl`](#sl) | Kamailio scripting concepts |
| SPI | [`glossary.md#spi`](#spi) | IMS and Diameter |
| SRTP | [`glossary.md#srtp`](#srtp) | NAT and media |
| SRV → DNS resolution | [`glossary.md#dns-resolution`](#dns-resolution) | SIP routing and transactions |
| STA → STR | [`glossary.md#str`](#str) | IMS and Diameter |
| stale | [`glossary.md#stale`](#stale) | Authentication |
| Stateful → Stateful proxy | [`glossary.md#stateful-proxy`](#stateful-proxy) | SIP routing and transactions |
| Stateful proxy | [`glossary.md#stateful-proxy`](#stateful-proxy) | SIP routing and transactions |
| Stateless → Stateless proxy | [`glossary.md#stateless-proxy`](#stateless-proxy) | SIP routing and transactions |
| stateless (module) → sl | [`glossary.md#sl`](#sl) | Kamailio scripting concepts |
| Stateless proxy | [`glossary.md#stateless-proxy`](#stateless-proxy) | SIP routing and transactions |
| Statistics | [`glossary.md#statistics`](#statistics) | Operations |
| Status code | [`glossary.md#status-code`](#status-code) | SIP basics |
| STR | [`glossary.md#str`](#str) | IMS and Diameter |
| SUBSCRIBE | [`glossary.md#subscribe`](#subscribe) | SIP basics |
| Suspend → Suspend and resume | [`glossary.md#suspend-and-resume`](#suspend-and-resume) | ferrosip-specific |
| Suspend and resume | [`glossary.md#suspend-and-resume`](#suspend-and-resume) | ferrosip-specific |
| T1 and T2 → Retransmission | [`glossary.md#retransmission`](#retransmission) | SIP routing and transactions |
| `t_suspend` → Suspend and resume | [`glossary.md#suspend-and-resume`](#suspend-and-resume) | ferrosip-specific |
| Tag | [`glossary.md#tag`](#tag) | SIP basics |
| TCP reader → Worker | [`glossary.md#worker`](#worker) | ferrosip-specific |
| tel URI | [`glossary.md#tel-uri`](#tel-uri) | SIP basics |
| Test block | [`glossary.md#test-block`](#test-block) | ferrosip-specific |
| tm | [`glossary.md#tm`](#tm) | Kamailio scripting concepts |
| To tag → Tag | [`glossary.md#tag`](#tag) | SIP basics |
| TOML config → ferrosip.toml | [`glossary.md#ferrosiptoml`](#ferrosiptoml) | ferrosip-specific |
| topoh and topos → Topology hiding | [`glossary.md#topology-hiding`](#topology-hiding) | SIP routing and transactions |
| Topology hiding | [`glossary.md#topology-hiding`](#topology-hiding) | SIP routing and transactions |
| trace (module) → siptrace | [`glossary.md#siptrace`](#siptrace) | Operations |
| Transaction | [`glossary.md#transaction`](#transaction) | SIP routing and transactions |
| Transformation | [`glossary.md#transformation`](#transformation) | Kamailio scripting concepts |
| Trigger point | [`glossary.md#trigger-point`](#trigger-point) | IMS and Diameter |
| txn → tm | [`glossary.md#tm`](#tm) | Kamailio scripting concepts |
| UAA → UAR | [`glossary.md#uar`](#uar) | IMS and Diameter |
| UAC | [`glossary.md#uac`](#uac) | SIP basics |
| UAR | [`glossary.md#uar`](#uar) | IMS and Diameter |
| UAS | [`glossary.md#uas`](#uas) | SIP basics |
| UDA → UDR | [`glossary.md#udr`](#udr) | IMS and Diameter |
| UDR | [`glossary.md#udr`](#udr) | IMS and Diameter |
| UE | [`glossary.md#ue`](#ue) | IMS and Diameter |
| User agent | [`glossary.md#user-agent`](#user-agent) | SIP basics |
| User agent client → UAC | [`glossary.md#uac`](#uac) | SIP basics |
| User agent server → UAS | [`glossary.md#uas`](#uas) | SIP basics |
| User equipment → UE | [`glossary.md#ue`](#ue) | IMS and Diameter |
| User-Data-Request → UDR | [`glossary.md#udr`](#udr) | IMS and Diameter |
| usrloc | [`glossary.md#usrloc`](#usrloc) | Kamailio scripting concepts |
| `$var` → Pseudo-variable (pv) | [`glossary.md#pseudo-variable-pv`](#pseudo-variable-pv) | Kamailio scripting concepts |
| Via | [`glossary.md#via`](#via) | SIP routing and transactions |
| Watchdog → DWR | [`glossary.md#dwr`](#dwr) | IMS and Diameter |
| Watcher | [`glossary.md#watcher`](#watcher) | SIP basics |
| Web UI | [`glossary.md#web-ui`](#web-ui) | ferrosip-specific |
| WebRTC | [`glossary.md#webrtc`](#webrtc) | NAT and media |
| WebSocket | [`glossary.md#websocket`](#websocket) | NAT and media |
| webui → Web UI | [`glossary.md#web-ui`](#web-ui) | ferrosip-specific |
| Worker | [`glossary.md#worker`](#worker) | ferrosip-specific |
| Worker thread → Worker | [`glossary.md#worker`](#worker) | ferrosip-specific |
| WS and WSS → WebSocket | [`glossary.md#websocket`](#websocket) | NAT and media |
| WWW-Authenticate → Challenge | [`glossary.md#challenge`](#challenge) | Authentication |
| xavp | [`glossary.md#xavp`](#xavp) | Kamailio scripting concepts |
| `$xavp` → xavp | [`glossary.md#xavp`](#xavp) | Kamailio scripting concepts |
| XCAP | [`glossary.md#xcap`](#xcap) | SIP basics |

## SIP basics

### ACK

The request that confirms a final reply to an INVITE. For a 2xx it is a new request sent end to end. For an error reply it belongs to the INVITE's transaction and goes only one hop. [RFC 3261 §13.2.2.4, §17.1.1.3]

See also: [INVITE](#invite), [Transaction](#transaction), [Final reply](#final-reply).

### AoR

Address of record: the public SIP address of a user, such as `sip:alice@example.com`. People call the AoR, and the registrar maps it to the devices where the user can be reached right now. It is the To URI of a REGISTER. [RFC 3261 §6, §10]

See also: [Registrar](#registrar), [Location service](#location-service), [Contact](#contact).

### B2BUA

Back-to-back user agent: a server that ends the incoming call and starts a new one on the other side, with its own dialogs and Call-IDs. PBXs and session border controllers work this way. ferrosip is a proxy, not a B2BUA. [RFC 3261 §6, RFC 7092]

See also: [Proxy](#proxy), [SBC](#sbc).

### BLF

Busy lamp field: the lights on a desk phone that show whether colleagues are on a call. Phones get this by subscribing to the `dialog` event package. The NOTIFY bodies are `application/dialog-info+xml` documents. [RFC 4235]

See also: [Event package](#event-package), [Presence](#presence), [Dialog](#dialog).

### BYE

The request that ends an established call. Either side may send it. [RFC 3261 §15]

See also: [Dialog](#dialog), [In-dialog request](#in-dialog-request).

### Call-ID

A header with a unique id that groups all messages of one call or one registration. Together with the From and To tags it identifies a dialog. [RFC 3261 §8.1.1.4]

```text
Call-ID: a84b4c76e66710@192.0.2.10
```

See also: [Tag](#tag), [Dialog](#dialog), [CSeq](#cseq).

### CANCEL

A request that stops an INVITE that has not been answered yet, for example when the caller hangs up while it rings. The callee answers the CANCEL with 200 and the INVITE with 487. A proxy also cancels the other branches when one answers. [RFC 3261 §9]

See also: [Forking](#forking), [Branch](#branch), [INVITE](#invite).

### Contact

A header that gives the address where a user agent can be reached directly. In a REGISTER it is the binding to store. In an INVITE or its 200 it is where later requests of the dialog go. [RFC 3261 §8.1.1.8, §20.10]

```text
Contact: <sip:alice@192.0.2.10:5060;transport=udp>;expires=3600;q=0.8
```

See also: [Location service](#location-service), [q-value](#q-value), [Dialog](#dialog).

### CSeq

Command sequence: a header with a number and a method, such as `CSeq: 314159 INVITE`. The number goes up with each new request in a dialog, so the receiver can spot old or repeated requests. A reply copies the CSeq of its request. [RFC 3261 §8.1.1.5]

See also: [Call-ID](#call-id), [Transaction](#transaction).

### Diversion header

A header a proxy adds when it sends a call somewhere other than the dialed user, for example to voicemail. It names the original callee and the reason, such as `user-busy` or `no-answer`. [RFC 5806]

```text
Diversion: <sip:101@pbx.example.com>;reason=user-busy
```

See also: [Header field](#header-field), [Forking](#forking).

### E.164

The international phone number format: a `+`, the country code, then the subscriber number, at most 15 digits in all. Carriers and gateways exchange numbers in this form. [ITU-T E.164]

```text
+493012345678
```

See also: [tel URI](#tel-uri), [ENUM](#enum), [PSTN](#pstn).

### Entity tag

An ID (`SIP-ETag`) the presence server returns for an accepted PUBLISH. The client sends it back in `SIP-If-Match` to refresh, change or remove that publication. [RFC 3903]

See also: [PUBLISH](#publish), [Presence](#presence).

### Event package

The name of a kind of state you can subscribe to, given in the `Event` header. Examples: `presence`, `dialog` (calls, for BLF), `reg` (registrations) and `message-summary` (voicemail). [RFC 6665 §7]

```text
Event: dialog
```

See also: [SUBSCRIBE](#subscribe), [BLF](#blf), [Reg event](#reg-event).

### Final reply

A reply with a code of 200 or more. It ends the transaction. A 2xx means success, and anything from 300 up is a failure. [RFC 3261 §7.2]

See also: [Provisional reply](#provisional-reply), [Transaction](#transaction), [Failure route](#failure-route).

### Gateway

A device that connects SIP to the ordinary phone network (PSTN). It turns SIP calls into phone calls and back. A proxy that has several gateways picks one per call, for example with LCR.

See also: [PSTN](#pstn), [LCR](#lcr), [E.164](#e164).

### Header field

A `Name: value` line in a SIP message, like an HTTP header. Some have a short compact form (`v` for Via, `m` for Contact). The `.cfg` language reads them with `$hdr(Name)`, and `.fsr` with `msg.headers["Name"]`. [RFC 3261 §7.3]

See also: [Pseudo-variable (pv)](#pseudo-variable-pv), [Lumps](#lumps).

### INVITE

The request that starts a call. It usually carries an SDP offer for the media. It is the only request with a three-way handshake: INVITE, a final reply, then ACK. [RFC 3261 §13]

See also: [ACK](#ack), [re-INVITE](#re-invite), [SDP](#sdp).

### Max-Forwards

A header that counts down by one at each hop, like the IP TTL. A request that arrives with 0 is answered `483 Too Many Hops`, which stops routing loops. In `.fsr`: `guard msg.max_forwards > 0 else reply(TooManyHops)`. [RFC 3261 §8.1.1.6]

See also: [Proxy](#proxy), [Lint](#lint).

### MESSAGE

A request that carries an instant message in its body, outside any call. [RFC 3428]

See also: [Method](#method).

### Method

The verb of a SIP request, the first word of its first line. The common ones are REGISTER, INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY and PUBLISH. In `.fsr` a method is a constant: `if msg.method == INVITE { … }`. [RFC 3261 §7.1]

See also: [INVITE](#invite), [REGISTER](#register), [OPTIONS](#options).

### NOTIFY

A request that carries the current state to a subscriber. One comes at once after a SUBSCRIBE, and more follow whenever the state changes. [RFC 6665]

See also: [SUBSCRIBE](#subscribe), [Event package](#event-package).

### OPTIONS

A request that asks a server what it supports. In practice it is mostly a ping: load balancers and the `keepalive` module send OPTIONS and treat a 2xx as "alive". [RFC 3261 §11]

See also: [Keepalive](#keepalive), [Dispatcher](#dispatcher).

### P-Asserted-Identity

A header in which a trusted network states who the caller really is, after checking it. Proxies remove it from requests that come from outside the trusted network. `Privacy: id` asks that it not be shown to the far end. Short name: PAI. [RFC 3325]

```text
P-Asserted-Identity: <sip:+493012345678@example.com>
```

See also: [Header field](#header-field), [P-Associated-URI](#p-associated-uri).

### PIDF

Presence Information Data Format: the XML body (`application/pidf+xml`) that carries a presentity's state in a PUBLISH or NOTIFY. [RFC 3863]

See also: [Presence](#presence), [PUBLISH](#publish).

### Presence

A SIP service that shares a user's state (online, busy, on the phone) with people who ask for it. Watchers subscribe to the state, and the presence server notifies them when it changes. ferrosip's `presence` module is the server. [RFC 3856]

See also: [SUBSCRIBE](#subscribe), [NOTIFY](#notify), [PUBLISH](#publish), [Event package](#event-package).

### Presentity

The user whose presence state ("online", "on a call") others can watch. Its address is the Request-URI of a presence SUBSCRIBE. [RFC 3856]

See also: [Presence](#presence), [Watcher](#watcher), [PUBLISH](#publish).

### Provisional reply

A 1xx reply. It says "working on it" and is never the last word. `100 Trying` stops the sender from retransmitting, and `180 Ringing` or `183 Session Progress` tell the caller about progress. [RFC 3261 §7.2, §21.1]

See also: [Final reply](#final-reply), [Status code](#status-code).

### Proxy

A SIP server that forwards requests towards their target and passes replies back, without taking part in the call itself. It may change the R-URI and add headers such as Via and Record-Route, but it does not answer for the user. ferrosip is a proxy. [RFC 3261 §16]

See also: [Stateless proxy](#stateless-proxy), [Stateful proxy](#stateful-proxy), [B2BUA](#b2bua).

### PSTN

The public switched telephone network: the ordinary phone network with numbers. A PSTN gateway or a carrier trunk connects SIP to it. [ITU-T E.164 numbers]

See also: [LCR](#lcr), [Dispatcher](#dispatcher).

### PUBLISH

A request that a device uses to upload its own state to the presence server, which then notifies the watchers. ferrosip's `presence_client` module (Kamailio's pua) sends PUBLISH on behalf of other modules. [RFC 3903]

See also: [Presence](#presence), [NOTIFY](#notify).

### R-URI

The Request-URI: the address in the first line of a request (`INVITE sip:bob@example.com SIP/2.0`). It says who the request is for, and proxies rewrite it as they route. `.cfg` reads and sets it as `$ru`, `.fsr` as `msg.ruri`. [RFC 3261 §8.1.1.1]

See also: [Destination URI](#destination-uri), [AoR](#aor), [Proxy](#proxy).

### re-INVITE

An INVITE sent inside an existing call to change it, for example to put it on hold or to move the media. It has the dialog's tags and goes along the dialog's route. [RFC 3261 §14]

See also: [In-dialog request](#in-dialog-request), [Dialog](#dialog).

### Reg event

The `reg` event package: a subscription to the registration state of a user. IMS uses it so phones and the P-CSCF learn when a registration ends or changes. ferrosip's S-CSCF serves it. [RFC 3680]

See also: [Event package](#event-package), [S-CSCF](#s-cscf), [IMS](#ims).

### REGISTER

The request a device sends to tell the registrar "I am alice, reach me here". The To header holds the AoR and the Contact header holds the device's address. An `Expires` value sets how long the binding lasts, and `Expires: 0` removes it. [RFC 3261 §10.2]

```text
REGISTER sip:example.com SIP/2.0
To: <sip:alice@example.com>
Contact: <sip:alice@192.0.2.10:5060>;expires=3600
```

See also: [Registrar](#registrar), [Contact](#contact), [Location service](#location-service).

### Registrar

A server that accepts REGISTER requests and stores where each user can be reached. ferrosip's registrar is the `location` module (Kamailio's registrar and usrloc). `location.save()` stores the bindings and answers the REGISTER itself. [RFC 3261 §10]

See also: [REGISTER](#register), [Location service](#location-service), [usrloc](#usrloc).

### Resource list

A list URI a user subscribes to once to get the state of every member of the list. The NOTIFYs carry an index of the members, called RLMI. A server that handles these is a resource list server (RLS). [RFC 4662]

See also: [SUBSCRIBE](#subscribe), [Presence](#presence), [XCAP](#xcap).

### SBC

Session border controller: a device at the edge of a network that hides the inside, fixes NAT problems and often relays media. Most SBCs are B2BUAs. ferrosip can do much of this job as a proxy, with topology hiding and a media relay. [RFC 7092]

See also: [B2BUA](#b2bua), [Topology hiding](#topology-hiding), [Media relay](#media-relay).

### SCA

Shared Call Appearances: several phones share one line, and each phone sees which call slots ("appearances") on the line are in use. It is a BroadSoft extension built on SUBSCRIBE/NOTIFY.

See also: [BLF](#blf), [Presence](#presence).

### SIP

The Session Initiation Protocol. It sets up, changes and ends calls and other sessions between endpoints. Its messages are text, much like HTTP: a request line or a status line, header fields, a blank line and an optional body. [RFC 3261]

```text
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds
From: <sip:alice@example.com>;tag=1928301774
To: <sip:bob@example.com>
Call-ID: a84b4c76e66710@192.0.2.10
CSeq: 314159 INVITE
Max-Forwards: 70
Contact: <sip:alice@192.0.2.10:5060>
```

See also: [Method](#method), [Status code](#status-code), [SIP URI](#sip-uri).

### SIP URI

The address format of SIP. It looks like an email address with a scheme: `sip:alice@example.com`, or `sips:` when every hop must use TLS. It can carry a port and parameters, such as `sip:alice@192.0.2.10:5070;transport=tcp`. [RFC 3261 §19.1]

See also: [AoR](#aor), [R-URI](#r-uri).

### Status code

The three-digit number in a reply, as in HTTP. The first digit is its class: 1xx provisional, 2xx success, 3xx redirect, 4xx client error, 5xx server error and 6xx global failure. Examples: `180 Ringing`, `200 OK`, `404 Not Found`, `486 Busy Here`. [RFC 3261 §21]

See also: [Provisional reply](#provisional-reply), [Final reply](#final-reply).

### SUBSCRIBE

A request that asks to be told about some state for a while (the `Expires` time). The server answers it and then sends NOTIFY requests. [RFC 6665]

See also: [NOTIFY](#notify), [Event package](#event-package), [Presence](#presence).

### Tag

A random value in the From and To headers (`From: <sip:alice@example.com>;tag=1928301774`). The caller sets the From tag, and the callee adds the To tag in its reply. A request whose To header has a tag belongs to an existing dialog. [RFC 3261 §19.3]

See also: [Dialog](#dialog), [In-dialog request](#in-dialog-request), [Call-ID](#call-id).

### tel URI

A URI that names a phone number instead of a SIP address. It has no host part, so a proxy needs a rule (or ENUM) to find where to send it. [RFC 3966]

```text
tel:+493012345678
```

See also: [SIP URI](#sip-uri), [E.164](#e164), [ENUM](#enum).

### UAC

User agent client: the side that sends a request in one exchange. A phone that places a call acts as a UAC for that INVITE. ferrosip also acts as a UAC when it sends its own requests, such as OPTIONS probes or a BYE that ends a dialog. [RFC 3261 §6]

See also: [UAS](#uas), [User agent](#user-agent), [Transaction](#transaction).

### UAS

User agent server: the side that receives a request and answers it. One device is a UAC for the requests it sends and a UAS for the ones it receives. [RFC 3261 §6]

See also: [UAC](#uac), [User agent](#user-agent).

### User agent

An endpoint that sends and answers SIP requests: a desk phone, a softphone app, a voicemail server or a browser. It holds the user's side of each call. [RFC 3261 §6]

See also: [UAC](#uac), [UAS](#uas), [Proxy](#proxy).

### Watcher

The subscriber that receives NOTIFYs about a presentity's state. Whether a watcher may see the state is decided by authorization rules. [RFC 3856]

See also: [Presentity](#presentity), [SUBSCRIBE](#subscribe), [NOTIFY](#notify).

### XCAP

XML Configuration Access Protocol: a way to store XML documents such as resource lists and presence authorization rules. In ferrosip the presence modules read these documents from a database table. [RFC 4825]

See also: [Resource list](#resource-list), [Watcher](#watcher).

## SIP routing and transactions

### Branch

One copy of a request sent to one target. A stateful proxy that forks makes one branch per target, all in the same transaction. In a `.cfg`, `$T_branch_idx` is the branch number. [RFC 3261 §16.6]

See also: [Forking](#forking), [Branch parameter](#branch-parameter), [Branch route](#branch-route).

### Branch parameter

The `branch` parameter of a Via header, a unique id that starts with the magic cookie `z9hG4bK`. It names one transaction at one hop, so replies and retransmissions can be matched. A forking proxy gives each of its branches its own value. [RFC 3261 §8.1.1.7]

See also: [Via](#via), [Transaction](#transaction), [Branch](#branch).

### Destination set

The list of extra targets a request will be forked to, besides the R-URI. `lookup()` fills it with every contact of the user, and `append_branch()` adds one. [Kamailio: destination set]

See also: [Forking](#forking), [Branch](#branch).

### Destination URI

The next hop to send a request to, when that differs from the R-URI, such as the address a phone registered from. `.cfg` sets it as `$du`, `.fsr` as `msg.dst_uri`. The R-URI still says who the request is for. [Kamailio: `$du`]

See also: [R-URI](#r-uri), [Outbound proxy](#outbound-proxy).

### Dialog

A call, as SIP sees it: a lasting relation between two user agents, created by a 2xx to an INVITE and ended by a BYE. It is identified by the Call-ID and the two tags. The `dialog` module tracks dialogs so the proxy can count calls, time them out and end them. [RFC 3261 §12]

See also: [Transaction](#transaction), [Tag](#tag), [Dialog profile](#dialog-profile).

### DNS resolution

How a proxy turns a host name in a SIP URI into an address. It looks up NAPTR records to pick a transport, then SRV records (`_sip._udp.example.com`) for hosts and ports, then A or AAAA records. ferrosip does this in the `txn` module. [RFC 3263]

See also: [Destination blocklist](#destination-blocklist), [SIP URI](#sip-uri).

### ENUM

A way to map an E.164 phone number to a URI through DNS: the digits are reversed into a domain name, and its NAPTR records give the URI. [RFC 6116]

```text
+4930123 -> 3.2.1.0.3.9.4.e164.arpa -> sip:user@example.com
```

See also: [E.164](#e164), [DNS resolution](#dns-resolution), [tel URI](#tel-uri).

### Final response timer

How long a transaction waits for a final reply. In ferrosip `fr_timer` applies until the first provisional reply, and `fr_inv_timer` applies while an INVITE rings. When it runs out, the branch counts as a `408 Request Timeout`. [Kamailio: tm `fr_timer`, `fr_inv_timer`]

See also: [Transaction](#transaction), [Retransmission](#retransmission).

### Forking

Sending one request to several targets. Parallel forking rings them all at once, and the first to answer wins. Serial forking tries them one after another, in order of q-value. ferrosip's `fork_by_q` mixes both: groups of equal q ring together. [RFC 3261 §16.6–16.7]

```toml
[modules.txn]
fork_by_q = true   # serial by q, equal q in parallel
```

See also: [q-value](#q-value), [Branch](#branch), [CANCEL](#cancel).

### GRUU

Globally routable user agent URI: an address that reaches one specific device of a user, not all of them. The registrar hands it out in the 200 to a REGISTER when the device asks with `Supported: gruu`. [RFC 5627]

See also: [SIP Outbound](#sip-outbound), [Registrar](#registrar).

### In-dialog request

A request inside an existing dialog, such as BYE, re-INVITE or an ACK for a 2xx. Its To header has a tag. It follows the route set that Record-Route built, so a script checks `has_totag()` (`.cfg`) or `msg.has_to_tag` (`.fsr`) and calls `loose_route()`. [RFC 3261 §12.2]

See also: [Initial request](#initial-request), [Record-Route](#record-route), [Loose routing](#loose-routing).

### Initial request

A request that does not belong to an existing dialog, such as a new INVITE, REGISTER or OPTIONS. It has no To tag. Routing scripts usually treat these in full and pass in-dialog requests along their recorded route. [RFC 3261 §12]

See also: [In-dialog request](#in-dialog-request), [Tag](#tag).

### Location service

The table that maps each AoR to its current contacts, called bindings. The registrar fills it, and `location.lookup()` reads it to find where to send a call. Kamailio calls it usrloc and the "location" table. [RFC 3261 §10]

See also: [Registrar](#registrar), [usrloc](#usrloc), [AoR](#aor).

### Loose routing

The normal way to follow a Route header: the R-URI keeps the final target, and the Route header holds the hops on the way. Each proxy removes its own entry and sends to the next. The `;lr` parameter marks a loose router. `loose_route()` does this in a script. [RFC 3261 §16.12, §19.1.1]

See also: [Route](#route), [Record-Route](#record-route).

### Outbound proxy

A proxy that a user agent sends all its requests to, whatever the target. Phones are usually set up with one. [RFC 3261 §8.1.2]

See also: [Proxy](#proxy), [SIP Outbound](#sip-outbound).

### Path

A header that edge proxies add to a REGISTER, so that calls to the user later pass through them on the way in. The registrar stores the Path with the binding and puts it into Route when it forwards a call. Turn it on with `use_path` in `[modules.location]`. [RFC 3327]

See also: [Service-Route](#service-route), [Registrar](#registrar), [Route](#route).

### q-value

A preference between 0 and 1 on a Contact (`;q=0.8`). Higher q is tried first when forking serially. [RFC 3261 §16.6, §20.10]

See also: [Forking](#forking), [Contact](#contact).

### received

A Via parameter that a server adds when the sender's address in Via differs from the address the packet came from. It records the real source IP, which matters behind NAT. ferrosip stamps it on arrival. [RFC 3261 §18.2.1]

```text
Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1;received=203.0.113.7;rport=40312
```

See also: [rport](#rport), [Via](#via), [NAT](#nat).

### Record-Route

A header a proxy adds to an initial request to stay on the path of the whole dialog. The user agents copy the list into their route set, and later in-dialog requests then pass through the proxy. `record_route()` (`.cfg`) adds it. [RFC 3261 §16.6, §20.30]

```text
Record-Route: <sip:192.0.2.1;lr>
```

See also: [Route](#route), [Loose routing](#loose-routing), [In-dialog request](#in-dialog-request).

### Retransmission

Over UDP, a SIP message may get lost, so the sender sends it again on a timer until it gets an answer. The timer starts at T1 (500 ms) and doubles up to T2 (4 s). Over TCP and TLS there are no retransmissions. [RFC 3261 §17.1]

See also: [Transaction](#transaction), [Final response timer](#final-response-timer).

### Route

A header that lists the proxies a request must pass through before it reaches the R-URI. In-dialog requests carry the route set from Record-Route, and a REGISTER's Path or a Service-Route also ends up here. [RFC 3261 §20.34]

```text
Route: <sip:192.0.2.1;lr>, <sip:198.51.100.2;lr>
```

See also: [Record-Route](#record-route), [Loose routing](#loose-routing), [Path](#path).

### rport

A Via parameter for the source port. The sender adds an empty `;rport`, and the server fills in the port the packet came from and sends the reply there. This makes replies cross NAT. ferrosip replies to the source port by default, as if `force_rport()` were always on. [RFC 3581]

See also: [received](#received), [NAT](#nat), [Via](#via).

### Service-Route

A header the registrar returns in the 200 to a REGISTER. It lists the proxies that the user's own outgoing requests must pass through. IMS uses it so a phone's requests reach its S-CSCF. [RFC 3608]

See also: [Path](#path), [S-CSCF](#s-cscf), [Outbound proxy](#outbound-proxy).

### SIP Outbound

A standard way for devices behind NAT to keep a connection open to the proxy and use it for calls to them. Each device has an instance id (`+sip.instance`). Each of its connections, called a flow, has a `reg-id`. If one flow fails (`430 Flow Failed`), the proxy tries the next. [RFC 5626]

```text
Contact: <sip:alice@192.0.2.10>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-000A95A0E128>";reg-id=1
```

See also: [Keepalive](#keepalive), [NAT](#nat), [GRUU](#gruu).

### Stateful proxy

A proxy that keeps a transaction for each request it forwards. It retransmits over UDP, forks to several targets, picks the best reply and can try again after a failure. In ferrosip, `relay()`, `await txn.relay()` and `t_relay()` are stateful. [RFC 3261 §16]

See also: [Transaction](#transaction), [Forking](#forking), [tm](#tm).

### Stateless proxy

A proxy that forwards each message and forgets it at once. It does not retransmit, does not fork and does not see the final outcome. It is fast and uses no memory per call. Replies find their way back through the Via headers. [RFC 3261 §16.11]

See also: [Stateful proxy](#stateful-proxy), [sl](#sl), [Via](#via).

### Topology hiding

Removing internal addresses (Via, Record-Route, Contact) from messages before they leave the network, so outsiders cannot see its layout. ferrosip's `topology` module does it (Kamailio's topoh and topos). [Kamailio: `topoh`, `topos`]

See also: [SBC](#sbc), [Via](#via).

### Transaction

One request plus all its replies, up to the final reply (and the ACK for an INVITE error). Retransmissions and replies are matched to it by the Via branch parameter. Kamailio's `tm` module, `txn` in ferrosip, keeps transactions. [RFC 3261 §17]

See also: [Branch parameter](#branch-parameter), [tm](#tm), [Stateful proxy](#stateful-proxy).

### Via

A header that records the path a request took. Each hop adds its own Via on top, and replies retrace them in reverse, each hop removing its own. [RFC 3261 §8.1.1.7, §20.42]

```text
Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds;rport
```

See also: [Branch parameter](#branch-parameter), [received](#received), [rport](#rport).

## Authentication

### Challenge

The server's demand for credentials. A registrar or user agent answers `401 Unauthorized` with a `WWW-Authenticate` header. A proxy answers `407 Proxy Authentication Required` with `Proxy-Authenticate`. The client retries with an `Authorization` or `Proxy-Authorization` header. [RFC 3261 §22.2–22.3]

```text
WWW-Authenticate: Digest realm="example.com", nonce="b7c9036d", qop="auth", algorithm=MD5
```

See also: [Digest authentication](#digest-authentication), [Realm](#realm), [stale](#stale).

### cnonce

The client nonce: a random value the client adds when `qop` is used. It makes the answer depend on the client's randomness too. [RFC 7616 §3.4]

See also: [Nonce](#nonce), [qop](#qop).

### Digest authentication

SIP's password check, borrowed from HTTP. The server answers a request with a challenge, and the client repeats it with a hash of the password, the nonce and the request. The password itself never crosses the network. ferrosip supports MD5 and SHA-256. [RFC 3261 §22, RFC 7616, RFC 8760]

See also: [Challenge](#challenge), [Nonce](#nonce), [HA1](#ha1).

### HA1

The hash of `username:realm:password`. A server can store HA1 instead of the plain password and still check digest answers. In ferrosip's users file a line looks like `alice md5:4a3b…` or `alice sha256:…`. [RFC 7616 §3.4.2]

See also: [Digest authentication](#digest-authentication), [Realm](#realm).

### nc

Nonce count: a counter the client sends with each request that reuses the same nonce (`nc=00000001`, then `00000002`). The server rejects a count it has already seen, which stops replays. [RFC 7616 §3.4]

See also: [Nonce](#nonce), [qop](#qop).

### Nonce

A one-time random value the server puts in a challenge. The client must hash it into its answer, so an old answer cannot be replayed later. ferrosip's nonces are stateless: they hold an expiry and a signature, so any worker can check them. [RFC 7616 §3.3]

See also: [nc](#nc), [stale](#stale), [cnonce](#cnonce).

### qop

Quality of protection: which parts the digest covers. `qop=auth` covers the request line and credentials. `qop=auth-int` also covers the body. With qop the client must send `cnonce` and `nc`. [RFC 7616 §3.3]

See also: [nc](#nc), [cnonce](#cnonce), [Digest authentication](#digest-authentication).

### Realm

The name of the protection area in a challenge, usually the SIP domain (`realm="example.com"`). The client uses it to pick the right username and password, and it is part of HA1. [RFC 3261 §22.1]

See also: [HA1](#ha1), [Challenge](#challenge), [Diameter realm](#diameter-realm).

### stale

A challenge parameter. `stale=true` tells the client that its password was right but the nonce has expired or was reused. The client then retries with the new nonce without asking the user again. [RFC 7616 §3.3]

See also: [Nonce](#nonce), [Challenge](#challenge).

## NAT and media

### DTLS

Datagram TLS: TLS over UDP. WebRTC uses it on the media path to agree on the SRTP keys (DTLS-SRTP). The media relay handles it. ferrosip only passes it flags such as `DTLS=off`. [RFC 6347, RFC 5764]

See also: [SRTP](#srtp), [WebRTC](#webrtc), [Media relay](#media-relay).

### ICE

Interactive Connectivity Establishment: a way for two endpoints to try several address pairs and pick one that works through NAT. Browsers use it. A media relay can remove it (`ICE=remove`) when the other side is a plain SIP phone. [RFC 8445]

See also: [WebRTC](#webrtc), [NAT](#nat), [Media relay](#media-relay).

### Keepalive

A small message sent at regular intervals to keep a NAT mapping or a connection open, or to check that a peer is alive. It can be an OPTIONS request, a CRLF over TCP or a WebSocket ping. ferrosip's `keepalive` module also probes destinations with OPTIONS and runs an event when one goes up or down. [RFC 5626 §4.4]

See also: [NAT](#nat), [OPTIONS](#options), [SIP Outbound](#sip-outbound).

### Media relay

A server that sits in the media path and forwards RTP between the two sides. It fixes one-way audio behind NAT and can convert between WebRTC and plain RTP. ferrosip controls rtpengine (or rtpflux) over its "ng" control protocol with the `media` module: `media.offer()` on the INVITE and `media.answer()` on the reply. [Kamailio: `rtpengine`]

See also: [RTP](#rtp), [SDP](#sdp), [NAT](#nat).

### NAT

Network address translation: a home router or firewall that rewrites private addresses (10.x, 192.168.x) into a public one. SIP writes addresses inside its messages, so a phone behind NAT often gives addresses that cannot be reached. The proxy fixes this with `received`, `rport`, Contact rewriting (the `nat` module, Kamailio's nathelper) and keepalives. [RFC 3581, RFC 5626]

See also: [received](#received), [rport](#rport), [Keepalive](#keepalive), [Media relay](#media-relay).

### Offer and answer

The model for agreeing on media. One side sends an SDP offer, usually in the INVITE, and the other replies with an SDP answer, usually in the 183 or 200. [RFC 3264]

See also: [SDP](#sdp), [INVITE](#invite).

### RTP

Real-time Transport Protocol: the UDP packets that carry the audio and video once a call is set up. RTP does not pass through the SIP proxy unless a media relay is used. [RFC 3550]

See also: [SDP](#sdp), [Media relay](#media-relay), [SRTP](#srtp).

### SDP

Session Description Protocol: the body of an INVITE or its reply that describes the media. It lists the IP address, ports and codecs each side wants to use. [RFC 8866]

```text
c=IN IP4 192.0.2.10
m=audio 49170 RTP/AVP 0 8
```

See also: [Offer and answer](#offer-and-answer), [RTP](#rtp), [Media relay](#media-relay).

### SRTP

Secure RTP: RTP with encryption and integrity checks. WebRTC always uses it. [RFC 3711]

See also: [RTP](#rtp), [DTLS](#dtls), [WebRTC](#webrtc).

### WebRTC

The browser standard for real-time audio and video. A browser can make SIP calls by sending SIP over a WebSocket and media over SRTP with ICE and DTLS. [RFC 8825]

See also: [WebSocket](#websocket), [ICE](#ice), [DTLS](#dtls).

### WebSocket

A long-lived two-way connection that starts as an HTTP request and is upgraded. SIP over WebSocket lets browsers talk SIP. ferrosip listens on it with `-l ws:IP:PORT`, or `wss:` for TLS. [RFC 6455, RFC 7118]

See also: [WebRTC](#webrtc), [Keepalive](#keepalive).

## Kamailio scripting concepts

### AVP

Attribute-value pair, in a Kamailio script: a variable written `$avp(name)` that belongs to the transaction. It is still there in failure and reply routes, and after `await` in `.fsr`. Assigning adds a value on top, so one name can hold a list. `.fsr` `let` variables are AVPs. [Kamailio: `$avp`]

See also: [xavp](#xavp), [Pseudo-variable (pv)](#pseudo-variable-pv), [Diameter AVP](#diameter-avp).

### Branch flags

Flags that belong to one branch, not the whole transaction, set with `setbflag()`. Flags set before `save()` are stored with the contact and come back on `lookup()`. The `nat` module uses one to know which contacts to keep alive. [Kamailio: branch flags]

See also: [Flags](#flags), [Branch](#branch), [Keepalive](#keepalive).

### Branch route

`branch_route[NAME]`: a block that runs once for each branch just before it is sent. It can change that branch only, or drop it. It is armed with `t_on_branch("NAME")`. [Kamailio: tm `t_on_branch`]

See also: [Branch](#branch), [Forking](#forking).

### .cfg

A Kamailio routing script. It holds global settings, `loadmodule` and `modparam` lines, and route blocks written in Kamailio's own language. ferrosip runs `.cfg` files unchanged, and `ferrosip import` converts them to `.fsr`. [Kamailio: core cookbook]

```text
request_route {
    if (!mf_process_maxfwd_header("10")) { sl_send_reply("483", "Too Many Hops"); exit; }
    t_relay();
}
```

See also: [Route block](#route-block), [.fsr](#fsr), [Preprocessor](#preprocessor).

### Destination blocklist

A short-lived list of next hops that just failed (no answer, send error, 503). Forking and DNS failover skip them until they expire. [Kamailio: `dst_blocklist`, `blst`]

See also: [DNS resolution](#dns-resolution), [Forking](#forking).

### Dialog profile

A named group of active dialogs, used to count calls. A script adds a call to a profile, then asks how many calls the profile holds to enforce a limit. [Kamailio: dialog `set_dlg_profile`, `get_profile_size`]

```text
set_dlg_profile("caller", "$fU");
get_profile_size("caller", "$fU", "$var(n)");
if ($var(n) > 2) { sl_send_reply("486", "Too many calls"); exit; }
```

See also: [Dialog](#dialog).

### Dispatcher

Kamailio's load balancer module, `balancer` in ferrosip. It holds sets of destinations, picks one per call by an algorithm (round robin, hash of Call-ID, weight, …), probes them with OPTIONS and skips the ones that are down. [Kamailio: `dispatcher`]

```text
ds_select_dst("1", "4");   # set 1, round robin
```

See also: [LCR](#lcr), [Keepalive](#keepalive).

### DMQ

Kamailio's distributed message queue: proxies send each other SIP messages to keep shared state, such as htable items or registrations, in step. ferrosip does not implement it.

See also: [htable](#htable).

### Event route

`event_route[module:event]`: a block a module runs when something happens outside a normal request, such as a gateway going down (`event_route[dispatcher:dst-down]`) or a WebSocket handshake. In `.fsr` these are `on …` event handlers. [Kamailio: `event_route`]

See also: [Event handler](#event-handler), [Route block](#route-block).

### Failure route

`failure_route[NAME]`: a block that runs when every branch of a transaction failed or timed out, before the error goes back to the caller. It can try another target, such as voicemail or the next gateway. It is armed per transaction with `t_on_failure("NAME")`. In `.fsr` the code after `await txn.relay()` does this job. [Kamailio: tm `t_on_failure`]

```text
failure_route[VOICEMAIL] {
    if (t_check_status("486|408")) { rewriteuri("sip:vm@10.0.0.9"); t_relay(); }
}
```

See also: [await](#await), [Route block](#route-block), [tm](#tm).

### Fixup

The step at startup that turns a function's text arguments into ready-to-use values: numbers, compiled regexes, templates or resolved route names. Errors in arguments show up at startup, not on the first call. [Kamailio: fixup functions]

See also: [Module](#module), [.cfg](#cfg).

### Flags

Message flags: numbered on/off bits attached to a request and its transaction, set with `setflag(1)` and tested with `isflagset(1)`. Scripts use them to remember things such as "this caller is behind NAT". In `.fsr` they have names: `flag NATED`, then `msg.set(NATED)`. [Kamailio: core flags]

See also: [Branch flags](#branch-flags).

### htable

Kamailio's shared hash tables: key-value storage shared by all workers, with optional expiry. A script reads them as `$sht(table=>key)`. In ferrosip the module is `shared_tables`, and `.fsr` declares them as `shared table`. [Kamailio: `htable`]

See also: [Shared table](#shared-table).

### Kamailio

A widely used open-source SIP server written in C. ferrosip copies its design, runs its `.cfg` scripts and implements about 100 of its modules. [kamailio.org]

See also: [.cfg](#cfg), [Module](#module), [Import](#import).

### kamcmd

Kamailio's command-line tool for RPC commands. ferrosip's equivalent is `ferroctl`. [Kamailio: `kamcmd`]

See also: [ferroctl](#ferroctl), [RPC](#rpc).

### KEMI

Kamailio Embedded Interface: writing the routing in a general language, such as Lua, instead of `.cfg`. Module functions are called through the `KSR` object, as in `KSR.tm.t_relay()`. ferrosip supports Lua this way with the `lua` module. [Kamailio: KEMI, `app_lua`]

See also: [.cfg](#cfg), [.fsr](#fsr).

### LCR

Least cost routing: picking the cheapest or preferred gateway for a phone number by its prefix. ferrosip's `carriers` module is Kamailio's lcr. [Kamailio: `lcr`]

See also: [Dispatcher](#dispatcher), [PSTN](#pstn).

### Lumps

The list of edits to a message (add this header, remove those bytes) that is applied in one pass when the message is sent. Because of lumps, a change in the script does not show up when the script reads the message again. [Kamailio: `data_lump`]

See also: [Header field](#header-field).

### modparam

A `.cfg` line that sets a module parameter: `modparam("tm", "fr_timer", 30000)`. In `ferrosip.toml` the same thing is `[modules.txn] fr_timer = "30s"`. [Kamailio: `modparam`]

See also: [Module](#module), [ferrosip.toml](#ferrosiptoml).

### Module

A plug-in that adds functions, variables, parameters and RPC commands to the core. Examples are tm for transactions, registrar for REGISTER and dispatcher for load balancing. In ferrosip every module is compiled in, and `ferrosip.toml` names them with ferrosip names such as `txn` or `location`. [Kamailio: `loadmodule`]

See also: [modparam](#modparam), [Module name](#module-name), [ferrosip.toml](#ferrosiptoml).

### myself

A script keyword that matches the proxy's own addresses and domains. `if ($ru == myself)` asks "is this request for me?". [Kamailio: `myself`]

See also: [R-URI](#r-uri).

### Onreply route

`onreply_route[NAME]`: a block that runs for each reply of one transaction, before tm handles it. It can edit the reply or drop a provisional one. It is armed with `t_on_reply("NAME")`. [Kamailio: tm `t_on_reply`]

See also: [Reply route](#reply-route), [Failure route](#failure-route).

### Preprocessor

The `#!` directives in a `.cfg` that change the script before it is parsed, such as `#!define WITH_AUTH` and `#!ifdef WITH_AUTH`. ferrosip takes `--define WITH_AUTH` on the command line. [Kamailio: core preprocessor directives]

See also: [.cfg](#cfg), [Feature switch](#feature-switch).

### Pseudo-variable (pv)

A `$name` in a `.cfg` script that reads or writes part of the message or some state. `$ru` is the R-URI, `$fU` the From user, `$si` the source IP, `$hdr(Name)` a header, and `$var(x)` a script variable. Modules add their own. [Kamailio: `pv` module]

```text
if ($fU == "alice") { $du = "sip:10.0.0.5"; }
```

See also: [AVP](#avp), [xavp](#xavp), [Transformation](#transformation).

### Reply route

`reply_route`: a block that runs for every reply that arrives, before any transaction handling. In `.fsr` it is `on reply(r: Reply)`. [Kamailio: `reply_route`]

See also: [Onreply route](#onreply-route), [Event handler](#event-handler).

### Request route

`request_route`: the main route block, run once for each request that arrives. In `.fsr` it is `route main(msg: Request)`. [Kamailio: `request_route`]

See also: [Route block](#route-block), [.fsr](#fsr).

### Return code convention

How Kamailio script functions report results. A positive number means true or success, a negative number means false or a kind of failure, and 0 stops the script, like `exit`. The last code is in `$rc`. For example `auth_check()` returns -2 for a wrong password and -4 for a stale nonce. [Kamailio: core return values]

See also: [Pseudo-variable (pv)](#pseudo-variable-pv), [.cfg](#cfg).

### Route block

A named block of script code. Kamailio runs different kinds at different moments: `request_route` for each request, `failure_route`, `onreply_route`, `branch_route` and `event_route` for later events. `route[NAME]` is a plain subroutine, called with `route(NAME)`. [Kamailio: core routing blocks]

See also: [Request route](#request-route), [Failure route](#failure-route), [Event route](#event-route).

### Sipwise

A company whose Kamailio-based platform adds patches to some Kamailio modules. A ferrosip README says "Sipwise" where it follows those patched modules rather than upstream Kamailio.

See also: [Kamailio](#kamailio).

### sl

Kamailio's stateless reply module, `stateless` in ferrosip. `sl_send_reply("404", "Not Found")` answers a request without keeping a transaction. [Kamailio: `sl`]

See also: [Stateless proxy](#stateless-proxy), [tm](#tm).

### tm

Kamailio's transaction module, `txn` in ferrosip. It makes the proxy stateful: it keeps transactions, retransmits, forks, runs failure and reply routes and offers `t_relay()`. [Kamailio: `tm`]

See also: [Transaction](#transaction), [Stateful proxy](#stateful-proxy), [Failure route](#failure-route).

### Transformation

A function applied to a pseudo-variable inside `$(…)`, written in braces. `$(fU{s.len})` is the length of the From user, and `$(ru{uri.host})` the R-URI's host. They can be chained. [Kamailio: transformations]

See also: [Pseudo-variable (pv)](#pseudo-variable-pv).

### usrloc

Kamailio's user location module: the in-memory table of registered contacts, optionally saved to a database. With the registrar module it forms ferrosip's `location` module. `ferroctl ul.dump` lists it. [Kamailio: `usrloc`]

See also: [Location service](#location-service), [Registrar](#registrar).

### xavp

Extended AVP: a transaction variable that holds a list of records with named fields, written `$xavp(root=>field)`. Modules use it for structured data, such as tm's list of contacts for serial forking. [Kamailio: `xavp`]

See also: [AVP](#avp).

## IMS and Diameter

### 3GPP

The standards body for mobile networks. It writes the Technical Specifications (TS) that define IMS, such as TS 23.228 and TS 29.228. [3gpp.org]

See also: [IMS](#ims).

### AAR

AA-Request (Rx), and its answer AAA. The P-CSCF sends it to the PCRF with the call's media description, to reserve resources. In `.fsr`: `await ims_qos.authorize_media("orig")`. [3GPP TS 29.214 §4.4.1]

See also: [Rx](#rx), [PCRF](#pcrf), [STR](#str).

### AKA

Authentication and Key Agreement: the SIM-card-based authentication of mobile networks, used in IMS through digest (`Digest-AKAv1-MD5`). It also produces the keys for IPsec. [RFC 3310, 3GPP TS 33.203]

See also: [MAR](#mar), [IPsec security association](#ipsec-security-association), [Digest authentication](#digest-authentication).

### AS

Application server: a server that adds a service to IMS calls, such as voicemail, call forwarding or conferencing. The S-CSCF routes requests to it over the ISC interface when an iFC matches. [3GPP TS 23.228]

See also: [iFC](#ifc), [ISC](#isc), [Sh](#sh).

### ASR

Abort-Session-Request: a Diameter server, such as the PCRF on Rx, tells the client to end a session at once. The answer is ASA. [RFC 6733 §8.5]

See also: [Rx](#rx), [STR](#str).

### CCR

Credit-Control-Request (Ro), and its answer CCA. An initial CCR reserves credit when a call starts, update CCRs reserve more while it lasts, and a termination CCR reports what was used when it ends. [RFC 4006 §3.1, 3GPP TS 32.299]

See also: [Ro](#ro), [OCS](#ocs).

### CER

Capabilities-Exchange-Request, and its answer CEA: the first messages on a new Diameter connection. The peers tell each other their identity and which applications (Cx, Rx, Ro…) they support. [RFC 6733 §5.3]

See also: [Diameter peer](#diameter-peer), [DWR](#dwr).

### CSCF

Call Session Control Function: the SIP servers of IMS. There are three roles, the P-CSCF, I-CSCF and S-CSCF. A call usually passes through all of them. [3GPP TS 23.228]

See also: [P-CSCF](#p-cscf), [I-CSCF](#i-cscf), [S-CSCF](#s-cscf).

### Cx

The Diameter interface between the I-CSCF or S-CSCF and the HSS. Its commands are UAR, LIR, MAR and SAR. [3GPP TS 29.228, TS 29.229]

See also: [HSS](#hss), [UAR](#uar), [MAR](#mar).

### Diameter

The authentication, authorization and accounting protocol of IMS, a successor of RADIUS. It runs over TCP, SCTP or TLS (port 3868) between fixed peers. Its messages are binary lists of AVPs. ferrosip's `sip-diameter` crate and `diameter` module (Kamailio's cdp) implement it. [RFC 6733]

See also: [Diameter AVP](#diameter-avp), [Diameter peer](#diameter-peer), [Cx](#cx).

### Diameter AVP

Attribute-value pair, in Diameter: one field of a message. Each has a code, flags, an optional vendor id (10415 for 3GPP) and typed data. For example Session-Id is code 263 and User-Data is code 702 from vendor 10415. [RFC 6733 §4]

See also: [Diameter](#diameter), [AVP](#avp).

### Diameter peer

A Diameter node that this node has a direct connection to. Peers open the connection with CER/CEA and keep it checked with DWR/DWA. In ferrosip they are listed in the `diameter` module's XML or `peer` parameters. [RFC 6733 §2.1, §5]

See also: [CER](#cer), [DWR](#dwr), [Diameter realm](#diameter-realm).

### Diameter realm

The administrative domain of a Diameter node, such as `ims.example.com`. Requests are routed by their Destination-Realm, through a table of peers per realm. [RFC 6733 §2.7]

See also: [Diameter peer](#diameter-peer), [Realm](#realm).

### DPR

Disconnect-Peer-Request: a Diameter peer says it is closing the connection on purpose, and the other side answers with DPA. [RFC 6733 §5.4]

See also: [CER](#cer), [Diameter](#diameter).

### DWR

Device-Watchdog-Request, and its answer DWA: a keepalive between Diameter peers. A peer that stops answering is treated as down and reconnected. [RFC 6733 §5.5, RFC 3539]

See also: [CER](#cer), [Diameter peer](#diameter-peer).

### ESP

Encapsulating Security Payload: the IPsec protocol that protects each packet, with integrity and optionally encryption. IMS IPsec between a phone and the P-CSCF uses ESP in transport mode. [RFC 4303]

See also: [IPsec security association](#ipsec-security-association), [SPI](#spi).

### HSS

Home Subscriber Server: the subscriber database of IMS. It stores identities, keys and service profiles, and answers the CSCFs over Cx and application servers over Sh. [3GPP TS 23.228]

See also: [Cx](#cx), [Sh](#sh), [IMPU](#impu).

### I-CSCF

Interrogating-CSCF: the entry point of a home network. It asks the HSS over Cx which S-CSCF serves the user (UAR for a REGISTER, LIR for a call) and forwards the request there. [3GPP TS 24.229]

See also: [UAR](#uar), [LIR](#lir), [S-CSCF](#s-cscf).

### iFC

Initial filter criteria: rules in a user's service profile that say which application servers get which requests, for example "send INVITEs to this user to the voicemail AS". The S-CSCF checks them for each initial request. [3GPP TS 29.228 Annex B]

See also: [AS](#as), [S-CSCF](#s-cscf), [ISC](#isc).

### IMPI

IMS private user identity: the identity used to authenticate, in the form `user@realm`. It is never used to route calls. [3GPP TS 23.228 §4.3.3]

See also: [IMPU](#impu), [AKA](#aka).

### Implicit registration set

A group of IMPUs that are registered together. When the user registers one of them, all of them become registered. The HSS sends the set in the user's profile. [3GPP TS 23.228 §4.3.3.4]

See also: [IMPU](#impu), [SAR](#sar).

### IMPU

IMS public user identity: a public address of a subscriber, such as `sip:+15551234567@ims.example.com` or `tel:+15551234567`. Others call this identity. One subscriber can have several. [3GPP TS 23.228 §4.3.3]

See also: [IMPI](#impi), [Implicit registration set](#implicit-registration-set).

### IMS

IP Multimedia Subsystem: the SIP-based core network that mobile operators use for VoLTE and VoWiFi calls. It is SIP plus a set of fixed server roles and Diameter links between them. ferrosip's `mod-ims` implements the CSCF roles. [3GPP TS 23.228]

See also: [CSCF](#cscf), [Diameter](#diameter), [3GPP](#3gpp).

### IPsec security association

A set of keys and settings that protects traffic between two addresses with IPsec. In IMS the phone and the P-CSCF set up a pair of them during registration, and later SIP traffic between them goes through them. ferrosip's `ims_ipsec_pcscf` negotiates them and can install them in the kernel. [3GPP TS 33.203, RFC 4301]

See also: [Security-Client](#security-client), [P-CSCF](#p-cscf), [AKA](#aka).

### ISC

IMS Service Control: the SIP interface between the S-CSCF and application servers. ferrosip's `ims_isc` module routes requests over it. [3GPP TS 24.229]

See also: [AS](#as), [iFC](#ifc).

### LIR

Location-Info-Request (Cx), and its answer LIA. The I-CSCF sends it on a call to ask the HSS which S-CSCF serves the called user. In `.fsr`: `await ims_icscf.locate()`. [3GPP TS 29.228 §6.1.4]

See also: [I-CSCF](#i-cscf), [UAR](#uar), [Cx](#cx).

### MAR

Multimedia-Auth-Request (Cx), and its answer MAA. The S-CSCF sends it to get authentication vectors (challenges and expected answers) from the HSS before it challenges a REGISTER. [3GPP TS 29.228 §6.3]

See also: [S-CSCF](#s-cscf), [AKA](#aka), [SAR](#sar).

### OCS

Online Charging System: the prepaid balance server. The S-CSCF or an application server reserves credit from it over Ro before and during a call. [3GPP TS 32.296]

See also: [Ro](#ro), [CCR](#ccr).

### P-Associated-URI

A header in the 200 to an IMS REGISTER. It lists the other public identities registered together with the one the device used: its implicit registration set. [RFC 7315]

```text
P-Associated-URI: <sip:alice@ims.test>, <tel:+4930111>
```

See also: [Implicit registration set](#implicit-registration-set), [IMPU](#impu).

### P-CSCF

Proxy-CSCF: the phone's first hop into IMS, like an outbound proxy. It secures the link to the phone with IPsec, checks the identities the phone asserts, and asks the PCRF over Rx for media resources. [3GPP TS 24.229]

See also: [IPsec security association](#ipsec-security-association), [Rx](#rx), [CSCF](#cscf).

### PCRF

Policy and Charging Rules Function: the server that grants network resources (bandwidth, QoS) for a call's media. The P-CSCF talks to it over Rx. [3GPP TS 23.203]

See also: [Rx](#rx), [AAR](#aar), [P-CSCF](#p-cscf).

### Ro

The Diameter interface for online (prepaid) charging, between the S-CSCF or an application server and the OCS. Its command is CCR. [3GPP TS 32.299, RFC 4006]

See also: [OCS](#ocs), [CCR](#ccr).

### RTR

Registration-Termination-Request: on the Cx interface, the HSS tells the S-CSCF to de-register a user, and the S-CSCF answers with RTA. [3GPP TS 29.228]

See also: [Cx](#cx), [HSS](#hss), [SAR](#sar).

### Rx

The Diameter interface between the P-CSCF and the PCRF, used to reserve and release network resources for a call's media. Its commands are AAR and STR. [3GPP TS 29.214]

See also: [PCRF](#pcrf), [AAR](#aar), [STR](#str).

### S-CSCF

Serving-CSCF: the registrar and main service node of IMS. It authenticates users with vectors from the HSS, keeps their registrations, sends calls to application servers by iFC and serves the reg event. [3GPP TS 24.229]

See also: [MAR](#mar), [SAR](#sar), [iFC](#ifc), [Reg event](#reg-event).

### SAR

Server-Assignment-Request (Cx), and its answer SAA. The S-CSCF sends it after a successful registration (or on de-registration) to tell the HSS it serves the user, and gets back the user's profile with the iFCs. [3GPP TS 29.228 §6.1.2]

See also: [S-CSCF](#s-cscf), [MAR](#mar), [iFC](#ifc).

### Security-Client

The `Security-Client`, `Security-Server` and `Security-Verify` headers. They let a client and server agree on a security mechanism such as IPsec: the client lists what it offers, the server answers what it chose, and the client repeats the server's list to prove nothing was changed. [RFC 3329]

```text
Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1111; spi-s=2222; port-c=5062; port-s=5064
```

See also: [IPsec security association](#ipsec-security-association), [P-CSCF](#p-cscf).

### Sh

The Diameter interface between an application server and the HSS. The AS uses it to read and update user data. ferrosip can answer and send such requests from the script (`on diameter.request`). [3GPP TS 29.328, TS 29.329]

See also: [AS](#as), [HSS](#hss).

### SPI

Security Parameter Index: the number that identifies one IPsec security association. Each side picks the SPIs for the SAs it receives on. [RFC 4301]

See also: [IPsec security association](#ipsec-security-association), [ESP](#esp).

### STR

Session-Termination-Request, and its answer STA. On Rx the P-CSCF sends it when a call ends, so the PCRF releases the resources. [3GPP TS 29.214, RFC 6733 §8.4]

See also: [AAR](#aar), [Rx](#rx).

### Trigger point

The conditions inside an iFC that decide whether a request goes to an application server. They test the method, headers, Request-URI, SDP, and the session case: whether the request is originating (from the user) or terminating (to the user). [3GPP TS 29.228]

See also: [iFC](#ifc), [S-CSCF](#s-cscf).

### UAR

User-Authorization-Request (Cx), and its answer UAA. The I-CSCF sends it on a REGISTER to ask the HSS whether the user may register and which S-CSCF to use. In `.fsr`: `await ims_icscf.authorize()`. [3GPP TS 29.228 §6.1.1]

See also: [I-CSCF](#i-cscf), [LIR](#lir), [Cx](#cx).

### UDR

User-Data-Request: on the Sh interface, an application server reads a user's data from the HSS. The answer is UDA. [3GPP TS 29.328]

See also: [Sh](#sh), [HSS](#hss).

### UE

User equipment: the phone or other device of an IMS subscriber. [3GPP TS 23.228]

See also: [P-CSCF](#p-cscf), [IMS](#ims).

## ferrosip-specific

### await

The `.fsr` keyword that waits for a result that takes time, such as a relayed request's final reply, an HTTP call or a Diameter answer. The worker does other work meanwhile, and the code after `await` runs with its variables intact when the result arrives. [docs/fsr.md](fsr.md#await)

```rust
let res = await txn.relay(msg, timeout: 30s)
match res {
    Final(r) if r.code == BusyHere => voicemail(msg)
    Final(r) => forward(r)
    Timeout => reply(RequestTimeout)
}
```

See also: [Suspend and resume](#suspend-and-resume), [Failure route](#failure-route), [.fsr](#fsr).

### Check

`ferrosip check`: loads and checks the configuration and routing without starting the server, like `kamailio -c`. It reports every error at once with its position. [docs/running.md](running.md)

See also: [Lint](#lint), [Lowering](#lowering).

### Dialog variable

A `.fsr` value that lives as long as a call: `dialog var caller: Str`, then `dialog.caller = msg.from.user`. It is stored as a dialog variable of the `dialog` module (`$dlg_var`). [docs/fsr.md](fsr.md#state)

See also: [Dialog](#dialog), [Shared table](#shared-table).

### Escape hatch

The untyped `.fsr` forms that reach Kamailio features directly: `pv("$avp(x)")` and `kamailio.call("fn", …)`. `ferrosip import` uses them where no typed form fits, and `ferrosip lint -W raw_kamailio` lists them. [docs/fsr.md](fsr.md#the-escape-hatch-to-kamailio)

See also: [Import](#import), [Lint](#lint).

### Event handler

An `on …` block in `.fsr` that runs when something happens outside a request: `on reply`, `on dialog.ended`, `on timer(every: 30s)`, `on http`, and others. It lowers to a Kamailio event route. [docs/fsr.md](fsr.md#events)

See also: [Event route](#event-route), [.fsr](#fsr).

### Feature switch

A boolean in the `[feature]` table of `ferrosip.toml`. Modules can use it to turn on and off (`enabled = "${feature.nat}"`), and `.fsr` reads it as a constant (`import { features } from config`). It replaces Kamailio's `#!ifdef WITH_X`. [docs/config-toml.md](config-toml.md)

See also: [Overlay](#overlay), [Preprocessor](#preprocessor).

### ferroctl

The command-line RPC client, like Kamailio's kamcmd. `ferroctl fmt` also formats routing scripts. [tools/ferroctl](../tools/ferroctl/README.md)

```bash
ferroctl stats.get_statistics all
ferroctl ul.dump
```

See also: [RPC](#rpc), [kamcmd](#kamcmd).

### ferrosip.toml

The configuration file that says what runs: listeners, TLS, modules and their parameters, feature switches and the routing entry file. Every parameter is checked against the module's schema. [docs/config-toml.md](config-toml.md)

```toml
[[listen]]
proto = "udp"
addr = "0.0.0.0:5060"

[modules.txn]
fr_timer = "30s"

[routing]
entry = "routes/main.fsr"
```

See also: [.fsr](#fsr), [Overlay](#overlay), [Schema](#schema).

### .fsr

ferrosip's own typed routing language. It reads like Rust: routes and functions, `let`, `match`, `await` and event handlers. It is type-checked before it runs and compiles to the same route tree as a `.cfg`. [docs/fsr.md](fsr.md)

```rust
route main(msg: Request) {
    guard msg.max_forwards > 0 else reply(TooManyHops)
    let found = location.lookup() else return reply(NotFound)
    relay(msg)
}
```

See also: [ferrosip.toml](#ferrosiptoml), [await](#await), [Lowering](#lowering).

### Import

`ferrosip import`: converts a Kamailio `.cfg` into a `ferrosip.toml` and `routes/main.fsr` that behave the same. [docs/import.md](import.md)

```bash
ferrosip import kamailio.cfg -o myproxy --define WITH_AUTH
```

See also: [.cfg](#cfg), [Escape hatch](#escape-hatch).

### Lint

`ferrosip lint`: a checker that points at code that works but is probably a mistake, such as an open relay, a REGISTER saved without auth or an unused variable. `--fix` applies the mechanical fixes. [docs/lint.md](lint.md)

See also: [Check](#check), [Escape hatch](#escape-hatch).

### Live reload

`ferroctl cfg.reload`: re-reads the routing and `ferrosip.toml` while the server runs. New routes take over for new messages, and reloadable parameters change at once. Others are reported as needing a restart. [docs/script.md](script.md#reloading-the-script-cfgreload)

See also: [RPC](#rpc), [Schema](#schema).

### Lowering

Compiling `.fsr` into the route tree a `.cfg` would produce. `ferrosip check --lowered` prints the result as `.cfg` text. [docs/fsr.md](fsr.md#lowering)

See also: [.fsr](#fsr), [Escape hatch](#escape-hatch).

### Module name

The short ferrosip name of a module or a group of Kamailio modules, used in `ferrosip.toml` and as the `.fsr` namespace. Examples: `txn` for tm, `location` for usrloc and registrar, `balancer` for dispatcher. Kamailio names work too. [docs/config-toml.md](config-toml.md)

See also: [Module](#module), [ferrosip.toml](#ferrosiptoml).

### Overlay

An extra TOML file merged on top of `ferrosip.toml`, for one environment: `--overlay envs/prod.toml`. Tables merge, and other values replace. `--set path=value` overrides single values after that. `ferrosip check --explain` shows where each value came from. [docs/config-toml.md](config-toml.md)

See also: [ferrosip.toml](#ferrosiptoml), [Feature switch](#feature-switch).

### RPC

Remote procedure call: the control interface of a running server. ferrosip speaks JSON-RPC 2.0 on a Unix socket (and over HTTP with the `http` module). Modules add commands such as `ul.dump`, `stats.get_statistics` or `cfg.reload`. [docs/running.md](running.md#management-rpc-statistics-database)

See also: [ferroctl](#ferroctl), [kamcmd](#kamcmd), [Statistics](#statistics).

### Scenario suite

The runnable configurations in `examples/scenarios`, from a small OPTIONS responder to multi-proxy and IMS setups. Each has its edge cases tested end to end by `tests/e2e_scenarios.py`. [examples/scenarios](../examples/scenarios/README.md)

See also: [Test block](#test-block).

### Schema

The typed description of a module's parameters (name, type, unit, default, whether it is reloadable), written in Rust next to the module. Config checks, `ferrosip schema` and the generated reference docs all come from it. [docs/modules-reference.md](modules-reference.md)

See also: [ferrosip.toml](#ferrosiptoml), [Module name](#module-name).

### Shared table

A `.fsr` key-value table shared by all workers, with an optional time to live. It is stored in an htable. [docs/fsr.md](fsr.md#state)

```rust
shared table bans: Map<Str, Bool> ttl 10m
```

See also: [htable](#htable), [Dialog variable](#dialog-variable).

### sipflood

The project's load generator and dummy UAS, used for the benchmarks. [tools/sipflood](../tools/sipflood/README.md)

See also: [SIPp](#sipp), [UAS](#uas).

### Suspend and resume

Parking a request's transaction while it waits for something, then continuing the script when the answer comes. Retransmissions are absorbed meanwhile and the worker handles other messages. `await` is built on it, as are Kamailio's `t_suspend()` and `t_continue()`. [Kamailio: tmx `t_suspend`, `t_continue`]

See also: [await](#await), [Transaction](#transaction).

### Test block

A `test "name" { … }` block in `.fsr` that sends fake SIP messages through the routing and checks what comes out. `ferrosip test` runs them with the real modules and a recording network, without sockets. [docs/fsr.md](fsr.md#tests)

See also: [.fsr](#fsr), [Scenario suite](#scenario-suite).

### Web UI

A read-only admin page served by the `webui` module, with live counters, registrations, dialogs and logs. [crates/mod-webui](../crates/mod-webui/README.md)

See also: [Statistics](#statistics), [Prometheus metric](#prometheus-metric).

### Worker

A thread that receives, parses and routes SIP messages. Each UDP worker has its own socket on the same port (`SO_REUSEPORT`), and TCP readers each own a set of connections. Set the UDP count with `-n` or `[core] workers`. Kamailio uses processes for this (`children`). [docs/architecture.md](architecture.md)

See also: [Suspend and resume](#suspend-and-resume).

## Operations

### CDR

Call detail record: one line or database row per call with who called whom, when and for how long. It is used for billing and reports. ferrosip's `cdr` module (Kamailio's acc) writes them. [Kamailio: `acc`]

See also: [Dialog](#dialog), [Transaction](#transaction).

### Counter

A number that only goes up, such as the total of requests received. Rates come from comparing two readings. [Prometheus: metric types]

See also: [Gauge](#gauge), [Prometheus metric](#prometheus-metric).

### Gauge

A number that goes up and down, such as the current count of transactions or registered users. [Prometheus: metric types]

See also: [Counter](#counter), [Statistics](#statistics).

### Graceful shutdown

How ferrosip stops on SIGTERM or SIGINT. It refuses new connections and answers new initial requests with 503, lets running transactions finish within `--shutdown-timeout`, saves state and exits 0. [docs/running.md](running.md#production-behaviour-limits-failures-shutdown)

See also: [Initial request](#initial-request), [Transaction](#transaction).

### Grafana

A dashboard tool that draws graphs from Prometheus data. The project ships a dashboard in `examples/monitoring`. [grafana.com]

See also: [Prometheus metric](#prometheus-metric).

### HEP

Homer Encapsulation Protocol: a small wrapper that sends a copy of a SIP message, with its addresses and timestamp, to a capture server. ferrosip sends HEPv3 with siptrace. [HEP v3 specification, sipcapture.org]

See also: [HOMER](#homer), [siptrace](#siptrace).

### HOMER

An open-source capture system that stores SIP traffic received as HEP and lets you search and view calls. `examples/homer` runs it next to ferrosip. [sipcapture.org]

See also: [HEP](#hep), [siptrace](#siptrace).

### pcap

The standard capture file format of tcpdump and Wireshark. ferrosip's `sip_dump` module can write the SIP traffic it sends and receives as `.pcap` files, to open in Wireshark. [tcpdump.org: pcap]

See also: [sipdump](#sipdump), [HEP](#hep).

### Prometheus metric

A value that Prometheus, a monitoring system, collects by fetching an HTTP page in its text format at regular intervals. ferrosip's `prometheus` module serves its statistics this way, with labels and latency histograms. `examples/monitoring` adds a Grafana dashboard on top. [prometheus.io: exposition formats]

```text
ferrosip_sip_requests_received_total{method="INVITE"} 1520
```

See also: [Statistics](#statistics), [Counter](#counter), [Grafana](#grafana).

### sipdump

The module (`sip_dump` in ferrosip) that writes every SIP message in and out to text files, pcap files or an event route. It sees messages exactly as sent and received, including after TLS decryption. [Kamailio: `sipdump`]

See also: [pcap](#pcap), [siptrace](#siptrace).

### SIPp

A widely used open-source SIP traffic generator, driven by XML scenarios. The project's interop tests use it to place calls through ferrosip. [sipp.sourceforge.net]

See also: [sipflood](#sipflood).

### siptrace

The module (`trace` in ferrosip) that copies SIP messages to a capture server as HEP packets, or stores them in a database. [Kamailio: `siptrace`]

See also: [HEP](#hep), [HOMER](#homer), [sipdump](#sipdump).

### Statistics

Named counters and gauges kept by the core and the modules, with Kamailio's names such as `core:rcv_requests`, `tm:current` or `usrloc:registered_users`. Read them with `ferroctl stats.get_statistics all`, or through Prometheus. [Kamailio: `statistics`, kex]

See also: [Counter](#counter), [Gauge](#gauge), [Prometheus metric](#prometheus-metric).
