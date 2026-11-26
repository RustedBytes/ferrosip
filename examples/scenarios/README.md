# Scenarios

This directory holds 40 complete configurations that you can copy as a
starting point for a real deployment. Each one is a
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) plus an
[`.fsr`](../../docs/glossary.md#fsr) routing file. They range from one
feature to multi-proxy topologies. Each one runs end to end with real
[SIP](../../docs/glossary.md#sip) traffic, so together they form the
[scenario suite](../../docs/glossary.md#scenario-suite).

Ports, peers and paths come from `${ENV:-default}`. So every directory also
runs on its own. Each has a README with its topology, what it shows, the
edge cases it checks and how to run it by hand.

```bash
cargo build --release
python3 tests/e2e_scenarios.py                    # all, 4 in parallel (a minute or two)
python3 tests/e2e_scenarios.py --only m02 l01     # by name or prefix
python3 tests/e2e_scenarios.py --size small       # small | medium | large
```

For every scenario the runner (`tests/e2e_scenarios.py`):
1. checks each configuration with `ferrosip check`, `ferrosip lint -D
   warnings` and `ferrosip fmt --check` (see
   [check](../../docs/glossary.md#check) and
   [lint](../../docs/glossary.md#lint));
2. runs `tests/scenarios/<name>.py`, which starts the proxies and fake
   peers (UAs, gateways, HTTP services) from `tests/sipkit.py` on the
   scenario's own ports;
3. fails on any panic in a proxy's log.

Some scenarios need a database server, Redis or rtpflux. They start their
own (`sipkit.Postgres`, `MariaDb`, `Redis`). Where that software isn't
installed, they are reported as skipped.

## Small: one feature and its edge cases

| scenario | shows | edge cases |
|---|---|---|
| [s01-options-responder](s01-options-responder/) | `guard` chains, `sip.check()`, `sip.options_reply()`, a source check | [Max-Forwards](../../docs/glossary.md#max-forwards) 0 → 483, a malformed request is not relayed, [OPTIONS](../../docs/glossary.md#options) for another host relayed |
| [s02-static-relay](s02-static-relay/) | everything to one upstream, `[modules.txn]` timers | silent upstream → 408 after `fr_timer`, ringing forever → 408 + [CANCEL](../../docs/glossary.md#cancel), closed port, [Via](../../docs/glossary.md#via) `received`/`rport` |
| [s03-registrar-only](s03-registrar-only/) | `location.save()` and its limits | expiry capping, 423 Interval Too Brief, `max_contacts`, `*` unregister, Expires 0, refresh, [Path](../../docs/glossary.md#path) |
| [s04-digest-auth](s04-digest-auth/) | `auth.check` / `auth.challenge`, users file with [HA1s](../../docs/glossary.md#ha1), SHA-256 and MD5 | 401 vs 407, wrong password, [stale](../../docs/glossary.md#stale) nonce, user mismatch → 403, a second check of the same credentials |
| [s05-acl-allowlist](s05-acl-allowlist/) | `msg.src.ip in [...]` and the `acl` module | allowed vs refused sources, `ferrosip lint` clean without an `allow` |
| [s06-message-edits](s06-message-edits/) | `text.*` header and body edits, [R-URI](../../docs/glossary.md#r-uri) rewrite, the same in `on reply` | Content-Length right after every edit, 8 KB headers |
| [s07-flood-ban](s07-flood-ban/) | [`shared table`](../../docs/glossary.md#shared-table) counters with a ttl, `on timer`, `on http` API | ban after N, expiry, listing and clearing bans over HTTP |
| [s08-feature-overlays](s08-feature-overlays/) | [`--overlay`](../../docs/glossary.md#overlay), `--set`, `check --explain`, [`[feature]`](../../docs/glossary.md#feature-switch) switches | dev vs prod behaviour from one routing file |
| [s09-transports](s09-transports/) | UDP, TCP, TLS and [WS](../../docs/glossary.md#websocket) listeners, `[tls.default]` | UDP→TCP and TLS→UDP relays, double [Record-Route](../../docs/glossary.md#record-route), a 3 KB+ message over TCP |
| [s10-routing-tests](s10-routing-tests/) | [`test` blocks](../../docs/glossary.md#test-block) run by `ferrosip test`: `send`, `answer`, `wait`, mocks | a deliberately failing test reported as failing, [retransmissions](../../docs/glossary.md#retransmission) not counted as relays |
| [s11-live-reload](s11-live-reload/) | [`cfg.reload`](../../docs/glossary.md#live-reload) of the `.fsr` and of TOML values under traffic | a broken edit is refused and nothing changes, [`await`](../../docs/glossary.md#await) continuations survive a reload |

## Medium: one proxy in a realistic role

| scenario | shows | edge cases |
|---|---|---|
| [m01-registrar-proxy](m01-registrar-proxy/) | auth + location, parallel [forking](../../docs/glossary.md#forking), `route_set` | 404 unknown vs 480 not registered, the first 200 wins and the other [branch](../../docs/glossary.md#branch) is CANCELed, caller CANCEL while both ring |
| [m02-gateway-failover](m02-gateway-failover/) | `await txn.relay` in a `for` over gateways, `match` on the result | 503 → next, timeout → next, 486/603 stop, all fail → 503, CANCEL while ringing |
| [m03-voicemail](m03-voicemail/) | ring timer with `await`, retargeting, Diversion, `txn.drop_replies()` | busy / no answer / unregistered → voicemail, 3xx and 6xx forwarded, CANCEL during the voicemail leg → 487 |
| [m04-pstn-trunk](m04-pstn-trunk/) | number normalisation, `match` with ranges, trunk ACL, [P-Asserted-Identity](../../docs/glossary.md#p-asserted-identity) | [E.164](../../docs/glossary.md#e164), national, international, emergency short codes, invalid → 484, `Privacy: id` |
| [m05-nat-edge](m05-nat-edge/) | `nat.is_behind`, `nat.fix_contact`, the [NAT](../../docs/glossary.md#nat) branch flag | a private [Contact](../../docs/glossary.md#contact) behind 127.0.0.1, calls back to the real source, `received`/`rport` on the Via |
| [m06-webrtc-gateway](m06-webrtc-gateway/) | a WS listener next to UDP, contact aliases | WS registers and calls a UDP phone and back, double Record-Route, [BYE](../../docs/glossary.md#bye) from either side |
| [m07-load-balancer](m07-load-balancer/) | `balancer` with probing, `on balancer.down/up`, failover loop | round-robin distribution, a dead server skipped, Record-Route kept on the failover branch |
| [m08-http-routing](m08-http-routing/) | `await http.get` with templated URL and headers | service 404 / 500 / slow / down → fallbacks, what the service received |
| [m09-presence](m09-presence/) | [PUBLISH](../../docs/glossary.md#publish), [SUBSCRIBE](../../docs/glossary.md#subscribe)/[NOTIFY](../../docs/glossary.md#notify), dialog-info, resource lists | publication expiry, list refresh and unsubscribe in the [dialog](../../docs/glossary.md#dialog) |
| [m10-cdr](m10-cdr/) | `dialog.manage()`, `on dialog.ended` [CDRs](../../docs/glossary.md#cdr) to a collector, a `Reason` on the proxy's own BYEs (`tm:local-request`) | caller BYE, callee BYE, prepaid timeout with BYE, plausible durations |
| [m11-rate-limits](m11-rate-limits/) | `pipe_limits` per source, `limits` pipe and queue | 503 + Retry-After, recovery after the window, [in-dialog requests](../../docs/glossary.md#in-dialog-request) not limited |
| [m12-topology-hiding](m12-topology-hiding/) | [topoh](../../docs/glossary.md#topology-hiding) with `mask_ip` | no internal Via, Contact or Record-Route at the carrier; [ACK](../../docs/glossary.md#ack), BYE and [re-INVITE](../../docs/glossary.md#re-invite) still route both ways |
| [m13-redis-state](m13-redis-state/) | two proxies sharing a block list and a call counter in Redis (`redis`) | a block via one enforced by the other, key expiry, Redis stopped (reads fail open, writes 503), restarted, frozen |
| [m14-lua-routing](m14-lua-routing/) | `lua.run` with the [KSR](../../docs/glossary.md#kemi) API picking a target or rejecting | a Lua error, a missing function, reload (and a broken reload), per-[worker](../../docs/glossary.md#worker) state, UTF-8 |
| [m15-media-relay](m15-media-relay/) | `media` offer/answer/delete against [rtpflux](../../docs/glossary.md#media-relay) (skipped without it) | [RTP](../../docs/glossary.md#rtp) both ways, hold and resume, BYE either side, CANCEL and 486 delete the session, no `m=` line, [ICE](../../docs/glossary.md#ice) removed, relay down → 500 |
| [m16-json-webhooks](m16-json-webhooks/) | a JSON event per call with `json_doc` and `await http.post`; the answer routes | malformed, missing or wrongly typed fields, CRLF injection refused, escaping in display names, a 300 KB answer |
| [m17-credential-store](m17-credential-store/) | HA1s in Redis behind a shared-table cache, `auth.pv_check` with `$au` / `$ar`, one phone per user (`location.save(4)`), `fetch_contacts` + `$ulc` over HTTP | unknown user, wrong password, credentials of another user → 403, a password change applies at once, Redis down: cached users still register, others 503 |

## Large: several proxies, or many features at once

| scenario | topology | edge cases |
|---|---|---|
| [l01-edge-core](l01-edge-core/) | flood-banning edge → [registrar](../../docs/glossary.md#registrar) core with Path | registration through the edge, calls both ways, in-dialog requests through both proxies, flood ban |
| [l02-shared-location](l02-shared-location/) | two registrars on one SQLite [location](../../docs/glossary.md#location-service) table | register on A and call via B, restarts, devices on both registrars kept |
| [l03-carrier-interconnect](l03-carrier-interconnect/) | [SBC](../../docs/glossary.md#sbc) between customers and two carriers | carrier failover, normalisation, topology hiding, per-customer limit, CDRs naming the carrier that answered |
| [l04-small-business-pbx](l04-small-business-pbx/) | one proxy: registrar, voicemail, forwarding, [BLF](../../docs/glossary.md#blf), CDRs | call forwarding set over HTTP, BLF of a call answered at once, voicemail on busy / no answer |
| [l05-lb-cluster](l05-lb-cluster/) | load balancer in front of 3 ferrosip app proxies | an app proxy killed mid-test: failover, marked down by probing, up again after a restart |
| [l06-multi-tenant](l06-multi-tenant/) | tenants by domain, routes from imported `.fsr` files | per-tenant users and limits, one tenant can't reach another's users |
| [l07-call-center](l07-call-center/) | hunt group: serial by q, then all at once, then voicemail; dialogs matched by the `did` cookie; supervisor transfer (`dialog.refer`) and callback (`dialog.bridge`) over HTTP | agents busy or not answering, CANCEL mid-hunt → 487, all agents logged out, a forged or missing cookie → 481 |
| [l08-imported-kamailio](l08-imported-kamailio/) | [Kamailio's](../../docs/glossary.md#kamailio) stock config → [`ferrosip import`](../../docs/glossary.md#import) → `lint --fix` | the import passes check, lint and fmt; the same traffic gets the same answers as the [`.cfg`](../../docs/glossary.md#cfg) |
| [l09-postgres-cluster](l09-postgres-cluster/) | two registrars on PostgreSQL: auth_db, write-through location read with `sql`, a numbers table | each finds the other's registrations, users and numbers added at run time, quotes in SQL values, Postgres restarted |
| [l10-mysql-accounting](l10-mysql-accounting/) | acc rows and CDRs in MariaDB, dialogs with `db_mode` | answered / busy / no answer / canceled rows, a BYE after a proxy restart, the database down while a call ends |
| [l11-ims-core](l11-ims-core/) | [P-CSCF](../../docs/glossary.md#p-cscf) → [I-CSCF](../../docs/glossary.md#i-cscf) → [S-CSCF](../../docs/glossary.md#s-cscf) with a fake [HSS](../../docs/glossary.md#hss) ([Cx](../../docs/glossary.md#cx) over TLS); the S-CSCF's registrations and [reg-event](../../docs/glossary.md#reg-event) subscriptions in SQLite | registration with [digest](../../docs/glossary.md#digest-authentication) and [AKA](../../docs/glossary.md#aka), Path/[Service-Route](../../docs/glossary.md#service-route), a call through the core, identity checks, unknown user, HSS silent or down, re- and de-registration, reg-event NOTIFYs continuing across an S-CSCF restart |
| [l12-imported-failure-routes](l12-imported-failure-routes/) | the stock config with voicemail and the 3xx / 401 / 407 blocks, as `.cfg` and as its import (`failure_route` → `await txn.relay` + `match`) | busy / no answer / silent → voicemail, a voicemail loop → 500 at `max_branches`, voicemail 503 → 500, 404 and 500 forwarded, 302 / 401 / 407 → 404, CANCEL during the voicemail leg → 487: the same answers and relay counts from both |
