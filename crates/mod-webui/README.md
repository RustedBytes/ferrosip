# mod-webui

The `webui` [module](../../docs/glossary.md#module) is a read-only admin
[web UI](../../docs/glossary.md#web-ui) in the browser. Use it when an
operator needs to see what ferrosip is doing right now. It never changes
anything.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `webui` | none (ferrosip's own) | Live overview, registrations, calls, transactions, connections, routing, data and logs |

```toml
# ferrosip.toml
[modules.webui]
listen = "127.0.0.1:8090"
user = "admin"
password_hash = "sha256:9f0c…:4cc4…"   # ferroctl webui-hash
```

The module has no routing functions. The `[modules.webui]` section in
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) loads it, and
`enabled = false` turns it off.

```bash
ferroctl webui-hash            # type the password, get the password_hash value
```

[`ferroctl`](../../docs/glossary.md#ferroctl) prints the hash. Open
`http://127.0.0.1:8090/` and log in.

## Pages

Each section is shown only when its modules are loaded.

| Page | What it shows |
|---|---|
| Overview | Live tiles with 5-minute sparklines (requests/s, replies/s, transactions, active dialogs, registered users, TCP/TLS/WS connections, retransmissions/s, timeouts/s); final replies by class per second; version, uptime, memory, threads, script path, panics; listeners; loaded modules |
| Statistics | Every counter and gauge, its rate per second and recent history; filter by group |
| Registrations | Registered users (search, sort, pages); a user opens their contacts (expires in, received address, user agent, path, q); outbound `uac` registrations |
| Calls | Active dialogs (state, duration, parties, contacts); totals by state; AI calls (`ai`: in progress and the last 100 ended, with provider, prompt, end reason); `dlgs`; `cnxcc` credit clients |
| Transactions | `tm` counters, the DNS destination blocklist, `tsilo` |
| Connections | Open TCP/TLS/WS connections: peer, local address, direction, age, idle time, TLS version, SNI; limits |
| Routing | Dispatcher destinations (state, probing, load, latency), LCR gateways and rules, dialplan rules by id, mtree, prefix routes |
| Health | Keepalive targets, RTPengine nodes, Diameter peers, IMS (P-CSCF contacts, S-CSCF users, Ro sessions, IPsec SAs without keys) |
| Security | Pike, ratelimit and pipelimit pipes, secfilter, user blocklist, permissions (address and trusted tables), domains |
| Data | Hash tables and their items, custom config variables, siptrace/sipdump state |
| Presence | Presentities, watchers, SCA subscriptions and appearances |
| Logs | Live tail of the last log lines (`log_buffer`), level filter, search |

The glossary explains the terms in this table:
[transaction](../../docs/glossary.md#transaction),
[dialog](../../docs/glossary.md#dialog),
[statistics](../../docs/glossary.md#statistics),
[Contact](../../docs/glossary.md#contact),
[destination blocklist](../../docs/glossary.md#destination-blocklist),
[dispatcher](../../docs/glossary.md#dispatcher),
[LCR](../../docs/glossary.md#lcr),
[keepalive](../../docs/glossary.md#keepalive),
RTPengine ([media relay](../../docs/glossary.md#media-relay)),
[Diameter peer](../../docs/glossary.md#diameter-peer),
[IMS](../../docs/glossary.md#ims),
[P-CSCF](../../docs/glossary.md#p-cscf),
[S-CSCF](../../docs/glossary.md#s-cscf),
[Ro](../../docs/glossary.md#ro),
[IPsec SA](../../docs/glossary.md#ipsec-security-association),
hash tables ([htable](../../docs/glossary.md#htable)),
[siptrace](../../docs/glossary.md#siptrace),
[sipdump](../../docs/glossary.md#sipdump) and
[presence](../../docs/glossary.md#presence).

Views refresh every `refresh_ms` (2 s) while they're open. The header's
Pause button stops all polling.

Tables longer than 25 rows get pages (first/previous/page numbers/next/
last). They also get a rows-per-page choice (25, 50, 100, 250) that the
browser remembers. On screens narrower than 800 px the navigation moves
behind a ☰ menu button.

## Parameters

| Name | Default | Description |
|---|---|---|
| `listen` | none (required) | `ip:port` of the HTTP listener. ferrosip exits at startup if it can't bind it |
| `user` | none (required) | Login name |
| `password_hash` | none (required) | `sha256:<salt>:<hex of sha256(salt ‖ password)>`, from `ferroctl webui-hash` |
| `realm` | `ferrosip` | Basic-auth realm |
| `max_connections` | 64 | Concurrent HTTP connections; the next one gets 503 |
| `refresh_ms` | 2000 | How often the UI polls (minimum 500) |
| `log_buffer` | 2000 | Log lines kept in memory for the Logs page (0: off) |

## Security

- **Read-only.** The API answers GET and HEAD only. Anything else gets 405.
  In the code, each API path maps to one read-only
  [RPC](../../docs/glossary.md#rpc). Its parameters are fixed or taken
  from named query arguments. The client never names an RPC. Methods that
  change state can't be reached (`*.reload`, `*.set_*`, `ul.rm`,
  `dlg.end_dlg`, `rtpengine.ping`, …). A unit test checks the route table
  against them.
- **Authentication** on every request: HTTP Basic auth, compared in
  constant time. An address with five failed logins within a minute gets
  429 for a minute.
- **Transport.** Basic auth sends the password with each request. Listen
  on 127.0.0.1 and use an SSH tunnel, or put a TLS reverse proxy (nginx,
  Caddy) in front.
- **Headers:**
  - a strict Content-Security-Policy (same origin only, no inline
    scripts);
  - `X-Frame-Options: DENY`, `nosniff`, `no-referrer`;
  - API answers are `no-store`.
- **Limits.** Request heads are capped at 8 KiB. Request bodies are
  refused. Idle connections close after 15 s.
- **Data shown:** registered users' addresses and user agents, call
  parties, ACLs. Treat access to the UI as access to that data.

## API

You can use the UI's JSON API directly
(`curl -u admin:… http://127.0.0.1:8090/api/v1/registrations?q=alice`):

- `GET /api/v1/meta`: version, refresh interval, and the available
  sections with their paths.
- `GET /api/v1/stats`: all statistics, with kind and a timestamp.
- One path per view: `info`, `registrations`, `registrations/contacts?aor=`,
  `dialogs`, `dispatcher`, `htable/items?table=`, `dialplan?dpid=`,
  `connections`, `logs?after=<seq>`… (`src/api.rs` has the list). The
  `aor` argument is an [AoR](../../docs/glossary.md#aor).
- Lists accept `q` (search), `sort` (`field` or `-field`), `offset`, and
  `limit` (up to 500). They answer `{total, offset, limit, rows}`.

No RPC pages its results. So the server fetches a list whole and then cuts
it. A result is cached for a second, so several open browsers cost one
fetch.

## Development

The app lives in `ui/`:
- Preact 11, TypeScript, esbuild;
- no CSS framework; light and dark follow the system; usable on a phone.

The built bundle (`assets/`, about 18 KB gzipped) is committed and
embedded with `include_bytes!`. So building ferrosip needs no Node.

```bash
cd crates/mod-webui/ui
npm ci
npm run check            # tsc --noEmit + build into ../assets
cargo build --release    # embeds the new bundle
```

Builds are reproducible. CI rebuilds the bundle and fails if `assets/`
differs from the committed files.

Tests:
- `tests/e2e_webui.py`: the HTTP API, auth and limits, against real data.
- `tests/webui_browser.mjs`: Playwright in Chromium. It visits every page,
  follows the drill-downs, renders in dark mode and at phone width, and
  fails on any console error.

## Testing

- `tests/e2e_webui.py` runs over HTTP against a proxy with real
  registrations, a call, a dispatcher set and an htable entry. It checks:
  - Basic auth (401, then 429 after repeated failures);
  - every API section's rows, with filters, sorting and paging;
  - the embedded app (gzip, ETag/304) and the security headers;
  - that nothing writes (405), unknown paths (404) and path traversal (400);
  - the connection limit (503 for the 65th) and recovery.
- `tests/webui_browser.mjs` runs in Chromium (Playwright). It opens every
  page, drills into a registration and a table, and fails on any console
  error or failed request. It also takes the screenshots in
  `docs/screenshots/`.
