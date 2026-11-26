# mod-prometheus

The `prometheus` [module](../../docs/glossary.md#module) lets a Prometheus
server scrape ferrosip. Use it when you want dashboards and alerts for
traffic, latency and process health. It serves
[Prometheus metrics](../../docs/glossary.md#prometheus-metric) on an HTTP
listener of its own. It exports:
- native names and labels;
- latency histograms;
- process metrics.

| Module | [Kamailio](../../docs/glossary.md#kamailio) module (`loadmodule`) | Purpose |
|---|---|---|
| `prometheus` | none (ferrosip's own; Kamailio has `xhttp_prom`, see below) | Metrics on its own HTTP listener |

A [Grafana](../../docs/glossary.md#grafana) dashboard and a ready-to-run
stack are in [`examples/monitoring`](../../examples/monitoring/).

```toml
# ferrosip.toml
[modules.prometheus]
listen = "127.0.0.1:9095"
bearer_token_file = "/run/secrets/metrics"   # optional
```

The module has no routing functions. The `[modules.prometheus]` section in
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) loads it, and
`enabled = false` turns it off.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ferrosip
    authorization: { credentials_file: /run/secrets/metrics }   # if a token is set
    static_configs: [{ targets: ["ferrosip:9095"] }]
```

## Endpoints

| Path | |
|---|---|
| `/metrics` (`path`) | The text exposition format 0.0.4, gzip when asked |
| `/-/healthy` | 200 `ok`, no token needed |
| `/` | A link to the metrics |

Only GET and HEAD are served. At most `max_connections` (16) clients can
connect at once. The next one gets 503. The same text is also available
through the [RPC](../../docs/glossary.md#rpc) command `prometheus.metrics`.

## Parameters

| Name | Default | Description |
|---|---|---|
| `listen` | none (required) | `ip:port`. ferrosip exits at startup if it can't bind it |
| `path` | `/metrics` | Metrics path |
| `prefix` | `ferrosip_` | Put before every name except `process_*` |
| `bearer_token` / `bearer_token_file` | none | When set, `/metrics` needs `Authorization: Bearer <token>` (compared in constant time) |
| `max_connections` | 16 | Concurrent HTTP connections |
| `groups` | all | Comma list of [statistic](../../docs/glossary.md#statistics) groups to include (e.g. `core,tm,usrloc`). Histograms, labelled counters and process metrics are always included |

## Metrics

A metric family appears once something has created it. A
[counter](../../docs/glossary.md#counter) appears on its first use. A
module's metrics appear when the module is loaded.

**SIP and transactions**

The `tm` rows come from the [tm](../../docs/glossary.md#tm) module, which
tracks each [transaction](../../docs/glossary.md#transaction). The `sl`
rows come from [sl](../../docs/glossary.md#sl), which sends replies
without keeping state.

| Name | Type | Labels |
|---|---|---|
| `ferrosip_sip_requests_received_total` | counter | `method` (INVITE, ACK, BYE, CANCEL, REGISTER, OPTIONS, MESSAGE, other) |
| `ferrosip_sip_messages_received_total` | counter | `kind` (request, reply, invalid) |
| `ferrosip_request_route_seconds` | histogram | `method`: time to run `request_route` (`route main`) (10 µs … 100 ms) |
| `ferrosip_tm_transactions_total`, `ferrosip_tm_local_transactions_total` | counter | |
| `ferrosip_tm_transactions` | gauge | in memory now |
| `ferrosip_tm_replies_total` | counter | `class` (2xx … 6xx): finals sent upstream |
| `ferrosip_tm_replies_received_total` / `_sent_total` / `_generated_total` | counter | |
| `ferrosip_tm_retransmissions_total`, `ferrosip_tm_timeouts_total` | counter | |
| `ferrosip_tm_transaction_seconds` | histogram | `method` (INVITE, other), `class`: request in to final reply out (5 ms … 30 s) |
| `ferrosip_tm_invite_first_reply_seconds` | histogram | INVITE in to its first reply above 100 out: post-dial delay |
| `ferrosip_sl_replies_total` | counter | `class` (1xx … 6xx): stateless replies |
| `ferrosip_sl_replies_sent_total` | counter | |

`request_route` is the [request route](../../docs/glossary.md#request-route).
"Finals" are [final replies](../../docs/glossary.md#final-reply).

**State, transport and calls**

| Name | Type | Labels |
|---|---|---|
| `ferrosip_dialogs` | gauge | `state` (active, early) |
| `ferrosip_usrloc_registered_users`, `ferrosip_usrloc_contacts` | gauge | |
| `ferrosip_tcp_connections` | gauge | TCP/TLS/WS |
| `ferrosip_tcp_connections_accepted_total` | counter | |
| `ferrosip_tcp_connections_rejected_total` | counter | `reason` (max_connections, per_ip_limit) |
| `ferrosip_udp_receive_errors_total` | counter | |
| `ferrosip_ai_calls_active`, `ferrosip_ai_calls_total`, `ferrosip_ai_calls_failed_total` | gauge / counter | |
| `ferrosip_ai_connect_seconds` | histogram | `provider` |
| `ferrosip_ai_call_seconds` | histogram | `provider`, `outcome` (answered, failed, cancelled) |

`ferrosip_dialogs` counts each [dialog](../../docs/glossary.md#dialog).
The `usrloc` gauges come from the [usrloc](../../docs/glossary.md#usrloc)
registration store. WS is [WebSocket](../../docs/glossary.md#websocket).

**Process and build**

| Name | Type | Labels |
|---|---|---|
| `ferrosip_panics_total` | counter | |
| `ferrosip_send_errors_total` | counter | |
| `ferrosip_build_info` | gauge | `version` |
| `process_cpu_seconds_total`, `process_resident_memory_bytes`, `process_virtual_memory_bytes`, `process_open_fds`, `process_max_fds`, `process_threads`, `process_start_time_seconds` | | standard client-library names |

**Everything else:** every other statistic is exported as
`ferrosip_<group>_<name>`. That covers other modules and `counters` script
counters. A counter gets `_total` at the end. For example, `app.pings`
becomes `ferrosip_app_pings_total`.

## Cost

Per request, the SIP path does:
- a counter increment;
- two clock reads around `request_route`;
- one histogram observe.

That totals about 76 ns, all lock-free atomics. Transactions add one or
two observes. An A/B measurement in
[`bench/BASELINE.md`](../../bench/BASELINE.md) shows the cost is within
noise.

## prometheus or xhttp_prom?

- **`xhttp_prom`** keeps Kamailio's names (`kamailio_tm_2xx`), so
  dashboards built for Kamailio keep working. It has no labels and no
  histograms. The `xhttp` listener serves it.
- **`prometheus`** has the native names, labels and histograms that the
  bundled dashboard uses. It runs on a bounded listener of its own.

Both can run at once.

## Security

- The metrics reveal traffic levels and the software version.
- Listen on a private address, or set a bearer token.
- Plain HTTP sends the token in clear. Put a TLS proxy in front when the
  traffic crosses untrusted networks.

## Testing

`tests/e2e_prometheus.py` starts a proxy with tm, usrloc, dialog and the
exporter. It sends real traffic: REGISTERs, stateless OPTIONS, relayed
MESSAGEs and an INVITE that rings for 100 ms. Then it checks `/metrics`:
- the Bearer token is required (401 without), `/-/healthy` is open;
- the exposition format parses strictly (HELP/TYPE once per family, valid
  names and labels, `_total` counters, cumulative buckets with
  `+Inf == _count`);
- the values match the traffic: requests by method, replies by class,
  users, dialogs, the routing and transaction histograms (the ringing delay
  in the INVITE's buckets), process metrics and build info;
- gzip, 405 for POST, and 503 at the connection limit with recovery after.

CI checks the Grafana dashboard against a live stack
(`examples/monitoring`, `.github/workflows/monitoring-example.yml`).
