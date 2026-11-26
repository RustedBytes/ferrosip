# ferrosip with HOMER

This example shows how to record every SIP message that passes through
ferrosip, so you can search and inspect calls later. It runs ferrosip next
to a [HOMER](../../docs/glossary.md#homer) stack in Docker. Use it as a
template when you need call tracing in production.

[HOMER](https://github.com/sipcapture/homer) captures and searches SIP
traffic. ferrosip's [`siptrace`](../../docs/glossary.md#siptrace) module
sends every [transaction](../../docs/glossary.md#transaction) to
heplify-server as [HEPv3](../../docs/glossary.md#hep). It does this in the
same way as [Kamailio](../../docs/glossary.md#kamailio)
([Homer's Kamailio example](https://github.com/sipcapture/homer/wiki/Examples%3A-Kamailio)).
heplify-server stores the traffic in the database. homer-app is the web UI.

```bash
cd examples/homer
docker compose up -d --build       # builds ferrosip from the repo root
python3 smoke.py                   # REGISTER + a call through ferrosip, then checks HOMER has them
```

Open <http://localhost:9080> and log in as `admin` / `sipcapture`. Search
for the [Call-ID](../../docs/glossary.md#call-id) that `smoke.py` prints,
or point your phones at `<host>:5060`.

| Service | Image | Ports (host) |
|---|---|---|
| `ferrosip` | built from `Dockerfile` | 5060 udp/tcp (host network) |
| `heplify-server` | `sipcapture/heplify-server` | 9060/udp HEP, 9061/tcp HEP |
| `homer-webapp` | `ghcr.io/sipcapture/homer-app` | 9080 → 80 (web UI) |
| `db` | `timescale/timescaledb:latest-pg16` | (internal) |

The HOMER part is sipcapture/homer7-docker's
`heplify-server/hom7-timescaledb-all`, without Grafana, Prometheus, Loki
and Telegraf. Data is kept for 5 days (`HEPLIFYSERVER_DBDROPDAYS`).

## What ferrosip sends

`ferrosip.cfg` is a small [registrar](../../docs/glossary.md#registrar) and
[proxy](../../docs/glossary.md#proxy):
- registered users are reached with `lookup()` and `t_relay()`;
- [in-dialog requests](../../docs/glossary.md#in-dialog-request) follow the
  `record_route()` set (see [Record-Route](../../docs/glossary.md#record-route)).

Tracing:

```
loadmodule "siptrace"
modparam("siptrace", "duplicate_uri", "sip:127.0.0.1:9060")   # heplify-server
modparam("siptrace", "hep_capture_id", 2001)
modparam("siptrace", "trace_flag", 22)

request_route {
    setflag(22);        # trace this request's transaction, in and out
    ...
}
```

- **Captured:** with the [flag](../../docs/glossary.md#flags) set, HOMER
  receives:
  - the request as received and as relayed;
  - the 100 Trying;
  - every reply in both directions.

  For a call that's the [INVITE](../../docs/glossary.md#invite), 100, 180,
  200, [ACK](../../docs/glossary.md#ack), [BYE](../../docs/glossary.md#bye)
  and its 200, each seen on both sides of the proxy.
- **Log records:** `hlog("$ci", "…")` adds a log record with the Call-ID as
  correlation ID. It shows up with the call in HOMER.
- **Other options:** `sip_trace("sip:other-homer:9060")` sends a call to a
  second collector. `sip_trace_mode("d")` traces whole
  [dialogs](../../docs/glossary.md#dialog). See
  [siptrace](../../crates/mod-extra/README.md#trace-siptrace).

## Notes

- **Networking:** ferrosip uses the host network, because SIP carries
  addresses in its headers. It sends HEP to the port that heplify-server
  publishes on the host. If ferrosip runs elsewhere, set `duplicate_uri` to
  `sip:<this host>:9060`.
- **Production:**
  - change the database password (`homerSeven` in three places);
  - change homer-app's `admin` password;
  - pin the HOMER image versions: upstream uses `latest` too.
- **CI:** the "HOMER example" workflow runs this setup and `smoke.py` when
  the example or siptrace changes, and weekly.
