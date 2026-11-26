# mod-async

Asynchronous processing, HTTP and JSON in the routing script. Use it when a
script step is slow, such as a timer, an HTTP query or a long task, and you
don't want it to hold up a SIP [worker](../../docs/glossary.md#worker).

How it works:

1. The slow step [suspends](../../docs/glossary.md#suspend-and-resume) the
   [transaction](../../docs/glossary.md#transaction) in
   [tm](../../docs/glossary.md#tm) (`Tm::suspend`) instead of blocking the
   worker.
2. The work runs on a thread pool or timer that the module owns.
3. Afterwards the script continues on the same transaction (`Tm::resume`).
   It keeps its script state: header edits, `$ru`/`$du`, branches, AVPs and
   flags.

The crate also holds blocking HTTP (`http_client`), JSON helpers
(`jansson`, `json`), and the `jsonrpcs` script function and FIFO transport.

The modules that suspend need `tm`, loaded first. The generic tm functions
`t_suspend()` / `t_continue()` and `$T(id_index)` / `$T(id_label)` live in
mod-txn.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `async` | `async` | Resume a route or the next action after a delay; run a route on a pool thread |
| `http` | `http_async_client` | Non-blocking HTTP(S) query, then continue in a route with the response |
| `http_client` | `http_client` | Blocking HTTP(S) queries |
| `json_doc` | `jansson` | Read and build JSON documents |
| `json` | `json` | `json_get_field` |
| `admin` | `jsonrpcs` | Run RPC commands from the script; FIFO transport |

**Cargo feature `http`**: it is on by default for this crate. The binary
passes it on as its own `http` feature. `http_client` and
`http_async_client` use `ureq`. Without the feature, those two modules
aren't built, and loading either fails, naming the feature.

## async

Suspending functions exit the script: they return 0.

- `async_sleep` and `async_ms_sleep` continue with the next action of the
  same block, as in [Kamailio](../../docs/glossary.md#kamailio).
- `async_route` / `async_ms_route` / `async_task_route` continue in the
  named route.

They work in [`request_route`](../../docs/glossary.md#request-route) and in
routes called from it.

In [`.fsr`](../../docs/glossary.md#fsr), `async.sleep(duration)` is
`async_ms_sleep`. It takes any duration: `2s`, `500ms`. `async_route`,
`async_ms_route` and `async_task_route` take a route to resume in, so they
are not offered in `.fsr`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `workers` | 1 | Threads in the module's pool (1 to 256) |

`ms_timer` is accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `async_route(route, seconds)` | Suspend, then run `route[route]` after the delay. -1 if the route does not exist |
| `async_ms_route(route, ms)` | Same, with the delay in milliseconds |
| `async_sleep(seconds)` | Suspend, then continue with the next action after the delay |
| `async_ms_sleep(ms)` | Same, with the delay in milliseconds |
| `async_task_route(route)` | Suspend, then run `route[route]` on a pool thread now. -1 if the route does not exist |

If tm cannot suspend, its error code is returned.

**Example**

```toml
[modules.async]
workers = 4
```

```rust
import async

route main(msg: Request) {
    msg.headers["X-Before"] = "1"
    async.sleep(200ms)
    msg.headers["X-After"] = "1"      // runs 200 ms later, same transaction
    txn.relay()
}
```

**Differences from Kamailio**: `async_task_group_route` and the core
`async_workers` pool are not implemented. Each module has its own pool.

## http (http_async_client)

A non-blocking HTTP query from the script:

1. The script builds the request with `$http_req(key) = value`.
2. `http_async_query(url, route)` suspends the transaction.
3. The query runs on the module's pool.
4. `route[route]` continues the request. The response is in the `$http_*`
   variables.

It does HTTP(S) via ureq (rustls) and follows up to 3 redirects. The method
defaults to GET, or POST when a body is set.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `workers` | 1 | Query threads (1 to 256) |
| `connection_timeout` | 5000 | Request timeout in ms (overridden by `$http_req(timeout)`) |

`hash_size`, `tls_version`, `tls_verify_host`, `tls_verify_peer`,
`curl_verbose`, `curl_follow_redirect`, `memory_manager`,
`tls_client_cert`, `tls_client_key`, `tls_ca_path`, `tcp_keepalive`,
`tcp_ka_idle` and `tcp_ka_interval` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `http_async_query(url, route)` | Suspend and query `url`, then continue in `route[route]`. -1 if the route does not exist |

In `.fsr` the call is [awaited](../../docs/glossary.md#await). The script
goes on after it with a typed result:

- `let r = await http.get(url[, headers][, timeout: 2s])`;
- `await http.post(url, body[, content_type][, headers][, timeout:])`.
  `content_type` defaults to `application/json`;
- `await http.request(method, url[, body][, headers][, timeout:])`;
- the result has `r.ok` (Bool: a response arrived), `r.status` (Int),
  `r.reason`, `r.body`, `r.error` (Str) and `r.ms` (Int);
- `headers` are `Name: value` lines;
- it can't be used after `await txn.relay(…)`.

**Pseudo-variables**

| Name | Description |
|---|---|
| `$http_req(key)` | Write-only request builder. Keys: `method`, `body`, `hdr` (appends a `Name: value` header), `timeout` (ms), `username`, `password` (Basic auth), `all` (reset). The TLS keys, `suspend`, `authmethod` and `follow_redirect` are accepted and ignored |
| `$http_ok` | 1 if a response arrived, 0 on a transport error |
| `$http_err` | Transport error text, or null |
| `$http_rs` | Status code (null on a transport error) |
| `$http_rr` | Reason phrase: the standard one for `$http_rs` (the HTTP client does not keep the server's own text) |
| `$http_rb` | Response body |
| `$http_bs` | Body size |
| `$http_hdr(name)` | A response header (case-insensitive) |
| `$http_time` | Query duration in ms |

These are [pseudo-variables](../../docs/glossary.md#pseudo-variable-pv) of
the `.cfg` language.

**Example**

```rust
import http

route main(msg: Request) {
    let r = await http.get("http://routing.local/next?to={msg.ruri.user}", headers: "X-Caller: {msg.from.user}", timeout: 2s)
    if r.ok && r.status == 200 {
        msg.dst_uri = "sip:{r.body}"
        relay(msg)
    }
    reply(ServiceUnavailable, "Routing service down")
}
```

The request waits while the query runs, with its transaction suspended. The
SIP workers go on with other messages.

In a `.cfg`, the same is `$http_req(hdr) = "X-Caller: $fU"` and
`http_async_query("http://routing.local/next?to=$rU", "ROUTE_REPLY")`, with
the rest in `route[ROUTE_REPLY]`.

The parameters go in `[modules.http_async_client]`. Don't use
`[modules.http]` for them: it also loads the HTTP server (`xhttp`), which
needs `listen`.

**Differences from Kamailio**: no client certificates or TLS verification
settings, and no connection hash table.

## http_client

Blocking HTTP(S) queries from the script. They hold the SIP worker for the
duration of the request. A `User-Agent` header is always sent.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `httpcon` | none | Named connection `name=>base_url` (repeatable) |
| `connection_timeout` | 4 | Request timeout in seconds |
| `query_result` | 1 | 1 = return only the first line of the body (as Kamailio does). Other values = the whole body |
| `useragent` | `ferrosip (http_client)` | User-Agent header |

`keep_connections`, `tlsverifyserver`, `tlsverifyhost`, `maxdatasize`,
`httpredirect`, `httpproxy`, `httpproxyport`, `tlsversion`, `authmethod`,
`config_file`, `query_maxdatasize`, `timeout_mode`, `cipher_suites` and
`netinterface` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `http_client_query(url[, post[, hdrs]], $res)` | GET, or POST when `post` is non-empty. `hdrs` are CRLF-separated. Stores the body in `$res`. Returns the HTTP status code, or -1 on a transport error (then `$curlerror(error)` is set). Alias `http_query` |
| `http_connect(con, path[, content_type, data], $res)` | Query `<base_url>/<path>` of connection `con`. With `content_type` and `data` it POSTs. Same return values, and -1 for an unknown connection |

**Pseudo-variables**: `$curlerror(error)`, the last transport error of this
message (null if none).

**Example**

```toml
[modules.http_client]
httpcon = ["api=>http://127.0.0.1:8080/api"]
query_result = false              # the whole body
```

The result arguments are `let` variables:

```rust
import http_client, json_doc

route main(msg: Request) {
    let body = ""
    let host = ""
    let port = ""
    http_client.get("http://routing.local/route?user={msg.ruri.user}", body)
    json_doc.get("target.host", body, host)
    json_doc.get("target.port", body, port)
    msg.dst_uri = "sip:{host}:{port}"
    txn.relay()
}
```

## json_doc (jansson)

JSON documents held in script variables. Paths look like `a.b[2].c`. The
module takes no parameters.

Value types for `jansson_set` / `jansson_append`:

- `string` (`str`);
- `integer` (`int`);
- `real`, `true`, `false`, `null`;
- `object` / `array` (`obj`, `json`). The value is parsed as JSON.

**Functions** (1 on success, -1 on a parse error or a missing path)

| Signature | Description |
|---|---|
| `jansson_get(path, json, $dst)` | Value at `path` |
| `jansson_array_size(path, json, $dst)` | Length of the array at `path` |
| `jansson_get_field(json, field, $dst)` | Top-level field |
| `jansson_set(type, path, value, $doc)` | Set `path` in the document in `$doc`. Starts a new object if `$doc` is null |
| `jansson_append(type, path, value, $doc)` | Append to the array at `path` (created if needed) |
| `jansson_xdecode(json, xavp)` | Object → one `$xavp(xavp)` item. Array of objects → one item each |
| `jansson_xencode(xavp, $dst)` | First item of `$xavp(xavp)` → JSON object (keys sorted) |

See [xavp](../../docs/glossary.md#xavp).

**Example**

```rust
let doc = ""                      // empty: jansson.set starts a new object
let out = ""
let first = ""
json_doc.set("string", "caller", msg.from.user, doc)
json_doc.append("string", "list", "a", doc)
json_doc.set("true", "flags.vip", "", doc)
http_client.connect_post("api", "/echo", "application/json", doc, out)
json_doc.get("list[0]", out, first)
```

## json

**Functions**

| Signature | Description |
|---|---|
| `json_get_field(json, field, $dst)` | Top-level field. 1 / -1 |

The `{json.parse,path}` [transformation](../../docs/glossary.md#transformation)
(`$(var(x){json.parse,a.b})`) is part of the core. It works without loading
either module.

## admin (jsonrpcs)

`jsonrpc_exec` runs a JSON-RPC request against the same
[RPC](../../docs/glossary.md#rpc) table as
[`ferroctl`](../../docs/glossary.md#ferroctl).

With `fifo_name` set, the module creates a FIFO and reads it like Kamailio's
`kamctl` transport:

- Each request carries `"reply_name"`.
- The response is written to that FIFO in `fifo_reply_dir`, or to the
  absolute path given.
- Names containing `..` are refused. So are relative names containing `/`.

The UNIX socket used by `ferroctl` belongs to the core, not to this module.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `fifo_name` | none (no FIFO) | Path of the FIFO to create |
| `fifo_reply_dir` | `/tmp/` | Directory of the reply FIFOs. It is a prefix, so include the trailing `/` |

`transport`, `fifo_mode`, `fifo_group`, `fifo_user`, `dgram_socket`,
`dgram_mode`, `pretty_format` and `tcp_socket` are accepted and ignored.

**Functions**

| Signature | Description |
|---|---|
| `jsonrpc_exec(json)` | Run one request. The result is in `$jsonrpl(...)`. Returns 1 |

**Pseudo-variables**:

- `$jsonrpl(code)`: 200, or the JSON-RPC error code;
- `$jsonrpl(text)`: "OK" or the error message;
- `$jsonrpl(body)`: the full JSON-RPC response.

**Example**

```toml
[modules.admin]                   # jsonrpcs
fifo_name = "/run/ferrosip/ferrosip_fifo"
```

`.fsr` has `admin.exec(request)`, but the answer is only in the
`$jsonrpl(...)` variables. So this example uses a Kamailio-style
[`.cfg`](../../docs/glossary.md#cfg):

```
request_route {
    jsonrpc_exec("{\"jsonrpc\":\"2.0\",\"method\":\"core.version\",\"id\":1}");
    xlog("L_INFO", "rpc: $jsonrpl(code) $jsonrpl(body)\n");
}
```

**Differences from Kamailio**: only the FIFO transport. This module has no
datagram or TCP socket transports.

## Testing

- `tests/e2e_async.py`: `async_ms_sleep` (including two in one block),
  `async_route`, `async_task_route`, `http_async_query` with `$http_*`
  (success and transport error). Also tm's `t_suspend` / `t_continue`,
  retransmissions and CANCEL while suspended, the suspend timeout, and
  `sql_query_async` (mod-extra).
- `tests/e2e_fsr.py`: `await http.get` in `.fsr`. It runs
  [`ferrosip test`](../../docs/glossary.md#test-block) with a local HTTP
  server: relay to the body, a 404, a service that is down.
- `tests/e2e_json.py`: `http_client_query`, `http_connect` with `httpcon`,
  `$curlerror`, status codes as return values, the jansson functions,
  `json_get_field`, `{json.parse,...}`, `jsonrpc_exec` and the FIFO
  transport.
- Unit tests: Basic-auth base64, FIFO request splitting.
- Fuzzing: `fuzz/fuzz_targets/dns.rs` also fuzzes the JSON path code
  (`sip_core::json::get` / `slot`) that jansson uses.
