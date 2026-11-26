# ferroctl

`ferroctl` lets you inspect and control a running ferrosip from the shell.
Use it to read counters, list registrations and calls, or reload the
routing script without a restart. It is the command-line client for
ferrosip's JSON-[RPC](../../docs/glossary.md#rpc) control socket, the
equivalent of [Kamailio's](../../docs/glossary.md#kamailio)
[`kamcmd`](../../docs/glossary.md#kamcmd). It also formats routing scripts
(`ferroctl fmt`, see below).

It sends one JSON-RPC 2.0 request over the Unix socket that
`ferrosip --rpc-socket` opens. It prints the result as pretty JSON.

```bash
ferroctl [-s SOCKET] <method> [params…]
```

| Option | Default | Meaning |
|---|---|---|
| `-s SOCKET` | `/tmp/ferrosip-rpc.sock` | Control socket path; must be the first argument |

Parameters that parse as JSON (numbers, `true`/`false`, objects, arrays) are
sent as JSON. Anything else is sent as a string. So `ferroctl dlg.end_dlg 1 2`
sends two integers, and `ferroctl stats.get_statistics tm:` sends the string
`"tm:"`.

## Formatting scripts: `ferroctl fmt`

```bash
ferroctl fmt etc/ferrosip.cfg            # rewrite in place ("formatted etc/ferrosip.cfg")
ferroctl fmt --check etc/*.cfg           # change nothing; exit 1 and list files that would change
ferroctl fmt < in.cfg > out.cfg          # stdin to stdout (also: ferroctl fmt -)
```

`fmt` runs locally and doesn't need the control socket. It re-indents the
routing script:
- 4 spaces per `{ }` level;
- `case`/`default` bodies one level below their label;
- continuation lines inside open `( )` one level deeper.

It also trims trailing whitespace and collapses runs of blank lines.
Everything else on a line, including comments, stays as written.

A script that doesn't parse is refused, with the parser's line number. The
formatted output must lex to exactly the same tokens as the input. So
formatting never changes what a script does. Formatting is idempotent.

| Exit | Meaning |
|---|---|
| 0 | Formatted (or, with `--check`, already formatted) |
| 1 | `--check`: at least one file would change |
| 2 | A file can't be read or written, or doesn't parse |

## Examples

```bash
ferroctl system.listMethods                 # every RPC the loaded modules registered
ferroctl stats.get_statistics all           # all statistics
ferroctl stats.get_statistics tm:           # one group
ferroctl tm.stats                           # transactions, incl. current / branch_index
ferroctl ul.dump                            # registered contacts (usrloc)
ferroctl dlg.list                           # active dialogs (dialog)
ferroctl dispatcher.list                    # destinations and their state
ferroctl cfg.reload                         # reload the routing script's routes
ferroctl -s /run/ferrosip/ctl.sock core.uptime
```

The glossary explains these terms:
[statistics](../../docs/glossary.md#statistics),
[transactions](../../docs/glossary.md#transaction),
[usrloc](../../docs/glossary.md#usrloc),
[dialogs](../../docs/glossary.md#dialog),
[dispatcher](../../docs/glossary.md#dispatcher) and
[`cfg.reload`](../../docs/glossary.md#live-reload).

Which methods exist depends on the [modules](../../docs/glossary.md#module)
loaded. `system.listMethods` lists them. Each module's README documents its
own.

## Output and exit status

| Exit | Output |
|---|---|
| 0 | The `result` member, pretty-printed JSON, on stdout |
| 1 | `error: <message>` on stderr (RPC error), or a connect or protocol error |
| 2 | Usage error (no method given) |

Because the output is JSON, it works well with `jq`:

```bash
ferroctl tm.stats | jq .current
```

## Protocol

The protocol is newline-delimited JSON-RPC 2.0. The server reads requests
line by line, so one connection can carry several. ferroctl sends one:

```json
{"jsonrpc": "2.0", "id": 1, "method": "ul.dump", "params": []}
```

Each request gets one line back, `{"jsonrpc":"2.0","id":1,"result":…}` or
`{…,"error":{"message":…}}`. Any client that writes such a line to the
socket can drive ferrosip. The test suites do the same through this binary.
