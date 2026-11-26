# l08-imported-kamailio (large)

This scenario models a migration from [Kamailio](../../../docs/glossary.md#kamailio).
It takes Kamailio's stock `etc/kamailio.cfg` (vendored, unmodified, in
`tests/compat/kamailio`), turns it into a ferrosip configuration, and runs
it. It proves that [`ferrosip import`](../../../docs/glossary.md#import)
produces a clean configuration, and that the import answers the same
traffic exactly as the original [`.cfg`](../../../docs/glossary.md#cfg)
does.

```
kamailio.cfg ──ferrosip import --define ACTIVE──▶ ferrosip.toml + routes/main.fsr
                                                  │ ferrosip lint --fix   (trailing returns, …)
                                                  │ ferrosip check · lint -D warnings · fmt --check
                                                  ▼
UA ──UDP──▶ ferrosip -f kamailio.cfg   ┐ the same traffic to both:
UA ──UDP──▶ ferrosip --config import   ┘ they must answer it the same way
```

The generated files are not kept here. `import.sh` holds the exact
commands, and the test runs it into its temp directory. Without a
`ferrosip.toml` in this directory, the runner's static checks have
nothing to do. The script runs them on the import instead.

**Shows**:
- `ferrosip import` with a `--define` (see
  [preprocessor](../../../docs/glossary.md#preprocessor));
- `ferrosip lint --fix` cleaning up after the import. It removes 24
  trailing `return`s (see [lint](../../../docs/glossary.md#lint));
- the result passes `check`, `lint -D warnings` and `fmt --check` with no
  further edits;
- it runs with `-l` and `--rpc-socket` given on the command line, because
  the stock config has no `listen=`.

**Edge cases checked** (`tests/scenarios/l08_imported_kamailio.py`). Each
runs against the original `.cfg` and against the import, and the two are
then compared.
- The traffic of `tests/e2e_compat.py`'s stock test:
  - [OPTIONS](../../../docs/glossary.md#options) to the server →
    `200 Keepalive`;
  - [REGISTER](../../../docs/glossary.md#register) saved (200 with the
    contact);
  - [INVITE](../../../docs/glossary.md#invite) to an unknown user →
    `404 Not Found`, and the [ACK](../../../docs/glossary.md#ack) isn't
    answered;
  - [MESSAGE](../../../docs/glossary.md#message) to the registered user
    is relayed to her contact, and her 200 comes back. A
    [retransmission](../../../docs/glossary.md#retransmission) is
    absorbed: the 200 is resent, and nothing is relayed again.
- An INVITE to the registered user is relayed with the proxy's
  [Record-Route](../../../docs/glossary.md#record-route), and the
  [BYE](../../../docs/glossary.md#bye) goes through it.
- Her 486 is forwarded (`failure_route[MANAGE_FAILURE]`; in the import
  the code after `await txn.relay`). A
  [CANCEL](../../../docs/glossary.md#cancel) while she rings gives 487,
  and she gets the CANCEL.
- An INVITE whose Via has no branch can't be relayed: `t_relay` fails at
  once and `send_reply_error()` answers 400 (no failure route runs).
- `Max-Forwards: 0` → 483.
- An in-dialog BYE for an unknown dialog → `404 Not here`.
- A `friendly-scanner` User-Agent is dropped without a reply.
- An [R-URI](../../../docs/glossary.md#r-uri) over 512 bytes →
  `403 R-URI too large`.
- No `ERROR` and no panic in either log.

**Run it by hand**: `sh import.sh /tmp/l08`, then
`ferrosip --config /tmp/l08/ferrosip.toml -l udp:127.0.0.1:5060`.
