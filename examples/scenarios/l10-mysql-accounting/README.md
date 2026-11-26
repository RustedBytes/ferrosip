# l10-mysql-accounting (large)

This scenario models call accounting into MySQL/MariaDB (`cdr`,
[Kamailio](../../../docs/glossary.md#kamailio) acc). It writes:
- one row per [INVITE](../../../docs/glossary.md#invite)
  [transaction](../../../docs/glossary.md#transaction): in `acc` when it is
  answered, and in `missed_calls` when it fails;
- one row in `cdrs` per answered call when it ends (see
  [CDR](../../../docs/glossary.md#cdr)).

The [dialogs](../../../docs/glossary.md#dialog) are stored too
(`[modules.dialog] db_mode`). So a call outlives a proxy restart, and its
CDR is still written. It proves that every call outcome gives the right
row, and it documents what is lost while the database is down.

```
alice ──INVITE──▶ ferrosip ──────────────────────────▶ PBX (features.callee)
                  dialog.manage(), flags ACC, ACC_MISSED   200 / busy 486 / ring / no answer
                    │
                    ├─ acc: final reply < 300 ──▶ acc            ┐
                    ├─ acc: final reply ≥ 300 ──▶ missed_calls   │ MySQL / MariaDB (DB_URL)
                    ├─ dialog db_mode realtime ─▶ dialog         │
                    └─ acc cdr_enable: call ends ▶ cdrs          ┘
```

**Shows**:
- `[modules.cdr]` with `db_flag`, `db_missed_flag`, `db_extra`
  (`src_user=$fU;dst_user=$rU`) and `cdr_enable`;
- `[modules.dialog] db_mode = "realtime"` with `db_url`;
- `.fsr` named [flags](../../../docs/glossary.md#flags) set with
  `msg.set(…)`;
- `[modules.txn]` timers for an unanswered call.

**Flags.** acc selects transactions by flag number. `.fsr` flags get
their bits from the compiler, from 31 down in declaration order
(docs/fsr.md). So `ACC` and `ACC_MISSED` must stay the first two flags of
`main.fsr`. Then they are bits 31 and 30, the numbers in `ferrosip.toml`.
`ferrosip check --lowered` shows `setflag(31)` and `setflag(30)` (see
[lowering](../../../docs/glossary.md#lowering)).

**Database down.** The SIP side doesn't wait for the database. A
[BYE](../../../docs/glossary.md#bye) is answered at once, and new calls
are connected.
- What can't be written is lost and logged
  (`ERROR: acc: writing cdrs: …`, also for `acc` rows and dialog writes).
  There is no retry queue, as in Kamailio.
- The dialog row of a call that ended during the outage stays in the
  table, because its delete failed. The next start loads it as a live
  dialog until its timeout (`default_timeout`, 12 h). Delete such rows by
  hand after an outage.
- MySQL must be up when ferrosip starts. The dialog module loads its
  table then, and a database it can't reach stops the start.

**Edge cases checked** (`tests/scenarios/l10_mysql_accounting.py`, rows
read with `MariaDb.sql`):
- Answered:
  - an `acc` row (INVITE 200, alice → 200);
  - a `dialog` row while the call lasts;
  - a `cdrs` row after the BYE, with a duration between 1 s and the time
    it was held, and a start time near the call's;
  - the `dialog` row deleted, and no `missed_calls` row.
- Busy: 486 and a `missed_calls` row with 486. No `acc`, `cdrs` or
  `dialog` row.
- No answer: the PBX rings after 1.5 s and never answers. fr_inv_timer
  (3 s) runs from the 180 (see
  [final response timer](../../../docs/glossary.md#final-response-timer)).
  So 408 comes about 3 s after it (RFC 3261 timer C, Kamailio's tm), with
  a `missed_calls` row with 408. **Fails today**: ferrosip answers 408
  3 s after the INVITE, 1.5 s after the 180. The timer of a ringing
  branch is extended to fr_inv_timer counted from the INVITE, instead of
  restarted at the 1xx.
- Canceled: 180, then alice's [CANCEL](../../../docs/glossary.md#cancel).
  487 and a `missed_calls` row with 487 for the INVITE. The CANCEL itself
  makes no `acc` row.
- A call answered, then the proxy restarted:
  - `dlg.list` has the call again;
  - alice's BYE goes through (200, and the PBX gets it);
  - the `cdrs` row is written with the duration since the answer before
    the restart;
  - the `dialog` row is deleted.
- The database stopped during a call:
  - the BYE gets 200 in under 3 s, and a new call is connected;
  - the lost CDR is logged;
  - the ended call's `dialog` row is still there when the database is
    back;
  - the next call gets its `acc` and `cdrs` rows, because the proxy
    reconnected;
  - after another restart, `dlg.list` shows the ended call as a live
    dialog (from the stale row).

**Run it by hand** (with a ferrosip built with the MySQL driver:
`cargo build --release --features ferrosip/db-all`): load
`etc/schema/mysql.sql` into a database. Then run
`ferrosip --config ferrosip.toml` with `SIP_PORT` (5060), `CALLEE`
(`sip:127.0.0.1:5080`) and `DB_URL`
(`mysql://user@127.0.0.1:3306/ferrosip`).
