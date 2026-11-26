# l12-imported-failure-routes (large)

This scenario checks the [failure route](../../../docs/glossary.md#failure-route)
of an imported [Kamailio](../../../docs/glossary.md#kamailio) config. It
takes Kamailio's stock `etc/kamailio.cfg` (vendored, unmodified, in
`tests/compat/kamailio`), as
[l08](../l08-imported-kamailio/README.md) does, but with voicemail and the
3xx / 401 / 407 blocks switched on. [`ferrosip import`](../../../docs/glossary.md#import)
turns `route[RELAY]`'s `t_on_failure("MANAGE_FAILURE")` + `t_relay()` into
`let res = await txn.relay(msg)` + `match`, and
`failure_route[MANAGE_FAILURE]` into a function called after it. The
scenario proves that this restructuring answers every failure case exactly
like the original [`.cfg`](../../../docs/glossary.md#cfg).

```
kamailio.cfg ──ferrosip import --define ACTIVE WITH_VOICEMAIL WITH_BLOCK3XX WITH_BLOCK401407──▶ ferrosip.toml + routes/main.fsr
                                    (l08's import.sh: lint --fix · check · lint -D warnings · fmt --check)

bob ──UDP──▶ ferrosip -f kamailio.cfg   ┐──▶ alice (registered; answers as each probe needs)
bob ──UDP──▶ ferrosip --config import   ┘──▶ vm    (voicemail.srv_ip / srv_port, set over RPC)
```

**Shows**:
- `import.sh` runs l08's script with the four defines;
- the voicemail server's address is set at run time on both proxies over
  [RPC](../../../docs/glossary.md#rpc): `cfg.set_now_string voicemail
  srv_ip|srv_port`. These are the config variables the script reads with
  `$sel(cfg_get.voicemail.*)`;
- short tm timers on both: `fr_timer` 2 s and `fr_inv_timer` 3 s. tm's
  timers can't be changed over RPC. So the `.cfg` runs as a copy with its
  two `modparam`s edited, and the import runs with `--set
  modules.tm.fr_timer=2s --set modules.tm.fr_inv_timer=3s`.

**Edge cases checked** (`tests/scenarios/l12_imported_failure_routes.py`).
Each runs against the original `.cfg` and against the import, and the two
are then compared.
- Alice busy (486) → `MANAGE_FAILURE` sends the call to voicemail, which
  answers 200.
- Alice busy, and voicemail busy (486) → the
  [serial forking](../../../docs/glossary.md#forking) to voicemail repeats
  until the transaction has `max_branches` (12)
  [branches](../../../docs/glossary.md#branch): alice's and 11 to
  voicemail. Then `t_relay` fails at once in failure code, and the caller
  gets `500 Forking capacity exceeded (12/TM)`.
- Alice busy, voicemail unavailable (503) → the caller gets tm's own
  `500 Service Unavailable` (a 503 isn't forwarded). The stock cfg sets `failure_reply_mode` to 3, so
  alice's 486 stopped competing when the voicemail leg started:
  `t_check_status` sees the 503, and voicemail is not tried again.
- Alice 404 → forwarded, voicemail not tried.
- Alice rings and never answers → after `fr_inv_timer` she gets a
  [CANCEL](../../../docs/glossary.md#cancel), and the call goes to voicemail
  (200).
- Alice silent (no reply at all) → after `fr_timer` the call goes to
  voicemail (200).
- Alice 302, 401 or 407 → `404 Not found` (`WITH_BLOCK3XX`,
  `WITH_BLOCK401407`), voicemail not tried.
- Alice 500 → forwarded, voicemail not tried.
- Alice busy, voicemail rings, the caller cancels → voicemail gets the
  CANCEL, `MANAGE_FAILURE` stops at `t_is_canceled()`, and the caller gets
  voicemail's 487 (alice's 486 no longer competes).
- No `ERROR` and no panic in either log.

**Run it by hand**: `sh import.sh /tmp/l12`, then
`ferrosip --config /tmp/l12/ferrosip.toml -l udp:127.0.0.1:5060`, and
`ferroctl cfg.set_now_string voicemail srv_ip 127.0.0.1`.
