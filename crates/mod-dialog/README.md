# mod-dialog

Call tracking: the proxy follows each INVITE
[dialog](../../docs/glossary.md#dialog) from start to end. Use it when you
need to count active calls, limit call length, end calls from the proxy, or
attach data to a call. It is a port of
[Kamailio](../../docs/glossary.md#kamailio)'s `dialog` module.

It keeps a state machine per call. When a call times out, it ends the call
by sending a [BYE](../../docs/glossary.md#bye) to both sides. It also
provides:

- in-dialog [keep-alives](../../docs/glossary.md#keepalive);
- [dialog profiles](../../docs/glossary.md#dialog-profile), for counting
  calls;
- per-dialog variables and flags;
- call transfer (`dlg_refer`) and click-to-dial (`dlg_bridge`);
- event routes, statistics and RPCs;
- optional database persistence.

Other modules use it through its API: `acc` [CDRs](../../docs/glossary.md#cdr),
`cnxcc`, `pua_dialoginfo`, `dispatcher`, `ims_charging` and `ims_qos`. It
sends its BYEs, OPTIONS, REFERs and INVITEs through
[tm](../../docs/glossary.md#tm)'s [UAC](../../docs/glossary.md#uac) API. So
`tm` must be loaded first.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `dialog` | `dialog` | Dialog state, timeouts and BYEs, keep-alives, profiles, flags, `$dlg_var`, `$dlg`, `$dlg_ctx`, REFER and bridging, `dlg.*` RPCs, `dialog` table |

## Quick start

[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml):

```toml
[modules.dialog]
default_timeout = "2h"
profiles_with_value = "caller"
profiles_no_value = "calls"
```

The routing ([`.fsr`](../../docs/glossary.md#fsr); tm loads by itself):

```rust
import dialog

dialog var account: Str                    // $dlg_var(account)

on dialog.ended(d: Dialog) {               // event_route[dialog:end]
    log.info("call {d.call_id} ended, account {d.account}\n")
}

route main(msg: Request) {
    if msg.has_to_tag {
        if dialog.is_known() {
            log.info("in-dialog {msg.method}\n")
        }
        relay(msg)
    }
    if msg.method == INVITE {
        dialog.manage()
        dialog.set_profile("calls")
        dialog.set_profile_value("caller", msg.from.user)
        dialog.account = msg.from.user
        dialog.set_property("timeout-bye")
    }
    relay(msg)
}
```

`$dlg(attr)` and `$dlg_ctx(attr)` have no `.fsr` form in routes. Dialog
[handlers](../../docs/glossary.md#event-handler) read the same attributes as
`d.call_id`, `d.state`, `d.started_at`, …. See
[dialog variable](../../docs/glossary.md#dialog-variable).

## Parameters

| Name | Default | Description |
|---|---|---|
| `default_timeout` | 43200 | Lifetime (s) of a confirmed dialog, counted from the 2xx. Minimum 1. |
| `early_timeout` | 300 | Unconfirmed dialogs are removed (as failed) this many seconds after the INVITE. Minimum 1. |
| `send_bye` | 0 | 1: send BYE to both sides when any dialog times out. Per dialog: `dlg_set_property("timeout-bye")`. |
| `ka_interval` | 0 | Seconds between in-dialog OPTIONS keep-alives, for dialogs with `ka-src` / `ka-dst` set. 0 = off. |
| `profiles_with_value` | none | `"a;b"`: profiles that take a value. Can be repeated. |
| `profiles_no_value` | none | `"a;b"`: profiles without a value. Can be repeated. |
| `db_url` | none | sip-db URL for the `dialog` table. Required when `db_mode` > 0. |
| `db_mode` | `off` (0) | Stores confirmed dialogs in the `dialog` table and loads them at startup. 1 (realtime) writes every change at once. 2 (delayed) writes every `db_update_period` and at shutdown. 3 (shutdown) writes only at shutdown. |
| `db_update_period` | 60 | Seconds between the writes of `db_mode` 2. |
| `dlg_flag` | -1 (none) | A message [flag](../../docs/glossary.md#flags). An initial INVITE that tm relays (`t_relay`, `t_newtran`) with this flag set gets a dialog, as with `dlg_manage()`. |
| `dlg_match_mode` | 1 | How in-dialog requests find their dialog. 0: by the Record-Route cookie only. 1: by the cookie, else by Call-ID and tags. 2: by Call-ID and tags only, and no cookie is added. |
| `rr_param` | `did` | Name of the Record-Route cookie parameter. |
| `timeout_noreset` | 0 | 1: in-dialog requests restart no dialog's timeout. This is the `timeout-noreset` property for every dialog. |
| `bridge_controller` | `sip:controller@ferrosip.invalid` | From of `dlg_bridge`'s INVITE, and Referred-By of the REFERs. |
| `bridge_contact` | `sip:controller@<our address>` | Contact of `dlg_bridge`'s call leg. |

`ka_timer`, `hash_size`, `timeout_avp`, `track_cseq_updates` and
`enable_stats` are accepted and ignored.

In `[modules.dialog]` the types differ (`ferrosip schema dialog`):

- times are durations (`"2h"`, `"5m"`). A bare number is seconds;
- `send_bye` is a bool;
- `db_mode` is `"off"`, `"realtime"`, `"delayed"` or `"shutdown"`.

## Functions

| Function | Description |
|---|---|
| `dlg_manage()` | On an [initial](../../docs/glossary.md#initial-request) INVITE (no To tag), creates the dialog. If one with the same Call-ID and From tag exists (a retransmission), it finds that one. Returns 1. On other requests it returns 1 if the request matched a known dialog, else -1. |
| `is_known_dlg()` | 1 if the current message belongs to a dialog, else -1. |
| `dlg_set_timeout(secs[, h_entry, h_id])` | Sets the lifetime of the current dialog, or of the one with `h_id`. `h_entry` is accepted but not used. For a confirmed dialog the timeout restarts from now. Later in-dialog requests restart it with this lifetime (Kamailio's `update_dlg_timeout()`). Arguments may be variables. Returns -1 without a dialog, with no dialog with `h_id`, or for `secs` ≤ 0 (Kamailio's `w_dlg_set_timeout()`). For the dialog a request will create with `dlg_flag`, set `$dlg_ctx(timeout)` instead. |
| `dlg_set_timeout_by_profile(profile[, value], secs)` | As in Kamailio: every dialog of the profile that is early or later gets the lifetime `secs`. Unconfirmed ones are skipped. The lifetime restarts from now when the dialog is confirmed, as with `dlg_set_timeout()`. For a profile with values, `value` picks the dialogs with that value (an empty value is -1). Without it, or for a profile without values, all of them are picked. Returns 1, also when no dialog matched. `secs` may be a variable (Kamailio reads it as a literal number). |
| `dlg_bye("all" \| "caller" \| "callee")` | Sends BYE to one or both sides of the current confirmed dialog. `"all"` also ends the dialog. -1 if there is no confirmed dialog or no BYE could be sent. |
| `dlg_set_property(p)` / `dlg_reset_property(p)` | `p` is one of: `timeout-bye` (BYE both sides on timeout), `ka-src` / `ka-dst` (keep-alives to the caller / callee), `timeout-noreset` (in-dialog requests don't restart the timeout). Without a dialog, it applies to the one this request will create. |
| `dlg_setflag(n)` / `dlg_resetflag(n)` | Sets / clears dialog flag `n` (0–31) on the current dialog. It also sets it in the dialog context, so a dialog that this request creates later (`dlg_flag`) gets it. Stored with the dialog in the database. |
| `dlg_isflagset(n)` | 1 if flag `n` is set on the current dialog, else -1. Without a dialog it checks the dialog context. |
| `dlg_get(callid, ftag, ttag)` | Finds the dialog with these ids, in either direction. It becomes the current one for `$dlg`, `$dlg_var`, `dlg_bye`, …. -1 if there is none. |
| `dlg_refer(side, to)` | Sends REFER with `Refer-To: <to>` inside the confirmed current dialog to `"caller"` or `"callee"`. It sends it as the other party (its From, To, CSeq and Contact), with `Referred-By: <bridge_controller>`. The dialog stays as it is. The referred side ends it with its BYE. |
| `dlg_bridge(from, to, op[, sdp])` | Calls `from`: an INVITE from `bridge_controller`, via [outbound proxy](../../docs/glossary.md#outbound-proxy) `op` unless it is empty, with an on-hold SDP or `sdp`. When `from` answers, it ACKs and sends REFER with `Refer-To: <to>`. After the REFER's final reply it sends BYE. 1 if the INVITE went out. |
| `set_dlg_profile(profile[, value])` | Adds the current dialog to a profile. Whether a value is needed is checked at startup against `profiles_with_value` / `profiles_no_value`. |
| `unset_dlg_profile(profile[, value])` | Removes it. Without a value, every entry of that profile is removed. 1 if something was removed, else -1. |
| `is_in_profile(profile[, value])` | 1 if the current dialog is in the profile (with that value, when given), else -1. |
| `get_profile_size(profile[, value], $var)` | Stores the number of live dialogs in the profile (with that value, when given) in `$var`. |

In `.fsr` they are `dialog.manage()`, `dialog.is_known()`,
`dialog.set_timeout()`, `dialog.bye()`, `dialog.set_property()`,
`dialog.set_profile()` / `dialog.set_profile_value()`,
`dialog.profile_size()`, `dialog.set_timeout_by_profile()` /
`dialog.set_timeout_by_profile_value()`, `dialog.set_flag()` /
`dialog.reset_flag()` / `dialog.is_flag_set()`, `dialog.get()`,
`dialog.refer()`, `dialog.bridge()`, and the others in
`docs/functions-reference.md`.

## Pseudo-variables

| Variable | Description |
|---|---|
| `$dlg_var(name)` | Read/write variable of the current dialog. Assigning `$null` deletes it. With `db_mode`, writes are stored in the database. |
| `$dlg(attr)` | Read-only: `h_id`, `h_entry`, `state` (1–5), `callid`, `from_uri`, `from_tag`, `to_uri`, `to_tag`, `start_ts` (Unix time of the 2xx), `timeout` (Unix time the dialog expires), `lifetime` (seconds), `sflags` (`dlg_setflag` flags), `from_contact`, `to_contact`, `from_cseq`, `to_cseq`, `from_rs`, `to_rs` (route sets), `toroute_name` (timeout route). In `dialog:end` also `end_reason` and `duration`. `$null` without a dialog. |
| `$dlg_ctx(attr)` | The dialog context of the message. Read/write: `on` (1: tm's relay creates the dialog, like `dlg_flag`), `flags`, `timeout` (seconds), `timeout_bye` (0/1), `timeout_route` (name of a `route` run when the dialog times out, before it ends). Writes to the last three also change the current dialog. Read-only: `set` (1 if the message has a dialog), `dir` (1 from the caller, 2 from the callee, 0 no dialog). |

These are [pseudo-variables](../../docs/glossary.md#pseudo-variable-pv) of
the `.cfg` language.

## Event routes

| Route | Runs when |
|---|---|
| `event_route[dialog:start]` (`.fsr`: `on dialog.started`) | A 2xx confirms the dialog. Runs on the reply. |
| `event_route[dialog:end]` (`on dialog.ended`) | A dialog ends: BYE (runs on the BYE), timeout, `dlg_bye("all")`, `dlg.end_dlg`, or a failed keep-alive. |
| `event_route[dialog:failed]` (`on dialog.failed`) | An unconfirmed dialog ends: a final ≥ 300 went upstream, or `early_timeout` expired. |

Inside these [event routes](../../docs/glossary.md#event-route), `$dlg(...)`
and `$dlg_var(...)` refer to the dialog. In `.fsr` use the handler's `d.*`
fields and the declared `dialog var`s.

## RPC commands

| Command | Description |
|---|---|
| `dlg.list` | All dialogs: `h_entry`, `h_id`, `call-id`, `from_uri`, `from_tag`, `to_uri`, `to_tag`, `state`, `start_ts`, `timeout`, `caller_contact`, `callee_contact`, `variables`, `profiles`. |
| `dlg.list_ctx` | The same, each with a `context` object: `sflags`, `lifetime`, `timeout_bye`, `ka_src`, `ka_dst`, `timeout_noreset`, `timeout_route`. |
| `dlg.dlg_list <callid> [from_tag]` / `dlg.dlg_list_ctx …` | The dialogs with this Call-ID (and From tag). |
| `dlg.end_dlg <h_entry> <h_id>` | Sends BYE both ways and ends a confirmed dialog (found by `h_id`). |
| `dlg.terminate_dlg <callid> <from_tag> <to_tag>` | The same, for the dialog with these ids. |
| `dlg.is_alive <h_entry> <h_id>` | 0 if the dialog is confirmed, else an error. |
| `dlg.bridge_dlg <from> <to> [op]` | `dlg_bridge(from, to, op)`. |
| `dlg.profile_get_size <profile> [value]` | Number of dialogs in a profile. |
| `dlg.profile_list <profile> [value]` | The dialogs in a profile, in the `dlg.list` format. |
| `dlg.stats_active` | Counts by state: `starting` (1), `connecting` (2), `answering` (3), `ongoing` (4), `all`. |
| `dlg.set_state <callid> <from_tag> <to_tag> [state]` | Forces the state (1–5, default 5) of the dialog with these ids (tags in either order) and answers `Done`. Errors use Kamailio's texts: `Need the callid, from tag,to tag and state`, `Invalid state value`, `Dialog not found`. It is meant for 4 → 5: the dialog is dropped quietly, with no BYE, no `dialog:end` and no CDR, as in Kamailio. Forcing a never-confirmed dialog to 3 or 4 starts its lifetime now. |
| `dlg.briefing [fmt]` | Per dialog: `h_entry`, `h_id` and the fields that `fmt` names (default `ftcFT`). `f` from_uri, `t` to_uri, `c` call-id, `F` from_tag, `T` to_tag, `I` init_ts, `S` start_ts, `E` end_ts, `s` state. |

## Statistics

| Name | Kind | Meaning |
|---|---|---|
| `dialog:active_dialogs` | gauge | Confirmed dialogs (states 3 and 4) |
| `dialog:early_dialogs` | gauge | Dialogs not yet confirmed (states 1 and 2) |
| `dialog:processed_dialogs` | counter | Dialogs created |
| `dialog:failed_dialogs` | counter | Dialogs that failed before confirmation |
| `dialog:expired_dialogs` | counter | Confirmed dialogs that hit their timeout |

## Behaviour notes

- **Key and matching**: a dialog is keyed by
  [Call-ID](../../docs/glossary.md#call-id) + From
  [tag](../../docs/glossary.md#tag).
  - When the dialog is created, and `dlg_match_mode` isn't 2, the
    [Record-Route](../../docs/glossary.md#record-route) of the INVITE gets
    `;did=<h_entry>.<h_id>`. This happens whether `record_route()` comes
    before or after. The format is Kamailio's: hex with the least
    significant digit first.
  - [In-dialog requests](../../docs/glossary.md#in-dialog-request) are
    matched by the `did` of our Route entry, checked against the Call-ID and
    tags. In mode 1 or 2 they are also matched by Call-ID and tags in either
    direction.
  - Matching happens before `request_route` runs, through the
    `observe_request` hook. Only modules that opt in to this hook pay for it.
- **`dlg_flag`**: tm calls the dialog module when a request gets its
  transaction (`t_relay`, `t_newtran`). This is Kamailio's TMCB_REQUEST_IN.
  An initial INVITE with the flag set (or `$dlg_ctx(on)` = 1) gets its dialog
  there. It uses the settings made earlier in the dialog context
  (`dlg_setflag`, `dlg_set_property`, `$dlg_ctx`).
- **Timeouts**: as in Kamailio (`dlg_onroute()`), every in-dialog request
  except BYE restarts the timeout of a confirmed dialog with its lifetime.
  The `timeout-noreset` property or modparam turns this off. The
  [ACK](../../docs/glossary.md#ack) that confirms the call always restarts
  it. On timeout, the route in `$dlg_ctx(timeout_route)` runs first, with the
  dialog current. Then come the BYEs and `dialog:end`.
- **States**: 1 unconfirmed → 2 early (1xx with a To tag) → 3 confirmed
  (2xx) → 4 confirmed by ACK → 5 deleted (BYE, timeout, or a final ≥ 300
  before confirmation).
- **Replies**: the state follows the replies that tm sends upstream
  (`Tm::on_reply_out`), not every branch reply.
  - With [forking](../../docs/glossary.md#forking), a 486 from one branch
    doesn't end a call that another branch may still answer.
  - tm's own 408 and 487 also end unconfirmed dialogs.
  - A second 2xx, from another forked branch, doesn't change a confirmed
    dialog.
- **Timeout BYEs**: the BYEs use the stored contacts, CSeqs and
  [route sets](../../docs/glossary.md#route).
  - The callee's route set is the Record-Route entries added downstream of
    us in the 2xx. The caller's is the Record-Route of the INVITE.
  - Without a route set, a BYE goes to the address that the INVITE (caller)
    or the 2xx (callee) came from.
  - The BYE to the callee uses the caller's highest
    [CSeq](../../docs/glossary.md#cseq) + 1, and vice versa.
  - The timer thread checks dialogs every second.
- **Keep-alives**: every `ka_interval` seconds,
  [OPTIONS](../../docs/glossary.md#options) goes to the sides marked
  `ka-src` / `ka-dst`. A 408 or 481 answer ends the call with BYEs.
- **Database**:
  - With `db_mode` 1, a row is written when the dialog is confirmed and
    again whenever `$dlg_var` changes. It is deleted when the dialog ends.
  - Mode 2 collects these changes. It applies them every `db_update_period`
    seconds and at shutdown.
  - Mode 3 rewrites the table with the confirmed dialogs at shutdown.
  - Variables, profiles, dialog flags, the timeout route and the
    `timeout-bye` / `timeout-noreset` settings are stored as JSON in the
    `xdata` column.
  - Rows whose timeout has passed are skipped at load.
  - `etc/schema/*.sql` create the table.
- **Bridge and REFER**: tm's UAC API sends them. `t_uac` can start an
  INVITE. tm ACKs a non-2xx. The dialog module ACKs the 2xx itself, once.
  The bridge's call leg isn't a tracked dialog.

## Differences from Kamailio

- `dlg_match_mode` defaults to 1 (cookie, then SIP ids), not Kamailio's 0.
  So calls are still tracked when their in-dialog requests don't carry our
  Route. That happens without `record_route()`, or when a UA sends them
  straight to us. Set it to 0 for Kamailio's strict behaviour.
- Dialog variables, flags and settings are kept in the `xdata` JSON column.
  They are not in a separate `dialog_vars` table or in `sflags` /
  `toroute_name` columns. There is no [DMQ](../../docs/glossary.md#dmq) replication.
- `dlg_refer` doesn't end the dialog when the REFER succeeds. The referred
  UA's BYE does. `dlg_bridge` ACKs the 2xx once: a retransmitted 2xx isn't
  ACKed again. Its default `bridge_controller` is
  `sip:controller@ferrosip.invalid`.
- `$dlg_ctx(timeout)` sets the lifetime of the dialog the request creates.
  Writes to `$dlg_ctx(timeout)`, `timeout_bye` and `timeout_route` also
  change the current dialog. In Kamailio they only change the context
  (`dlg_var.c`), and the lifetime of a new dialog comes from
  `timeout_avp`. ferrosip accepts `timeout_avp` and ignores it. There is no
  `$dlg_ctx(timeout_route_id)`.
- Not implemented: `dlg.list_match`, `dlg_remote_profile`,
  `dlg_db_load_*`.
- `dlg.briefing`'s `T` gives the To tag. Kamailio's prints the From tag
  there: `rpc_dlg_briefing()` adds `tag[DLG_CALLER_LEG]` for both.
- `dlg.set_state 5` removes the dialog at once. Kamailio keeps it in memory
  until its cleanup timer runs.

## Testing

- `tests/e2e_dialog.py`:
  - `dlg_flag` with `t_relay`;
  - the `did` cookie and `dlg_match_mode` 0 (matched with it, not without);
  - dialog flags in the context and in the dialog;
  - `$dlg_ctx(dir/set/flags)`, `dlg_get`, `dlg_refer`;
  - `dlg.list_ctx` / `dlg.dlg_list[_ctx]` / `dlg.is_alive` /
    `dlg.terminate_dlg`;
  - `db_mode` 2 flushes;
  - `timeout-noreset` against a dialog whose timeout an INFO restarts;
  - `dlg_set_timeout()`: -1 before the dialog exists. On a dialog, the next
    in-dialog request restarts the new lifetime;
  - the timeout route;
  - `dlg_set_timeout_by_profile` (with and without a value);
  - `dlg.briefing` (default and `sIE` fields);
  - `dlg.set_state` (errors, 5 without BYE, 3);
  - `dlg_bridge` / `dlg.bridge_dlg` (INVITE, ACK, REFER, BYE; a 486).
- `tests/e2e_state.py`: call setup and `dlg.list`, in-dialog ACK matching
  with `$dlg_var` and state 4, profiles (`get_profile_size`,
  `dlg.profile_get_size`), BYE, failed dialogs, `dlg_set_timeout` +
  `timeout-bye` BYEs, `dlg.end_dlg`, the three event routes, statistics,
  and `db_mode=1` reload after a restart.
- `tests/soak.py`: checks that `dlg.stats_active` drains to 0 after load.
- `acc`, `cnxcc`, `pua_dialoginfo` and dispatcher use dialog in
  `tests/e2e_carrier.py`, `tests/e2e_extra.py`, `tests/e2e_presence.py` and
  `tests/e2e_routing.py`.
- Unit tests in `src/lib.rs`: parsing of Call-ID, tags, CSeq, Contact and
  Record-Route; the `did` cookie format; matching by cookie and by SIP ids
  in the three `dlg_match_mode`s.
