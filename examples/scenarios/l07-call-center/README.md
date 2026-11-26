# l07-call-center (large)

This scenario models a call-center hunt group. Agents log in by
registering to the group's [AoR](../../../docs/glossary.md#aor), `sales`,
each with a [q-value](../../../docs/glossary.md#q-value). A call to
`sales` hunts through them in q order and overflows to voicemail. A
supervisor can transfer calls and start callbacks over HTTP. It proves the
hunt order, that a caller's hang-up stops the hunt, that forged in-dialog
requests are refused, and that transfer and callback work.

```
customer ──INVITE sales──▶ acd ── q 1.0 ─▶ a1 (3s) ── busy / no answer ─┐
                                ┌──────────────────────────────────────┘
                                └─ q 0.7 ─▶ a2 (3s) ── … ─┐
                                ┌─────────────────────────┘
                                └─ q 0.3 ─▶ a3 + a4 in parallel (3s) ── … ─▶ voicemail

supervisor ──POST /transfer?<call-id> supervisor──▶ acd ──REFER (in the call)──▶ customer
supervisor ──POST /callback customer──▶ acd ──INVITE sales (dialog.bridge, hunts)──▶ agent
                                            ◀── 200 ── ACK, REFER sip:customer, BYE ──▶ agent
```

**Shows**:
- `location.lookup()`, then `txn.load_contacts()` / `txn.next_contacts()`
  with `[modules.txn] fork_by_q = true`. Each step rings one q-group.
  Agents with the same q ring in parallel, so the last group rings
  "everyone left" at once (see [forking](../../../docs/glossary.md#forking)).
- Each step is `await txn.relay(msg, timeout: 3s)` in a `while true` loop.
  That is the per-agent ring time. The loop:
  - forwards a 2xx;
  - stops on `txn.is_canceled()` with a 487;
  - otherwise tries the next group.
- When the groups run out, it calls a `voicemail` helper. That helper is
  also used when nobody is logged in.
- Auth for agents and customers comes from one users file. All agents log
  in as `sales`.

Every call is a tracked [dialog](../../../docs/glossary.md#dialog)
(`dialog.manage()`), with `[modules.dialog] dlg_match_mode = 0`. The ACD's
[Record-Route](../../../docs/glossary.md#record-route) carries the dialog
cookie `;did=<h_entry>.<h_id>`.
[In-dialog requests](../../../docs/glossary.md#in-dialog-request) are
matched to their call by that cookie only. The route refuses one that
matches no call (`dialog.is_known()`) with 481, before following the route
set.

The supervisor API (`[modules.http]`, `on http`):
- `POST /transfer?<call-id>` with a user name:
  - `dialog.get()` finds the answered call by its
    [Call-ID](../../../docs/glossary.md#call-id) and the
    [tags](../../../docs/glossary.md#tag). `on dialog.started` stored
    those in two [shared tables](../../../docs/glossary.md#shared-table),
    and `on dialog.ended` removes them;
  - `dialog.refer("caller", …)` sends the customer a REFER inside the
    call, as the agent, with `Referred-By` the `bridge_controller`.
- `POST /callback` with the customer's user name:
  - `dialog.bridge()` calls `sip:sales@…` with the ACD itself as
    [outbound proxy](../../../docs/glossary.md#outbound-proxy). So the
    callback hunts like a customer call. The route lets
    [INVITEs](../../../docs/glossary.md#invite) from the ACD's own address
    in without auth;
  - it then REFERs the agent who answers to the customer, and hangs up
    its own leg.

**Edge cases checked** (`tests/scenarios/l07_call_center.py`):
- Four agents log in with q 1.0, 0.7, 0.3, 0.3.
- a1 answers: only a1 rang.
- a1 busy → a2 answers. a3 and a4 never rang.
- a1 rings without answering. After its 3s it is canceled, and a2
  answers.
- a1 and a2 busy: a3 and a4 ring in parallel. a4 answers, and a3 is
  canceled.
- Everybody busy or silent → voicemail gets the call for
  `sip:sales@cc.example.com`.
- The customer cancels while a2 rings (a1 was busy). a2 is canceled,
  a3/a4 never ring, and voicemail is not called. The customer must get
  487. After the caller's [CANCEL](../../../docs/glossary.md#cancel) the
  code after `await` runs, as [Kamailio](../../../docs/glossary.md#kamailio)
  runs the [failure_route](../../../docs/glossary.md#failure-route) of a
  canceled [transaction](../../../docs/glossary.md#transaction). The
  route's `txn.is_canceled()` check answers 487, not a1's earlier 486.
- The dialog cookie:
  - the ACD's Record-Route has `;did=`;
  - an INFO with a forged cookie or without one gets
    `481 Call Does Not Exist` and never reaches the agent;
  - one with the right cookie is relayed (200);
  - after the [BYE](../../../docs/glossary.md#bye) the same cookie gets
    481.
- Transfer:
  - unknown call → 404, and a target that isn't a user name → 400;
  - the customer gets a REFER inside the answered call: same Call-ID,
    From the agent's tag, To its own, sent to its
    [Contact](../../../docs/glossary.md#contact). It has `Refer-To:
    <sip:supervisor@cc.example.com>` and `Referred-By: <sip:acd@…>`;
  - after the customer's BYE, a transfer of that call → 404.
- Callback:
  - a1 is busy. a2 gets the INVITE from `sip:acd@cc.example.com` with the
    cookie in its Record-Route;
  - then a2 gets the [ACK](../../../docs/glossary.md#ack), a REFER to
    `<sip:customer@cc.example.com>` and the BYE;
  - a bad customer → 400.
- All agents log out (`Contact: *`, `Expires: 0`) → voicemail at once.

**Run it by hand**: `ferrosip --config ferrosip.toml` from `acd/`.
`SIP_PORT` is 5060, `HTTP_PORT` 8080, and `VOICEMAIL`
`sip:127.0.0.1:5090`. Agents register as `sales` (password in `users`)
with `;q=` on their Contact. Then run
`curl -d customer http://127.0.0.1:8080/callback`.
