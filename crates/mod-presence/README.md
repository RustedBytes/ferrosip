# mod-presence

This crate covers SIP events, [presence](../../docs/glossary.md#presence) and
messaging. Use it when phones need to see each other's status, share a line,
receive messages sent while they were offline, or watch a whole buddy list
with one subscription.

It contains:

- a presence server for [PUBLISH](../../docs/glossary.md#publish),
  [SUBSCRIBE](../../docs/glossary.md#subscribe) and
  [NOTIFY](../../docs/glossary.md#notify) (RFC 3903, RFC 6665). It has the
  `presence` ([PIDF](../../docs/glossary.md#pidf)) and `dialog` (dialog-info) [event
  packages](../../docs/glossary.md#event-package);
- a PUBLISH client that other modules use;
- publication of [dialog](../../docs/glossary.md#dialog) state from the
  `dialog` module;
- BroadSoft [Shared Call Appearances](../../docs/glossary.md#sca);
- offline message storage;
- a resource list server (RFC 4662).

A [presentity](../../docs/glossary.md#presentity) is the user whose state is published. A [watcher](../../docs/glossary.md#watcher) is the
subscriber who wants to see it. Presentities and subscriptions are kept in
memory.

Presence, sca and rls share the SUBSCRIBE dialogs and the NOTIFY sender
(`notifier.rs`). NOTIFYs go out through the [UAC](../../docs/glossary.md#uac)
API of [tm](../../docs/glossary.md#tm). They follow the watcher's
[Record-Route](../../docs/glossary.md#record-route) set, or else its source
address. Every module here needs `tm` (`txn`). With
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml), `tm` loads first by
itself.

| Module | [Kamailio](../../docs/glossary.md#kamailio) module (`loadmodule`) | Purpose |
|---|---|---|
| `presence` | `presence` | Handles PUBLISH and SUBSCRIBE, sends NOTIFYs when state changes |
| `presence` | `presence_xml` | Event package `presence` (`application/pidf+xml`) |
| `presence` | `presence_dialoginfo` | Event package `dialog` (`application/dialog-info+xml`) |
| `presence_client` | `pua` | PUBLISH client for other modules, with entity tags and refreshes |
| `presence_client` | `pua_dialoginfo` | Publishes dialog-info for the caller and callee of tracked dialogs |
| `shared_lines` | `sca` | Shared Call Appearances (`call-info`, `line-seize`) |
| `offline_messages` | `msilo` | Stores MESSAGEs for offline users, delivers them on REGISTER |
| `resource_lists` | `rls` | Resource lists: one subscription for the state of every list member |

## presence

Publications are kept per (presentity, event), with entity tags and expiry.
A watcher is notified when a publication is added, changes its body, is
removed or expires. The event packages come from `presence_xml` and
`presence_dialoginfo`. Load them after `presence`. A presentity is
identified by `sip:user@host`, with no port or parameters.

`handle_publish()` and `handle_subscribe()` send the reply themselves.

PUBLISH:

- A new publication gets 200 with `SIP-ETag` and `Expires`.
- With `SIP-If-Match`, it is a refresh. The refresh gets a new entity tag,
  and a body replaces the old one. With `Expires: 0`, the publication is
  removed.
- An unknown entity tag gets 412.
- A new publication without a body gets 400.
- An unknown event gets 489 with `Allow-Events`.

SUBSCRIBE:

- A new subscription gets 200 and an initial NOTIFY.
- A refresh in the dialog gets 200 and a NOTIFY.
- `Expires: 0` gets 200 and a terminated NOTIFY. An initial SUBSCRIBE with
  `Expires: 0` is a one-time fetch.
- An unknown dialog gets 481.
- An expiry below `min_expires` gets 423 with `Min-Expires`.
- An unknown event gets 489.
- A 481 or 408 answer to a NOTIFY ends the subscription.
- Expired subscriptions get a terminated NOTIFY.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `max_expires` | 3600 | Upper limit for PUBLISH expiry. Alias `max_expires_publish`. A PUBLISH without `Expires` gets 3600, capped by this limit |
| `max_expires_subscribe` | 3600 | Upper limit for subscription expiry |
| `min_expires` | 0 | Shorter subscriptions get 423. `Expires: 0` is exempt |
| `default_expires` | 3600 | Expiry of a SUBSCRIBE without `Expires` |

Accepted for compatibility and ignored: `subs_db_mode`, `db_url`,
`presentity_table`, `active_watchers_table`, `watchers_table`,
`server_address`, `fallback2db`, `send_fast_notify`, `expires_offset`,
`clean_period`, `db_update_period`, `waitn_time`, `notifier_processes`,
`publ_cache`, `subs_htable_size`, `pres_htable_size`, `timeout_rm_subs`,
`sip_uri_match`, `enable_sphere_check`, `local_log_level`, `startup_mode`,
`retry_presentity_cleanup`.

**Functions**

| Signature | Description |
|---|---|
| `handle_publish([sender_uri])` | Handles a PUBLISH, as described above. 1 after a 200, -1 after an error reply. `presence.presentity_list` shows `sender_uri`. It defaults to the From header |
| `handle_subscribe([watcher_uri])` | Handles a SUBSCRIBE, as described above. 1 or -1. The argument is ignored |
| `pres_has_subscribers(uri, event)` | 1 if `uri` has active watchers for `event`, -1 otherwise |
| `pres_refresh_watchers(uri, event[, type])` | Sends every watcher of `uri`/`event` a NOTIFY with the current state. Returns 1. `type` is ignored |
| `pres_update_watchers(uri, event)` | Same as `pres_refresh_watchers` |
| `pres_auth_status(watcher, presentity)` | Always 1 (active), because there are no authorization rules |

**RPC commands**

| Command | Description |
|---|---|
| `presence.presentity_list` | Publications: pres_uri, event, etag, expires (seconds left), sender |
| `presence.presentity_show <uri> [event]` | Merged state (content_type, body). The event defaults to `presence` |
| `presence.watcher_list` | Subscriptions: pres_uri, watcher, event, expires, callid |
| `presence.refreshWatchers <uri> <event>` | Sends the watchers a NOTIFY. Returns how many |
| `presence.cleanup` | Drops expired publications and subscriptions now |

See [RPC](../../docs/glossary.md#rpc).

**Example**

The event packages have no script functions, so their sections load them:

```toml
[modules.presence]
max_expires_subscribe = "10m"

[modules.presence_xml]         # the presence event package

[modules.presence_dialoginfo]  # the dialog event package
```

```rust
import presence

route main(msg: Request) {
    match msg.method {
        PUBLISH => presence.handle_publish()
        SUBSCRIBE => presence.handle_subscribe()
        _ => reply(NotFound, "Not here")
    }
}
```

**Differences from Kamailio**

- State is in memory only, like `subs_db_mode=0`. Presentities and
  subscriptions are lost on restart. The database parameters are ignored.
- There are no [XCAP](../../docs/glossary.md#xcap) authorization rules. Every subscription is active and
  `pres_auth_status()` returns 1.
- There is no `presence.winfo` package.

## presence (presence_xml)

This module registers the `presence` event package (`application/pidf+xml`).
A presentity can have several publications, one per device. Then the NOTIFY
body is the first document's `<presence>` element. It holds the children of
all of them: tuples, persons, devices and notes.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `force_dummy_presence` | 0 | 1: a presentity without publications is notified as a PIDF with one `closed` tuple. Otherwise the NOTIFY has no body |

Accepted for compatibility and ignored: `force_active`,
`integrated_xcap_server`, `xcap_table`, `disable_presence`, `disable_winfo`,
`disable_bla`, `passive_mode`, `pidf_manipulation`, `xcap_server`,
`db_url`, `default_expires`, `force_presence_single_body`,
`presence_single_body_priorities`, `presence_single_body_lookup_element`.

**Functions**

| Signature | Description |
|---|---|
| `pres_check_basic(uri, status)` | 1 if a `<basic>` element of the merged state equals `status` (`open` / `closed`, case-insensitive). -1 otherwise |
| `pres_check_activities(uri, activity)` | 1 if the `<activities>` element contains an element named `activity`, such as `busy`. -1 otherwise |

**Example**

```toml
[modules.presence_xml]
force_dummy_presence = true
```

```rust
import presence

// in a route
if presence.check_basic("sip:alice@example.com", "open") {
    log.info("alice is online\n")
}
```

## presence (presence_dialoginfo)

This module registers the `dialog` event package
(`application/dialog-info+xml`). It merges the `<dialog>` elements of all
publications into one `<dialog-info>` document. The document's `version` is
set to the subscription's NOTIFY count. It has no script functions.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `force_single_dialog` | 0 | 1: keep only the dialog in the most advanced state. The order is confirmed, early, proceeding, trying |
| `force_dummy_dialog` | 0 | 1: a presentity without publications is notified as an empty `<dialog-info>`. Otherwise there is no body |

## presence_client (pua)

This is the PUBLISH client that `pua_dialoginfo` uses. Each publication
(entity, event, id) keeps its entity tag. It is refreshed with
`SIP-If-Match` shortly before it expires: a tenth of the expiry early, but
at least 10 s early.

- A 412 starts a fresh publication.
- An update made while a PUBLISH is in flight is queued. It is sent after
  the answer arrives.
- The PUBLISH [R-URI](../../docs/glossary.md#r-uri), From and To are the
  presentity URI.

It has no script functions.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `outbound_proxy` | none | Next hop for PUBLISHes that name none. The default is the R-URI |

Accepted for compatibility and ignored: `db_url`, `db_table`, `db_mode`,
`hash_size`, `min_expires`, `default_expires`, `update_period`,
`check_remote_contact`, `fetch_rows`, `dlginfo_increase_version`,
`reginfo_increase_version`.

**RPC commands**

| Command | Description |
|---|---|
| `pua.publish <pres_uri> <expires> <event> <content_type> <body>` | Sends a publication. An empty body or `.` only refreshes |

## presence_client (pua_dialoginfo)

This module publishes RFC 4235 dialog-info for every dialog that the
`dialog` module tracks (`dlg_manage()`). It publishes for the caller
(`direction="initiator"`) and for the callee (`direction="recipient"`). The
states are trying, early, confirmed and terminated. The terminated state is
published only for a party that got an earlier publication. Load `pua` and
`dialog` first.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `presence_server` | none | Where the PUBLISHes go. Otherwise pua's `outbound_proxy`, then the R-URI |
| `caller_trying` | 1 | Publish the trying state for the caller. [Sipwise](../../docs/glossary.md#sipwise): 0 publishes the caller only from the first [provisional reply](../../docs/glossary.md#provisional-reply) |
| `callee_trying` | 0 | Publish the trying state for the callee |
| `include_callid` | 1 | `call-id` attribute on `<dialog>` |
| `include_tags` | 1 | `local-tag` / `remote-tag` attributes |
| `include_localremote` | 1 | `<local>` and `<remote>` identity and target elements |
| `override_lifetime` | 3600 | Expires of the publications. Terminated states use 10 s |
| `send_publish_flag` | -1 | Only dialogs with this [flag](../../docs/glossary.md#flags) set are published. -1 = all |

Accepted for compatibility and ignored: `caller_confirmed`,
`use_pubruri_avps`, `pubruri_caller_avp`, `pubruri_callee_avp`,
`disable_caller_publish_flag`, `disable_callee_publish_flag`,
`pubruri_caller_dlg_var`, `pubruri_callee_dlg_var`, `callee_entity_avp`.

**Example** (`pua` and `dialog` load with `pua_dialoginfo`)

```toml
[modules.pua_dialoginfo]
presence_server = "sip:127.0.0.1:5060"
caller_trying = false
```

```rust
import dialog

route main(msg: Request) {
    if msg.method == INVITE && !msg.has_to_tag {
        dialog.manage()
    }
    relay(msg)
}
```

## shared_lines (sca)

This module implements BroadSoft Shared Call Appearances (SCA). Several
phones share one line, and each call on it uses an appearance. Phones that
share a line subscribe to its [AoR](../../docs/glossary.md#aor) for two
events:

- `call-info`: the state of every appearance;
- `line-seize`: take an appearance before dialing.

Calls on the line update the appearances. Every `call-info` subscriber then
gets a NOTIFY with a `Call-Info` header that lists them
(`appearance-index`, `appearance-state`, `appearance-uri`).

- `line-seize`: the lowest free appearance becomes `seized` for that phone.
  When all are in use, the answer is 480. The appearance is released when
  the line-seize subscription ends or expires.
- A call from an SCA phone is an [INVITE](../../docs/glossary.md#invite)
  with `Call-Info: ...;appearance-index=N`. Its appearance goes to
  progressing, then alerting on 18x, active on
  [2xx](../../docs/glossary.md#final-reply), and idle on >= 300.
- An answered call to the line takes the lowest free appearance. This
  applies to a line with `call-info` subscribers. The 2xx gets a `Call-Info`
  header. It also gets `P-Asserted-Identity` from `pai_avp` (Sipwise).
- A [re-INVITE](../../docs/glossary.md#re-invite) in either direction
  switches held / active from the [SDP](../../docs/glossary.md#sdp).
  `a=sendonly`, `a=inactive` or `c=IN IP4 0.0.0.0` means held.
- A [BYE](../../docs/glossary.md#bye) or
  [CANCEL](../../docs/glossary.md#cancel) from either side frees the
  appearance. These are the Sipwise upstream-flow and notify-after-BYE
  fixes.
- Unsubscribing from call-info is answered with a terminated NOTIFY that
  carries the appearances (Sipwise call-info unsubscribe).

**Parameters**

| Name | Default | Description |
|---|---|---|
| `max_appearances` | 10 | Appearances per line (1-99) |
| `pai_avp` | none | Sipwise: [AVP](../../docs/glossary.md#avp) (name or `$avp(...)`) whose value goes into a `P-Asserted-Identity` on the 2xx of an answered shared-line call. Nothing is added when it is empty |

Accepted for compatibility and ignored: `db_url`, `subs_table`,
`db_update_interval`, `hash_table_size`, `call_info_max_expires`,
`line_seize_max_expires`, `purge_expired_interval`, `onhold_bflag`,
`server_address`, `from_uri_avp`, `to_uri_avp`, `debug`.

**Functions**

| Signature | Description |
|---|---|
| `sca_handle_subscribe()` | Handles a `call-info` or `line-seize` SUBSCRIBE and replies. Other events get 489. When no appearance is free, the answer is 480. Returns 1 or -1 |
| `sca_call_info_update([mask])` | Updates appearances from INVITE, re-INVITE, BYE and CANCEL requests and from INVITE replies. Call it in the request route and in an [`onreply_route`](../../docs/glossary.md#onreply-route). `mask`: 1 caller side, 2 callee side, 3 both (default; 0 means 3). Further arguments are ignored. Returns 1, or -1 for a message without From/To/Call-ID/CSeq |

**RPC commands**

| Command | Description |
|---|---|
| `sca.all_subscriptions` | aor, event, subscriber, contact, expires |
| `sca.all_appearances` | aor, index, state, uri, callid |
| `sca.release_appearance <aor> <index>` | Frees an appearance and notifies the line |

**Example**

```rust
import shared_lines, dialog

route main(msg: Request) {
    let event = msg.headers["Event"]
    if msg.method == SUBSCRIBE && (event == "call-info" || event == "line-seize") {
        shared_lines.handle_subscribe()
    }
    if msg.has_to_tag {
        shared_lines.call_info_update()
        relay(msg)
    }
    if msg.method == INVITE {
        dialog.manage()
        shared_lines.call_info_update()
        relay(msg)
    }
}

// the replies to INVITEs (the .cfg version arms an onreply_route with t_on_reply)
on reply(r: Reply) where r.method == INVITE {
    shared_lines.call_info_update()
}
```

**Differences from Kamailio**: subscriptions and appearances are in memory
only. The database parameters are ignored.

## offline_messages (msilo)

This module stores [MESSAGEs](../../docs/glossary.md#message) for offline
users in a database table. It delivers them when the user
[registers](../../docs/glossary.md#register).

- Delivered messages go through tm to the first
  [Contact](../../docs/glossary.md#contact) of the REGISTER. They are sent
  to the address the REGISTER came from.
- The original sender is in From.
- With `add_date`, a `Date` header holds the time the message was stored.
- Each message is deleted from the table once it is answered with a 2xx.
- Expired messages are removed every `clean_period` seconds.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database with the messages |
| `db_table` | `silo` | Table name |
| `expire_time` | 259200 | Seconds a stored message is kept |
| `clean_period` | 60 | Seconds between removals of expired messages |
| `add_date` | 1 | Add a `Date` header to delivered messages |
| `max_messages` | 0 | Messages stored per user. 0 = unlimited |

Accepted for compatibility and ignored: `from_address`, `contact_hdr`,
`content_type_hdr`, `offline_message`, `reminder`, `outbound_proxy`,
`check_time`, `send_time`, `use_contact`, the `sc_*` column-name
parameters, `snd_time_avp`, `extra_hdrs_avp`, `notify_offline`.

**Functions**

| Signature | Description |
|---|---|
| `m_store([owner])` | Stores the current MESSAGE for `owner`. The default owner is the R-URI. Does not reply. -1 for a non-MESSAGE, a full mailbox (`max_messages`) or a database error |
| `m_dump([owner])` | Call it for a REGISTER after `save()`. Sends the stored messages of `owner`. The default owner is the To URI. 1 if at least one was sent. -1 otherwise: none stored, no Contact, or `Contact: *` |

**RPC commands**

| Command | Description |
|---|---|
| `msilo.count` | Number of stored messages |

**Database tables**: `silo` (`id`, `src_addr`, `dst_addr`, `username`,
`domain`, `inc_time`, `exp_time`, `ctype`, `body`). It is not in
`etc/schema/`. `tests/e2e_presence.py` has a db_text definition.

**Example**

```toml
[modules.offline_messages]
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"
```

```rust
import location, offline_messages

route main(msg: Request) {
    if msg.method == REGISTER {
        if location.save_and_continue() {
            offline_messages.dump()
        }
        exit
    }
    if msg.method == MESSAGE && !location.lookup() {
        guard offline_messages.store() else reply(ServerInternalError, "Not stored")
        reply(Accepted, "Accepted")
    }
    relay(msg)
}
```

`location.save_and_continue()` answers the REGISTER like
`location.save()`, but the route goes on. The stored messages follow the
200 OK, and only when the save worked. End the route yourself (`exit`).

**Differences from Kamailio**: there are no reminders, no delivery-time
(`send_time`) messages and no offline notification to the sender.

## resource_lists (rls)

This module implements resource lists (RFC 4662). A watcher subscribes once
to a list URI and gets the state of every member of the list.

Lists are read from the `xcap` table at startup and with `rls.reload`. Rows
with `doc_type` 6 hold rls-services documents
(`<service uri="sip:friends@example.com"><list><entry uri="..."/>...`).

A SUBSCRIBE to a list URI with `Supported: eventlist` gets NOTIFYs with
`Require: eventlist` and a `multipart/related` body. The body holds:

- an [RLMI](../../docs/glossary.md#resource-list) document (`application/rlmi+xml`) that lists the members;
- one part per member that has state.

The members' state comes from the local `presence` module, for the events
`presence` and `dialog`. When a member's state changes, the list's
subscribers get a new NOTIFY. Load `rls` after `presence`.

**Parameters**

| Name | Default | Description |
|---|---|---|
| `db_url` | none (required) | Database with the XCAP documents. Alias `xcap_db_url` |
| `xcap_table` | `xcap` | Table name |

Accepted for compatibility and ignored: `server_address`, `rlsubs_table`,
`rlpres_table`, `integrated_xcap_server`, `to_presence_code`,
`rls_event`, `outbound_proxy`, `max_expires`, `waitn_time`,
`clean_period`, `max_notify_body_length`, `db_mode`, `hash_size`,
`rls_db_url`, `rlmi_db_url`.

**Functions**

| Signature | Description |
|---|---|
| `rls_handle_subscribe([watcher_uri])` | 1 if the R-URI is a list: the SUBSCRIBE was handled and answered. Without `Supported: eventlist` the answer is 421. -1 if it is not a list, so the script can fall back to `handle_subscribe()`. The argument is ignored |

**RPC commands**

| Command | Description |
|---|---|
| `rls.reload` | Re-reads the lists. Returns how many |
| `rls.lists` | Lists and their members |

**Database tables**: `xcap`. Only `doc` and `doc_type` are read. It is not
in `etc/schema/`. `tests/e2e_presence.py` has a db_text definition.

**Example** (`presence` loads with `rls`)

```toml
[modules.resource_lists]
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"

[modules.presence_xml]   # the presence event package for the members
```

```rust
import presence, resource_lists

route main(msg: Request) {
    if msg.method == SUBSCRIBE {
        if resource_lists.handle_subscribe() {
            exit
        }
        presence.handle_subscribe()
    }
}
```

**Differences from Kamailio**: there are no back-end subscriptions to remote
presence servers. Members are read from the local presence module only.
Subscriptions are in memory.

## Testing

- `tests/e2e_presence.py` runs the proxy as its own presence server. It
  covers:
  - presence: SUBSCRIBE and initial NOTIFY, PUBLISH with [SIP-ETag](../../docs/glossary.md#entity-tag),
    merging of two publications, refresh with `SIP-If-Match`, 412,
    489 with Allow-Events, unsubscribe, `presence.presentity_show`,
    `presence.watcher_list`;
  - presence_dialoginfo / pua_dialoginfo: `force_dummy_dialog`,
    `caller_trying=0`, early / confirmed / terminated with increasing
    `version`;
  - rls: 421 without eventlist, multipart RLMI NOTIFY, re-notify on a
    member change;
  - sca: line-seize, call-info, progressing → alerting → active, hold via
    re-INVITE, BYE from the far end, answered call to the line,
    `sca.all_appearances`, `sca.release_appearance`;
  - msilo: `m_store`, delivery with Date on REGISTER via `m_dump`,
    deletion after delivery.
- Unit tests: XML helpers, PIDF and dialog-info merging and `version`
  rewrite, SCA `Call-Info` headers and hold detection, msilo `Date`
  formatting, rls-services parsing.
