# Modules

An overview of the module groups. Each crate's README is the full reference: parameters, functions, pseudo-variables and RPC commands; every parameter is also in [modules-reference.md](modules-reference.md).

## Utility modules (mod-sip)

> Full reference: [`mod-sip`](../crates/mod-sip/README.md).

Each one loads when the routing uses its functions (with
`--config`; a `.cfg` without it needs `loadmodule`), with Kamailio's
function names and semantics (and a typed `.fsr` name for each:
[functions-reference.md](functions-reference.md)). Arguments may contain variables wherever Kamailio
accepts them.

| module | functions |
|---|---|
| `sl` | `sl_send_reply`, `send_reply` (+ `sl:*` reply statistics) |
| `textops` | `is_present_hf(_re)`, `append_hf`/`insert_hf` (optionally relative to a header), `remove_hf(_re/_exp)`, `search`, `search_body`, `search_hf`, `search_append`, `replace(_all)`, `replace_body(_all/_atonce)`, `subst`/`subst_uri`/`subst_user`/`subst_body`/`subst_hf` (`/re/repl/ig`, `\1`, variables in the replacement), `has_body`, `is_method`, `set_body`, `set_reply_body`, `append_to_reply`, `append_time`, `starts_with`, `cmp_str`, `cmp_istr`, `str_find` |
| `textopsx` | `remove_body`, `change_reply_status`, `keep_hf`, `fnmatch` |
| `siputils` | `has_totag`, `is_user`, `is_e164`, `is_uri_user_e164`, `is_alphanum`, `is_numeric`, `uri_param`, `add_uri_param`, `cmp_uri`, `cmp_aor`, `is_request`, `is_reply`, `is_supported`, `options_reply`, `tel2sip` |
| `sanity` | `sanity_check([checks[, uri_checks]])` with Kamailio's bit masks (default 3047/7), replies (400/416/420+Unsupported), `autodrop`, `noreply` |
| `xlog` | `xlog([level,] fmt)`, `xlogl`, `xalert`/`xcrit`/`xerr`/`xwarn`/`xnotice`/`xinfo`/`xdbg`/`xbug`; level via `--debug` / `setdebug` |
| `cfgutils` | `rand_event`, `rand_set/reset/get_prob`, `sleep`, `usleep`, `lock`/`trylock`/`unlock`, `set/reset/is_gflag` |
| `corex` | `send_data`, `send`, `set/reset/isxflagset`, `is_faked_msg`, `has_ruri_user`, `file_read`, `file_write` |
| `kex` | `setsflag`/`resetsflag`/`issflagset`, `setdsturi`/`resetdsturi`/`isdsturiset`, `pv_printf`, `km_append_branch`, `setdebug`/`resetdebug` |
| `statistics` | `update_stat`, `reset_stat`, `modparam("statistics", "variable", …)` |
| `pv` | `pv_isset`, `pv_unset`, `is_int`, `typeof`, `not_empty`, `xavp_params_explode` |
| `ipops` | `is_ip`, `is_ipv4`, `is_ipv6`, `is_pure_ip`, `is_ipv6_reference`, `ip_type`, `compare_ips`, `ip_is_in_subnet`/`is_in_subnet` (CIDR lists), `is_ip_rfc1918`, `dns_query` + `$dns(id=>addr[i])`, `dns_sys_match_ip` |

Body edits (`set_body`, `replace_body`, `subst_body`, …) compose. The core
keeps one body override and fixes Content-Length (and Content-Type) when
the message is rendered. rtpengine's SDP rewriting will use the same
mechanism.

## Routing, NAT and access control (mod-routing)

> Full reference: [`mod-routing`](../crates/mod-routing/README.md).

```toml
[modules.balancer]                          # dispatcher
list_file = "/etc/ferrosip/dispatcher.list"
ds_ping_interval = "10s"
```

```rust
import route_set, balancer

route main(msg: Request) {
    if msg.has_to_tag {
        if route_set.follow() {       // loose_route()
            relay(msg)
        }
        reply(NotFound, "Not here")
    }
    route_set.record()
    guard balancer.select(1, 4) else reply(ServiceUnavailable, "No gateway")    // ds_select_dst
    // Each 5xx or timeout marks the gateway and tries the next one.
    while true {
        let res = await txn.relay(msg)
        match res {
            Final(r) if r.code < 500 => forward(r)
            _ => {
                balancer.mark("ip")
                guard balancer.next() else reply(ServiceUnavailable, "All gateways failed")
            }
        }
    }
}

on balancer.down(e: Destination) {     // event_route[dispatcher:dst-down]
    log.warn("gateway {e.uri} is down\n")
}
```

| module | functions / features |
|---|---|
| `rr` | `record_route([params])`, `record_route_preset(addr[, addr2])`, `record_route_advertised_address`, `add_rr_param`, `remove_record_route`, `loose_route`, `loose_route_preloaded`, `check_route_param`, `is_direction`, `$route_uri`; params `enable_double_rr` (1), `append_fromtag` (1), `enable_full_lr` |
| `path` | `add_path([user])`, `add_path_received([user])` (`;received=` is honoured by `loose_route` on the way back) |
| `nathelper` | `nat_uac_test(flags)` (1 Contact private, 2 Via ≠ source, 4 Via private, 8 SDP private, 16 Via port ≠ source port, 32 source private, 64 WebSocket, 128 Contact port ≠ source port, 256 SDP ≠ source), `fix_nated_contact`, `fix_nated_register`, `fix_nated_sdp(flags[, ip])` (1 `a=direction:active`, 2 `c=`, 8 `o=`), `add_rcv_param([1])`, `set_contact_alias`/`add_contact_alias([ip, port, proto])`, `handle_ruri_alias`, `is_rfc1918`; keep-alive pinging of registered contacts: `natping_interval`, `ping_nated_only`, `nat_bflag`, `sipping_bflag` (SIP OPTIONS, else 4-byte UDP / CRLFCRLF keep-alives), `sipping_from`, `sipping_method` |
| `dispatcher` | `ds_select_dst`/`ds_select_domain`/`ds_select(set, alg[, limit])`, `ds_next_dst`/`ds_next_domain`, `ds_set_dst`/`ds_set_domain`, `ds_mark_dst([a\|i\|d\|t\|p…])`, `ds_is_from_list([group[, mode[, uri]]])`, `ds_list_exists`, `ds_is_active`; algorithms 0–3 (hash Call-ID/From/To/R-URI), 4 round-robin, 5 auth user, 6 random, 7 hash `hash_pvar`, 8 priority order, 9 `weight=`, 10 call load (least calls relative to the `maxload=` attribute; Call-ID tracked, released when the dialog ends or by `ds_load_unset()`, moved by `ds_next_dst`; `ds_load_update()`), 11 `rweight=`, 12 parallel forking, 13 latency (lowest EWMA of the probe RTTs, `ds_latency_estimator_alpha`; `ds_ping_latency_stats` shows AVG/STD/EST/MAX/TIMEOUT and LOAD in `dispatcher.list`); failover list in `$xavp(_dsdst_)` (`uri`, `grp`, `attrs`, `priority`); OPTIONS probing through the tm UAC API (`ds_ping_interval`, `ds_ping_method`, `ds_ping_from`, `ds_probing_mode`, `ds_probing_threshold`, `ds_inactive_threshold`, `ds_ping_reply_codes`); `event_route[dispatcher:dst-down/dst-up]`; data from `list_file` or the `dispatcher` table (`db_url`); RPC `dispatcher.reload`, `.list`, `.set_state`, `.ping_active` |
| `permissions` | `allow_source_address([grp])`, `allow_address(grp, ip, port)`, `allow_source_address_group()`, `allow_address_group(ip, port)`, `allow_trusted([ip, proto[, uri]])`, `peer_tag_avp`; tables `address` (subnets, port 0 = any) and `trusted` (regex on From / R-URI, priority); `allow_routing([basename \| allow_file, deny_file])` and `allow_register(basename \| allow_file, deny_file)` with Kamailio's `.allow` / `.deny` files (`"from-regex" : "ruri-regex"`, `ALL`, `EXCEPT`; allow, then deny, else allowed; `allow_register` checks the To URI against every Contact); RPC `permissions.addressReload/trustedReload/addressDump/trustedDump/reload` |
| `domain` | `is_domain_local(domain\|uri)`, `is_from_local`, `is_uri_host_local`; `register_myself` makes the domains match `uri == myself`; RPC `domain.reload`, `domain.dump` |
| `alias_db` | `alias_db_lookup(table[, flags])` (`d` ignore domain, `r` reverse, `m` every match as a branch), `use_domain`, column-name parameters |
| `group` | `is_user_in("Request-URI"\|"To"\|"From"\|"Credentials"\|uri-variable, group)`, `use_domain`, column-name parameters |

How Record-Route works: `record_route()` only records the request. tm
renders the header for each branch once it knows the outgoing transport
and interface. A call that crosses from UDP to TCP/TLS/WS, or between
interfaces, gets two entries (`;r2=on`): the top one facing the callee,
the second facing the caller. `loose_route()` removes our entries (both
of an r2 pair) and sends to the next Route, or to the R-URI when none is
left. A pre-loaded Route that isn't ours is followed as is.

Core additions in this phase: `setbflag`/`resetbflag`/`isbflagset`
(branch flags of the R-URI branch), and `force_rport`/`add_rport`. The
last two are no-ops because replies already go to the source address
and port.

## Shared state, security and dialogs (mod-limits, mod-dialog)

> Full reference: [`mod-limits`](../crates/mod-limits/README.md), [`mod-dialog`](../crates/mod-dialog/README.md).

| module | functions / features |
|---|---|
| `htable` | tables from `modparam("htable", "htable", "name=>autoexpire=300;initval=0;updateexpire=1;dbtable=t;dbmode=1")`; `$sht(t=>key)` (keys may contain variables, `$null` deletes), `$shtex`, `$shtinc`/`$shtdec` (atomic), `$shtcn`/`$shtcv` (`~~re`, `%~prefix`, `~%suffix`, `==str`); `sht_rm`, `sht_rm_name_re`, `sht_rm_value_re`, `sht_rm_name`/`sht_rm_value`/`sht_has_name`/`sht_has_str_value` (`re`, `sw`, `ew`, `eq`, `in`), `sht_reset`, `sht_setxs`/`sht_setxi` (with expiry), `sht_is_null`, `sht_lock`/`sht_unlock`; `event_route[htable:mod-init]`, `event_route[htable:expired:<table>]` with `$shtrecord(key/value)`; db load (`db_url`), write-back for dbmode=1; RPC `htable.get/sets/seti/delete/dump/flush/reload/store/listTables` |
| `pike` | `pike_check_req()`, `pike_check_ip(ip)`; `sampling_time_unit`, `reqs_density_per_unit`, `remove_latency`; `event_route[pike:blocked]`; RPC `pike.top` |
| `ratelimit` | `rl_check([pipe])`; `pipe` = `id:ALGORITHM:limit`, `queue` = `id:METHOD` (or `*`), `timer_interval`; RPC `rl.stats`, `rl.get_pipes`, `rl.set_pipe` |
| `pipelimit` | `pl_check(name[, alg, limit])` (pipes from the `pl_pipes` table or created on the fly), `pl_drop([retry_after[, low, high]])`; RPC `pl.stats`, `pl.list`, `pl.set_pipe`, `pl.reload` |
| `secfilter` | `secf_check_ua`, `secf_check_from_hdr`, `secf_check_to_hdr`, `secf_check_contact_hdr`, `secf_check_ip`, `secf_check_country`, `secf_check_dst`, `secf_check_sqli_all`, `secf_check_sqli_hdr` (2 allowlisted / 1 unknown / -2 blocklisted); RPC `secfilter.reload/print/add_bl/add_wl/add_dst/stats` |
| `userblocklist` | `check_user_blocklist(user, domain[, number[, table]])`, `check_user_allowlist(…)`, `check_blocklist([table])`, `check_allowlist(table)` — longest prefix wins; RPC `userblocklist.reload_blocklist/dump_blocklist/check_blocklist` |
| `dialog` | `dlg_manage()` or `dlg_flag` (an INVITE relayed with that flag set), `is_known_dlg()`, `dlg_set_timeout(secs[, h_entry, h_id])`, `dlg_bye(all\|caller\|callee)`, `dlg_set_property`/`dlg_reset_property` (`timeout-bye`, `ka-src`, `ka-dst`, `timeout-noreset`), `dlg_setflag`/`dlg_resetflag`/`dlg_isflagset`, `dlg_get(callid, ftag, ttag)`, `dlg_refer(side, to)`, `dlg_bridge(from, to, op)`, `set_dlg_profile`, `unset_dlg_profile`, `is_in_profile`, `get_profile_size`; `$dlg_var(name)`, `$dlg(h_id\|state\|callid\|sflags\|…)`, `$dlg_ctx(on\|flags\|timeout\|timeout_bye\|timeout_route\|set\|dir)`; `event_route[dialog:start/end/failed]`; params `default_timeout`, `early_timeout`, `send_bye`, `ka_interval`, `profiles_with_value`, `profiles_no_value`, `dlg_flag`, `dlg_match_mode` + `rr_param` (Record-Route `did` cookie), `db_url` + `db_mode` (realtime, delayed every `db_update_period`, shutdown), `bridge_controller`; stats `dialog:active_dialogs`, `early_dialogs`, `processed_dialogs`, `failed_dialogs`, `expired_dialogs`; RPC `dlg.list[_ctx]`, `dlg.dlg_list[_ctx]`, `dlg.end_dlg`, `dlg.terminate_dlg`, `dlg.is_alive`, `dlg.bridge_dlg`, `dlg.profile_get_size`, `dlg.profile_list`, `dlg.stats_active` |
| `auth_db` | credentials for `www_authorize(realm, "subscriber")` & co. from a table: `db_url`, `calculate_ha1`, `use_domain`, column names (HA1 column MD5 or SHA-256), `load_credentials` → `$avp(col)` |
| `usrloc` | `db_url` + `db_mode` 1 (write-through), 2 (write-back every `timer_interval`), 3 (as 1); contacts reloaded at startup |

How dialog tracking works: a dialog follows the replies tm *sends
upstream* (`Tm::on_reply_out`), not every branch reply. With forking, a
486 from one branch doesn't kill a call another branch may still answer.
tm's own 408/487 also end unconfirmed dialogs. In-dialog requests are
matched by the `did` cookie the dialog adds to our Record-Route and/or
by Call-ID and tags in either direction (`dlg_match_mode`), through the
`Module::observe_request/observe_reply` hook. Only modules that opt in
are called, so it costs nothing otherwise. BYEs on timeout use the
stored contacts, CSeqs and route sets (the Record-Route entries on each
side of ours) and go out through tm's UAC API.

Not implemented: dialog_vars in a separate table (they're in `xdata`),
DMQ replication. `dlg_match_mode` defaults to 1 (Kamailio: 0).

## Media, carrier routing and accounting (mod-media, mod-carrier)

> Full reference: [`mod-media`](../crates/mod-media/README.md), [`mod-carrier`](../crates/mod-carrier/README.md).

```toml
[modules.media]                 # rtpengine
rtpengine_sock = "udp:127.0.0.1:2223"

[modules.carriers]              # lcr
db_url = "sqlite:///var/lib/ferrosip/ferrosip.db"
```

```rust
import carriers, media

route main(msg: Request) {
    guard carriers.load_gateways(1) else reply(ServerInternalError, "LCR error")
    guard carriers.next_gateway() else reply(ServiceUnavailable, "No gateway")
    media.manage("replace-origin replace-session-connection ICE=remove")
    while true {
        let res = await txn.relay(msg)
        match res {
            Final(r) if r.code != ServiceUnavailable => forward(r)
            _ => {                                  // 503 or no answer
                carriers.defunct_gateway(60s)
                guard carriers.next_gateway() else reply(ServiceUnavailable, "No gateway")
            }
        }
    }
}

on reply(r: Reply) where r.has_sdp {
    media.manage()
}
```

| module | functions / features |
|---|---|
| `rtpengine` | `rtpengine_offer`/`answer`/`delete`/`manage([flags])`, `rtpengine_query` (+ `$rtpstat`), `rtpengine_query_v("j", $var)`, `start_recording`/`stop_recording`, `block_dtmf`/`unblock_dtmf`, `block_media`/`unblock_media`, `silence_media`/`unsilence_media`, `set_rtpengine_set`; Kamailio's flag syntax (`replace-*`, `ICE=`, `RTP/AVP`…, `direction=`, `codec-*`, `transcode-*`, `via-branch=`, `received-from=`, `key=value`); weighted nodes and sets (`rtpengine_sock`), calls stick to their node, a node that times out (`rtpengine_tout_ms` × `rtpengine_retr`) is disabled for `rtpengine_disable_tout`; RPC `rtpengine.show`, `rtpengine.enable`, `rtpengine.ping` |
| `dialplan` | `dp_translate(id[, "$src/$dst"])`, `dp_match(id, input)`, `dp_replace(id, input, $dst)`; match_op 0 string / 1 regex / 2 fnmatch, `match_len`, `subst_exp` + `repl_exp` (`\1`), `attrs_pvar`; a broken rule is skipped, not fatal (Sipwise patch); RPC `dialplan.reload/dump/translate` |
| `lcr` | `load_gws(lcr_id[, uri_user[, caller_uri]])`, `next_gw()` (strip/prefix, hostname vs IP + `$du`, transport, params), `defunct_gw(period)`, `inactivate_gw()` (+ OPTIONS `ping_interval` re-activation), `from_gw`, `from_any_gw`, `to_gw`, `to_any_gw`; ordering by longest prefix → priority → randomized weight (`priority_ordering`), stopper rules, `dont_strip_or_prefix_flag`, `tag_avp`, `flags_avp`, `rule_id_avp`, `lcr_id_avp`; **Sipwise:** `stopper_mode`, `lcr_stats` (requests/replies per gateway by method/class), `gw_id_avp`; RPC `lcr.reload/dump_gws/dump_rules/defunct_gw/load_gws/stats` |
| `acc` | `log_flag`, `db_flag`, `log_missed_flag`, `db_missed_flag`, `failed_transaction_flag`, `early_media`, `log_extra`/`db_extra` (`name=$pv;…`), `acc_log_request`, `acc_db_request`; tables `acc`, `missed_calls`; CDRs from dialog (`cdr_enable`, `cdr_extra` from `$dlg_var`, table `cdrs`) |
| `uac` | `uac_replace_from`/`uac_replace_to([display,] uri)` with automatic restore on replies and in-dialog requests both ways, `uac_restore_from`/`_to`, `uac_auth()` (401/407 in failure_route; `credential` or `auth_*_avp`), `$uac_req(…)` + `uac_req_send()`, remote registrations from `uacreg` (digest auth, refresh, retry), `uac_reg_lookup`, `uac_reg_status`; RPC `uac.reg_dump/reg_reload/reg_refresh` |
| `topoh` / `topos` | topology hiding through a send filter on every outgoing message: previous hops' Via headers carried in our own Via, Contacts replaced by `sip:<mask_ip>:<port>;line=<token>` and mapped back for in-dialog requests; topoh puts the data in the token (`mask_key`), topos keeps it on the proxy (`storage_ttl`) |

Core additions in this phase: `Tm::on_reply_out` hooks see the
transaction's request and AVPs/flags (acc, dialog);
`sip_core::module::FailureReply` carries the winning reply into
failure_route (uac_auth); `sip_core::net::set_send_filter` (topology
hiding).

The rtpengine module is tested against a real relay too:
[rtpflux](https://github.com/RustedBytes/rtpflux), which speaks the same ng
protocol (`tests/e2e_rtpflux.py`: SDP rewriting, RTP both ways, query,
delete).

Not implemented: rtpengine over TCP/WebSocket control sockets and the
MOS/statistics PVs; lcr `mtree`; acc RADIUS/diameter backends; uac
`restore_mode` via Record-Route parameters (we keep the originals in
memory); topoh Call-ID masking and Record-Route hiding.

## Presence, SCA and messaging (mod-presence)

> Full reference: [`mod-presence`](../crates/mod-presence/README.md).

```toml
# Modules without routing functions load with their section.
[modules.presence_xml]
[modules.presence_dialoginfo]
[modules.presence_client]
[modules.pua_dialoginfo]
presence_server = "sip:127.0.0.1:5060"
```

```rust
import presence, resource_lists, dialog

route main(msg: Request) {
    match msg.method {
        PUBLISH => presence.handle_publish()
        SUBSCRIBE => {
            if resource_lists.handle_subscribe() {    // a resource list: answered
                exit
            }
            presence.handle_subscribe()
        }
        INVITE => {
            if !msg.has_to_tag {
                dialog.manage()
            }
        }
        _ => {}
    }
    …
}
```

| module | functions / features |
|---|---|
| `presence` | `handle_publish([sender])` (RFC 3903: entity tags, refresh with `SIP-If-Match`, 412, Expires 0, 489 + Allow-Events), `handle_subscribe()` (RFC 6665 dialogs: 200 + initial NOTIFY, refresh, unsubscribe → terminated NOTIFY, 481/408 to a NOTIFY ends the subscription, expiry), `pres_has_subscribers`, `pres_refresh_watchers`, `pres_update_watchers`, `pres_auth_status`; NOTIFY on every state change and publication expiry; params `max_expires`, `min_expires`, `default_expires`; RPC `presence.presentity_list/presentity_show/watcher_list/refreshWatchers/cleanup` |
| `presence_xml` | event `presence` (`application/pidf+xml`): publications of all devices merged into one PIDF; `force_dummy_presence`; `pres_check_basic(uri, status)`, `pres_check_activities(uri, activity)` |
| `presence_dialoginfo` | event `dialog` (`application/dialog-info+xml`): dialogs merged, per-subscription `version`, `force_single_dialog`, `force_dummy_dialog` |
| `pua` | PUBLISH client for other modules (entity tags, refresh before expiry, 412 → fresh publication, updates queued while in flight), `outbound_proxy`; RPC `pua.publish` |
| `pua_dialoginfo` | dialog-info PUBLISHes for caller (initiator) and callee (recipient) from dialog state changes (trying → early → confirmed → terminated); `presence_server`, `callee_trying`, **Sipwise `caller_trying`**, `include_callid`, `include_tags`, `include_localremote`, `override_lifetime`, `send_publish_flag` |
| `sca` | Shared Call Appearances: `sca_handle_subscribe()` (call-info, line-seize with the lowest free appearance, 480 when none), `sca_call_info_update([mask])` (progressing/alerting/active/held/idle from INVITEs, replies, re-INVITE SDP direction, BYE/CANCEL in either direction; appearance for answered calls to the line, Call-Info in the 2xx); **Sipwise** `pai_avp`, call-info unsubscribe, NOTIFY after BYE, upstream-flow hold/pickup; RPC `sca.all_subscriptions/all_appearances/release_appearance` |
| `msilo` | `m_store([owner])` into the `silo` table, `m_dump([owner])` after `save()` delivers through tm to the registering contact (deleted on 2xx), `expire_time`, `clean_period`, `add_date`, `max_messages`; RPC `msilo.count` |
| `rls` | resource lists (RFC 4662) from the `xcap` table (rls-services documents): `rls_handle_subscribe()` (421 without `Supported: eventlist`), `multipart/related` NOTIFYs with RLMI + each member's state, re-notified when a member's presence changes; RPC `rls.reload`, `rls.lists` |

`notifier.rs` holds the subscription dialogs and the NOTIFY sender that
presence, sca and rls share. The NOTIFYs use tm's UAC API and follow the
watcher's Record-Route set or its source address. Dialog state reaches
pua_dialoginfo through a new `Dialog::on_state` hook.

Not implemented: XCAP authorization rules (every subscription is
active), `presence.winfo`, database persistence of presentities and
subscriptions (memory only, like `subs_db_mode=0`), the Sipwise
`presence_vqr` (vq-rtcpxr) package, and rls back-end subscriptions to
remote presence servers (members are read from the local presence
module).

## Tracing, credit control, data, Lua and HTTP (mod-extra, mod-lua)

> Full reference: [`mod-extra`](../crates/mod-extra/README.md), [`mod-lua`](../crates/mod-lua/README.md).

| module | functions / features |
|---|---|
| `siptrace` | HEPv3 to Homer (`duplicate_uri`, `hep_capture_id`, `auth_key`, `trace_flag`, `send_sock_addr`, `hep_mode_on`): `sip_trace([dst[, correlation_id[, mode]]])` (m message, t transaction, d dialog: later messages of the call in and out), `setflag(trace_flag)` traces a transaction, `sip_trace_mode`, `hlog`; RPC `siptrace.status`. Homer's Kamailio configs work as they are |
| `cnxcc` | `cnxcc_set_max_credit(customer, max, connect_cost, cost_per_second, initial_pulse, final_pulse)`, `cnxcc_set_max_time`, `cnxcc_set_max_channels`, `cnxcc_get_channel_count`, `cnxcc_terminate_all`; calls end with BYEs when credit runs out; RPC `cnxcc.active_clients/check_client/kill_call` |
| `tmx` | `t_is_failure_route`, `t_is_branch_route`, `t_is_reply_route`, `t_is_request_route`, `t_precheck_trans`, `t_flush_flags`, `$T_req(pv)`, `$T_rpl(pv)` |
| `uac_redirect` | `get_redirects(max[, reason])` in failure_route, `accept_filter`/`deny_filter`/`default_filter` |
| `avpops` | `avp_db_load`/`avp_db_store`/`avp_db_delete` (`usr_preferences`), `avp_delete`, `avp_copy`, `avp_pushto`, `avp_check`, `avp_print` |
| `sqlops` | `sqlcon` (any SQL driver), `sql_query`, `sql_query_async`, `sql_xquery`, `sql_pvquery`, `sql_result_free`, `$dbr(res=>rows/cols/[r,c]/colname[c])` |
| `mtree` | prefix trees from tables, `mt_match(tree, value, mode)`, RPC `mtree.reload/list/match` |
| `prefix_route` | `prefix_route([user])` runs `route[name]` of the longest prefix; RPC `prefix_route.reload/dump` |
| `speeddial` | `sd_lookup(table[, owner])` |
| `enum` | `enum_query`, `i_enum_query`, `enum_pv_query`, `is_from_user_enum` over DNS NAPTR (own resolver; `nameserver`, `domain_suffix`, `service`) |
| `outbound` | RFC 5626 flow tokens for edge proxies: HMAC'd tokens in the Path / Record-Route user part when the client's Contact has `;ob` (or `force_outbound_flag`), `loose_route` sends requests back over that flow; registrar `outbound_mode=1` answers `Require: outbound` |
| `tsilo` | `ts_store([uri])` after `t_relay()`, `ts_append(table, uri)` after `save()`: a client that registers while its call rings gets a branch of that transaction |
| `rtimer` | `timer` (`name=…;interval=10` or `100ms`) + `exec` (`timer=…;route=NAME`): periodic `route[NAME]` |
| `xhttp` / `xhttp_prom` | own HTTP listener (`listen`): `event_route[xhttp:request]` with `$hu`, `$hm`, `$hdr(…)`, `$rb`, `xhttp_reply(code, reason, ctype, body)`; POST `/RPC` = JSON-RPC; `/metrics` with every statistic (`xhttp_prom_beginning` "kamailio_", `xhttp_prom_stats`) |
| `ndb_redis` | RESP client: `server` "name=…;addr=…;port=…;db=…;pass=…", `redis_cmd(srv, "SET k %s", "$var(v)", res)`, `$redis(res=>type/value/info/size/value[n])`, `redis_free` |
| `app_lua` | Lua 5.4 (vendored, via mlua): `lua_run(func[, p1..p3])`, `lua_runstring`, `lua_dofile`, `load` parameter; KEMI-style `KSR.<module>.<function>(…)` reaches every exported function, `KSR.pv.get/sets/seti/unset/is_null`, `KSR.hdr.append/remove/is_present`, `KSR.info/err/…`, `KSR.x.exit/drop`; RPC `app_lua.reload` |
| registrar | GRUU (RFC 5627): `pub-gruu` / `temp-gruu` in the 200 for instances that `Supported: gruu`; `lookup()` of a GRUU reaches only that instance |
| registrar | `save(table, flags, uri)` (0x01 memory only, 0x02 no reply, 0x04 one contact per AoR, 0x10 the bindings for the script's reply; returns 1–4, -1, -2), `reg_send_reply()`, `lookup(table, uri)`, `lookup_branches`, `registered(table, uri, match_option, match_action)` (`xavp_cfg`, `xavp_rcd`), `unregister(table, uri[, ruid])`, `reg_fetch_contacts` / `reg_free_contacts` with `$ulc(profile=>attr)` and `$(ulc(profile=>addr)[i])` |
| `auth_ephemeral` | TURN-REST-style credentials (`expiry:user`, password = base64(HMAC(secret, user))): `autheph_check/www/proxy(realm)`, `autheph_authenticate(user, password)`, `secret`, `username_format`, `sha_algorithm` |

Core additions in this phase:
- named routes callable from modules (`RouteRunner::run_route`,
  `RouteHub::run_route_with`);
- KEMI access to exports and PVs;
- `sip_core::flow`, the RFC 5626 flow tokens;
- send taps (siptrace);
- `Tm::append_branch` / `txn_of` / `txn_pending` (tsilo, tmx);
- `Dialog::end_by_callid` (cnxcc);
- `t_reply` reasons may contain variables.

Not implemented: siptrace to a database and to SIP (non-HEP)
destinations, cnxcc with Redis, Lua as the whole routing engine
(`cfgengine "lua"`; call it with `lua_run` from the native script),
ndb_redis cluster mode.

## IMS (sip-diameter, mod-ims)

> Full reference: [`sip-diameter`](../crates/sip-diameter/README.md), [`mod-ims`](../crates/mod-ims/README.md).

`sip-diameter` is a small Diameter base stack. It provides the AVP/message
codec, plus peers over TCP:
- CER/CEA with application matching (5010 when none is in common), and
  the DWR/DWA watchdog (OKAY, SUSPECT, down);
- reconnect every `tc` seconds, and accepting incoming peers;
- blocking `request()` with hop-by-hop matching and a timeout;
- request handlers per (application, command).

It reads Kamailio's cdp XML configuration. The CSCF modules use it and keep
Kamailio's names and return codes:

| module | functions / features |
|---|---|
| `cdp` / `cdp_avp` | `config_file` (Kamailio's DiameterPeer XML) or `identity`, `realm`, `peer` "fqdn=…;realm=…;host=…;port=…;proto=tcp\|tls\|sctp", `listen` "[tls:\|sctp:]ip:port", `realm_route`, `default_route`, `tls_*`, `tc`, `transaction_timeout`; Diameter over TCP, TLS (client certificates both ways) and SCTP; realm route tables by metric, then default routes; RPC `cdp.list_peers` |
| `ims_auth` | Cx MAR/MAA: `ims_www_challenge(route, realm[, alg])`, `ims_proxy_challenge`, `ims_www_authenticate(realm)`, `ims_proxy_authenticate`; SIP Digest (HA1 from the HSS) and Digest-AKAv1-MD5 (nonce = base64(RAND‖AUTN), XRES as the password, `ck`/`ik` in the challenge); `name`, `cxdx_dest_realm`, `cxdx_forced_peer`, `registration_default_algorithm`, `registration_qop` |
| `ims_registrar_scscf` / `ims_usrloc_scscf` | `save([route,] "location")` sends SAR (REGISTRATION, RE_REGISTRATION, USER_DEREGISTRATION), parses User-Data (implicit set, iFCs), and answers 200 with Contact, Service-Route, P-Associated-URI and Path; `lookup`, `impu_registered`, `term_impu_registered`; on expiry, SAR TIMEOUT_DEREGISTRATION; `db_mode`/`db_url`: IMPU records, contacts and User-Data written through to the `impu` / `contact` tables and loaded at startup; RPC `ulscscf.showimpu`, `ulscscf.status` |
| `ims_isc` | `isc_match_filter("orig"\|"term", "location")` evaluates the iFC trigger points (Method, Request-URI, SIP header, session case, SDP line; CNF/DNF, negation, priority) and routes to the AS with `Route: <as;lr>, <scscf;lr;s=N;d=dir>`; when the request returns, the next iFC is tried; `isc_from_as(dir)` |
| `ims_registrar_pcscf` / `ims_usrloc_pcscf` | `pcscf_save_pending`, `save` on the 200 (in an onreply route), `pcscf_is_registered` (by source address), `pcscf_assert_identity(table, id)`, `pcscf_follows_service_routes`, `pcscf_force_service_routes`; RPC `ulpcscf.showcontacts` |
| `ims_qos` | Rx: `Rx_AAR(route, dir[, subscription_id[, type]])` sends one Media-Component-Description per SDP `m=` line; STR when the dialog ends; `Rx_STR()`; an ASR from the PCRF ends the call |
| `ims_charging` | Ro: `Ro_CCR(route, dir, units, …)` sends CCR-INITIAL, then CCR-UPDATE when the granted units run out; a refusal ends the call with BYEs; CCR-TERMINATION on hang-up; RPC `ro.sessions` |
| `ims_icscf` | `I_perform_user_authorization_request(route, caps)` (UAR: registration / de-registration / with capabilities), `I_perform_location_information_request(route, orig)` (LIR), `I_scscf_select(initial)` (`$du` = Server-Name, or the best `scscf_entry` for the returned mandatory/optional capabilities; "1" = next candidate), `I_scscf_drop`; `$avp(uaa_return_code)` / `$avp(lia_return_code)` |
| `ims_ipsec_pcscf` | RFC 3329 negotiation: `ipsec_create("location")` in the 401's onreply route (reads the REGISTER's Security-Client, allocates SPIs, adds Security-Server, strips `ck`/`ik` from the challenge), `ipsec_forward` (requests to the UE's protected server port), `ipsec_destroy`; RPC `ipsec.list`. With `ipsec_kernel=1`, the four ESP transport SAs and policies are installed and removed with `ip xfrm` (IK → hmac-sha1/md5-96, CK → aes-cbc / des-ede3-cbc / null; TS 33.203). The kernel's support is probed at startup and `ipsec.list` shows `kernel`: installed / unavailable / off |
| `ims_diameter_server` | `event_route[diameter:request]` answers incoming requests no IMS module takes (Sh…) from `$diameter_response`, reading `$diameter_command`, `$diameter_application`, `$diameter_request` (AVPs as JSON); `diameter_request([peer,] appid, cmd, json)` sends one and waits (answer in `$diameter_response`), `diameter_request_async()` hands the answer to `event_route[diameter:response]` |
| reg event | `ims_registrar_scscf`: `subscribe_to_reg("location")` and `can_subscribe_to_reg` (subscriber in the implicit set); `application/reginfo+xml` NOTIFYs (RFC 3680): a full document for each SUBSCRIBE, then partial ones (only the changed contacts, with their event) on registration, re-registration, de-registration and timeout, the version counting up |

How the test runs:
- `tests/e2e_ims.py` puts a UE behind a P-CSCF, then an S-CSCF, then an
  application server.
- A scripted Diameter peer plays HSS, PCRF and OCS.
- Covered: digest and AKA registration, iFC routing through the AS, Rx
  sessions, and a call cut off by the OCS.

Not implemented:
- TLS at the P-CSCF (`ims_ipsec_pcscf` covers IPsec). The kernel SA path
  is only unit-tested here: the CI sandbox (gVisor) has no XFRM, so
  `tests/e2e_ims.py` checks that this is detected and skips the
  installation check;
- the `s_cscf` database tables of `ims_icscf` (use `scscf_entry`);
- the P-CSCF subscribing to reg events itself;

## Asynchronous processing (mod-async)

> Full reference: [`mod-async`](../crates/mod-async/README.md).

A slow lookup (HTTP, a timer, a long task) suspends the transaction instead
of blocking a SIP worker. The script then continues on the same transaction
from another thread.

- **tm**:
  - `Tm::suspend` creates a transaction without branches. It answers
    retransmissions (INVITE: 100 Trying), turns a CANCEL into a 487, and
    after `fr_timer` (`fr_inv_timer` for an INVITE) plus the planned delay
    it answers 500.
  - `Tm::resume` rebuilds the request with its script state: header edits,
    `$ru`/`$du`, branches, `$avp`/`$xavp`/flags, Record-Route and armed
    routes.
  - A `t_relay()` there forks on that transaction. `t_reply()` or a
    stateless reply answers it, and retransmissions get that reply too.
  - Script functions: `t_suspend()`, `t_continue(index, label, route)`,
    `$T(id_index)`, `$T(id_label)`.
- **Script engine**: a suspending function exits the script. The engine
  records where it was (route, nested block, next action) and hands that
  continuation to the module. As in Kamailio, the rest of *that block* runs
  afterwards.

| module | functions / features |
|---|---|
| `async` | `async_route(route, s)`, `async_ms_route(route, ms)`, `async_sleep(s)`, `async_ms_sleep(ms)` (continue with the next action), `async_task_route(route)` (run on a pool thread now); `workers` |
| `http_async_client` | `.fsr`: `await http.get/post/request(…)`; `.cfg`: `http_async_query(url, route)`; build the request with `$http_req(method/body/hdr/timeout/username/password/all)`; the route sees `$http_ok`, `$http_err`, `$http_rs`, `$http_rr`, `$http_rb`, `$http_bs`, `$http_hdr(name)`, `$http_time`; `workers`, `connection_timeout`. HTTP(S) via ureq (rustls) |
| `sqlops` | `sql_query_async(con, query)`: fire and forget on a background thread |

In `.fsr`, the HTTP query is awaited and the script goes on after it
with a typed result (`r.ok`, `r.status`, `r.reason`, `r.body`, `r.error`,
`r.ms`); `http.post` and `http.request` work the same way:

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

In a Kamailio-style `.cfg`, the same is `http_async_query(url, route)`,
continuing in a named route with the `$http_*` variables.

`async_sleep` and `t_suspend` work in `request_route` and in routes called
from it, but not in failure, branch or reply routes. `async_task_group_route`
and Kamailio's `async_workers` core pool are not implemented (each module
has its own pool).

## JSON and REST (mod-async)

> Full reference: [`mod-async`](../crates/mod-async/README.md).

| module | functions / features |
|---|---|
| `http_client` | `http_client_query(url[, post[, hdrs]], $res)` returns the HTTP status (negative on transport errors, with `$curlerror(error)` set); `http_connect(con, path[, content_type, data], $res)` with `httpcon` "name=>base_url"; `connection_timeout` (s), `query_result` (1 = first body line, as in Kamailio), `useragent` |
| `jansson` | `jansson_get(path, json, $dst)`, `jansson_array_size`, `jansson_set(type, path, value, $doc)`, `jansson_append(…)`, `jansson_get_field`, `jansson_xdecode(json, xavp)`, `jansson_xencode(xavp, $dst)`. Paths look like `a.b[2].c`; types are string, integer, real, true, false, null, object, array |
| `json` | `json_get_field(json, field, $dst)`; the core transformation `$(var(x){json.parse,path})` |
| `jsonrpcs` | `jsonrpc_exec(json)` → `$jsonrpl(code/text/body)`; a FIFO transport like `kamctl` uses (`fifo_name`; the request carries `"reply_name"`, and the reply goes to that FIFO in `fifo_reply_dir`). The UNIX socket for `ferroctl` is the core's |

```rust
import http_client, json_doc

route main(msg: Request) {
    guard http_client.get("http://routing.local/route?user={msg.ruri.user}", body) else reply(ServiceUnavailable)
    json_doc.get("target.host", body, host)    // body, host, port: locals the calls fill
    json_doc.get("target.port", body, port)
    msg.dst_uri = "sip:{host}:{port}"
    relay(msg)
}
```

## Health checks, SIP dumps and the event API (mod-ops)

> Full reference: [`mod-ops`](../crates/mod-ops/README.md).

| module | functions / features |
|---|---|
| `keepalive` | OPTIONS probes through the tm UAC API every `ping_interval` s; a 2xx means up. `is_alive(uri)` returns 1 (up), -1 (down) or -2 (unknown). State changes run `event_route[keepalive:dst-up]` / `[keepalive:dst-down]` with the destination as `$ru`. Parameters `destination` (repeatable), `ping_from`, `delete_counter`; RPC `keepalive.list/get/add/del/flush` |
| `sipdump` | every message in and out (`observe_*` hooks + send tap) to `<folder>/<fprefix><date>.data` in Kamailio's text format (`mode` 1), and/or `.pcap` (`mode` 4: raw IPv4/IPv6 with UDP or TCP headers built from the addresses, so Wireshark decodes SIP), and/or stderr (`mode` 8); `rotate` s; `sipdump_send(tag)`; RPC `sipdump.enable [0/1]` |
| `evapi` | TCP event API (`bind_addr`, netstrings or lines with `netstring_format=0`): `evapi_relay`, `evapi_unicast/multicast(data, tag)`, `evapi_set_tag`, `evapi_close`, `evapi_async_relay(data)` (suspends the transaction; the app answers with `$T(id_index)`/`$T(id_label)` and `event_route[evapi:message-received]` resumes it with `t_continue`); routes `evapi:connection-new/closed/message-received` with `$evapi(msg/srcaddr/srcport/conidx)`; RPC `evapi.clients` |

`mode` 2 runs `event_route[sipdump:msg]` for every record, on the writer
thread (off the SIP path), with `$sipdump(tag/data/len/proto/af/src_ip/
src_port/dst_ip/dst_port/time)`.

## Web UI (mod-webui)

> Full reference: [`mod-webui`](../crates/mod-webui/README.md).

The `webui` module (`[modules.webui]`) gives operators a read-only
browser view.
- **Pages:** overview and statistics (live tiles, rates, sparklines),
  registrations and their contacts, active calls, transactions, TCP/TLS/WS
  connections, routing (dispatcher, LCR, dialplan), health (keepalive,
  RTPengine, Diameter, IMS), security tables, hash tables and config
  variables, presence, and a live log tail.
- **What appears:** a section shows only when its modules are loaded.
- **Size:** the app (Preact + TypeScript) is about 17 KB gzipped and
  embedded in the binary.

```toml
[modules.webui]
listen = "127.0.0.1:8090"
user = "admin"
password_hash = "sha256:…"   # ferroctl webui-hash
```

- **Read-only:** every API path maps to one read-only RPC, and only
  GET/HEAD are served.
- **Access:** Basic auth is mandatory, and failed logins are throttled.
  Listen on localhost or behind a TLS reverse proxy.
- **Tests:** CI checks the committed bundle is current and runs a
  Playwright smoke test over every page.

## Voice AI calls (mod-ai)

> Full reference: [`mod-ai`](../crates/mod-ai/README.md).

The `ai` module answers a call with OpenAI Realtime or Gemini Live,
using a system prompt taken from the call (for example a header):

```rust
import ai

route main(msg: Request) {
    if ai.dialog() {          // ACK/BYE/CANCEL of AI calls
        exit
    }
    if msg.method == INVITE && msg.ruri.user == "ai" {
        ai.answer("openai", msg.headers["X-AI-Prompt"])   // or "gemini"; optional voice
    }
    …
}
```

- **The call:** ferrosip is the far end. It answers with G.711
  (PCMU/PCMA), runs the RTP itself, and bridges it to the provider's
  WebSocket.
  - OpenAI: µ-law passthrough.
  - Gemini: 16/24 kHz PCM, resampled.
  - Barge-in, a greeting, and an `end_call` function the model uses to
    hang up.
- **Limits:** `max_calls`, `max_duration`, an RTP timeout.
- **Management:** `ferroctl ai.list` and `ai:*` statistics.
- **Security:** take the prompt only from trusted callers, since it
  steers the AI and spends your API credit.

## Prometheus and Grafana (mod-prometheus)

> Full reference: [`mod-prometheus`](../crates/mod-prometheus/README.md);
> dashboard and stack: [`examples/monitoring`](../examples/monitoring/).

```toml
[modules.prometheus]
listen = "127.0.0.1:9095"
```

`/metrics` has:
- requests by method;
- replies by class;
- latency histograms:
  - `request_route` time;
  - transaction time by method and class;
  - INVITE post-dial delay;
  - AI call connect time and length;
- dialogs, registrations, connections and AI calls;
- `process_*` metrics.

The latency instrumentation costs about 76 ns per request (measured in
`bench/BASELINE.md`). `xhttp_prom` remains for Kamailio-compatible names.
