# mod-media

Control of an external [media relay](../../docs/glossary.md#media-relay).
Use it when the call audio should pass through a relay instead of going
straight between the phones, for example to get through
[NAT](../../docs/glossary.md#nat) or to record calls. ferrosip itself only
handles SIP. The relay carries the [RTP](../../docs/glossary.md#rtp).

The `rtpengine` module drives one or more
[rtpengine](https://github.com/sipwise/rtpengine) instances. It also works
with any relay that speaks the same protocol, such as
[rtpflux](https://github.com/RustedBytes/rtpflux). It talks to them over the
"ng" control protocol: bencode dictionaries over UDP, each prefixed by a
cookie.

The relay returns rewritten [SDP](../../docs/glossary.md#sdp), which
replaces the message body. This works in requests. It also works in
replies, from `on reply` (`onreply_route` in a `.cfg`). Content-Length is
fixed when the message is sent.

The crate also exposes its bencode codec (`mod_media::bencode`), which is
fuzzed.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `media` | `rtpengine` | Offer/answer/delete and media control commands to rtpengine nodes |

In [`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) and
[`.fsr`](../../docs/glossary.md#fsr) the module is `media`:
`[modules.media]`, `media.offer()`, `media.answer()`…. The names are in
[docs/functions-reference.md](../../docs/functions-reference.md).

## media (rtpengine)

Nodes are grouped into sets.

- A call sticks to the node that handled it. The node is remembered per
  Call-ID until `delete`.
- A new call picks a node by a weighted hash of its Call-ID.
- A node may not answer within `rtpengine_tout_ms` after `rtpengine_retr`
  tries. It is then disabled for `rtpengine_disable_tout` seconds, and the
  next enabled node of the set is tried.
- A node that answers with an error ends the call with -1. There is no
  failover in that case.
- `rtpengine_sock` is required. The module refuses to start without it.

Flags use [Kamailio](../../docs/glossary.md#kamailio)'s syntax and are
translated into the ng dictionary:

- plain words (`trust-address`, `asymmetric`, ...) go into `flags`;
- `replace-*`, `SDES-*`, `rtcp-mux-*`, `T38-*` / `T.38-*` (or `replace=x`
  and so on) build the matching lists;
- `RTP/AVP`, `RTP/SAVP`, `RTP/AVPF`, `RTP/SAVPF`, `UDP/TLS/RTP/SAVP`,
  `UDP/TLS/RTP/SAVPF` set `transport-protocol`;
- `direction=x` (repeatable) builds the `direction` list;
- `transcode-*`, `codec-transcode-*`, `codec-strip-*`, `codec-offer-*`,
  `codec-mask-*`, `codec-set-*`, `codec-except-*`, `codec-accept-*`,
  `codec-consume-*` build the `codec` dictionary;
- `received-from=ip` overrides the address. By default offer and answer
  send the message's source address;
- `via-branch=1` or `via-branch=auto` sends the top
  [Via branch](../../docs/glossary.md#branch-parameter). `via-branch=2` is
  ignored. Any other value is sent as is;
- any other `key=value` becomes a dictionary entry (`ICE=remove`,
  `DTLS=off`, `label=x`, ...). See [ICE](../../docs/glossary.md#ice) and
  [DTLS](../../docs/glossary.md#dtls).

**Parameters**

| Name | Default | Description |
|---|---|---|
| `rtpengine_sock` | none (required) | `[set ==] udp:host:port[=weight] ...`. Repeat it for more sets. Only `udp:`, `udp4:`, `udp6:` control sockets. A missing set id means set 0, and a missing weight means 1 |
| `rtpengine_tout_ms` | 1000 | Milliseconds to wait for each answer (min 1) |
| `rtpengine_retr` | 5 | Tries per node before it is disabled (min 1) |
| `rtpengine_disable_tout` | 60 | Seconds a node stays disabled after a timeout |
| `setid_default` | 0 | Set used when `set_rtpengine_set()` was not called |

Accepted for compatibility and ignored: `rtpengine_allow_op`,
`queried_nodes_limit`, `hash_table_size`, `hash_table_tout`,
`extra_id_pv`, `setid_avp`, `read_sdp_pv`, `write_sdp_pv`,
`rtp_inst_pvar`, `control_cmd_tos`, `mos_min_pv`, `mos_max_pv`,
`mos_average_pv`.

**Functions**

All of them return 1 on success. They return -1 when the message lacks a
Call-ID/From tag, when no node answered, or when the node returned an
error.

| Signature | Description |
|---|---|
| `rtpengine_offer([flags])` | ng `offer` with the message's SDP. The body is replaced by the SDP of the answer. -1 if there is no body. See [offer and answer](../../docs/glossary.md#offer-and-answer) |
| `rtpengine_answer([flags])` | ng `answer`, the same as above |
| `rtpengine_delete([flags])` | ng `delete`. Forgets the call's node |
| `rtpengine_manage([flags])` | Picks the command. For requests: INVITE or UPDATE with SDP → offer, ACK with SDP → answer, BYE/CANCEL → delete. For replies to INVITE/UPDATE: 180-299 with SDP → answer, >= 300 → delete. Anything else does nothing and returns 1 |
| `rtpengine_query([flags])` | ng `query`. The result feeds `$rtpstat` for the rest of this message |
| `rtpengine_query_v("j", $var)` | ng `query`. The whole reply goes as JSON into `$var`. Only format `"j"` |
| `start_recording([flags])` / `stop_recording([flags])` | ng `start recording` / `stop recording` |
| `block_dtmf([flags])` / `unblock_dtmf([flags])` | ng `block DTMF` / `unblock DTMF` |
| `block_media([flags])` / `unblock_media([flags])` | ng `block media` / `unblock media` |
| `silence_media([flags])` / `unsilence_media([flags])` | ng `silence media` / `unsilence media` |
| `set_rtpengine_set(id)` | Use set `id` for the following calls on this message. -1 if the set is not configured |

**Pseudo-variables**

| Name | Description |
|---|---|
| `$rtpstat` | After `rtpengine_query()`: `RTP: <bytes> bytes, <packets> packets, <errors> errors; RTCP: <bytes> bytes, <packets> packets, <errors> errors`, taken from the reply's `totals`. Null otherwise. Read-only |

**RPC commands**

| Command | Description |
|---|---|
| `rtpengine.show [url\|all]` | Nodes: url, weight, disabled, recheck_ticks (seconds until re-enabled; -1 = disabled by `rtpengine.enable`) |
| `rtpengine.enable <url\|all> <0\|1>` | Enable or disable nodes by hand. Returns how many matched. A node disabled this way stays disabled until it is enabled again |
| `rtpengine.ping [url\|all]` | ng `ping` to the nodes. `success` re-enables a timed-out node. `fail` disables it for `rtpengine_disable_tout` |

**Example**

```toml
[modules.media]                   # rtpengine
rtpengine_sock = [
    "udp:127.0.0.1:2223=2 udp:127.0.0.1:2224",   # set 0
    "1 == udp:10.0.0.9:2223",                    # set 1
]
rtpengine_tout_ms = "500ms"
```

```rust
import media

route main(msg: Request) {
    if msg.has_to_tag {
        if msg.method == BYE {
            media.delete()
        }
        relay(msg)
    }
    guard media.offer("replace-origin replace-session-connection ICE=remove RTP/AVP via-branch=1") else reply(ServerInternalError, "Media relay failed")
    relay(msg)
}

// Instead of t_on_reply() + onreply_route: runs for every reply with SDP.
on reply(r: Reply) where r.has_sdp {
    media.answer()
}
```

**Differences from Kamailio**

- Only UDP control sockets. `tcp:`, `ws:` and `wss:` are refused at
  startup.
- No MOS or statistics pseudo-variables: `mos_*_pv` are ignored. `$rtpstat`
  shows only the RTP and RTCP totals.
- `setid_avp`, `read_sdp_pv` and `write_sdp_pv` are ignored. The set comes
  from `set_rtpengine_set()` or `setid_default`. The SDP is always read from
  and written to the message body.
- An error answer from a node is not retried on another node.

## Testing

- `tests/e2e_carrier.py`, against a fake ng server:
  - the `rtpengine_offer` SDP rewrite and Content-Length;
  - the ng offer dictionary (call-id, from-tag, flags, replace, ICE,
    transport-protocol, received-from, via-branch);
  - `rtpengine_answer` in `onreply_route`, `rtpengine_delete` on BYE;
  - `rtpengine_query` with `$rtpstat`;
  - a dead node in set 1 being disabled;
  - `rtpengine.show` and `rtpengine.ping`.
- `tests/e2e_rtpflux.py`, against a real relay,
  [rtpflux](https://github.com/RustedBytes/rtpflux). CI builds rtpflux, pinned
  to a commit in `ci.yml`. Without the binary the test is skipped.
  It runs one call through a `.cfg` (`rtpengine_manage` in the request and
  `onreply_route`) and one through `.fsr` (`media.offer` / `media.answer` /
  `media.delete`). It checks:
  - the offer and the answer rewritten to relay ports from rtpflux's range;
  - rtpflux listing the call;
  - 20 RTP packets each way relayed from the relay's ports, with payloads
    intact (latching on both sides);
  - rtpflux's `query` counting them;
  - the BYE deleting the call, after which nothing is relayed.

  `RTPFLUX=/path/to/rtpflux` picks the binary. The default is
  `../rtpflux/target/release/rtpflux`.
- Unit tests: flag translation and `rtpengine_sock` parsing; the bencode
  round trip and an oversized string length.
- Fuzz target `fuzz/fuzz_targets/bencode.rs`: decodes arbitrary input with
  `mod_media::bencode::B::decode` and re-encodes it.
