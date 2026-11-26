# m15-media-relay (medium)

This scenario models calls whose audio goes through a
[media relay](../../../docs/glossary.md#media-relay). The proxy handles
the signalling. The relay carries the [RTP](../../../docs/glossary.md#rtp)
audio, so the two phones never need to reach each other directly. The
relay speaks rtpengine's ng protocol: rtpengine itself, or
[rtpflux](https://github.com/RustedBytes/rtpflux) as in the test. It
proves that media flows both ways through the relay, that hold and resume
work, and that every way a call can end frees the relay session.

```
           INVITE (SDP: alice:pa)          INVITE (SDP: relay:Rb)
alice ───────────────────▶ ferrosip ───────────────────────────▶ bob
  ▲   200 (SDP: relay:Ra)  │   ▲  │ ng offer / answer / delete      │
  └────────────────────────┘   │  ▼                                 │
                              ┌─────────┐                           │
  alice:pa ◀── RTP ──▶ Ra     │ rtpflux │     Rb ◀── RTP ──▶ bob:pb │
                              └─────────┘
  offer:  the INVITE (and any re-INVITE with SDP)
  answer: on reply, 180..299 with SDP
  delete: BYE (either side); after the await on any non-2xx (486, 487 after CANCEL, timeout)
```

The offer and answer are the [SDP](../../../docs/glossary.md#sdp)
[offer and answer](../../../docs/glossary.md#offer-and-answer).

**Shows**:
- `media.offer(flags)` before `await txn.relay`;
- `media.answer` in `on reply(r) where r.has_sdp && r.code in 180..299`;
- `media.delete()` on [BYE](../../../docs/glossary.md#bye), and in the
  `match` after the `await` for every outcome but a 2xx;
- [re-INVITEs](../../../docs/glossary.md#re-invite) offered again in the
  same session;
- the ng flags as a [`[feature]`](../../../docs/glossary.md#feature-switch)
  constant (`replace-origin replace-session-connection
  ICE=remove`);
- `[modules.media] rtpengine_sock` from `${MEDIA_RELAY}`;
- `rtpengine_retr = 2`, so a dead relay is given up on in about 2 s.

A [CANCEL](../../../docs/glossary.md#cancel) is only relayed. The
INVITE's `await` then gets the 487 and deletes the session. So there is
one place that cleans up.

**Edge cases checked** (`tests/scenarios/m15_media_relay.py`):
- The offer bob gets and the answer alice gets both point at the relay:
  127.0.0.1, two different ports from rtpflux's range. Both have the
  right Content-Length. rtpflux lists the call.
- Real RTP, 5 packets each way, reaches the other side intact from the
  relay's port.
- Hold:
  - a re-INVITE with `a=sendonly` reaches bob as `a=sendonly`;
  - bob's `a=recvonly` comes back, on the same relay ports;
  - alice's media still flows while on hold;
  - resume with `a=sendrecv` gives media both ways again.
- BYE from the caller and BYE from the callee each delete the session.
  rtpflux no longer lists it, and nothing is relayed any more.
- CANCEL while ringing (the offer had created a session) and a 486: the
  session is deleted.
- An SDP with no `m=` line (RFC 4566 allows it): the call goes through,
  and bob gets an SDP without media too.
- An offer with [ICE](../../../docs/glossary.md#ice) candidates (host and
  srflx): bob's SDP has no `a=candidate` / `a=ice-*` and no trace of the
  srflx address. Its media still goes through the relay.
- The relay is down: 500 `Media relay failed`, and bob never sees the
  INVITE.

The test starts rtpflux itself on ports of the scenario's block. It uses
`$RTPFLUX`, else `../rtpflux/target/release/rtpflux`. The test is skipped
without it.

**Run it by hand**: start a relay with ng on `127.0.0.1:2223`. For
rtpflux, that is `rtpflux -c rtpflux.toml` with
`[control] listen = ["127.0.0.1:2223"]`. Then run
`ferrosip --config ferrosip.toml`. `SIP_PORT` is 5060 and `MEDIA_RELAY` is
`udp:127.0.0.1:2223`.
