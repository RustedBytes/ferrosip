# mod-ai

Answer SIP calls with a realtime voice AI. Use it when you want a phone
number that a caller can talk to, such as an automated front desk. The `ai`
module lets a caller talk to **OpenAI Realtime** or **Gemini Live**.

ferrosip answers the call itself. It bridges the caller's audio to the
provider's voice model. The system prompt comes from the call, for example
from a header that the calling system sets.

| Module | Kamailio module (`loadmodule`) | Purpose |
|---|---|---|
| `ai` | none (ferrosip's own) | Answer calls with OpenAI Realtime or Gemini Live |

```
caller ──SIP──▶ ferrosip ──WebSocket (TLS)──▶ OpenAI Realtime / Gemini Live
       ◀─RTP──▶ (G.711 ⇄ provider audio)
```

The caller's audio arrives as [RTP](../../docs/glossary.md#rtp). ferrosip
talks to the provider over a [WebSocket](../../docs/glossary.md#websocket).

```toml
# ferrosip.toml
[modules.ai]
media_ip = "203.0.113.10"                    # the address callers send RTP to
openai_key_file = "/run/secrets/openai"      # or OPENAI_API_KEY in the environment
```

```rust
// routing (.fsr)
import ai, acl

route main(msg: Request) {
    if ai.dialog() { exit }                  // ACK, BYE, CANCEL… of AI calls
    if msg.method == INVITE && msg.ruri.user == "ai" {
        // Only trusted callers may choose the prompt (see Security).
        guard acl.source_allowed(1) else reply(Forbidden, "Forbidden")
        ai.answer("openai", msg.headers["X-AI-Prompt"])
    }
    …
}
```

The module loads when the routing calls `ai.*`. `[modules.ai]` in
[`ferrosip.toml`](../../docs/glossary.md#ferrosiptoml) sets its parameters.

Example: a call to `sip:ai@…` carries
`X-AI-Prompt: You are the front desk of Hotel Lumen. Be brief.`
An assistant that follows that prompt answers it.

## Functions

In [`.fsr`](../../docs/glossary.md#fsr): `ai.answer(provider, prompt[, voice])`
and `ai.dialog()`. In a Kamailio-style [`.cfg`](../../docs/glossary.md#cfg):
`ai_answer()` and `ai_dialog()`.

**`ai_answer(provider, prompt [, voice])`**: answers an
[initial](../../docs/glossary.md#initial-request)
[INVITE](../../docs/glossary.md#invite) with the AI. Every argument may
contain variables.

- `provider`: `openai` or `gemini`.
- `prompt`: the system prompt / instructions.
  - A header can't carry line breaks. So a value that starts with `b64:` is
    base64-decoded first: `X-AI-Prompt: b64:TGluZSBvbmUKTGluZSB0d28=`.
  - An empty prompt uses `default_prompt`.
- `voice`: overrides the provider's default voice for this call.

The function sends `100 Trying` and opens the provider session. Then it
answers `200 OK` with an [SDP](../../docs/glossary.md#sdp) answer. It
returns 1, and the script should `exit`. In `.fsr` the route ends by itself.

If it can't take the call, it replies and returns -1. A `Warning:` header
says why:

| Reply | When |
|---|---|
| 488 | No PCMU/PCMA in the offer, SRTP, or no SDP |
| 486 | `max_calls` reached |
| 503 | The provider is unreachable or refused the session (e.g. a bad key: `Warning: 399 ferrosip "AI provider unavailable: HTTP/1.1 401 …"`), no key is configured, or no RTP port is free |
| 400 | Prompt too long, bad base64, no Contact |
| 500 | Unknown provider name |

**`ai_dialog()`**: handles requests that belong to an AI call. Call it
first in `request_route` (`route main`). It returns -1 for anything else.

- INVITE retransmissions get the last reply again.
- It handles ACK, BYE, and CANCEL. A CANCEL before the answer gets 200, and
  the INVITE then gets 487.
- It handles a [re-INVITE](../../docs/glossary.md#re-invite): a new media
  address for the same stream.
- It handles OPTIONS/INFO/UPDATE.

The SIP side of every AI call runs on the shared UA engine
([`sip-ua`](../sip-ua/README.md)): the INVITE server transaction, 100
Trying, the 200 OK retransmitted until the ACK (BYE after 32 s without
one), CANCEL/487, BYE in both directions, re-INVITE and session timers a
caller asks for. Callers that resend their INVITE, or send their CANCEL,
with a new Via branch are still matched, by Call-ID, From tag, CSeq and
Via sent-by (`lenient_matching`). The module no longer needs `tm`.

## The call

- **Media:**
  - G.711 PCMU or PCMA at 8 kHz, in 20 ms packets. ferrosip picks the first
    of these that the caller offers. It sends and receives the RTP itself,
    from a port in `rtp_port_min`–`rtp_port_max`.
  - Symmetric RTP: it sends to where the caller's packets come from. This
    gets through [NAT](../../docs/glossary.md#nat).
  - It sends silence while the AI is quiet. This keeps NAT bindings open.
- **OpenAI:** µ-law both ways, so audio passes through without
  transcoding. A-law callers are transcoded. Server VAD handles
  turn-taking.
- **Gemini:** caller audio is resampled to 16 kHz PCM. The answer (24 kHz
  PCM) is resampled to 8 kHz with a windowed-sinc filter.
- **Barge-in:** the caller may talk over the AI. OpenAI signals this with
  `input_audio_buffer.speech_started`, Gemini with `interrupted`. Queued
  audio is then dropped at once. OpenAI is told how much was heard
  (`conversation.item.truncate`), so its transcript matches.
- **Greeting:** once connected, the AI gets `first_message` as a user turn,
  so it speaks first. Set it to `""` to let the caller speak first.
- **Ending:**
  - The caller's BYE closes the provider session.
  - The model can hang up. It is given an `end_call` function, and ferrosip
    sends BYE once the goodbye has played.
  - ferrosip also sends BYE when:
    - the provider closes the session;
    - no RTP arrives for `rtp_timeout`;
    - `max_duration` passes;
    - no ACK arrives for the 200 within 32 s;
    - ferrosip shuts down.
- **One thread per call** runs the RTP and the WebSocket.

## Parameters

| Name | Default | Description |
|---|---|---|
| `openai_key` / `openai_key_file` | `$OPENAI_API_KEY` | API key (the file is read at startup) |
| `openai_model` | `gpt-realtime` | Realtime model |
| `openai_voice` | `marin` | Default voice |
| `openai_url` | `wss://api.openai.com/v1/realtime` | Endpoint (`?model=` is appended) |
| `gemini_key` / `gemini_key_file` | `$GEMINI_API_KEY` | API key |
| `gemini_model` | `gemini-2.5-flash-native-audio-preview-09-2025` | Live model (`models/` is added) |
| `gemini_voice` | `Puck` | Default voice |
| `gemini_url` | `wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent` | Endpoint (`?key=` is appended) |
| `media_ip` | the SIP address | IP put in the SDP answer. Set it when listening on 0.0.0.0 or behind NAT |
| `rtp_port_min`, `rtp_port_max` | 30000, 30999 | RTP ports (even ones are used) |
| `max_calls` | 100 | Concurrent AI calls. Beyond that: 486 |
| `max_duration` | 1800 | Seconds before ferrosip hangs up |
| `rtp_timeout` | 30 | Seconds without RTP from the caller before hanging up |
| `connect_timeout` | 5000 | ms to open the provider session. The caller hears ringing silence meanwhile |
| `first_message` | "(The phone call has just been connected. Greet the caller.)" | Sent as the first user turn. `""`: the AI waits |
| `default_prompt` | a short generic assistant prompt | Used when the prompt argument is empty |
| `prompt_max` | 16384 | Longest prompt accepted (bytes, after base64) |
| `end_call_tool` | 1 | Offer the model the `end_call` function |
| `rtp_latch` | 1 | Send RTP to where the caller's RTP comes from |
| `tls_ca_file` | Mozilla roots | PEM CAs for `wss://` (a self-hosted gateway or a private CA) |

Model names and voices change often. They are parameters, so new ones need
no rebuild.

## Management

- `ferroctl ai.list` lists the calls in progress, with:
  - provider, state, From/To, codec, RTP addresses;
  - duration, and packets each way.
- `ferroctl ai.recent` lists the last 100 finished calls, newest first.
  Each has:
  - its `outcome`: `answered`, `failed` or `cancelled`;
  - the `reason` it ended, e.g. `caller hung up`, `the AI ended the call`,
    `no RTP from the caller`, `provider unavailable: HTTP/1.1 401 …`;
  - when it `ended`.

  Calls refused before ferrosip tries the provider (488, 486, 400, 500) are
  not listed. They keep their `Warning:` header and log line.
- Both lists include each call's prompt (and voice override).
- The [web UI](../../docs/glossary.md#web-ui) (`[modules.webui]`) shows
  them under **Calls → AI calls**: tiles, calls in progress, and recently
  ended calls. The tables show a preview of the prompt. The call's details
  show it in full.
- [Statistics](../../docs/glossary.md#statistics): `ai:active_calls`,
  `ai:calls`, `ai:failed_calls`.

## Security and cost

- **The prompt is power.** Anyone who can reach `ai_answer` with their own
  header decides what the AI says, and runs up your provider bill.
  - Take the prompt only from trusted sources:
    - an authenticated subscriber;
    - your own PBX, by address (`acl.source_allowed()`, Kamailio
      `allow_source_address`);
    - a fixed prompt chosen by the dialled number (`msg.ruri.user` → a
      [shared table](../../docs/glossary.md#shared-table) or dialplan).
  - Remove the header from anything else
    (`msg.headers.remove("X-AI-Prompt")`).
- **Bounding use:**
  - `max_calls` and `max_duration` limit concurrency and length;
  - `limits` (`pike` / `ratelimit`) in front of `ai.answer` limits call
    attempts.
- **Keys:**
  - Keep them in files or the environment, not in the config.
  - The Gemini key travels in the URL query, as that API requires. Error
    logs name only the provider's host.
- **Unencrypted media.** Audio between the caller and ferrosip is plain RTP,
  not [SRTP](../../docs/glossary.md#srtp). The provider leg is TLS.

## Testing

`tests/e2e_ai.py` runs real SIP calls against a mock OpenAI and a mock
Gemini. Each mock is a local WebSocket server. The Gemini one runs over TLS
with a private CA. It covers:

- prompt, model, key and voice delivery;
- audio both ways: byte-exact for the OpenAI echo, audible after Gemini's
  resampling;
- the greeting;
- retransmissions and `ai.list`;
- BYE in both directions;
- `end_call`, a provider drop and the RTP timeout;
- CANCEL while connecting, a 401 from the provider, and the codec, SRTP and
  provider-name refusals.

The wire formats follow the providers' published realtime protocols: OpenAI
GA events, also accepting the beta `response.audio.delta`. They are tested
against the mocks, not against the live services.
