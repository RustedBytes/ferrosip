//! The two realtime voice APIs, as message translation only: what to send
//! after connecting, how caller audio goes up, and what the provider's
//! messages mean for the call. No I/O here.
//!
//! - OpenAI Realtime (GA protocol): `wss://api.openai.com/v1/realtime?model=…`,
//!   `Authorization: Bearer`. G.711 µ-law both ways, so no resampling.
//!   The beta event names (`response.audio.delta`) are accepted too.
//! - Gemini Live: `BidiGenerateContent` with `?key=`. 16 kHz PCM up,
//!   24 kHz PCM down (the rate is read from each chunk's MIME type).

use crate::audio::{self, Codec, Resampler};
use serde_json::{Value, json};
use sip_transport::ws::base64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    OpenAi,
    Gemini,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "openai" => Some(Kind::OpenAi),
            "gemini" | "google" => Some(Kind::Gemini),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::OpenAi => "openai",
            Kind::Gemini => "gemini",
        }
    }
}

/// One provider's settings (modparams).
#[derive(Clone, Debug)]
pub struct Cfg {
    pub url: String,
    pub model: String,
    pub key: String,
    pub voice: String,
}

/// What this call's session asks for.
pub struct Setup<'a> {
    pub prompt: &'a str,
    pub voice: &'a str,
    /// A user turn sent once connected so the AI speaks first ("" = wait
    /// for the caller).
    pub first_message: &'a str,
    /// Offer an `end_call` function the model can use to hang up.
    pub end_call_tool: bool,
}

const END_CALL: &str = "end_call";
const END_CALL_HELP: &str = "Hang up the phone call. Use it after saying goodbye, when the caller is done or asks to end the call.";

/// The WebSocket URL and headers to open a session.
pub fn target(kind: Kind, cfg: &Cfg) -> (String, Vec<(&'static str, String)>) {
    let sep = if cfg.url.contains('?') { '&' } else { '?' };
    match kind {
        Kind::OpenAi => (format!("{}{sep}model={}", cfg.url, url_enc(&cfg.model)), vec![("Authorization", format!("Bearer {}", cfg.key))]),
        Kind::Gemini => (format!("{}{sep}key={}", cfg.url, url_enc(&cfg.key)), vec![]),
    }
}

fn url_enc(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

#[derive(Debug, PartialEq)]
pub enum Action {
    /// Audio for the caller (8 kHz PCM), with the provider's item id.
    Play(Vec<i16>, Option<String>),
    /// The caller started talking over the AI: stop playback.
    Interrupt,
    /// The model asked to end the call (after what it is saying).
    Hangup,
    /// Send this to the provider.
    Send(String),
    /// Ready for audio (Gemini: after `setupComplete`).
    Ready,
    Log(String),
}

/// Per-call protocol state.
pub struct Session {
    kind: Kind,
    codec: Codec,
    ready: bool,
    first_message: String,
    up: Option<Resampler>,
    down: Option<(u32, Resampler)>,
    seen_calls: Vec<String>,
}

impl Session {
    pub fn new(kind: Kind, codec: Codec) -> Self {
        Session {
            kind,
            codec,
            ready: kind == Kind::OpenAi,
            first_message: String::new(),
            up: (kind == Kind::Gemini).then(|| Resampler::new(8000, 16000)).flatten(),
            down: None,
            seen_calls: Vec::new(),
        }
    }

    /// Messages to send right after the WebSocket opens.
    pub fn setup(&mut self, cfg: &Cfg, s: &Setup<'_>) -> Vec<String> {
        let voice = if s.voice.is_empty() { cfg.voice.as_str() } else { s.voice };
        match self.kind {
            Kind::OpenAi => {
                let mut session = json!({
                    "type": "realtime",
                    "model": cfg.model,
                    "instructions": s.prompt,
                    "output_modalities": ["audio"],
                    "audio": {
                        "input": {"format": {"type": "audio/pcmu"}, "turn_detection": {"type": "server_vad"}},
                        "output": {"format": {"type": "audio/pcmu"}, "voice": voice},
                    },
                });
                if s.end_call_tool
                    && let Some(o) = session.as_object_mut()
                {
                    o.insert(
                        "tools".into(),
                        json!([{"type": "function", "name": END_CALL, "description": END_CALL_HELP, "parameters": {"type": "object", "properties": {}}}]),
                    );
                    o.insert("tool_choice".into(), json!("auto"));
                }
                let mut v = vec![json!({"type": "session.update", "session": session}).to_string()];
                if !s.first_message.is_empty() {
                    v.push(json!({"type": "conversation.item.create", "item": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": s.first_message}]}}).to_string());
                    v.push(json!({"type": "response.create"}).to_string());
                }
                v
            }
            Kind::Gemini => {
                let model = if cfg.model.starts_with("models/") { cfg.model.clone() } else { format!("models/{}", cfg.model) };
                let mut setup = json!({
                    "model": model,
                    "generationConfig": {
                        "responseModalities": ["AUDIO"],
                        "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": voice}}},
                    },
                    "systemInstruction": {"parts": [{"text": s.prompt}]},
                });
                if s.end_call_tool
                    && let Some(o) = setup.as_object_mut()
                {
                    o.insert("tools".into(), json!([{"functionDeclarations": [{"name": END_CALL, "description": END_CALL_HELP}]}]));
                }
                // The greeting waits for setupComplete.
                self.first_message = s.first_message.to_string();
                vec![json!({"setup": setup}).to_string()]
            }
        }
    }

    /// One RTP payload from the caller → the message carrying it (None
    /// until the session is ready).
    pub fn audio(&mut self, payload: &[u8]) -> Option<String> {
        if !self.ready || payload.is_empty() {
            return None;
        }
        match self.kind {
            Kind::OpenAi => {
                let ulaw: Vec<u8> = match self.codec {
                    Codec::Pcmu => payload.to_vec(),
                    Codec::Pcma => payload.iter().map(|&b| audio::ulaw_encode(audio::alaw_decode(b))).collect(),
                };
                Some(json!({"type": "input_audio_buffer.append", "audio": base64(&ulaw)}).to_string())
            }
            Kind::Gemini => {
                let pcm: Vec<i16> = payload.iter().map(|&b| self.codec.decode(b)).collect();
                let mut up = Vec::with_capacity(pcm.len().saturating_mul(2));
                self.up.as_mut()?.push(&pcm, &mut up);
                Some(json!({"realtimeInput": {"audio": {"data": base64(&audio::pcm16_to_le(&up)), "mimeType": "audio/pcm;rate=16000"}}}).to_string())
            }
        }
    }

    /// Tell OpenAI how much of an interrupted answer the caller heard.
    pub fn truncate(&self, item: &str, heard_ms: u64) -> Option<String> {
        (self.kind == Kind::OpenAi)
            .then(|| json!({"type": "conversation.item.truncate", "item_id": item, "content_index": 0, "audio_end_ms": heard_ms}).to_string())
    }

    pub fn on_message(&mut self, msg: &[u8], out: &mut Vec<Action>) {
        let Ok(v) = serde_json::from_slice::<Value>(msg) else {
            out.push(Action::Log(format!("not JSON: {}", String::from_utf8_lossy(msg.get(..120).unwrap_or(msg)))));
            return;
        };
        match self.kind {
            Kind::OpenAi => self.openai(&v, out),
            Kind::Gemini => self.gemini(&v, out),
        }
    }

    fn function_call(&mut self, name: &str, id: &str, out: &mut Vec<Action>) {
        if self.seen_calls.iter().any(|c| c == id) {
            return;
        }
        self.seen_calls.push(id.to_string());
        let ok = name == END_CALL;
        let result = if ok { "the call will end after your last words" } else { "unknown function" };
        match self.kind {
            Kind::OpenAi => out.push(Action::Send(
                json!({"type": "conversation.item.create", "item": {"type": "function_call_output", "call_id": id, "output": json!({"result": result}).to_string()}}).to_string(),
            )),
            Kind::Gemini => out.push(Action::Send(json!({"toolResponse": {"functionResponses": [{"id": id, "name": name, "response": {"result": result}}]}}).to_string())),
        }
        if ok {
            out.push(Action::Hangup);
        } else {
            out.push(Action::Log(format!("model called unknown function {name:?}")));
        }
    }

    fn openai(&mut self, v: &Value, out: &mut Vec<Action>) {
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        match s("type").unwrap_or("") {
            "response.output_audio.delta" | "response.audio.delta" => {
                if let Some(b) = s("delta").and_then(base64_decode) {
                    out.push(Action::Play(b.iter().map(|&u| audio::ulaw_decode(u)).collect(), s("item_id").map(str::to_string)));
                }
            }
            "input_audio_buffer.speech_started" => out.push(Action::Interrupt),
            "response.output_item.done" => {
                let item = &v["item"];
                if item["type"] == "function_call" {
                    self.function_call(item["name"].as_str().unwrap_or(""), item["call_id"].as_str().unwrap_or(""), out);
                }
            }
            "response.function_call_arguments.done" => {
                if let (Some(name), Some(id)) = (s("name"), s("call_id")) {
                    self.function_call(name, id, out);
                }
            }
            "error" => {
                let e = &v["error"];
                let msg = e["message"].as_str().unwrap_or("");
                // An interrupted item may already be gone: not worth a log line.
                if e["code"] != "item_truncate_invalid_item_id" {
                    out.push(Action::Log(format!("openai error: {} {msg}", e["code"].as_str().or(e["type"].as_str()).unwrap_or(""))));
                }
            }
            _ => {}
        }
    }

    fn gemini(&mut self, v: &Value, out: &mut Vec<Action>) {
        if v.get("setupComplete").is_some() {
            self.ready = true;
            out.push(Action::Ready);
            if !self.first_message.is_empty() {
                let text = std::mem::take(&mut self.first_message);
                out.push(Action::Send(json!({"clientContent": {"turns": [{"role": "user", "parts": [{"text": text}]}], "turnComplete": true}}).to_string()));
            }
        }
        if let Some(sc) = v.get("serverContent") {
            if sc["interrupted"] == true {
                out.push(Action::Interrupt);
            }
            for p in sc.pointer("/modelTurn/parts").and_then(Value::as_array).into_iter().flatten() {
                let d = &p["inlineData"];
                let (Some(mime), Some(data)) = (d["mimeType"].as_str(), d["data"].as_str()) else { continue };
                if !mime.starts_with("audio/pcm") {
                    continue;
                }
                let rate = mime.split(';').find_map(|p| p.trim().strip_prefix("rate=")).and_then(|r| r.parse().ok()).unwrap_or(24000u32);
                let Some(bytes) = base64_decode(data) else { continue };
                let pcm = audio::pcm16_from_le(&bytes);
                if self.down.as_ref().is_none_or(|(r, _)| *r != rate) {
                    let Some(r) = Resampler::new(rate, 8000) else {
                        out.push(Action::Log(format!("gemini: cannot resample audio at {rate} Hz")));
                        continue;
                    };
                    self.down = Some((rate, r));
                }
                let mut o = Vec::with_capacity((pcm.len() / 3).saturating_add(1));
                if let Some((_, r)) = self.down.as_mut() {
                    r.push(&pcm, &mut o);
                }
                out.push(Action::Play(o, None));
            }
        }
        for c in v.pointer("/toolCall/functionCalls").and_then(Value::as_array).into_iter().flatten() {
            self.function_call(c["name"].as_str().unwrap_or(""), c["id"].as_str().unwrap_or(""), out);
        }
        if v.get("goAway").is_some() {
            out.push(Action::Log(format!("gemini goAway: {}", v["goAway"])));
        }
        if let Some(e) = v.get("error") {
            out.push(Action::Log(format!("gemini error: {e}")));
        }
    }
}

/// Standard or URL-safe base64, padding optional, whitespace ignored.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "c is inside the matched range, so c - start < 26 and + 26/52 < 64; bits < 8 on entry to each step, so bits + 6 < 14 and bits - 8 runs only when bits >= 8; len / 4 * 3 < len"
)]
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    // `=` is padding: at most two, and nothing but more padding or
    // whitespace after the first.
    let mut padding = 0u8;
    for c in s.bytes() {
        let v = match c {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => {
                padding = padding.saturating_add(1);
                if padding > 2 {
                    return None;
                }
                continue;
            }
            _ if padding > 0 => return None,
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation, reason = "the next decoded byte is the low 8 bits of the accumulator")]
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Cfg {
        Cfg { url: "wss://example/x".into(), model: "m1".into(), key: "k/1".into(), voice: "v0".into() }
    }

    #[test]
    fn b64() {
        assert_eq!(base64_decode(&base64(b"hello world!?")).unwrap(), b"hello world!?");
        assert_eq!(base64_decode("aGk").unwrap(), b"hi");
        assert_eq!(base64_decode("a-_w").unwrap(), base64_decode("a+/w").unwrap());
        assert!(base64_decode("a*b").is_none());
    }

    #[test]
    fn openai_flow() {
        assert_eq!(target(Kind::OpenAi, &cfg()).0, "wss://example/x?model=m1");
        assert_eq!(target(Kind::OpenAi, &cfg()).1[0].1, "Bearer k/1");
        assert_eq!(target(Kind::Gemini, &cfg()).0, "wss://example/x?key=k%2F1");
        let mut s = Session::new(Kind::OpenAi, Codec::Pcma);
        let m = s.setup(&cfg(), &Setup { prompt: "Be brief.", voice: "", first_message: "Hi", end_call_tool: true });
        assert_eq!(m.len(), 3);
        let u: Value = serde_json::from_str(&m[0]).unwrap();
        assert_eq!(u["session"]["instructions"], "Be brief.");
        assert_eq!(u["session"]["audio"]["output"]["voice"], "v0");
        assert_eq!(u["session"]["audio"]["input"]["format"]["type"], "audio/pcmu");
        assert_eq!(u["session"]["tools"][0]["name"], "end_call");
        // A-law from the caller goes up as µ-law.
        let a: Value = serde_json::from_str(&s.audio(&[0xD5, 0xD5]).unwrap()).unwrap();
        assert_eq!(base64_decode(a["audio"].as_str().unwrap()).unwrap(), vec![audio::ulaw_encode(audio::alaw_decode(0xD5)); 2]);
        let mut out = Vec::new();
        s.on_message(br#"{"type":"response.output_audio.delta","item_id":"it1","delta":"//8="}"#, &mut out);
        assert_eq!(out, vec![Action::Play(vec![0, 0], Some("it1".into()))]);
        out.clear();
        s.on_message(br#"{"type":"input_audio_buffer.speech_started"}"#, &mut out);
        s.on_message(br#"{"type":"response.function_call_arguments.done","name":"end_call","call_id":"c1","arguments":"{}"}"#, &mut out);
        s.on_message(br#"{"type":"response.output_item.done","item":{"type":"function_call","name":"end_call","call_id":"c1"}}"#, &mut out);
        assert_eq!(out.len(), 3, "{out:?}");
        assert_eq!(out[0], Action::Interrupt);
        assert!(matches!(&out[1], Action::Send(m) if m.contains("function_call_output") && m.contains("\"c1\"")));
        assert_eq!(out[2], Action::Hangup);
        assert!(s.truncate("it1", 120).unwrap().contains("\"audio_end_ms\":120"));
    }

    #[test]
    fn gemini_flow() {
        let mut s = Session::new(Kind::Gemini, Codec::Pcmu);
        let m = s.setup(&cfg(), &Setup { prompt: "P", voice: "Kore", first_message: "Hello?", end_call_tool: false });
        assert_eq!(m.len(), 1);
        let u: Value = serde_json::from_str(&m[0]).unwrap();
        assert_eq!(u["setup"]["model"], "models/m1");
        assert_eq!(u["setup"]["systemInstruction"]["parts"][0]["text"], "P");
        assert_eq!(u["setup"]["generationConfig"]["speechConfig"]["voiceConfig"]["prebuiltVoiceConfig"]["voiceName"], "Kore");
        assert!(u["setup"].get("tools").is_none());
        assert!(s.audio(&[0xFF; 160]).is_none(), "no audio before setupComplete");
        let mut out = Vec::new();
        s.on_message(br#"{"setupComplete":{}}"#, &mut out);
        assert_eq!(out[0], Action::Ready);
        assert!(matches!(&out[1], Action::Send(m) if m.contains("clientContent") && m.contains("Hello?")));
        let a: Value = serde_json::from_str(&s.audio(&[0xFF; 160]).unwrap()).unwrap();
        assert_eq!(a["realtimeInput"]["audio"]["mimeType"], "audio/pcm;rate=16000");
        // 160 samples at 8 kHz -> about 320 at 16 kHz (filter delay aside).
        let n = base64_decode(a["realtimeInput"]["audio"]["data"].as_str().unwrap()).unwrap().len() / 2;
        assert!((280..=320).contains(&n), "{n}");
        out.clear();
        let pcm = base64(&audio::pcm16_to_le(&[1000i16; 480]));
        let msg = format!(r#"{{"serverContent":{{"modelTurn":{{"parts":[{{"inlineData":{{"mimeType":"audio/pcm;rate=24000","data":"{pcm}"}}}}]}}}}}}"#);
        s.on_message(msg.as_bytes(), &mut out);
        assert!(matches!(&out[0], Action::Play(p, None) if (120..=160).contains(&p.len())), "{out:?}");
        out.clear();
        s.on_message(br#"{"serverContent":{"interrupted":true}}"#, &mut out);
        s.on_message(br#"{"toolCall":{"functionCalls":[{"id":"f1","name":"end_call","args":{}}]}}"#, &mut out);
        assert_eq!(out[0], Action::Interrupt);
        assert!(matches!(&out[1], Action::Send(m) if m.contains("toolResponse") && m.contains("\"f1\"")));
        assert_eq!(out[2], Action::Hangup);
    }

    #[test]
    fn gemini_bad_audio_rate() {
        // rate=0 (a resampler that would loop forever) and an odd prime rate
        // (billions of taps) are refused.
        let mut s = Session::new(Kind::Gemini, Codec::Pcmu);
        let pcm = base64(&audio::pcm16_to_le(&[1000i16; 480]));
        for rate in ["0", "4294967291"] {
            let mut out = Vec::new();
            let msg = format!(r#"{{"serverContent":{{"modelTurn":{{"parts":[{{"inlineData":{{"mimeType":"audio/pcm;rate={rate}","data":"{pcm}"}}}}]}}}}}}"#);
            s.on_message(msg.as_bytes(), &mut out);
            assert!(matches!(&out[..], [Action::Log(m)] if m.contains("cannot resample")), "{out:?}");
        }
    }

    fn parse(m: &str) -> Value {
        serde_json::from_str(m).unwrap()
    }

    fn feed(s: &mut Session, msg: &str) -> Vec<Action> {
        let mut out = Vec::new();
        s.on_message(msg.as_bytes(), &mut out);
        out
    }

    #[test]
    fn provider_names() {
        let cases: &[(&str, Option<Kind>)] = &[
            ("openai", Some(Kind::OpenAi)),
            (" OpenAI ", Some(Kind::OpenAi)),
            ("gemini", Some(Kind::Gemini)),
            ("Google", Some(Kind::Gemini)),
            ("", None),
            ("open-ai", None),
        ];
        for &(s, want) in cases {
            assert_eq!(Kind::parse(s), want, "{s:?}");
        }
        assert_eq!((Kind::OpenAi.name(), Kind::Gemini.name()), ("openai", "gemini"));
    }

    #[test]
    fn websocket_targets() {
        let c = |url: &str, model: &str, key: &str| Cfg { url: url.into(), model: model.into(), key: key.into(), voice: String::new() };
        // (kind, cfg, URL, headers)
        type Case = (Kind, Cfg, &'static str, Vec<(&'static str, String)>);
        let cases: Vec<Case> = vec![
            (
                Kind::OpenAi,
                c("wss://h/v1/realtime", "gpt-realtime", "sk"),
                "wss://h/v1/realtime?model=gpt-realtime",
                vec![("Authorization", "Bearer sk".into())],
            ),
            (Kind::OpenAi, c("wss://h/r?a=1", "m 1/x", "sk"), "wss://h/r?a=1&model=m%201%2Fx", vec![("Authorization", "Bearer sk".into())]),
            (Kind::Gemini, c("wss://h/g", "m", "AIza-_.~"), "wss://h/g?key=AIza-_.~", vec![]),
            (Kind::Gemini, c("wss://h/g?alt=x", "m", "k+=&é"), "wss://h/g?alt=x&key=k%2B%3D%26%C3%A9", vec![]),
        ];
        for (kind, cfg, url, headers) in cases {
            assert_eq!(target(kind, &cfg), (url.to_string(), headers), "{kind:?} {cfg:?}");
        }
    }

    #[test]
    fn openai_session_update_is_exact() {
        let mut s = Session::new(Kind::OpenAi, Codec::Pcmu);
        let m = s.setup(&cfg(), &Setup { prompt: "P", voice: "alloy", first_message: "", end_call_tool: false });
        assert_eq!(m.len(), 1, "no greeting: wait for the caller");
        assert_eq!(
            parse(&m[0]),
            json!({"type": "session.update", "session": {
                "type": "realtime", "model": "m1", "instructions": "P", "output_modalities": ["audio"],
                "audio": {
                    "input": {"format": {"type": "audio/pcmu"}, "turn_detection": {"type": "server_vad"}},
                    "output": {"format": {"type": "audio/pcmu"}, "voice": "alloy"},
                },
            }})
        );
        let m = s.setup(&cfg(), &Setup { prompt: "P", voice: "", first_message: "Hi \"there\"", end_call_tool: true });
        let u = parse(&m[0]);
        assert_eq!(
            u["session"]["tools"],
            json!([{"type": "function", "name": "end_call", "description": END_CALL_HELP, "parameters": {"type": "object", "properties": {}}}])
        );
        assert_eq!(u["session"]["tool_choice"], "auto");
        assert_eq!(
            parse(&m[1]),
            json!({"type": "conversation.item.create", "item": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Hi \"there\""}]}})
        );
        assert_eq!(parse(&m[2]), json!({"type": "response.create"}));
    }

    #[test]
    fn gemini_setup_is_exact() {
        let mut s = Session::new(Kind::Gemini, Codec::Pcma);
        let mut c = cfg();
        c.model = "models/gemini-x".into();
        let m = s.setup(&c, &Setup { prompt: "P", voice: "", first_message: "", end_call_tool: true });
        assert_eq!(
            parse(&m[0]),
            json!({"setup": {
                "model": "models/gemini-x",
                "generationConfig": {"responseModalities": ["AUDIO"], "speechConfig": {"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "v0"}}}},
                "systemInstruction": {"parts": [{"text": "P"}]},
                "tools": [{"functionDeclarations": [{"name": "end_call", "description": END_CALL_HELP}]}],
            }})
        );
        assert_eq!(feed(&mut s, r#"{"setupComplete":{}}"#), [Action::Ready], "no greeting configured");
    }

    #[test]
    fn gemini_greets_once_after_setup_complete() {
        let mut s = Session::new(Kind::Gemini, Codec::Pcmu);
        s.setup(&cfg(), &Setup { prompt: "P", voice: "", first_message: "Hello", end_call_tool: false });
        let out = feed(&mut s, r#"{"setupComplete":{}}"#);
        let Some(Action::Send(m)) = out.get(1) else { panic!("{out:?}") };
        assert_eq!(parse(m), json!({"clientContent": {"turns": [{"role": "user", "parts": [{"text": "Hello"}]}], "turnComplete": true}}));
        assert_eq!(feed(&mut s, r#"{"setupComplete":{}}"#), [Action::Ready], "the greeting is sent once");
    }

    #[test]
    fn caller_audio_messages() {
        let mut s = Session::new(Kind::OpenAi, Codec::Pcmu);
        assert_eq!(s.audio(&[]), None, "an empty payload sends nothing");
        assert_eq!(parse(&s.audio(&[0xFF, 0x00, 0x7F]).unwrap()), json!({"type": "input_audio_buffer.append", "audio": "/wB/"}));
        let mut a = Session::new(Kind::OpenAi, Codec::Pcma);
        let up = parse(&a.audio(&[0xD5, 0x55, 0xAA, 0x2A]).unwrap());
        let want: Vec<u8> = [0xD5u8, 0x55, 0xAA, 0x2A].iter().map(|&b| audio::ulaw_encode(audio::alaw_decode(b))).collect();
        assert_eq!(base64_decode(up["audio"].as_str().unwrap()).unwrap(), want);
        let mut g = Session::new(Kind::Gemini, Codec::Pcmu);
        assert_eq!(g.audio(&[0xFF; 160]), None, "Gemini waits for setupComplete");
        feed(&mut g, r#"{"setupComplete":{}}"#);
        assert_eq!(g.audio(&[]), None);
        let m = parse(&g.audio(&[0xFF; 160]).unwrap());
        assert_eq!(m["realtimeInput"]["audio"]["mimeType"], "audio/pcm;rate=16000");
        let pcm = audio::pcm16_from_le(&base64_decode(m["realtimeInput"]["audio"]["data"].as_str().unwrap()).unwrap());
        assert!(pcm.iter().all(|&v| v == 0), "µ-law silence stays silent");
    }

    #[test]
    fn truncate_messages() {
        let s = Session::new(Kind::OpenAi, Codec::Pcmu);
        assert_eq!(
            parse(&s.truncate("item_1", 0).unwrap()),
            json!({"type": "conversation.item.truncate", "item_id": "item_1", "content_index": 0, "audio_end_ms": 0})
        );
        assert_eq!(Session::new(Kind::Gemini, Codec::Pcmu).truncate("x", 5), None);
    }

    #[test]
    fn openai_events() {
        let mut s = Session::new(Kind::OpenAi, Codec::Pcmu);
        // (event, actions)
        let cases: Vec<(&str, Vec<Action>)> = vec![
            (r#"{"type":"response.audio.delta","delta":"/38="}"#, vec![Action::Play(vec![0, 0], None)]),
            (r#"{"type":"response.output_audio.delta","item_id":"i","delta":"AIA="}"#, vec![Action::Play(vec![-32124, 32124], Some("i".into()))]),
            (r#"{"type":"response.output_audio.delta","delta":"!!"}"#, vec![]),
            (r#"{"type":"response.output_audio.delta"}"#, vec![]),
            (r#"{"type":"input_audio_buffer.speech_started"}"#, vec![Action::Interrupt]),
            (r#"{"type":"response.output_item.done","item":{"type":"message","name":"end_call","call_id":"m"}}"#, vec![]),
            (r#"{"type":"response.function_call_arguments.done","call_id":"x"}"#, vec![]),
            (
                r#"{"type":"error","error":{"type":"invalid_request_error","code":"bad_thing","message":"nope"}}"#,
                vec![Action::Log("openai error: bad_thing nope".into())],
            ),
            (r#"{"type":"error","error":{"type":"server_error","message":"oops"}}"#, vec![Action::Log("openai error: server_error oops".into())]),
            (r#"{"type":"error","error":{"code":"item_truncate_invalid_item_id","message":"gone"}}"#, vec![]),
            (r#"{"type":"session.created"}"#, vec![]),
            (r#"{"no_type":1}"#, vec![]),
            (r#"[1,2]"#, vec![]),
            ("not json", vec![Action::Log("not JSON: not json".into())]),
        ];
        for (msg, want) in cases {
            assert_eq!(feed(&mut s, msg), want, "{msg}");
        }
        let long = "x".repeat(500);
        assert!(matches!(&feed(&mut s, &long)[..], [Action::Log(l)] if l.len() == "not JSON: ".len() + 120), "logs are cut at 120 bytes");
    }

    #[test]
    fn function_calls_answer_and_hang_up_once() {
        let mut s = Session::new(Kind::OpenAi, Codec::Pcmu);
        let out = feed(&mut s, r#"{"type":"response.function_call_arguments.done","name":"lookup","call_id":"c9"}"#);
        let [Action::Send(m), Action::Log(l)] = &out[..] else { panic!("{out:?}") };
        assert_eq!(
            parse(m),
            json!({"type": "conversation.item.create", "item": {"type": "function_call_output", "call_id": "c9", "output": "{\"result\":\"unknown function\"}"}})
        );
        assert_eq!(l, "model called unknown function \"lookup\"");
        assert!(
            feed(&mut s, r#"{"type":"response.function_call_arguments.done","name":"lookup","call_id":"c9"}"#).is_empty(),
            "the same call id is answered once"
        );
        let mut g = Session::new(Kind::Gemini, Codec::Pcmu);
        let out = feed(&mut g, r#"{"toolCall":{"functionCalls":[{"id":"a","name":"end_call"},{"id":"b","name":"other"},{"id":"a","name":"end_call"}]}}"#);
        assert_eq!(out.len(), 4, "{out:?}");
        let Action::Send(m) = &out[0] else { panic!("{out:?}") };
        assert_eq!(
            parse(m),
            json!({"toolResponse": {"functionResponses": [{"id": "a", "name": "end_call", "response": {"result": "the call will end after your last words"}}]}})
        );
        assert_eq!(out[1], Action::Hangup);
        assert!(matches!(&out[2], Action::Send(m) if parse(m)["toolResponse"]["functionResponses"][0]["response"]["result"] == "unknown function"));
        assert!(matches!(&out[3], Action::Log(_)));
    }

    #[test]
    fn gemini_events() {
        let mut s = Session::new(Kind::Gemini, Codec::Pcmu);
        let part =
            |mime: &str, data: &str| format!(r#"{{"serverContent":{{"modelTurn":{{"parts":[{{"inlineData":{{"mimeType":"{mime}","data":"{data}"}}}}]}}}}}}"#);
        let silence = base64(&audio::pcm16_to_le(&[0i16; 240]));
        assert!(feed(&mut s, &part("audio/mpeg", &silence)).is_empty(), "only PCM is played");
        assert!(feed(&mut s, &part("audio/pcm;rate=24000", "!!")).is_empty(), "bad base64 is skipped");
        assert!(feed(&mut s, r#"{"serverContent":{"modelTurn":{"parts":[{"text":"hi"}]}}}"#).is_empty(), "text parts are ignored");
        // No rate: 24 kHz. 16 kHz audio gets its own resampler.
        for mime in ["audio/pcm", "audio/pcm; rate=16000", "audio/pcm;rate=24000"] {
            let out = feed(&mut s, &part(mime, &silence));
            assert!(matches!(&out[..], [Action::Play(p, None)] if p.iter().all(|&v| v == 0)), "{mime}: {out:?}");
        }
        assert_eq!(feed(&mut s, r#"{"serverContent":{"interrupted":false,"turnComplete":true}}"#), []);
        assert_eq!(feed(&mut s, r#"{"goAway":{"timeLeft":"10s"}}"#), [Action::Log(r#"gemini goAway: {"timeLeft":"10s"}"#.into())]);
        assert_eq!(feed(&mut s, r#"{"error":{"code":400}}"#), [Action::Log(r#"gemini error: {"code":400}"#.into())]);
        assert_eq!(feed(&mut s, "{}"), []);
    }

    #[test]
    fn base64_decoder_cases() {
        let cases: &[(&str, Option<&[u8]>)] = &[
            ("", Some(b"")),
            ("TQ==", Some(b"M")),
            ("TWE", Some(b"Ma")),
            ("TWFu", Some(b"Man")),
            ("TW Fu\r\n", Some(b"Man")),
            ("-_-_", Some(&[0xfb, 0xff, 0xbf])),
            ("+/+/", Some(&[0xfb, 0xff, 0xbf])),
            ("TW.u", None),
            ("TWFu!", None),
            ("TQ= =", Some(b"M")),
            ("TQ=x", None),
            ("T=Q=", None),
            ("TQ===", None),
        ];
        for &(input, want) in cases {
            assert_eq!(base64_decode(input).as_deref(), want, "base64_decode({input:?})");
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(base64_decode(&base64(&all)).unwrap(), all);
    }
}
