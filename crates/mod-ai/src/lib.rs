//! `ai` — answer SIP calls with a realtime voice AI: OpenAI Realtime or
//! Gemini Live, with the system prompt taken from the call (a header).
//!
//! ```text
//! loadmodule "tm"
//! loadmodule "ai"
//! modparam("ai", "media_ip", "203.0.113.10")      # address for RTP in SDP
//! # keys: OPENAI_API_KEY / GEMINI_API_KEY from the environment, or:
//! # modparam("ai", "openai_key_file", "/run/secrets/openai")
//!
//! request_route {
//!     if (ai_dialog()) exit;                     # ACK/BYE/CANCEL… of AI calls
//!     if (is_method("INVITE") && $rU == "ai") {
//!         ai_answer("openai", "$hdr(X-AI-Prompt)");
//!         exit;
//!     }
//!     …
//! }
//! ```
//!
//! ferrosip is the far end of the call: it answers the INVITE (G.711
//! PCMU/PCMA, 20 ms), runs the RTP itself, and bridges the audio to the
//! provider's WebSocket. The model can end the call (an `end_call`
//! function); either side's hang-up ends both. See README.md.

mod audio;
mod call;
mod provider;
mod rtp;
mod sdp;
mod wsc;

use call::{Call, Ev, Phase, St};
use mod_txn::Tm;
use provider::Kind;
use sip_core::module::{DynStr, ReplyExtra};
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Module, Outbound, Registry};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

pub struct Config {
    pub openai: provider::Cfg,
    pub gemini: provider::Cfg,
    pub media_ip: Option<IpAddr>,
    pub port_min: u16,
    pub port_max: u16,
    pub max_calls: usize,
    pub max_duration: Duration,
    pub rtp_timeout: Duration,
    pub connect_timeout: Duration,
    pub first_message: String,
    pub default_prompt: String,
    pub prompt_max: usize,
    pub end_call_tool: bool,
    pub rtp_latch: bool,
    pub tls: Arc<rustls::ClientConfig>,
}

pub struct Inner {
    pub cfg: Config,
    pub tm: Arc<Tm>,
    pub net: OnceLock<Arc<dyn Outbound>>,
    calls: Mutex<HashMap<String, Arc<Call>>>,
    /// Calls not yet over (Done ones linger in `calls` for a while).
    pub active: AtomicUsize,
    pub total: AtomicU64,
    pub failed: AtomicU64,
    /// Round-robin RTP port slot (wraps).
    next_slot: AtomicUsize,
    any: AtomicBool,
    recent: Recent,
}

impl Inner {
    pub fn remember(&self, summary: serde_json::Value) {
        self.recent.push(summary);
    }
}

/// Summaries of the last finished calls (`ai.recent`, the web UI).
struct Recent {
    cap: usize,
    calls: Mutex<VecDeque<serde_json::Value>>,
}

impl Recent {
    fn new(cap: usize) -> Self {
        Recent { cap, calls: Mutex::new(VecDeque::with_capacity(cap)) }
    }

    fn push(&self, v: serde_json::Value) {
        let mut r = lock(&self.calls);
        if r.len() >= self.cap {
            r.pop_front();
        }
        r.push_back(v);
    }

    /// Newest first.
    fn list(&self) -> Vec<serde_json::Value> {
        lock(&self.calls).iter().rev().cloned().collect()
    }
}

#[derive(Default)]
struct Params(HashMap<String, String>);

#[derive(Default)]
pub struct Ai {
    params: Mutex<Params>,
    inner: OnceLock<Arc<Inner>>,
}

const PARAMS: &[&str] = &[
    "openai_url",
    "openai_model",
    "openai_voice",
    "openai_key",
    "openai_key_file",
    "gemini_url",
    "gemini_model",
    "gemini_voice",
    "gemini_key",
    "gemini_key_file",
    "media_ip",
    "rtp_port_min",
    "rtp_port_max",
    "max_calls",
    "max_duration",
    "rtp_timeout",
    "connect_timeout",
    "first_message",
    "default_prompt",
    "prompt_max",
    "end_call_tool",
    "rtp_latch",
    "tls_ca_file",
];

impl Module for Ai {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const ANSWER: &[Param] = &[arg("provider", Enum(&["openai", "gemini"])), arg("prompt", Str), opt("voice", Str)];
        Some(vec![
            sig("ai_answer", "answer", ANSWER, Ret::Action, "Answer the INVITE with a voice AI agent (prompt: instructions; \"b64:…\" for base64)")
                .allowed(ctx::REQUEST),
            sig("ai_dialog", "dialog", &[], Ret::Bool, "Handle a request within a call the AI answered (true: handled, it's replied)").allowed(ctx::REQUEST),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("openai_key", Ty::Str, "$OPENAI_API_KEY", "OpenAI API key (prefer openai_key_file)"),
            p("openai_key_file", Ty::Str, "", "File with the OpenAI API key"),
            p("openai_model", Ty::Str, "gpt-realtime", "Realtime model"),
            p("openai_voice", Ty::Str, "marin", "Default voice"),
            p("openai_url", Ty::Str, "wss://api.openai.com/v1/realtime", "Endpoint"),
            p("gemini_key", Ty::Str, "$GEMINI_API_KEY", "Gemini API key (prefer gemini_key_file)"),
            p("gemini_key_file", Ty::Str, "", "File with the Gemini API key"),
            p("gemini_model", Ty::Str, "gemini-2.5-flash-native-audio-preview-09-2025", "Live model"),
            p("gemini_voice", Ty::Str, "Puck", "Default voice"),
            p("gemini_url", Ty::Str, "wss://generativelanguage.googleapis.com/…/BidiGenerateContent", "Endpoint"),
            p("media_ip", Ty::Str, "", "IP in the SDP answer (default: the SIP address)"),
            p("rtp_port_min", Ty::Int { min: 1024, max: 65534 }, "30000", "Lowest RTP port"),
            p("rtp_port_max", Ty::Int { min: 1024, max: 65535 }, "30999", "Highest RTP port"),
            p("max_calls", UINT, "100", "Concurrent AI calls (beyond: 486)"),
            p("max_duration", Ty::Duration(Unit::Sec), "30m", "Longest call"),
            p("rtp_timeout", Ty::Duration(Unit::Sec), "30s", "Hang up after this long without RTP from the caller"),
            p("connect_timeout", Ty::Duration(Unit::Ms), "5s", "Time to open the provider session"),
            p("first_message", Ty::Str, "(The phone call has just been connected. Greet the caller.)", "First user turn (empty: the AI waits)"),
            p("default_prompt", Ty::Str, "", "Prompt when the call gives none"),
            p("prompt_max", UINT, "16384", "Longest prompt (bytes)"),
            p("end_call_tool", Ty::Bool, "true", "Offer the model an end_call function"),
            p("rtp_latch", Ty::Bool, "true", "Send RTP where the caller's comes from"),
            p("tls_ca_file", Ty::Str, "", "PEM CAs for wss:// (default: Mozilla roots)"),
        ])
    }

    fn name(&self) -> &'static str {
        "ai"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        if !PARAMS.contains(&name) {
            return Err(format!("ai: unknown parameter {name:?}"));
        }
        let s = match v {
            Arg::Int(_) => v.int()?.to_string(),
            _ => v.str()?.to_string(),
        };
        lock(&self.params).0.insert(name.to_string(), s);
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let tm = reg.api::<Tm>().ok_or("ai needs tm: put loadmodule \"tm\" before \"ai\"")?;
        let cfg = config(&lock(&self.params).0)?;
        let inner = Arc::new(Inner {
            next_slot: AtomicUsize::new(0),
            cfg,
            tm,
            net: OnceLock::new(),
            calls: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            any: AtomicBool::new(false),
            recent: Recent::new(100),
        });
        let _ = self.inner.set(inner.clone());

        let i = inner.clone();
        reg.export(
            "ai",
            "ai_answer",
            |a: &[Arg]| {
                let (provider, prompt, voice) = match a {
                    [p, q] => (p, q, None),
                    [p, q, v] => (p, q, Some(v)),
                    _ => return Err("ai_answer(provider, prompt [, voice])".into()),
                };
                let voice = voice.map(Arg::dyn_str).transpose()?;
                Ok((provider.dyn_str()?, prompt.dyn_str()?, voice))
            },
            move |ctx: &mut Ctx<'_, '_>, (p, prompt, voice): &(DynStr, DynStr, Option<DynStr>)| {
                let p = p.eval(ctx).into_owned();
                let prompt = prompt.eval(ctx).into_owned();
                let voice = voice.as_ref().map(|v| v.eval(ctx).into_owned()).unwrap_or_default();
                answer(&i, ctx, &p, &prompt, &voice)
            },
        );
        let i = inner.clone();
        reg.export("ai", "ai_dialog", |a: &[Arg]| sip_core::want_args(a, 0), move |ctx: &mut Ctx<'_, '_>, _: &()| in_dialog(&i, ctx));
        let i = inner.clone();
        reg.rpc.add("ai.list", "Calls answered by the AI module", move |_| {
            let calls = lock(&i.calls);
            Ok(serde_json::json!(calls.values().filter(|c| c.lock().phase != Phase::Done).map(|c| c.json()).collect::<Vec<_>>()))
        });
        let i = inner.clone();
        reg.rpc.add("ai.recent", "The last 100 finished AI calls, newest first, with why each ended", move |_| Ok(serde_json::json!(i.recent.list())));
        let i = inner.clone();
        sip_core::stats::gauge("ai", "active_calls", move || i64::try_from(i.active.load(Ordering::Relaxed)).unwrap_or(i64::MAX));
        let i = inner.clone();
        sip_core::stats::gauge("ai", "calls", move || i64::try_from(i.total.load(Ordering::Relaxed)).unwrap_or(i64::MAX));
        // Every series from the start (at 0), so dashboards show zeros, not gaps.
        for kind in [Kind::OpenAi, Kind::Gemini] {
            call::connect_hist(kind);
            for o in call::OUTCOMES {
                call::call_hist(kind, o);
            }
        }
        let i = inner;
        sip_core::stats::gauge("ai", "failed_calls", move || i64::try_from(i.failed.load(Ordering::Relaxed)).unwrap_or(i64::MAX));
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let Some(inner) = self.inner.get().cloned() else { return Ok(()) };
        let _ = inner.net.set(net);
        // Forget finished calls once their retransmissions are over.
        std::thread::Builder::new()
            .name("ai-reaper".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(5));
                    let mut calls = lock(&inner.calls);
                    calls.retain(|_, c| c.lock().ended.is_none_or(|t| t.elapsed() < Duration::from_secs(32)));
                    inner.any.store(!calls.is_empty(), Ordering::Relaxed);
                }
            })
            .map_err(|e| format!("cannot start the ai-reaper thread: {e}"))?;
        Ok(())
    }

    fn shutdown(&self) {
        let Some(inner) = self.inner.get() else { return };
        for c in lock(&inner.calls).values() {
            c.stopping.store(true, Ordering::Relaxed);
            c.send(Ev::Stop);
        }
        // Give the calls a moment to send their BYEs.
        let start = Instant::now();
        while inner.active.load(Ordering::Relaxed) > 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn config(p: &HashMap<String, String>) -> Result<Config, String> {
    let get = |k: &str| p.get(k).cloned();
    let num = |k: &str, d: u64| -> Result<u64, String> { get(k).map_or(Ok(d), |v| v.trim().parse().map_err(|_| format!("ai: {k} must be a number"))) };
    let key = |name: &str, env: &str| -> Result<String, String> {
        if let Some(path) = get(&format!("{name}_key_file")) {
            return std::fs::read_to_string(&path).map(|s| s.trim().to_string()).map_err(|e| format!("ai: {name}_key_file {path}: {e}"));
        }
        Ok(get(&format!("{name}_key")).or_else(|| std::env::var(env).ok()).unwrap_or_default().trim().to_string())
    };
    let openai = provider::Cfg {
        url: get("openai_url").unwrap_or_else(|| "wss://api.openai.com/v1/realtime".into()),
        model: get("openai_model").unwrap_or_else(|| "gpt-realtime".into()),
        voice: get("openai_voice").unwrap_or_else(|| "marin".into()),
        key: key("openai", "OPENAI_API_KEY")?,
    };
    let gemini = provider::Cfg {
        url: get("gemini_url")
            .unwrap_or_else(|| "wss://generativelanguage.googleapis.com/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent".into()),
        model: get("gemini_model").unwrap_or_else(|| "gemini-2.5-flash-native-audio-preview-09-2025".into()),
        voice: get("gemini_voice").unwrap_or_else(|| "Puck".into()),
        key: key("gemini", "GEMINI_API_KEY")?,
    };
    for c in [&openai, &gemini] {
        wsc::parse_url(&c.url).map_err(|e| format!("ai: {e}"))?;
    }
    let media_ip = get("media_ip").map(|s| s.trim().parse::<IpAddr>().map_err(|_| format!("ai: media_ip {s:?} is not an IP address"))).transpose()?;
    let (port_min, port_max) = (num("rtp_port_min", 30000)?, num("rtp_port_max", 30999)?);
    let (port_min, port_max) = match (u16::try_from(port_min), u16::try_from(port_max)) {
        (Ok(lo @ 1024..=65534), Ok(hi)) if hi >= lo => (lo, hi),
        _ => return Err("ai: rtp_port_min..rtp_port_max must be a range within 1024..65535".into()),
    };
    let first_message = get("first_message").unwrap_or_else(|| "(The phone call has just been connected. Greet the caller.)".into());
    Ok(Config {
        openai,
        gemini,
        media_ip,
        port_min,
        port_max,
        max_calls: usize::try_from(num("max_calls", 100)?).unwrap_or(usize::MAX),
        max_duration: Duration::from_secs(num("max_duration", 1800)?.max(1)),
        rtp_timeout: Duration::from_secs(num("rtp_timeout", 30)?.max(1)),
        connect_timeout: Duration::from_millis(num("connect_timeout", 5000)?.max(100)),
        first_message,
        default_prompt: get("default_prompt")
            .unwrap_or_else(|| "You are a helpful voice assistant answering a phone call. Keep your answers short and conversational.".into()),
        prompt_max: usize::try_from(num("prompt_max", 16384)?).unwrap_or(usize::MAX),
        end_call_tool: num("end_call_tool", 1)? != 0,
        rtp_latch: num("rtp_latch", 1)? != 0,
        tls: wsc::tls_config(get("tls_ca_file").as_deref()).map_err(|e| format!("ai: tls_ca_file {e}"))?,
    })
}

/// `<sip:x@y;lr>` / `"Name" <sip:…>;p` / `sip:x;p` → the URI.
pub fn uri_of(v: &str) -> String {
    let v = v.trim();
    match (v.find('<'), v.find('>')) {
        (Some(a), Some(b)) if b > a => v.get(a..b).and_then(|s| s.strip_prefix('<')).unwrap_or_default().to_string(),
        _ => v.split(';').next().unwrap_or("").trim().to_string(),
    }
}

/// Split a header value at commas outside quotes and `<…>`.
fn split_values(v: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth, mut quoted) = (Vec::new(), String::new(), 0i32, false);
    for c in v.chars() {
        match c {
            '"' => quoted = !quoted,
            '<' if !quoted => depth = depth.saturating_add(1),
            '>' if !quoted => depth = depth.saturating_sub(1),
            ',' if !quoted && depth == 0 => {
                out.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim().to_string()
}

fn has_tag(to: &str) -> bool {
    to_tag(to).is_some()
}

/// The `tag` parameter's value in a To/From header (after the URI's `>`,
/// or anywhere for an addr-spec without brackets).
fn to_tag(h: &str) -> Option<&str> {
    let params = h.rsplit_once('>').map_or(h, |(_, p)| p);
    params.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim().eq_ignore_ascii_case("tag").then(|| v.trim())
    })
}

fn warn(why: &str) -> Vec<u8> {
    format!("Warning: 399 ferrosip \"{why}\"\r\n").into_bytes()
}

fn bind_rtp(inner: &Inner, v6: bool) -> Option<UdpSocket> {
    // Even ports from lo (RTP convention): lo + 2·slot <= hi, round robin.
    let (lo, hi) = (inner.cfg.port_min, inner.cfg.port_max);
    let slots = NonZeroUsize::MIN.saturating_add(usize::from(hi.checked_sub(lo)? / 2));
    let ip: IpAddr = if v6 { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
    for _ in 0..slots.get() {
        let slot = inner.next_slot.fetch_add(1, Ordering::Relaxed) % slots;
        let Some(port) = u16::try_from(slot).ok().and_then(|k| k.checked_mul(2)).and_then(|o| lo.checked_add(o)) else { continue };
        if let Ok(s) = UdpSocket::bind(SocketAddr::new(ip, port)) {
            let _ = s.set_nonblocking(true);
            return Some(s);
        }
    }
    None
}

fn answer(inner: &Arc<Inner>, ctx: &mut Ctx<'_, '_>, provider: &str, prompt: &str, voice: &str) -> i32 {
    if ctx.msg.method() != Some(Method::Invite) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return -1;
    }
    let (Some(cid), Some(from), Some(to)) = (ctx.msg.get(HdrKind::CallId), ctx.msg.get(HdrKind::From), ctx.msg.get(HdrKind::To)) else { return -1 };
    let (callid, from_hdr, to_hdr) = (text(cid.body), text(from.body), text(to.body));
    if has_tag(&to_hdr) {
        return -1; // re-INVITE: ai_dialog()'s business
    }
    // A retransmission of an INVITE we're already handling.
    if let Some(c) = lock(&inner.calls).get(&callid).cloned() {
        resend(ctx, &c);
        return 1;
    }
    let Some(kind) = Kind::parse(provider) else {
        sip_core::elog!("ai: unknown provider {provider:?} (openai or gemini)");
        let _ = ctx.reply_with(500, "Server Internal Error", &warn("unknown AI provider"));
        return -1;
    };
    let pcfg = match kind {
        Kind::OpenAi => &inner.cfg.openai,
        Kind::Gemini => &inner.cfg.gemini,
    };
    if pcfg.key.is_empty() {
        sip_core::elog!("ai: no API key for {} (set {}_key, {}_key_file or the environment)", kind.name(), kind.name(), kind.name());
        let _ = ctx.reply_with(503, "Service Unavailable", &warn("AI provider not configured"));
        return -1;
    }
    if inner.active.load(Ordering::Relaxed) >= inner.cfg.max_calls {
        let _ = ctx.reply_with(486, "Busy Here", &warn("too many AI calls"));
        return -1;
    }
    let mut prompt = match prompt.trim().strip_prefix("b64:") {
        Some(b) => match provider::base64_decode(b) {
            Some(p) => String::from_utf8_lossy(&p).into_owned(),
            None => {
                let _ = ctx.reply_with(400, "Bad Request", &warn("prompt is not valid base64"));
                return -1;
            }
        },
        None => prompt.trim().to_string(),
    };
    if prompt.is_empty() {
        prompt = inner.cfg.default_prompt.clone();
    }
    if prompt.len() > inner.cfg.prompt_max {
        let _ = ctx.reply_with(400, "Bad Request", &warn("prompt too long"));
        return -1;
    }
    let body = String::from_utf8_lossy(&ctx.body()).into_owned();
    let offer = match sdp::parse_offer(&body) {
        Ok(o) => o,
        Err(e) => {
            let _ = ctx.reply_with(488, "Not Acceptable Here", &warn(&format!("SDP: {e}")));
            return -1;
        }
    };
    let Some(&codec) = offer.codecs.first() else {
        let _ = ctx.reply_with(488, "Not Acceptable Here", &warn("only PCMU and PCMA are supported"));
        return -1;
    };
    if offer.secure {
        let _ = ctx.reply_with(488, "Not Acceptable Here", &warn("SRTP is not supported"));
        return -1;
    }
    let contact = ctx.msg.get(HdrKind::Contact).map(|h| uri_of(&text(h.body))).unwrap_or_default();
    if contact.is_empty() {
        let _ = ctx.reply_with(400, "Bad Request", &warn("missing Contact"));
        return -1;
    }
    let buf = ctx.msg.buf;
    let rr: Vec<_> =
        ctx.msg.headers.iter().filter(|h| h.kind == HdrKind::RecordRoute).filter_map(|h| Some((text(h.body), buf.get(h.start..h.end)?.to_vec()))).collect();
    let routes: Vec<String> = rr.iter().flat_map(|(v, _)| split_values(v)).collect();
    let rr_lines = rr.iter().map(|(_, l)| String::from_utf8_lossy(l).into_owned()).collect::<String>();

    let adv = ctx.advertise(ctx.src.proto);
    let media_ip = inner.cfg.media_ip.unwrap_or_else(|| adv.ip());
    if media_ip.is_unspecified() {
        sip_core::elog!("ai: set modparam(\"ai\", \"media_ip\", …): the SIP address is a wildcard");
    }
    let Some(sock) = bind_rtp(inner, media_ip.is_ipv6()) else {
        let _ = ctx.reply_with(503, "Service Unavailable", &warn("no free RTP port"));
        return -1;
    };
    let local = SocketAddr::new(media_ip, sock.local_addr().map_or(0, |a| a.port()));
    let transport =
        if ctx.src.proto == sip_core::net::Proto::Udp { String::new() } else { format!(";transport={}", ctx.src.proto.via_name().to_ascii_lowercase()) };
    let host = match adv.ip() {
        IpAddr::V6(ip) => format!("[{ip}]:{}", adv.port()),
        ip => format!("{ip}:{}", adv.port()),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let tag = format!("{:016x}", sip_core::shm::fx_hash(callid.as_bytes()));
    let call = Arc::new(Call {
        tag,
        kind,
        from_hdr,
        to_hdr,
        contact,
        routes,
        rr_lines,
        src: ctx.src,
        invite: buf.to_vec(),
        codec,
        local,
        contact_uri: format!("sip:ai@{host}{transport}"),
        prompt,
        voice: voice.to_string(),
        session_id: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        started: Instant::now(),
        created: SystemTime::now(),
        st: Mutex::new(St {
            phase: Phase::Connecting,
            last_reply: None,
            remote: offer.addr,
            ended: None,
            cancelled: false,
            sdp_version: 1,
            reason: String::new(),
        }),
        tx: Mutex::new(tx),
        rtp_in: AtomicU64::new(0),
        rtp_out: AtomicU64::new(0),
        stopping: AtomicBool::new(false),
        callid: callid.clone(),
    });
    {
        let mut calls = lock(&inner.calls);
        calls.insert(callid.clone(), call.clone());
        inner.any.store(true, Ordering::Relaxed);
    }
    inner.active.fetch_add(1, Ordering::Relaxed);
    inner.total.fetch_add(1, Ordering::Relaxed);
    let _ = ctx.reply(100, "Trying");
    let (i, c) = (inner.clone(), call.clone());
    let spawned = std::thread::Builder::new().name("ai-call".into()).spawn(move || call::run(i, c, rx, sock));
    if spawned.is_err() {
        inner.active.fetch_sub(1, Ordering::Relaxed);
        lock(&inner.calls).remove(&callid);
        let _ = ctx.reply_with(503, "Service Unavailable", &warn("cannot start the call"));
        return -1;
    }
    sip_core::elog!("ai: call {callid} from {} answered by {} ({} {})", call.from_hdr, kind.name(), codec.name(), offer.addr);
    1
}

fn resend(ctx: &mut Ctx<'_, '_>, c: &Call) {
    let last = c.lock().last_reply.clone();
    match last {
        Some(r) => {
            let src = ctx.src;
            let _ = ctx.send(&src, &r);
        }
        None => {
            let _ = ctx.reply(100, "Trying");
        }
    }
}

/// Requests within (or about) a call we answered. -1: not ours.
fn in_dialog(inner: &Inner, ctx: &mut Ctx<'_, '_>) -> i32 {
    if !inner.any.load(Ordering::Relaxed) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
        return -1;
    }
    let Some(cid) = ctx.msg.get(HdrKind::CallId) else { return -1 };
    let Some(c) = lock(&inner.calls).get(&text(cid.body)).cloned() else { return -1 };
    let to = ctx.msg.get(HdrKind::To).map(|h| text(h.body)).unwrap_or_default();
    let method = ctx.msg.method();
    // The exact tag: a longer one that merely starts with ours is not ours.
    if to_tag(&to).is_some_and(|t| !t.eq_ignore_ascii_case(&c.tag)) {
        // Same Call-ID, another dialog (a fork elsewhere).
        if method != Some(Method::Ack) {
            let _ = ctx.reply(481, "Call/Transaction Does Not Exist");
        }
        return 1;
    }
    let phase = c.lock().phase;
    match method {
        Some(Method::Invite) if !has_tag(&to) => resend(ctx, &c),
        Some(Method::Ack) => c.send(Ev::Ack),
        Some(Method::Cancel) => {
            let _ = ctx.reply(200, "OK");
            let mut st = c.lock();
            if st.phase == Phase::Connecting {
                st.cancelled = true;
            }
        }
        _ if phase == Phase::Done => {
            let _ = ctx.reply(481, "Call/Transaction Does Not Exist");
        }
        Some(Method::Bye) => {
            let _ = ctx.reply(200, "OK");
            c.send(Ev::Bye);
        }
        Some(Method::Invite) => {
            // re-INVITE (hold, new address): same stream, new version.
            let body = String::from_utf8_lossy(&ctx.body()).into_owned();
            let version = {
                let mut st = c.lock();
                st.sdp_version = st.sdp_version.saturating_add(1);
                st.sdp_version
            };
            if let Ok(o) = sdp::parse_offer(&body) {
                c.send(Ev::Remote(o.addr));
            }
            ctx.ext_mut::<ReplyExtra>().body = Some(("application/sdp".into(), c.sdp(version).into_bytes()));
            let _ = ctx.reply_with(200, "OK", format!("Contact: <{}>\r\n", c.contact_uri).as_bytes());
        }
        _ => {
            let _ = ctx.reply(200, "OK"); // OPTIONS, INFO, UPDATE without SDP…
        }
    }
    1
}

#[cfg(test)]
mod tests {

    #[test]
    fn to_tag_is_the_exact_parameter_value() {
        assert_eq!(to_tag("<sip:a@b>;tag=abc"), Some("abc"));
        assert_eq!(to_tag("\"A;tag=x\" <sip:a@b;tag=uri>;TAG=abc;x=1"), Some("abc"), "the header's, not the URI's");
        assert_eq!(to_tag("sip:a@b;tag=abc"), Some("abc"), "addr-spec without brackets");
        assert_eq!(to_tag("<sip:a@b>"), None);
        // A longer tag that starts with ours is a different tag.
        assert!(!to_tag("<sip:a@b>;tag=abcdef").is_some_and(|t| t.eq_ignore_ascii_case("abc")));
        assert!(has_tag("<sip:a@b>;tag=1") && !has_tag("<sip:a@b>"));
    }

    use super::*;

    #[test]
    fn recent_ring() {
        let r = Recent::new(3);
        for n in 0..5 {
            r.push(serde_json::json!(n));
        }
        assert_eq!(r.list(), vec![serde_json::json!(4), serde_json::json!(3), serde_json::json!(2)]);
    }

    #[test]
    fn helpers() {
        assert_eq!(uri_of("\"A\" <sip:a@h;lr>;x=1"), "sip:a@h;lr");
        assert_eq!(uri_of("sip:a@h;expires=1"), "sip:a@h");
        assert_eq!(split_values("<sip:a;lr>, \"x,y\" <sip:b>,<sip:c>"), vec!["<sip:a;lr>", "\"x,y\" <sip:b>", "<sip:c>"]);
        assert!(has_tag("<sip:b@h>;TAG=1"));
        let mut p = HashMap::new();
        assert!(config(&p).is_ok());
        p.insert("media_ip".into(), "nope".into());
        assert!(config(&p).is_err());
        p.remove("media_ip");
        p.insert("gemini_url".into(), "https://x".into());
        assert!(config(&p).is_err());
        p.remove("gemini_url");
        p.insert("rtp_port_min".into(), "5000".into());
        p.insert("rtp_port_max".into(), "4000".into());
        assert!(config(&p).is_err());
    }

    #[test]
    fn uri_of_cases() {
        let cases: &[(&str, &str)] = &[
            ("<sip:p1;lr>", "sip:p1;lr"),
            ("  <sip:p1;lr>;x  ", "sip:p1;lr"),
            ("\"A, B\" <sips:b@h:5061;transport=tls>", "sips:b@h:5061;transport=tls"),
            ("sip:a@h", "sip:a@h"),
            ("sip:a@h ; p=1", "sip:a@h"),
            ("<>", ""),
            ("", ""),
            ("> <sip:x", "> <sip:x"),
        ];
        for &(v, want) in cases {
            assert_eq!(uri_of(v), want, "uri_of({v:?})");
        }
    }

    #[test]
    fn split_values_cases() {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("<sip:a>", &["<sip:a>"]),
            ("<sip:a>,<sip:b>", &["<sip:a>", "<sip:b>"]),
            (" <sip:a;x=\"1,2\"> , <sip:b> ,", &["<sip:a;x=\"1,2\">", "<sip:b>"]),
            ("<sip:a,b>", &["<sip:a,b>"]),
            ("\"a>b, c\" <sip:x>", &["\"a>b, c\" <sip:x>"]),
            (",,", &["", ""]),
        ];
        for &(v, want) in cases {
            assert_eq!(split_values(v), want, "split_values({v:?})");
        }
    }

    #[test]
    fn to_tags_and_warnings() {
        // `tag` is a header parameter (after `>`): one inside the URI is not.
        for (to, tagged) in
            [("<sip:b@h>", false), ("<sip:b@h>;tag=1", true), ("<sip:b@h>;Tag=x", true), ("<sip:b@h;tag=1>", false), ("<sip:b@h>;xtag=1", false)]
        {
            assert_eq!(has_tag(to), tagged, "{to}");
        }
        assert_eq!(warn("busy"), b"Warning: 399 ferrosip \"busy\"\r\n");
        assert_eq!(text(b"  a b \r\n"), "a b");
    }

    #[test]
    fn config_defaults_and_bounds() {
        let cfg = |pairs: &[(&str, &str)]| config(&pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect());
        let c = cfg(&[("openai_key", " sk "), ("gemini_key", "g")]).unwrap();
        assert_eq!(
            (c.openai.url.as_str(), c.openai.model.as_str(), c.openai.voice.as_str(), c.openai.key.as_str()),
            ("wss://api.openai.com/v1/realtime", "gpt-realtime", "marin", "sk")
        );
        assert_eq!((c.gemini.voice.as_str(), c.gemini.key.as_str()), ("Puck", "g"));
        assert_eq!((c.port_min, c.port_max, c.max_calls, c.prompt_max), (30000, 30999, 100, 16384));
        assert_eq!((c.max_duration, c.rtp_timeout, c.connect_timeout), (Duration::from_secs(1800), Duration::from_secs(30), Duration::from_millis(5000)));
        assert!(c.end_call_tool && c.rtp_latch && c.media_ip.is_none());
        let c =
            cfg(&[("max_duration", "0"), ("rtp_timeout", "0"), ("connect_timeout", "5"), ("end_call_tool", "0"), ("rtp_latch", "0"), ("media_ip", " ::1 ")])
                .unwrap();
        assert_eq!(
            (c.max_duration, c.rtp_timeout, c.connect_timeout),
            (Duration::from_secs(1), Duration::from_secs(1), Duration::from_millis(100)),
            "lower bounds"
        );
        assert!(!c.end_call_tool && !c.rtp_latch);
        assert_eq!(c.media_ip, Some("::1".parse().unwrap()));
        // (rtp_port_min, rtp_port_max, accepted)
        for (lo, hi, ok) in [
            ("1024", "1024", true),
            ("1024", "65535", true),
            ("1023", "2000", false),
            ("65535", "65535", false),
            ("2000", "1999", false),
            ("2000", "65536", false),
            ("x", "2000", false),
            ("-1", "2000", false),
        ] {
            assert_eq!(cfg(&[("rtp_port_min", lo), ("rtp_port_max", hi)]).is_ok(), ok, "{lo}..{hi}");
        }
        for (k, v) in [("max_calls", "many"), ("openai_url", "wss://"), ("openai_url", "wss://h:99999/"), ("openai_key_file", "/nonexistent/key")] {
            assert!(cfg(&[(k, v)]).is_err(), "{k}={v}");
        }
    }
}
