//! `rtpengine` — media relay control over rtpengine's "ng" protocol
//! (bencode dictionaries over UDP, each prefixed by a cookie).
//!
//! * `rtpengine_offer([flags])`, `rtpengine_answer([flags])`,
//!   `rtpengine_delete([flags])`, `rtpengine_manage([flags])` (picks
//!   offer / answer / delete from the message), `rtpengine_query([flags])`
//!   (`$rtpstat`), `rtpengine_query_v(fmt, $var)` (JSON), `start_recording`,
//!   `stop_recording`, `block_dtmf`/`unblock_dtmf`, `block_media`/
//!   `unblock_media`, `silence_media`/`unsilence_media`, `set_rtpengine_set(n)`.
//! * Flags are Kamailio's: words become `flags`, `replace-*` → `replace`,
//!   `RTP/AVP`… → `transport-protocol`, `direction=`, `ICE=`, `DTLS=`,
//!   `SDES-*`, `codec-*`/`transcode-*`, `via-branch=`, `received-from=`,
//!   other `key=value` → dictionary entries.
//! * The rewritten SDP replaces the body (Content-Length is fixed at render
//!   time), in requests and — from `onreply_route` — in replies.
//! * Nodes: `modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223=2 udp:…")`,
//!   sets with `"1 == udp:… udp:…"`; a call sticks to its node (Call-ID
//!   hash, remembered until delete). A node that doesn't answer within
//!   `rtpengine_tout_ms` × `rtpengine_retr` is disabled for
//!   `rtpengine_disable_tout` seconds and the next one is tried.
//! * RPC: `rtpengine.show`, `rtpengine.enable <url|all> <0|1>`, `rtpengine.ping`.

use sip_core::module::DynStr;
use sip_core::pv::{PvRef, PvSpec, Val};
use sip_core::serde_json::{Value, json};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Registry, ShardedMap, fx_hash};
use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub mod bencode;
use bencode::B;
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p, pr};

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &["rtpengine"];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    match name {
        "rtpengine" => Some(Arc::new(Rtpengine::default())),
        _ => None,
    }
}

struct Node {
    url: String,
    addr: SocketAddr,
    weight: u32,
    /// Unix seconds until which the node is disabled (0 = enabled; u64::MAX = by admin).
    disabled_until: AtomicU64,
}

impl Node {
    fn enabled(&self, now: u64) -> bool {
        self.disabled_until.load(Ordering::Relaxed) <= now
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    Offer,
    Answer,
    Delete,
    Query,
    StartRec,
    StopRec,
    BlockDtmf,
    UnblockDtmf,
    BlockMedia,
    UnblockMedia,
    SilenceMedia,
    UnsilenceMedia,
}

impl Op {
    fn command(self) -> &'static str {
        match self {
            Op::Offer => "offer",
            Op::Answer => "answer",
            Op::Delete => "delete",
            Op::Query => "query",
            Op::StartRec => "start recording",
            Op::StopRec => "stop recording",
            Op::BlockDtmf => "block DTMF",
            Op::UnblockDtmf => "unblock DTMF",
            Op::BlockMedia => "block media",
            Op::UnblockMedia => "unblock media",
            Op::SilenceMedia => "silence media",
            Op::UnsilenceMedia => "unsilence media",
        }
    }
}

/// Set chosen with `set_rtpengine_set()` for this message.
struct SelectedSet(u32);

/// Last `rtpengine_query` result.
struct QueryResult(B);

pub struct Rtpengine {
    socks: Mutex<Vec<String>>,
    sets: OnceLock<BTreeMap<u32, Vec<Arc<Node>>>>,
    default_set: AtomicU32,
    tout_ms: AtomicU64,
    retr: AtomicU32,
    disable_tout: AtomicU64,
    /// Call-ID → node URL (calls stick to a node until deleted).
    sticky: ShardedMap<String, (String, u64)>,
    seq: AtomicU64,
}

impl Default for Rtpengine {
    fn default() -> Self {
        Self {
            socks: Mutex::new(Vec::new()),
            sets: OnceLock::new(),
            default_set: AtomicU32::new(0),
            tout_ms: AtomicU64::new(1000),
            retr: AtomicU32::new(5),
            disable_tout: AtomicU64::new(60),
            sticky: ShardedMap::new(64),
            seq: AtomicU64::new(1),
        }
    }
}

/// `[set ==] url[=weight] url…`
/// The set id `s` if it names a configured set. Ids outside `u32` are
/// unknown sets, never wrapped onto a real one (`4294967296` is not set 0).
fn known_set(sets: Option<&BTreeMap<u32, Vec<Arc<Node>>>>, s: i64) -> Option<u32> {
    let id = u32::try_from(s).ok()?;
    sets.is_some_and(|x| x.contains_key(&id)).then_some(id)
}

fn parse_socks(specs: &[String]) -> Result<BTreeMap<u32, Vec<Arc<Node>>>, String> {
    let mut sets: BTreeMap<u32, Vec<Arc<Node>>> = BTreeMap::new();
    for spec in specs {
        let (set, list) = match spec.split_once("==") {
            Some((s, l)) => (s.trim().parse().map_err(|_| format!("rtpengine_sock: bad set id in {spec:?}"))?, l),
            None => (0, spec.as_str()),
        };
        for url in list.split_whitespace() {
            let (u, w) = match url.rsplit_once('=') {
                Some((u, w)) => (u, w.parse().map_err(|_| format!("rtpengine_sock: bad weight in {url:?}"))?),
                None => (url, 1),
            };
            let hp = u
                .strip_prefix("udp:")
                .or_else(|| u.strip_prefix("udp4:"))
                .or_else(|| u.strip_prefix("udp6:"))
                .ok_or_else(|| format!("rtpengine_sock: {u:?}: only udp: control sockets are supported"))?;
            let addr = hp.to_socket_addrs().map_err(|e| format!("rtpengine_sock {u}: {e}"))?.next().ok_or_else(|| format!("rtpengine_sock {u}: no address"))?;
            sets.entry(set).or_default().push(Arc::new(Node { url: u.to_string(), addr, weight: w.max(1), disabled_until: AtomicU64::new(0) }));
        }
    }
    Ok(sets)
}

/// Kamailio's rtpengine flag string → (flags list, replace list, dict entries…).
fn parse_flags(s: &str, dict: &mut Vec<(Vec<u8>, B)>) -> Option<String> {
    let mut flags = Vec::new();
    let mut lists: BTreeMap<&'static str, Vec<B>> = BTreeMap::new();
    let mut via_branch = None;
    for item in s.split_whitespace() {
        let (k, v) = match item.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (item, None),
        };
        let sub = |prefix: &str| -> Option<String> {
            if let Some(v) = v.filter(|_| k == prefix) {
                return Some(v.to_string());
            }
            k.strip_prefix(prefix).and_then(|r| r.strip_prefix('-')).map(String::from)
        };
        if let Some(x) = sub("replace") {
            lists.entry("replace").or_default().push(B::s(x));
        } else if let Some(x) = sub("SDES") {
            lists.entry("SDES").or_default().push(B::s(x));
        } else if let Some(x) = sub("rtcp-mux") {
            lists.entry("rtcp-mux").or_default().push(B::s(x));
        } else if let Some(x) = sub("T38").or_else(|| sub("T.38")) {
            lists.entry("T.38").or_default().push(B::s(x));
        } else if k == "received-from" {
            if let Some(ip) = v {
                dict.retain(|(key, _)| key != b"received-from");
                let fam = if ip.contains(':') { "IP6" } else { "IP4" };
                dict.push((b"received-from".to_vec(), B::List(vec![B::s(fam), B::s(ip)])));
            }
        } else if let Some(c) =
            ["transcode", "codec-transcode", "codec-strip", "codec-offer", "codec-mask", "codec-set", "codec-except", "codec-accept", "codec-consume"]
                .iter()
                .find(|c| k == **c || k.starts_with(&format!("{c}-")))
        {
            let sub_key = match *c {
                "transcode" | "codec-transcode" => "transcode",
                c => c.strip_prefix("codec-").unwrap_or(c),
            };
            let val = v.map(String::from).or_else(|| k.strip_prefix(c).and_then(|r| r.strip_prefix('-')).map(String::from)).unwrap_or_default();
            let codec = dict.iter_mut().find(|(key, _)| key == b"codec");
            let entry = (sub_key.as_bytes().to_vec(), B::List(vec![B::s(&val)]));
            match codec {
                Some((_, B::Dict(d))) => match d.iter_mut().find(|(key, _)| key == sub_key.as_bytes()) {
                    Some((_, B::List(l))) => l.push(B::s(&val)),
                    _ => d.push(entry),
                },
                _ => dict.push((b"codec".to_vec(), B::Dict(vec![entry]))),
            }
        } else if matches!(k, "RTP/AVP" | "RTP/SAVP" | "RTP/AVPF" | "RTP/SAVPF" | "UDP/TLS/RTP/SAVP" | "UDP/TLS/RTP/SAVPF") && v.is_none() {
            dict.push((b"transport-protocol".to_vec(), B::s(k)));
        } else if k == "direction" {
            lists.entry("direction").or_default().push(B::s(v.unwrap_or_default()));
        } else if k == "via-branch" {
            via_branch = v.map(String::from);
        } else if let Some(v) = v {
            dict.push((k.as_bytes().to_vec(), B::s(v)));
        } else {
            flags.push(B::s(k));
        }
    }
    if !flags.is_empty() {
        dict.push((b"flags".to_vec(), B::List(flags)));
    }
    for (k, v) in lists {
        dict.push((k.as_bytes().to_vec(), B::List(v)));
    }
    via_branch
}

/// From the message: (Call-ID, From tag, To tag, top Via branch).
fn ids(ctx: &mut Ctx<'_, '_>) -> Option<(String, String, Option<String>, Option<String>)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let callid = s(ctx.msg.get(HdrKind::CallId)?.body);
    let ftag = param(name_addr(ctx.msg.get(HdrKind::From)?.body).1, b"tag").map(s)?;
    let ttag = ctx.msg.get(HdrKind::To).and_then(|h| param(name_addr(h.body).1, b"tag")).map(s);
    let branch = ctx.msg.via1.and_then(|v| v.branch).map(s);
    Some((callid, ftag, ttag, branch))
}

impl Rtpengine {
    fn set_nodes(&self, set: u32) -> Vec<Arc<Node>> {
        self.sets.get().and_then(|s| s.get(&set)).cloned().unwrap_or_default()
    }

    fn all_nodes(&self) -> Vec<Arc<Node>> {
        self.sets.get().map(|s| s.values().flatten().cloned().collect()).unwrap_or_default()
    }

    /// Nodes to try for a call, sticky one first, then by weighted hash.
    fn candidates(&self, set: u32, callid: &str) -> Vec<Arc<Node>> {
        let t = unix_secs();
        let nodes: Vec<Arc<Node>> = self.set_nodes(set).into_iter().filter(|n| n.enabled(t)).collect();
        if nodes.is_empty() {
            return nodes;
        }
        let mut order: Vec<Arc<Node>> = Vec::with_capacity(nodes.len());
        if let Some((url, _)) = self.sticky.get_cloned(callid)
            && let Some(n) = nodes.iter().find(|n| n.url == url)
        {
            order.push(n.clone());
        }
        let total: u64 = nodes.iter().map(|n| u64::from(n.weight)).sum();
        let mut h = fx_hash(callid.as_bytes()).checked_rem(total).unwrap_or(0);
        // The node whose weight band holds h; the rest follow round-robin.
        let start = nodes
            .iter()
            .position(|n| match h.checked_sub(u64::from(n.weight)) {
                Some(left) => {
                    h = left;
                    false
                }
                None => true,
            })
            .unwrap_or(0);
        for n in nodes.iter().cycle().skip(start).take(nodes.len()) {
            if !order.iter().any(|o| Arc::ptr_eq(o, n)) {
                order.push(n.clone());
            }
        }
        order
    }

    /// One ng exchange with retries; None = no (valid) answer.
    fn exchange(&self, node: &Node, req: &B) -> Option<B> {
        thread_local! {
            static SOCK: Option<UdpSocket> = UdpSocket::bind("0.0.0.0:0").ok();
        }
        let cookie = format!("{:x}_{:x}", std::process::id(), self.seq.fetch_add(1, Ordering::Relaxed));
        let mut pkt = format!("{cookie} ").into_bytes();
        req.encode(&mut pkt);
        let tout = Duration::from_millis(self.tout_ms.load(Ordering::Relaxed).max(1));
        let tries = self.retr.load(Ordering::Relaxed).max(1);
        SOCK.with(|s| {
            let s = s.as_ref()?;
            let mut buf = vec![0u8; 65535];
            for _ in 0..tries {
                s.send_to(&pkt, node.addr).ok()?;
                let deadline = Instant::now().checked_add(tout)?;
                while let Some(left) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
                    let _ = s.set_read_timeout(Some(left));
                    let Ok((n, from)) = s.recv_from(&mut buf) else { break };
                    // Stale replies (other cookies) are skipped.
                    let reply = buf.get(..n).and_then(|d| d.strip_prefix(cookie.as_bytes())).and_then(|d| d.strip_prefix(b" "));
                    let Some(reply) = reply.filter(|_| from == node.addr) else { continue };
                    return B::decode(reply).map(|(b, _)| b);
                }
            }
            None
        })
    }

    /// Send `op` for this message; on success apply the SDP. Returns the response.
    fn call(&self, ctx: &mut Ctx<'_, '_>, op: Op, flags: &str) -> Option<B> {
        let (callid, ftag, ttag, branch) = ids(ctx)?;
        let mut dict: Vec<(Vec<u8>, B)> = vec![(b"command".to_vec(), B::s(op.command())), (b"call-id".to_vec(), B::s(&callid))];
        dict.push((b"from-tag".to_vec(), B::s(&ftag)));
        if let Some(t) = &ttag {
            dict.push((b"to-tag".to_vec(), B::s(t)));
        }
        let wants_sdp = matches!(op, Op::Offer | Op::Answer);
        if wants_sdp {
            let body = ctx.body();
            if body.is_empty() {
                return None;
            }
            dict.push((b"sdp".to_vec(), B::Str(body)));
            let ip = ctx.src.addr.ip();
            let fam = if ip.is_ipv4() { "IP4" } else { "IP6" };
            dict.push((b"received-from".to_vec(), B::List(vec![B::s(fam), B::s(ip.to_string())])));
        }
        match parse_flags(flags, &mut dict).as_deref() {
            Some("1") | Some("auto") => {
                if let Some(b) = &branch {
                    dict.push((b"via-branch".to_vec(), B::s(b)));
                }
            }
            Some(other) if !other.is_empty() && other != "2" => dict.push((b"via-branch".to_vec(), B::s(other))),
            _ => {}
        }
        let req = B::Dict(dict);
        let set = ctx.ext::<SelectedSet>().map_or(self.default_set.load(Ordering::Relaxed), |s| s.0);
        for node in self.candidates(set, &callid) {
            match self.exchange(&node, &req) {
                Some(resp) => {
                    if resp.get("result").and_then(B::str) != Some(b"ok") {
                        let why = resp.get("error-reason").and_then(B::str).map(|e| String::from_utf8_lossy(e).into_owned()).unwrap_or_default();
                        sip_core::log::log(sip_core::log::L_ERR, &format!("rtpengine: {} on {} failed: {why}", op.command(), node.url));
                        return None;
                    }
                    if op == Op::Delete {
                        self.sticky.remove(callid.as_str());
                    } else {
                        self.sticky.insert(callid.clone(), (node.url.clone(), unix_secs()));
                    }
                    if wants_sdp && let Some(sdp) = resp.get("sdp").and_then(B::str) {
                        ctx.set_body(sdp.to_vec(), None);
                    }
                    return Some(resp);
                }
                None => {
                    sip_core::log::log(sip_core::log::L_WARN, &format!("rtpengine: {} timed out, disabling it", node.url));
                    node.disabled_until.store(unix_secs().saturating_add(self.disable_tout.load(Ordering::Relaxed)), Ordering::Relaxed);
                }
            }
        }
        sip_core::log::log(sip_core::log::L_ERR, "rtpengine: no rtpengine node available");
        None
    }

    /// rtpengine_manage(): offer / answer / delete depending on the message.
    fn manage(&self, ctx: &mut Ctx<'_, '_>, flags: &str) -> i32 {
        let has_sdp = !ctx.body().is_empty();
        let op = if ctx.msg.is_request() {
            match ctx.msg.method() {
                // INVITE/UPDATE with SDP: an offer; ACK with SDP: the answer.
                Some(Method::Invite | Method::Update) if has_sdp => Some(Op::Offer),
                Some(Method::Ack) if has_sdp => Some(Op::Answer),
                Some(Method::Bye) | Some(Method::Cancel) => Some(Op::Delete),
                _ => None,
            }
        } else {
            let code = ctx.msg.status().unwrap_or(0);
            let invite = ctx.msg.parse_headers(HdrFlags::EOH).is_ok()
                && ctx.msg.get(HdrKind::CSeq).is_some_and(|h| matches!(Method::from_cseq(h.body), Method::Invite | Method::Update));
            match code {
                180..=299 if invite && has_sdp => Some(Op::Answer),
                300.. if invite => Some(Op::Delete),
                _ => None,
            }
        };
        match op {
            Some(op) => {
                if self.call(ctx, op, flags).is_some() {
                    1
                } else {
                    -1
                }
            }
            None => 1,
        }
    }

    fn node_json(&self, n: &Node) -> Value {
        let d = n.disabled_until.load(Ordering::Relaxed);
        json!({"url": n.url, "weight": n.weight, "disabled": d > unix_secs(), "recheck_ticks": if d == u64::MAX { -1 } else { i64::try_from(d.saturating_sub(unix_secs())).unwrap_or(i64::MAX) }})
    }

    fn ping(&self, n: &Node) -> bool {
        let ok = self.exchange(n, &B::Dict(vec![(b"command".to_vec(), B::s("ping"))])).is_some_and(|r| r.get("result").and_then(B::str) == Some(b"pong"));
        if !ok {
            n.disabled_until.store(unix_secs().saturating_add(self.disable_tout.load(Ordering::Relaxed)), Ordering::Relaxed);
        } else if n.disabled_until.load(Ordering::Relaxed) != u64::MAX {
            n.disabled_until.store(0, Ordering::Relaxed);
        }
        ok
    }

    fn nodes_for(&self, which: &str) -> Vec<Arc<Node>> {
        self.all_nodes().into_iter().filter(|n| which == "all" || n.url == which).collect()
    }
}

/// Exactly `N` arguments, as an array to destructure.
fn fixed_args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

/// Optional flags argument.
fn flags_fix(a: &[Arg]) -> Result<Option<DynStr>, String> {
    match a {
        [] => Ok(None),
        [flags] => Ok(Some(flags.dyn_str()?)),
        _ => Err("expected at most 1 argument (flags)".into()),
    }
}

fn eval(ctx: &mut Ctx<'_, '_>, f: &Option<DynStr>) -> String {
    f.as_ref().map(|f| f.eval(ctx).into_owned()).unwrap_or_default()
}

impl Module for Rtpengine {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, opt, sig};
        const FLAGS: &[Param] = &[opt("flags", Str)];
        const ANY: u8 = ctx::ROUTE | ctx::REPLY;
        const OUT: &[Param] = &[arg("out", Var)];
        const SET: &[Param] = &[arg("set", Int)];
        Some(vec![
            sig("rtpengine_offer", "offer", FLAGS, Ret::Bool, "Send the SDP offer to RTPengine and rewrite it (flags: RTPengine options)").allowed(ANY),
            sig("rtpengine_answer", "answer", FLAGS, Ret::Bool, "Send the SDP answer to RTPengine and rewrite it").allowed(ANY),
            sig("rtpengine_delete", "delete", FLAGS, Ret::Bool, "End the call's media session in RTPengine").allowed(ANY),
            sig("rtpengine_manage", "manage", FLAGS, Ret::Bool, "Offer, answer or delete, whichever the message calls for").allowed(ANY),
            sig("rtpengine_query", "query", FLAGS, Ret::Bool, "Fetch the session's media statistics (then readable in $rtpstat)").allowed(ANY),
            sig("rtpengine_query_v", "query_json", OUT, Ret::Bool, "Store the session's media statistics as JSON in a variable").fixed(&["j"]).allowed(ANY),
            sig("set_rtpengine_set", "use_set", SET, Ret::Bool, "Use this RTPengine set for the following commands").allowed(ANY),
            sig("start_recording", "start_recording", FLAGS, Ret::Bool, "Start recording the call's media").allowed(ANY),
            sig("stop_recording", "stop_recording", FLAGS, Ret::Bool, "Stop recording the call's media").allowed(ANY),
            sig("block_dtmf", "block_dtmf", FLAGS, Ret::Bool, "Stop relaying DTMF events").allowed(ANY),
            sig("unblock_dtmf", "unblock_dtmf", FLAGS, Ret::Bool, "Relay DTMF events again").allowed(ANY),
            sig("block_media", "block_media", FLAGS, Ret::Bool, "Stop relaying media").allowed(ANY),
            sig("unblock_media", "unblock_media", FLAGS, Ret::Bool, "Relay media again").allowed(ANY),
            sig("silence_media", "silence_media", FLAGS, Ret::Bool, "Replace the media with silence").allowed(ANY),
            sig("unsilence_media", "unsilence_media", FLAGS, Ret::Bool, "Stop replacing the media with silence").allowed(ANY),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("rtpengine_sock", Ty::List(&Ty::Str), "", "RTPengine control sockets, e.g. \"udp:127.0.0.1:2223\" (one set per entry)"),
            pr("rtpengine_tout_ms", Ty::Duration(Unit::Ms), "1s", "Reply timeout per try"),
            pr("rtpengine_retr", Ty::Int { min: 1, max: 100 }, "5", "Tries per command"),
            pr("rtpengine_disable_tout", Ty::Duration(Unit::Sec), "60s", "A node that failed is skipped this long"),
            pr("setid_default", UINT, "0", "Default set id"),
        ])
    }

    fn name(&self) -> &'static str {
        "rtpengine"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "rtpengine_sock" => lock(&self.socks).push(v.str()?.to_string()),
            "rtpengine_tout_ms" => self.tout_ms.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "rtpengine_retr" => self.retr.store(u32::try_from(v.int()?.max(1)).unwrap_or(u32::MAX), Ordering::Relaxed),
            "rtpengine_disable_tout" => self.disable_tout.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "setid_default" => {
                let id = u32::try_from(v.int()?.max(0)).map_err(|_| "rtpengine: setid_default out of range".to_string())?;
                self.default_set.store(id, Ordering::Relaxed);
            }
            "rtpengine_allow_op"
            | "queried_nodes_limit"
            | "hash_table_size"
            | "hash_table_tout"
            | "extra_id_pv"
            | "setid_avp"
            | "read_sdp_pv"
            | "write_sdp_pv"
            | "rtp_inst_pvar"
            | "control_cmd_tos"
            | "mos_min_pv"
            | "mos_max_pv"
            | "mos_average_pv" => {}
            _ => return Err(format!("rtpengine: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let socks = lock(&self.socks).clone();
        if socks.is_empty() {
            return Err("rtpengine: modparam(\"rtpengine\", \"rtpengine_sock\", …) is required".into());
        }
        let _ = self.sets.set(parse_socks(&socks)?);
        let m = "rtpengine";
        for (name, op) in [
            ("rtpengine_offer", Op::Offer),
            ("rtpengine_answer", Op::Answer),
            ("rtpengine_delete", Op::Delete),
            ("start_recording", Op::StartRec),
            ("stop_recording", Op::StopRec),
            ("block_dtmf", Op::BlockDtmf),
            ("unblock_dtmf", Op::UnblockDtmf),
            ("block_media", Op::BlockMedia),
            ("unblock_media", Op::UnblockMedia),
            ("silence_media", Op::SilenceMedia),
            ("unsilence_media", Op::UnsilenceMedia),
        ] {
            let me = self.clone();
            reg.export(m, name, flags_fix, move |ctx: &mut Ctx, f: &Option<DynStr>| {
                let f = eval(ctx, f);
                if me.call(ctx, op, &f).is_some() { 1 } else { -1 }
            });
        }
        let me = self.clone();
        reg.export(m, "rtpengine_manage", flags_fix, move |ctx: &mut Ctx, f: &Option<DynStr>| {
            let f = eval(ctx, f);
            me.manage(ctx, &f)
        });
        let me = self.clone();
        reg.export(m, "rtpengine_query", flags_fix, move |ctx: &mut Ctx, f: &Option<DynStr>| {
            let f = eval(ctx, f);
            match me.call(ctx, Op::Query, &f) {
                Some(r) => {
                    ctx.ext.retain(|e| !e.is::<QueryResult>());
                    ctx.ext.push(Box::new(QueryResult(r)));
                    1
                }
                None => -1,
            }
        });
        let me = self.clone();
        reg.export(
            m,
            "rtpengine_query_v",
            |a: &[Arg]| -> Result<PvRef, String> {
                let [fmt, out] = fixed_args(a)?;
                if fmt.str()? != "j" {
                    return Err("rtpengine_query_v: only format \"j\" (JSON) is supported".into());
                }
                match out {
                    Arg::Fmt(f) => f.single_pv().cloned().ok_or_else(|| "expected a variable".into()),
                    _ => Err("expected a variable".into()),
                }
            },
            move |ctx: &mut Ctx, out: &PvRef| match me.call(ctx, Op::Query, "") {
                Some(r) if out.set(ctx, Val::Str(r.to_json())).is_ok() => 1,
                _ => -1,
            },
        );
        let me = self.clone();
        reg.export(
            m,
            "set_rtpengine_set",
            |a: &[Arg]| {
                let [set] = fixed_args(a)?;
                set.dyn_int()
            },
            move |ctx: &mut Ctx, s: &sip_core::module::DynInt| {
                let Some(s) = s.eval(ctx).and_then(|s| known_set(me.sets.get(), s)) else { return -1 };
                ctx.ext.retain(|e| !e.is::<SelectedSet>());
                ctx.ext.push(Box::new(SelectedSet(s)));
                1
            },
        );
        reg.pv(
            "rtpstat",
            PvSpec::ro(|ctx, _| {
                let Some(QueryResult(r)) = ctx.ext::<QueryResult>() else { return Val::Null };
                let n = |path: &[&str]| -> i64 {
                    let mut cur = r;
                    for p in path {
                        match cur.get(p) {
                            Some(x) => cur = x,
                            None => return 0,
                        }
                    }
                    match cur {
                        B::Int(i) => *i,
                        _ => 0,
                    }
                };
                Val::Str(format!(
                    "RTP: {} bytes, {} packets, {} errors; RTCP: {} bytes, {} packets, {} errors",
                    n(&["totals", "RTP", "bytes"]),
                    n(&["totals", "RTP", "packets"]),
                    n(&["totals", "RTP", "errors"]),
                    n(&["totals", "RTCP", "bytes"]),
                    n(&["totals", "RTCP", "packets"]),
                    n(&["totals", "RTCP", "errors"])
                ))
            }),
        );
        let me = self.clone();
        reg.rpc.add("rtpengine.show", "rtpengine.show <url|all>", move |p| {
            let w = sip_core::rpc::str_param(p, 0).unwrap_or_else(|_| "all".into());
            Ok(json!(me.nodes_for(&w).iter().map(|n| me.node_json(n)).collect::<Vec<_>>()))
        });
        let me = self.clone();
        reg.rpc.add("rtpengine.enable", "rtpengine.enable <url|all> <0|1>", move |p| {
            let w = sip_core::rpc::str_param(p, 0)?;
            let on = sip_core::rpc::int_param(p, 1)? != 0;
            let nodes = me.nodes_for(&w);
            if nodes.is_empty() {
                return Err("no such rtpengine".into());
            }
            for n in &nodes {
                n.disabled_until.store(if on { 0 } else { u64::MAX }, Ordering::Relaxed);
            }
            Ok(json!(nodes.len()))
        });
        let me = self.clone();
        reg.rpc.add("rtpengine.ping", "rtpengine.ping <url|all>", move |p| {
            let w = sip_core::rpc::str_param(p, 0).unwrap_or_else(|_| "all".into());
            Ok(json!(me.nodes_for(&w).iter().map(|n| json!({"url": n.url, "status": if me.ping(n) { "success" } else { "fail" }})).collect::<Vec<_>>()))
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags() {
        let mut d = Vec::new();
        let vb = parse_flags(
            "trust-address replace-origin replace-session-connection ICE=remove RTP/AVP direction=pub direction=priv via-branch=1 codec-strip-PCMA transcode-opus foo=bar",
            &mut d,
        );
        assert_eq!(vb.as_deref(), Some("1"));
        let dd = B::Dict(d);
        assert_eq!(dd.get("flags"), Some(&B::List(vec![B::s("trust-address")])));
        assert_eq!(dd.get("replace"), Some(&B::List(vec![B::s("origin"), B::s("session-connection")])));
        assert_eq!(dd.get("ICE").and_then(B::str), Some(&b"remove"[..]));
        assert_eq!(dd.get("transport-protocol").and_then(B::str), Some(&b"RTP/AVP"[..]));
        assert_eq!(dd.get("direction"), Some(&B::List(vec![B::s("pub"), B::s("priv")])));
        assert_eq!(dd.get("foo").and_then(B::str), Some(&b"bar"[..]));
        let codec = dd.get("codec").unwrap();
        assert_eq!(codec.get("strip"), Some(&B::List(vec![B::s("PCMA")])));
        assert_eq!(codec.get("transcode"), Some(&B::List(vec![B::s("opus")])));
        let s = parse_socks(&["udp:127.0.0.1:2223=2 udp:127.0.0.1:2224".into(), "1 == udp:127.0.0.1:2225".into()]).unwrap();
        assert_eq!(s[&0].len(), 2);
        assert_eq!(s[&0][0].weight, 2);
        assert_eq!(s[&1][0].addr.port(), 2225);
        assert!(parse_socks(&["tcp:1.2.3.4:5".into()]).is_err());
    }

    #[test]
    fn set_ids_outside_u32_are_unknown() {
        let s = parse_socks(&["udp:127.0.0.1:2223".into(), "1 == udp:127.0.0.1:2225".into()]).unwrap();
        assert_eq!(known_set(Some(&s), 0), Some(0));
        assert_eq!(known_set(Some(&s), 1), Some(1));
        assert_eq!(known_set(Some(&s), 2), None);
        assert_eq!(known_set(Some(&s), 1 << 32), None, "must not wrap to set 0");
        assert_eq!(known_set(Some(&s), (1 << 32) + 1), None, "must not wrap to set 1");
        assert_eq!(known_set(Some(&s), -1), None);
        assert_eq!(known_set(None, 0), None);
    }
}

#[cfg(test)]
mod node_tests {
    use super::*;
    use sip_core::{Dest, Outbound, Proto, RouteHub, RouteNames, RouteRunner};

    fn engine(specs: &[&str]) -> Rtpengine {
        let r = Rtpengine::default();
        let _ = r.sets.set(parse_socks(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap());
        r
    }

    fn urls(v: &[Arc<Node>]) -> Vec<&str> {
        v.iter().map(|n| n.url.as_str()).collect()
    }

    #[test]
    fn parse_socks_sets_weights_and_errors() {
        let s = parse_socks(&["udp:127.0.0.1:1=0 udp4:127.0.0.1:2".into(), " 7 == udp6:[::1]:3=5 ".into(), "7==udp:127.0.0.1:4".into()]).unwrap();
        assert_eq!(s.keys().copied().collect::<Vec<_>>(), [0, 7]);
        assert_eq!(
            s[&0].iter().map(|n| (n.url.as_str(), n.weight)).collect::<Vec<_>>(),
            [("udp:127.0.0.1:1", 1), ("udp4:127.0.0.1:2", 1)],
            "weight 0 counts as 1"
        );
        assert_eq!(s[&7].iter().map(|n| (n.addr, n.weight)).collect::<Vec<_>>(), [("[::1]:3".parse().unwrap(), 5), ("127.0.0.1:4".parse().unwrap(), 1)]);
        for bad in ["x == udp:127.0.0.1:1", "udp:127.0.0.1:1=x", "tcp:127.0.0.1:1", "127.0.0.1:1", "udp:127.0.0.1", "-1 == udp:127.0.0.1:1"] {
            assert!(parse_socks(&[bad.into()]).is_err(), "{bad:?}");
        }
        assert!(parse_socks(&[]).unwrap().is_empty());
    }

    #[test]
    fn candidates_hold_every_enabled_node_once() {
        let r = engine(&["udp:127.0.0.1:1 udp:127.0.0.1:2=2 udp:127.0.0.1:3"]);
        for i in 0..200 {
            let c = r.candidates(0, &format!("call-{i}"));
            let mut u = urls(&c);
            u.sort_unstable();
            assert_eq!(u, ["udp:127.0.0.1:1", "udp:127.0.0.1:2", "udp:127.0.0.1:3"]);
        }
        let a = urls(&r.candidates(0, "same")).join(" ");
        assert_eq!(urls(&r.candidates(0, "same")).join(" "), a, "stable for a Call-ID");
        assert!(r.candidates(9, "x").is_empty(), "unknown set");
        assert!(Rtpengine::default().candidates(0, "x").is_empty(), "no sets");
    }

    #[test]
    fn candidates_follow_the_weights_and_rotate_from_the_pick() {
        let r = engine(&["udp:127.0.0.1:1=1 udp:127.0.0.1:2=3"]);
        let mut first = [0usize; 2];
        for i in 0..4000 {
            let c = r.candidates(0, &format!("{i}@host"));
            let idx = usize::from(c[0].addr.port() == 2);
            first[idx] += 1;
            let rest: Vec<u16> = c.iter().map(|n| n.addr.port()).collect();
            assert!(rest == [1, 2] || rest == [2, 1]);
        }
        assert!((800..=1200).contains(&first[0]), "about 1 in 4 on the weight-1 node: {first:?}");
        let r = engine(&["udp:127.0.0.1:1 udp:127.0.0.1:2 udp:127.0.0.1:3"]);
        for i in 0..50 {
            let ports: Vec<u16> = r.candidates(0, &i.to_string()).iter().map(|n| n.addr.port()).collect();
            let rotated = [[1, 2, 3], [2, 3, 1], [3, 1, 2]];
            assert!(rotated.contains(&ports.as_slice().try_into().unwrap()), "round-robin after the pick: {ports:?}");
        }
    }

    #[test]
    fn disabled_nodes_are_skipped_until_their_time() {
        let r = engine(&["udp:127.0.0.1:1 udp:127.0.0.1:2"]);
        let nodes = r.set_nodes(0);
        let now = unix_secs();
        nodes[0].disabled_until.store(now + 100, Ordering::Relaxed);
        assert_eq!(urls(&r.candidates(0, "c")), ["udp:127.0.0.1:2"]);
        nodes[1].disabled_until.store(u64::MAX, Ordering::Relaxed);
        assert!(r.candidates(0, "c").is_empty());
        nodes[0].disabled_until.store(now - 1, Ordering::Relaxed);
        assert_eq!(urls(&r.candidates(0, "c")), ["udp:127.0.0.1:1"]);
        assert!(nodes[0].enabled(now) && !nodes[0].enabled(now - 2));
        let n = &nodes[1];
        assert!(!n.enabled(u64::MAX - 1) && n.enabled(u64::MAX), "disabled by admin");
    }

    #[test]
    fn a_sticky_call_goes_to_its_node_first() {
        let r = engine(&["udp:127.0.0.1:1 udp:127.0.0.1:2 udp:127.0.0.1:3"]);
        for target in ["udp:127.0.0.1:1", "udp:127.0.0.1:2", "udp:127.0.0.1:3"] {
            r.sticky.insert("call".into(), (target.into(), 0));
            let c = r.candidates(0, "call");
            assert_eq!(c[0].url, target);
            assert_eq!(c.len(), 3);
        }
        r.set_nodes(0)[2].disabled_until.store(u64::MAX, Ordering::Relaxed);
        let c = r.candidates(0, "call");
        assert_eq!(c.len(), 2, "a disabled sticky node is not used");
        r.sticky.insert("call".into(), ("udp:gone:1".into(), 0));
        assert_eq!(r.candidates(0, "call").len(), 2);
    }

    #[test]
    fn nodes_for_and_node_json() {
        let r = engine(&["udp:127.0.0.1:1", "1 == udp:127.0.0.1:2=4"]);
        assert_eq!(r.nodes_for("all").len(), 2);
        assert_eq!(urls(&r.nodes_for("udp:127.0.0.1:2")), ["udp:127.0.0.1:2"]);
        assert!(r.nodes_for("udp:nope:1").is_empty());
        let n = &r.set_nodes(1)[0];
        assert_eq!(r.node_json(n), json!({"url": "udp:127.0.0.1:2", "weight": 4, "disabled": false, "recheck_ticks": 0}));
        n.disabled_until.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(r.node_json(n)["recheck_ticks"], json!(-1));
        assert_eq!(r.node_json(n)["disabled"], json!(true));
    }

    #[test]
    fn op_commands() {
        let cases = [
            (Op::Offer, "offer"),
            (Op::Answer, "answer"),
            (Op::Delete, "delete"),
            (Op::Query, "query"),
            (Op::StartRec, "start recording"),
            (Op::StopRec, "stop recording"),
            (Op::BlockDtmf, "block DTMF"),
            (Op::UnblockDtmf, "unblock DTMF"),
            (Op::BlockMedia, "block media"),
            (Op::UnblockMedia, "unblock media"),
            (Op::SilenceMedia, "silence media"),
            (Op::UnsilenceMedia, "unsilence media"),
        ];
        for (op, cmd) in cases {
            assert_eq!(op.command(), cmd);
        }
    }

    fn flags(s: &str) -> (B, Option<String>) {
        let mut d = Vec::new();
        let vb = parse_flags(s, &mut d);
        (B::Dict(d), vb)
    }

    #[test]
    fn parse_flags_cases() {
        let l = |v: &[&str]| B::List(v.iter().map(B::s).collect());
        // (flags, key, value)
        let cases: Vec<(&str, &str, B)> = vec![
            ("trust-address symmetric", "flags", l(&["trust-address", "symmetric"])),
            ("replace-origin", "replace", l(&["origin"])),
            ("replace=zero-address", "replace", l(&["zero-address"])),
            ("SDES-off SDES-no-AES_CM_128_HMAC_SHA1_32", "SDES", l(&["off", "no-AES_CM_128_HMAC_SHA1_32"])),
            ("rtcp-mux-offer rtcp-mux-demux", "rtcp-mux", l(&["offer", "demux"])),
            ("T38-decode T.38-force", "T.38", l(&["decode", "force"])),
            ("UDP/TLS/RTP/SAVPF", "transport-protocol", B::s("UDP/TLS/RTP/SAVPF")),
            ("direction=external direction=internal", "direction", l(&["external", "internal"])),
            ("ICE=force DTLS=passive", "ICE", B::s("force")),
            ("ICE=force DTLS=passive", "DTLS", B::s("passive")),
            ("received-from=10.0.0.9", "received-from", l(&["IP4", "10.0.0.9"])),
            ("received-from=2001:db8::9", "received-from", l(&["IP6", "2001:db8::9"])),
            ("record-call=yes", "record-call", B::s("yes")),
        ];
        for (s, key, want) in cases {
            assert_eq!(flags(s).0.get(key), Some(&want), "{s:?} → {key}");
        }
        assert_eq!(flags("").0, B::Dict(vec![]));
        assert_eq!(flags("RTP/AVP=x").0.get("RTP/AVP"), Some(&B::s("x")), "a protocol with a value is a plain entry");
    }

    #[test]
    fn parse_flags_codecs_merge_into_one_dictionary() {
        let (d, _) = flags("codec-strip-PCMA codec-strip=PCMU codec-offer-opus transcode-G722 codec-transcode=AMR codec-mask-all codec-except-telephone-event");
        let codec = d.get("codec").unwrap();
        let l = |v: &[&str]| B::List(v.iter().map(B::s).collect());
        assert_eq!(codec.get("strip"), Some(&l(&["PCMA", "PCMU"])));
        assert_eq!(codec.get("offer"), Some(&l(&["opus"])));
        assert_eq!(codec.get("transcode"), Some(&l(&["G722", "AMR"])));
        assert_eq!(codec.get("mask"), Some(&l(&["all"])));
        assert_eq!(codec.get("except"), Some(&l(&["telephone-event"])));
        let B::Dict(entries) = d else { panic!() };
        assert_eq!(entries.iter().filter(|(k, _)| k == b"codec").count(), 1);
    }

    #[test]
    fn parse_flags_via_branch_and_received_from_override() {
        assert_eq!(flags("via-branch=auto").1.as_deref(), Some("auto"));
        assert_eq!(flags("via-branch=1 via-branch=2").1.as_deref(), Some("2"), "the last one wins");
        assert_eq!(flags("via-branch").1, None);
        assert_eq!(flags("trust-address").1, None);
        let mut d = vec![(b"received-from".to_vec(), B::List(vec![B::s("IP4"), B::s("1.1.1.1")]))];
        parse_flags("received-from=2.2.2.2", &mut d);
        assert_eq!(d, [(b"received-from".to_vec(), B::List(vec![B::s("IP4"), B::s("2.2.2.2")]))], "replaces the source address");
        let (d, _) = flags("received-from");
        assert_eq!(d.get("received-from"), None);
    }

    struct NoNet;
    impl Outbound for NoNet {
        fn send(&self, _: &Dest, _: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn advertise(&self, _: Proto) -> Option<SocketAddr> {
            None
        }
    }

    /// An event route that runs `rtpengine_manage()` and keeps its result
    /// (with no nodes, a chosen operation fails: -1; none chosen: 1).
    struct Manage(Arc<Rtpengine>, Mutex<i32>);
    impl RouteRunner for Manage {
        fn run_failure(&self, _: usize, _: &mut Ctx<'_, '_>) {}
        fn run_onreply(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_branch(&self, _: usize, _: &mut Ctx<'_, '_>) -> bool {
            true
        }
        fn run_event(&self, _: usize, ctx: &mut Ctx<'_, '_>) -> bool {
            *lock(&self.1) = self.0.manage(ctx, "");
            true
        }
    }

    fn manage(first: &str, cseq: &str, sdp: bool) -> i32 {
        let body = if sdp { "v=0\r\n" } else { "" };
        let msg = format!(
            "{first}\r\nVia: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bKa\r\nFrom: <sip:a@x>;tag=f\r\nTo: <sip:b@x>;tag=t\r\nCall-ID: c\r\nCSeq: {cseq}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let runner = Arc::new(Manage(Arc::new(Rtpengine::default()), Mutex::new(i32::MIN)));
        let hub = RouteHub::default();
        hub.set_names(RouteNames { event: vec!["m".into()], ..Default::default() });
        hub.set_runner(runner.clone());
        hub.run_event_with("m", &NoNet, Some(msg.as_bytes()), |_| {});
        *lock(&runner.1)
    }

    #[test]
    fn manage_picks_the_operation_from_the_message() {
        // (first line, CSeq, with SDP, an operation is sent)
        let cases: &[(&str, &str, bool, bool)] = &[
            ("INVITE sip:b@x SIP/2.0", "1 INVITE", true, true),
            ("INVITE sip:b@x SIP/2.0", "1 INVITE", false, false),
            ("UPDATE sip:b@x SIP/2.0", "2 UPDATE", true, true),
            ("ACK sip:b@x SIP/2.0", "1 ACK", true, true),
            ("ACK sip:b@x SIP/2.0", "1 ACK", false, false),
            ("BYE sip:b@x SIP/2.0", "3 BYE", false, true),
            ("CANCEL sip:b@x SIP/2.0", "1 CANCEL", false, true),
            ("OPTIONS sip:b@x SIP/2.0", "1 OPTIONS", true, false),
            ("SIP/2.0 183 Session Progress", "1 INVITE", true, true),
            ("SIP/2.0 200 OK", "1 INVITE", true, true),
            ("SIP/2.0 200 OK", "1 INVITE", false, false),
            ("SIP/2.0 180 Ringing", "1 INVITE", false, false),
            ("SIP/2.0 100 Trying", "1 INVITE", true, false),
            ("SIP/2.0 200 OK", "2 BYE", true, false),
            ("SIP/2.0 486 Busy Here", "1 INVITE", false, true),
            ("SIP/2.0 487 Request Terminated", "1 OPTIONS", false, false),
        ];
        for &(first, cseq, sdp, sent) in cases {
            assert_eq!(manage(first, cseq, sdp), if sent { -1 } else { 1 }, "{first} / {cseq} / sdp {sdp}");
        }
    }
}
