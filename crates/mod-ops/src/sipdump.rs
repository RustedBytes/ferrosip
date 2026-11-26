//! `sipdump`: write every SIP message received and sent to files in
//! `folder`, for debugging without a packet capture. `mode` is a bitmask:
//! 1 = Kamailio's text format (`<fprefix><date>.data`), 4 = pcap
//! (`.pcap`, raw IPv4/IPv6 + UDP/TCP headers built from the addresses, so
//! Wireshark decodes SIP), 2 = run `event_route[sipdump:msg]` for every
//! record with `$sipdump(tag|data|len|proto|af|src_ip|src_port|dst_ip|
//! dst_port|time)` (on the writer thread, off the SIP path), 8 = stderr. Files rotate every `rotate`
//! seconds. `enable` switches it on at start; RPC `sipdump.enable [0|1]`
//! at run time. `sipdump_send(tag)` writes the current message with a tag
//! of your choice (whatever `enable` says).

use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs_f64;
use sip_core::{Arg, Ctx, Dest, Module, Outbound, Proto, Registry};
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
struct Rec {
    tag: String,
    time: f64,
    proto: Proto,
    src: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

pub struct SipDump {
    enabled: Arc<AtomicBool>,
    mode: AtomicU64,
    rotate: AtomicU64,
    folder: Mutex<String>,
    prefix: Mutex<String>,
    tx: OnceLock<Mutex<Sender<Rec>>>,
    net: OnceLock<Arc<dyn Outbound>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

impl Default for SipDump {
    fn default() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(false)),
            mode: AtomicU64::new(1),
            rotate: AtomicU64::new(7200),
            folder: Mutex::new("/tmp".into()),
            prefix: Mutex::new("ferrosip-sipdump-".into()),
            tx: OnceLock::new(),
            net: OnceLock::new(),
            hub: OnceLock::new(),
        }
    }
}

/// Whole seconds and microseconds of a Unix time, as pcap stores them.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float to int `as` truncates toward zero, saturates and maps NaN to 0: the clamp wanted for a wall-clock time"
)]
fn secs_micros(t: f64) -> (i64, u32) {
    (t as i64, (t.fract() * 1e6) as u32)
}

/// `YYYY-MM-DD--HH-MM-SS` (UTC) for file names, and the date line.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "civil-from-days on days = secs / 86400, so every term stays below 2^50: no overflow; divisors are constants"
)]
fn stamp(t: f64) -> (String, String) {
    let secs = secs_micros(t).0;
    let days = secs.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let s = secs.rem_euclid(86_400);
    (
        format!("{y:04}-{m:02}-{d:02}--{:02}-{:02}-{:02}", s / 3600, s / 60 % 60, s % 60),
        format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", s / 3600, s / 60 % 60, s % 60),
    )
}

fn text(r: &Rec) -> Vec<u8> {
    let fam = if r.src.is_ipv4() { "ipv4" } else { "ipv6" };
    let mut o = format!(
        "====================\ntag: {}\npid: {}\nprocess: 0\ntime: {:.6}\ndate: {}\nproto: {} {fam}\nsrcip: {}\nsrcport: {}\ndstip: {}\ndstport: {}\n~~~~~~~~~~~~~~~~~~~~\n",
        r.tag,
        std::process::id(),
        r.time,
        stamp(r.time).1,
        r.proto.via_name().to_ascii_lowercase(),
        r.src.ip(),
        r.src.port(),
        r.dst.ip(),
        r.dst.port()
    )
    .into_bytes();
    o.extend_from_slice(&r.data);
    o.extend_from_slice(b"||||||||||||||||||||\n");
    o
}

/// The internet checksum: one's-complement sum of 16-bit words.
fn csum(b: &[u8]) -> u16 {
    let words = b.chunks(2).map(|c| match *c {
        [hi, lo] => u16::from_be_bytes([hi, lo]),
        [hi] => u16::from_be_bytes([hi, 0]),
        _ => 0,
    });
    // End-around carry; after a carry the sum is <= 0xfffe, so adding it back cannot wrap.
    !words.fold(0u16, |acc, w| {
        let (sum, carry) = acc.overflowing_add(w);
        sum.wrapping_add(u16::from(carry))
    })
}

/// The snap length in [`PCAP_HEADER`].
const SNAPLEN: usize = 0xffff;

pub const PCAP_HEADER: [u8; 24] = [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0];

/// A 16-bit length field: saturates (the packet then exceeds what IP can
/// describe; the record is cut at the snap length anyway).
fn len16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

/// One pcap record (LINKTYPE_RAW): IP header + UDP or TCP header + data.
/// A packet over the snap length (65535, as IP allows) is captured up to
/// it, with its real length as the original length.
fn pcap(r: &Rec) -> Vec<u8> {
    let udp = r.proto == Proto::Udp;
    let mut l4 = Vec::with_capacity(20);
    l4.extend_from_slice(&r.src.port().to_be_bytes());
    l4.extend_from_slice(&r.dst.port().to_be_bytes());
    if udp {
        l4.extend_from_slice(&len16(r.data.len().saturating_add(8)));
        l4.extend_from_slice(&[0, 0]);
    } else {
        l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        // seq, ack, len 5, PSH|ACK
    }
    let payload = l4.len().saturating_add(r.data.len());
    let mut p = Vec::with_capacity(payload.saturating_add(40));
    match (r.src.ip(), r.dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let [len_hi, len_lo] = len16(payload.saturating_add(20));
            let [s0, s1, s2, s3] = s.octets();
            let [d0, d1, d2, d3] = d.octets();
            let proto = if udp { 17 } else { 6 };
            let mut h = [0x45, 0, len_hi, len_lo, 0, 0, 0x40, 0, 64, proto, 0, 0, s0, s1, s2, s3, d0, d1, d2, d3];
            [h[10], h[11]] = csum(&h).to_be_bytes();
            p.extend_from_slice(&h);
        }
        (s, d) => {
            let v6 = |a: IpAddr| match a {
                IpAddr::V6(x) => x.octets(),
                IpAddr::V4(x) => x.to_ipv6_mapped().octets(),
            };
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&len16(payload));
            p.extend_from_slice(&[if udp { 17 } else { 6 }, 64]);
            p.extend_from_slice(&v6(s));
            p.extend_from_slice(&v6(d));
        }
    }
    p.extend_from_slice(&l4);
    let orig = p.len().saturating_add(r.data.len());
    // Shorter than the room left: captured whole.
    p.extend_from_slice(r.data.get(..SNAPLEN.saturating_sub(p.len())).unwrap_or(&r.data));
    let mut rec = Vec::with_capacity(p.len().saturating_add(16));
    let (secs, micros) = secs_micros(r.time);
    // pcap's 32-bit seconds; the clock reads 0 before 1970.
    rec.extend_from_slice(&u32::try_from(secs).unwrap_or(if secs < 0 { 0 } else { u32::MAX }).to_le_bytes());
    rec.extend_from_slice(&micros.to_le_bytes());
    rec.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_le_bytes());
    rec.extend_from_slice(&u32::try_from(orig).unwrap_or(u32::MAX).to_le_bytes());
    rec.extend_from_slice(&p);
    rec
}

/// Create a dump file starting with `header`. A failure is logged, once
/// until a file can be created again (it is retried on every record).
fn open(path: &str, header: &[u8], failing: &mut bool) -> Option<File> {
    match File::create(path).and_then(|mut f| f.write_all(header).map(|_| f)) {
        Ok(f) => {
            *failing = false;
            Some(f)
        }
        Err(e) => {
            if !std::mem::replace(failing, true) {
                sip_core::log::log(sip_core::log::L_ERR, &format!("sipdump: cannot create {path}: {e}"));
            }
            None
        }
    }
}

impl SipDump {
    fn record(&self, tag: &str, proto: Proto, src: SocketAddr, dst: SocketAddr, data: &[u8]) {
        if let Some(tx) = self.tx.get() {
            let _ = lock(tx).send(Rec { tag: tag.into(), time: unix_secs_f64(), proto, src, dst, data: data.to_vec() });
        }
    }

    fn local(&self, proto: Proto) -> SocketAddr {
        self.net.get().and_then(|n| n.advertise(proto)).unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    fn rcv(&self, ctx: &Ctx<'_, '_>, tag: &str) {
        let src = ctx.src;
        self.record(tag, src.proto, src.addr, self.local(src.proto), &ctx.received());
    }

    /// Mode 2: `event_route[sipdump:msg]` with the record in `$sipdump(...)`.
    fn event(&self, r: &Rec) {
        let (Some(hub), Some(net)) = (self.hub.get(), self.net.get()) else { return };
        let rec = r.clone();
        hub.run_event_with("sipdump:msg", &**net, None, move |ctx| ctx.ext.push(Box::new(rec)));
    }

    fn writer(self: &Arc<Self>) -> Result<Sender<Rec>, String> {
        let me = self.clone();
        let (tx, rx) = channel::<Rec>();
        let mode = self.mode.load(Ordering::Relaxed);
        let rotate = self.rotate.load(Ordering::Relaxed).max(1) as f64;
        let (folder, prefix) = (lock(&self.folder).clone(), lock(&self.prefix).clone());
        std::thread::Builder::new()
            .name("sipdump".into())
            .spawn(move || {
                let (mut data, mut pc): (Option<File>, Option<File>) = (None, None);
                let mut opened = 0.0;
                let mut base = String::new();
                // Write errors are logged once per file.
                let (mut data_failed, mut pc_failed, mut open_failing) = (false, false, false);
                for r in rx {
                    if data.is_none() && pc.is_none() || r.time - opened >= rotate {
                        opened = r.time;
                        base = format!("{folder}/{prefix}{}", stamp(r.time).0);
                        data = (mode & 1 != 0).then(|| open(&format!("{base}.data"), &[], &mut open_failing)).flatten();
                        pc = (mode & 4 != 0).then(|| open(&format!("{base}.pcap"), &PCAP_HEADER, &mut open_failing)).flatten();
                        (data_failed, pc_failed) = (false, false);
                    }
                    if let Some(f) = data.as_mut()
                        && let Err(e) = f.write_all(&text(&r)).and_then(|_| f.flush())
                        && !std::mem::replace(&mut data_failed, true)
                    {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("sipdump: write to {base}.data: {e}"));
                    }
                    if let Some(f) = pc.as_mut()
                        && let Err(e) = f.write_all(&pcap(&r)).and_then(|_| f.flush())
                        && !std::mem::replace(&mut pc_failed, true)
                    {
                        sip_core::log::log(sip_core::log::L_ERR, &format!("sipdump: write to {base}.pcap: {e}"));
                    }
                    if mode & 8 != 0 {
                        let _ = std::io::stderr().write_all(&text(&r));
                    }
                    if mode & 2 != 0 {
                        me.event(&r);
                    }
                }
            })
            .map_err(|e| format!("cannot start the sipdump thread: {e}"))?;
        Ok(tx)
    }
}

impl Module for SipDump {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("enable", Ty::Bool, "false", "Dump messages from the start"),
            p("mode", Ty::Int { min: 0, max: 15 }, "1", "Bitmask: 1 text files, 2 event_route[sipdump:msg], 4 pcap files, 8 stderr"),
            p("rotate", Ty::Duration(Unit::Sec), "2h", "Start new files this often"),
            p("folder", Ty::Str, "/tmp", "Directory for the dump files"),
            p("fprefix", Ty::Str, "ferrosip-sipdump-", "File name prefix"),
        ])
    }

    fn name(&self) -> &'static str {
        "sipdump"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "enable" => self.enabled.store(v.int()? != 0, Ordering::Relaxed),
            "mode" => self.mode.store(u64::try_from(v.int()?).unwrap_or(0), Ordering::Relaxed),
            "rotate" => self.rotate.store(u64::try_from(v.int()?).unwrap_or(0).max(1), Ordering::Relaxed),
            "folder" => *lock(&self.folder) = v.str()?.trim_end_matches('/').into(),
            "fprefix" => *lock(&self.prefix) = v.str()?.into(),
            "wait" | "fage" | "event_callback" => {}
            _ => return Err(format!("sipdump: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, ctx, sig};
        const TAG: &[Param] = &[arg("tag", Str)];
        Some(vec![sig("sipdump_send", "send", TAG, Ret::Void, "Write this message to the dump with `tag` (even when dumping is off)").allowed(ctx::ANY)])
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.hub.set(reg.hub.clone());
        let _ = self.tx.set(Mutex::new(self.writer()?));
        reg.pv(
            "sipdump",
            sip_core::pv::PvSpec::ro(|c, p| {
                use sip_core::pv::Val;
                let Some(r) = c.ext::<Rec>() else { return Val::Null };
                match p.name.as_str() {
                    "tag" => Val::Str(r.tag.clone()),
                    "data" | "buf" => Val::str(&r.data),
                    "len" => Val::Int(i64::try_from(r.data.len()).unwrap_or(i64::MAX)),
                    "proto" => Val::Str(r.proto.via_name().to_ascii_lowercase()),
                    "af" => Val::Str(if r.src.is_ipv4() { "ipv4" } else { "ipv6" }.into()),
                    "src_ip" => Val::Str(r.src.ip().to_string()),
                    "src_port" => Val::Int(i64::from(r.src.port())),
                    "dst_ip" => Val::Str(r.dst.ip().to_string()),
                    "dst_port" => Val::Int(i64::from(r.dst.port())),
                    "time" => Val::Int(secs_micros(r.time).0),
                    _ => Val::Null,
                }
            })
            .with_param(),
        );
        let me = self.clone();
        sip_core::net::add_send_tap(Arc::new(move |d: &Dest, m: &[u8]| {
            if me.enabled.load(Ordering::Relaxed) {
                me.record("snd", d.proto, me.local(d.proto), d.addr, m);
            }
        }));
        let me = self.clone();
        reg.export(
            "sipdump",
            "sipdump_send",
            |a: &[Arg]| {
                let [tag] = crate::fixed_args(a)?;
                tag.dyn_str()
            },
            move |ctx: &mut Ctx, t: &DynStr| {
                let t = t.eval(ctx).into_owned();
                me.rcv(ctx, &t);
                1
            },
        );
        let flag = self.enabled.clone();
        reg.rpc.add("sipdump.enable", "Get or set sipdump (0/1)", move |p| {
            if let Ok(v) = sip_core::rpc::int_param(p, 0) {
                flag.store(v != 0, Ordering::Relaxed);
            }
            Ok(serde_json::json!({"enable": i32::from(flag.load(Ordering::Relaxed))}))
        });
        Ok(())
    }

    fn observes(&self) -> bool {
        true
    }

    fn observe_request(&self, ctx: &mut Ctx<'_, '_>) {
        if self.enabled.load(Ordering::Relaxed) {
            self.rcv(ctx, "rcv");
        }
    }

    fn observe_reply(&self, ctx: &mut Ctx<'_, '_>) {
        if self.enabled.load(Ordering::Relaxed) {
            self.rcv(ctx, "rcv");
        }
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let r = Rec {
            tag: "rcv".into(),
            time: 1.5,
            proto: Proto::Udp,
            src: "10.0.0.1:5060".parse().unwrap(),
            dst: "10.0.0.2:5070".parse().unwrap(),
            data: b"OPTIONS".to_vec(),
        };
        let p = pcap(&r);
        assert_eq!(u32::from_le_bytes(p[8..12].try_into().unwrap()) as usize, 20 + 8 + 7);
        assert_eq!(csum(&p[16..36]), 0, "IPv4 header checksum verifies");
        let t = String::from_utf8(text(&r)).unwrap();
        assert!(t.contains("srcip: 10.0.0.1\nsrcport: 5060\ndstip: 10.0.0.2") && t.ends_with("OPTIONS||||||||||||||||||||\n"));
        assert_eq!(stamp(0.0).0, "1970-01-01--00-00-00");
    }

    #[test]
    fn oversized_records_are_cut_at_the_snap_length() {
        for (proto, src) in [(Proto::Tcp, "10.0.0.1:5060"), (Proto::Udp, "[2001:db8::1]:5060")] {
            let r = Rec { tag: "rcv".into(), time: 1.0, proto, src: src.parse().unwrap(), dst: "10.0.0.2:5070".parse().unwrap(), data: vec![b'x'; 70_000] };
            let p = pcap(&r);
            let incl = u32::from_le_bytes(p[8..12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(p[12..16].try_into().unwrap()) as usize;
            assert_eq!(incl, SNAPLEN);
            assert_eq!(p.len(), 16 + SNAPLEN);
            assert!(orig > 70_000);
            // The IP length field saturates instead of wrapping.
            let ip_len = if proto == Proto::Tcp { &p[18..20] } else { &p[20..22] };
            assert_eq!(ip_len, [0xff, 0xff]);
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    fn rec(proto: Proto, src: &str, dst: &str, time: f64, data: &[u8]) -> Rec {
        Rec { tag: "rcv".into(), time, proto, src: src.parse().unwrap(), dst: dst.parse().unwrap(), data: data.to_vec() }
    }

    #[test]
    fn csum_matches_known_values() {
        // RFC 1071 §3 example, an IPv4 header from the wild, odd lengths.
        let cases: &[(&[u8], u16)] = &[
            (&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7], !0xddf2),
            (&[0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7], 0xb861),
            (&[], 0xffff),
            (&[0x01], !0x0100),
            (&[0xff, 0xff, 0xff, 0xff], 0x0000),
            (&[0xff, 0xff, 0x00, 0x01], 0xfffe),
        ];
        for &(b, want) in cases {
            assert_eq!(csum(b), want, "{b:02x?}");
        }
    }

    #[test]
    fn pcap_file_header() {
        assert_eq!(&PCAP_HEADER[..4], &0xa1b2_c3d4u32.to_le_bytes(), "magic, little endian, microseconds");
        assert_eq!(&PCAP_HEADER[4..8], &[2, 0, 4, 0], "version 2.4");
        assert_eq!(&PCAP_HEADER[8..16], &[0; 8], "zone, sigfigs");
        assert_eq!(u32::from_le_bytes(PCAP_HEADER[16..20].try_into().unwrap()), u32::try_from(SNAPLEN).unwrap());
        assert_eq!(u32::from_le_bytes(PCAP_HEADER[20..24].try_into().unwrap()), 101, "LINKTYPE_RAW");
    }

    #[test]
    fn pcap_ipv4_udp_record_bytes() {
        let p = pcap(&rec(Proto::Udp, "10.0.0.1:5060", "10.0.0.2:5070", 1_700_000_000.25, b"OPTIONS"));
        let want: &[u8] = &[
            0x00, 0xf1, 0x53, 0x65, // seconds 1700000000, LE
            0x90, 0xd0, 0x03, 0x00, // 250000 µs
            35, 0, 0, 0, 35, 0, 0, 0, // captured and original length
            0x45, 0, 0, 35, 0, 0, 0x40, 0, 64, 17, 0x26, 0xc8, 10, 0, 0, 1, 10, 0, 0, 2, // IPv4, DF, TTL 64, UDP, checksum
            0x13, 0xc4, 0x13, 0xce, 0, 15, 0, 0, // UDP 5060 → 5070, length 15, no checksum
            b'O', b'P', b'T', b'I', b'O', b'N', b'S',
        ];
        assert_eq!(p, want);
        assert_eq!(csum(&p[16..36]), 0);
    }

    #[test]
    fn pcap_ipv4_tcp_record_bytes() {
        let p = pcap(&rec(Proto::Tcp, "192.0.2.1:40000", "192.0.2.2:5060", 2.0, b"x"));
        assert_eq!(&p[..16], &[2, 0, 0, 0, 0, 0, 0, 0, 41, 0, 0, 0, 41, 0, 0, 0]);
        assert_eq!(&p[16..26], &[0x45, 0, 0, 41, 0, 0, 0x40, 0, 64, 6]);
        assert_eq!(csum(&p[16..36]), 0);
        assert_eq!(&p[36..56], &[0x9c, 0x40, 0x13, 0xc4, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0], "TCP, PSH|ACK, header length 20");
        assert_eq!(&p[56..], b"x");
        for proto in [Proto::Tls, Proto::Ws, Proto::Wss] {
            assert_eq!(pcap(&rec(proto, "192.0.2.1:40000", "192.0.2.2:5060", 2.0, b"x"))[25], 6, "{proto:?} is written as TCP");
        }
    }

    #[test]
    fn pcap_ipv6_and_mixed_families() {
        let p = pcap(&rec(Proto::Udp, "[2001:db8::1]:5060", "[2001:db8::2]:5060", 3.0, b"ab"));
        assert_eq!(u32::from_le_bytes(p[8..12].try_into().unwrap()), 40 + 8 + 2);
        assert_eq!(&p[16..24], &[0x60, 0, 0, 0, 0, 10, 17, 64], "version 6, payload 10, UDP, hop limit 64");
        assert_eq!(&p[24..40], &"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(&p[40..56], &"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(&p[56..64], &[0x13, 0xc4, 0x13, 0xc4, 0, 10, 0, 0]);
        let m = pcap(&rec(Proto::Tcp, "10.0.0.1:1", "[::1]:2", 3.0, b""));
        assert_eq!(m[16] >> 4, 6, "one IPv6 side: an IPv6 packet");
        assert_eq!(m[22], 6);
        assert_eq!(&m[24..40], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
    }

    #[test]
    fn pcap_record_at_the_snap_length_is_whole() {
        let room = SNAPLEN - 20 - 8;
        let p = pcap(&rec(Proto::Udp, "10.0.0.1:1", "10.0.0.2:2", 1.0, &vec![b'x'; room]));
        assert_eq!(p.len(), 16 + SNAPLEN);
        assert_eq!(&p[8..12], &p[12..16], "not cut");
        let p = pcap(&rec(Proto::Udp, "10.0.0.1:1", "10.0.0.2:2", 1.0, &vec![b'x'; room + 1]));
        assert_eq!(p.len(), 16 + SNAPLEN);
        assert_eq!(u32::from_le_bytes(p[12..16].try_into().unwrap()), u32::try_from(SNAPLEN + 1).unwrap());
    }

    #[test]
    fn times_before_1970_and_beyond_u32() {
        let at = |t: f64| pcap(&rec(Proto::Udp, "10.0.0.1:1", "10.0.0.2:2", t, b""))[..8].to_vec();
        assert_eq!(at(-5.5), [0, 0, 0, 0, 0, 0, 0, 0], "negative times read 0 (and 0 µs, not a wrapped fraction)");
        assert_eq!(at(5e10)[..4], [0xff; 4]);
        assert_eq!(at(f64::NAN), [0; 8]);
        let cases = [(0.0, (0, 0)), (1.5, (1, 500_000)), (59.000_25, (59, 250)), (-0.5, (0, 0)), (f64::INFINITY, (i64::MAX, 0))];
        for (t, want) in cases {
            let (s, us) = secs_micros(t);
            assert_eq!((s, us), want, "{t}");
        }
    }

    #[test]
    fn stamp_civil_dates() {
        let cases: &[(f64, &str, &str)] = &[
            (0.0, "1970-01-01--00-00-00", "1970-01-01 00:00:00 UTC"),
            (951_782_400.0, "2000-02-29--00-00-00", "2000-02-29 00:00:00 UTC"),
            (951_868_799.9, "2000-02-29--23-59-59", "2000-02-29 23:59:59 UTC"),
            (1_700_000_000.0, "2023-11-14--22-13-20", "2023-11-14 22:13:20 UTC"),
            (1_795_651_199.0, "2026-11-25--23-59-59", "2026-11-25 23:59:59 UTC"),
            (4_102_444_800.0, "2100-01-01--00-00-00", "2100-01-01 00:00:00 UTC"),
            (-1.0, "1969-12-31--23-59-59", "1969-12-31 23:59:59 UTC"),
        ];
        for &(t, file, line) in cases {
            assert_eq!(stamp(t), (file.to_string(), line.to_string()), "{t}");
        }
    }

    #[test]
    fn text_record_layout() {
        let r = Rec { tag: "snd".into(), ..rec(Proto::Tcp, "[2001:db8::1]:5061", "[2001:db8::2]:5062", 1.5, b"BYE sip:x SIP/2.0\r\n\r\n") };
        let want = format!(
            "====================\ntag: snd\npid: {}\nprocess: 0\ntime: 1.500000\ndate: 1970-01-01 00:00:01 UTC\nproto: tcp ipv6\nsrcip: 2001:db8::1\nsrcport: 5061\ndstip: 2001:db8::2\ndstport: 5062\n~~~~~~~~~~~~~~~~~~~~\nBYE sip:x SIP/2.0\r\n\r\n||||||||||||||||||||\n",
            std::process::id()
        );
        assert_eq!(String::from_utf8(text(&r)).unwrap(), want);
        let r = rec(Proto::Udp, "10.0.0.1:1", "10.0.0.2:2", 0.0, b"");
        assert!(String::from_utf8(text(&r)).unwrap().contains("\nproto: udp ipv4\n"));
    }

    #[test]
    fn len16_saturates() {
        assert_eq!(len16(0), [0, 0]);
        assert_eq!(len16(65_535), [0xff, 0xff]);
        assert_eq!(len16(65_536), [0xff, 0xff]);
        assert_eq!(len16(usize::MAX), [0xff, 0xff]);
    }

    #[test]
    fn params() {
        let d = SipDump::default();
        d.set_param("folder", &Arg::Str("/var/tmp//".into())).unwrap();
        assert_eq!(*lock(&d.folder), "/var/tmp");
        d.set_param("rotate", &Arg::Int(0)).unwrap();
        assert_eq!(d.rotate.load(Ordering::Relaxed), 1);
        d.set_param("mode", &Arg::Int(-1)).unwrap();
        assert_eq!(d.mode.load(Ordering::Relaxed), 0);
        d.set_param("enable", &Arg::Str("yes".into())).unwrap();
        assert!(d.enabled.load(Ordering::Relaxed));
        assert!(d.set_param("nope", &Arg::Int(1)).is_err());
    }
}
