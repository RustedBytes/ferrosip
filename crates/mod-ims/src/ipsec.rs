//! `ims_ipsec_pcscf`: the RFC 3329 security-agreement side of IPsec at a
//! P-CSCF (TS 33.203).
//!
//! * `ipsec_create("location")` runs in the onreply route of the 401 to a
//!   REGISTER. It reads the UE's `Security-Client` (from the request),
//!   allocates our SPIs, keeps the security association (the CK/IK from
//!   the S-CSCF's challenge), adds `Security-Server` to the 401 and strips
//!   `ck`/`ik` from WWW-Authenticate before the challenge reaches the UE.
//! * `ipsec_forward("location")` sends a request to the UE's protected
//!   server port (`port-s` of its Security-Client).
//! * `ipsec_destroy("location")` drops the association.
//! * RPC `ipsec.list`.
//!
//! With `ipsec_kernel=1` the four ESP transport-mode SAs and their policies
//! are installed in the kernel with `ip xfrm` (iproute2; needs CAP_NET_ADMIN
//! and XFRM support), keyed from IK (integrity) and CK (encryption) as in
//! TS 33.203, and removed by `ipsec_destroy`. Whether the kernel accepts
//! them is probed at startup; if not, a warning is logged and messages use
//! the negotiated ports in clear (`ipsec.list` shows `"kernel"`).
//! Parameters: `ipsec_client_port` (5062), `ipsec_server_port` (5063),
//! `ipsec_spi_id_start` (100), `ipsec_listen_addr` (our address for the
//! SAs; default the advertised UDP address), `ipsec_kernel`.

use mod_txn::Tm;
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::{Arg, Ctx, Dest, Module, Proto, Registry};
use sip_parser::HdrFlags;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug, Default)]
struct Sa {
    port_uc: u16,
    port_us: u16,
    spi_uc: u32,
    spi_us: u32,
    spi_pc: u32,
    spi_ps: u32,
    alg: String,
    ealg: String,
    has_keys: bool,
    /// Hex CK / IK from the challenge.
    ck: String,
    ik: String,
    /// Our address and ports, and whether the kernel SAs are installed.
    local: Option<IpAddr>,
    port_pc: u16,
    port_ps: u16,
    kernel: bool,
}

/// `ip` argument lists for the four SAs and policies of an association
/// (`add` = true) or to remove them.
fn xfrm_cmds(sa: &Sa, ue: IpAddr, pc: IpAddr, add: bool) -> Vec<Vec<String>> {
    let (auth, key) = match sa.alg.as_str() {
        "hmac-md5-96" => ("hmac(md5)", sa.ik.clone()),
        _ => ("hmac(sha1)", format!("{}00000000", sa.ik)), // 128-bit IK padded to 160
    };
    let enc: (String, String) = match sa.ealg.as_str() {
        "aes-cbc" => ("cbc(aes)".into(), format!("0x{}", sa.ck)),
        "des-ede3-cbc" => ("cbc(des3_ede)".into(), {
            // 3DES key = CK1 || CK2 || CK1 (TS 33.203 I.6). `ck` comes from
            // the wire: take characters, not bytes, so non-ASCII cannot panic.
            let ck1: String = sa.ck.chars().take(16).collect();
            format!("0x{}{ck1}", sa.ck)
        }),
        _ => ("ecb(cipher_null)".into(), String::new()),
    };
    // (src, dst, spi, sport, dport, dir)
    let flows = [
        (ue, pc, sa.spi_ps, sa.port_uc, sa.port_ps, "in"),  // UE client → our server
        (ue, pc, sa.spi_pc, sa.port_us, sa.port_pc, "in"),  // UE server → our client
        (pc, ue, sa.spi_us, sa.port_pc, sa.port_us, "out"), // our client → UE server
        (pc, ue, sa.spi_uc, sa.port_ps, sa.port_uc, "out"), // our server → UE client
    ];
    let mut out = Vec::new();
    for (src, dst, spi, sport, dport, dir) in flows {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (s, d, spi_hex, sp, dp) = (src.to_string(), dst.to_string(), format!("0x{spi:x}"), sport.to_string(), dport.to_string());
        let reqid = spi.to_string();
        if add {
            let mut st = v(&[
                "xfrm",
                "state",
                "add",
                "src",
                &s,
                "dst",
                &d,
                "proto",
                "esp",
                "spi",
                &spi_hex,
                "reqid",
                &reqid,
                "mode",
                "transport",
                "replay-window",
                "32",
                "auth-trunc",
                auth,
                &format!("0x{key}"),
                "96",
                "enc",
                &enc.0,
            ]);
            st.push(enc.1.clone()); // "" (an empty argument) for cipher_null
            st.extend(v(&["sel", "src", &s, "dst", &d, "proto", "udp", "sport", &sp, "dport", &dp]));
            out.push(st);
            out.push(v(&[
                "xfrm",
                "policy",
                "add",
                "src",
                &format!("{s}/32"),
                "dst",
                &format!("{d}/32"),
                "proto",
                "udp",
                "sport",
                &sp,
                "dport",
                &dp,
                "dir",
                dir,
                "tmpl",
                "src",
                &s,
                "dst",
                &d,
                "proto",
                "esp",
                "reqid",
                &reqid,
                "mode",
                "transport",
            ]));
        } else {
            out.push(v(&["xfrm", "state", "delete", "src", &s, "dst", &d, "proto", "esp", "spi", &spi_hex]));
            out.push(v(&[
                "xfrm",
                "policy",
                "delete",
                "src",
                &format!("{s}/32"),
                "dst",
                &format!("{d}/32"),
                "proto",
                "udp",
                "sport",
                &sp,
                "dport",
                &dp,
                "dir",
                dir,
            ]));
        }
    }
    out
}

fn run_ip(args: &[String]) -> Result<(), String> {
    let out = std::process::Command::new("ip").args(args).output().map_err(|e| format!("ip: {e}"))?;
    if out.status.success() { Ok(()) } else { Err(format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim())) }
}

pub struct Ipsec {
    port_pc: AtomicU16,
    port_ps: AtomicU16,
    spi: AtomicU32,
    /// Keyed by the UE's unprotected address (several UEs can share an IP).
    sas: Mutex<HashMap<SocketAddr, Sa>>,
    tm: OnceLock<Arc<Tm>>,
    listen: Mutex<Option<IpAddr>>,
    /// 0 off, 1 requested, 2 available, 3 requested but unavailable.
    kernel: std::sync::atomic::AtomicU8,
    net: OnceLock<Arc<dyn sip_core::Outbound>>,
}

impl Ipsec {
    /// Two consecutive SPIs (ours as client, as server). The counter wraps
    /// around the 32-bit space; a pair that would hold 0 (invalid) or
    /// straddle the wrap is skipped.
    fn next_spis(&self) -> (u32, u32) {
        loop {
            let base = self.spi.fetch_add(2, Ordering::Relaxed);
            if base != 0
                && let Some(next) = base.checked_add(1)
            {
                return (base, next);
            }
        }
    }
}

impl Default for Ipsec {
    fn default() -> Self {
        Self {
            port_pc: AtomicU16::new(5062),
            port_ps: AtomicU16::new(5063),
            spi: AtomicU32::new(100),
            sas: Mutex::default(),
            tm: OnceLock::new(),
            listen: Mutex::new(None),
            kernel: std::sync::atomic::AtomicU8::new(0),
            net: OnceLock::new(),
        }
    }
}

/// `name=value` parameters of a header value (`;`-separated), of its
/// first element when it lists several (`mech;…, mech;…`, `via, via`):
/// keys of a later one would replace the first one's.
fn params(v: &str) -> HashMap<String, String> {
    v.split(',')
        .next()
        .unwrap_or(v)
        .split(';')
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string()))
        .collect()
}

/// The value of header `name` in a raw message.
fn header(msg: &[u8], name: &str) -> Option<String> {
    let t = String::from_utf8_lossy(msg);
    let head = t.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// The UE's address from the request's first Via (`received` and `rport`
/// win over sent-by).
fn ue_of(req: &[u8]) -> Option<SocketAddr> {
    let via = header(req, "Via").or_else(|| header(req, "v"))?;
    let p = params(&via);
    let sent_by = via.split_whitespace().nth(1)?.split([';', ',']).next()?;
    let (host, port) = match sent_by.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(':') && p.parse::<u16>().is_ok() => (h, p.parse().ok()),
        _ => (sent_by, None),
    };
    let ip: IpAddr = match p.get("received").and_then(|r| r.parse().ok()) {
        Some(ip) => ip,
        None => host.trim_matches(|c| c == '[' || c == ']').parse().ok()?,
    };
    let port = p.get("rport").and_then(|r| r.parse().ok()).or(port).unwrap_or(5060);
    Some(SocketAddr::new(ip, port))
}

/// The UE's protected ports (`port-c`, `port-s`) from Security-Client
/// parameters; `None` when either is missing or not a port (1..=65535).
fn client_ports(p: &HashMap<String, String>) -> Option<(u16, u16)> {
    let port = |k: &str| p.get(k).and_then(|v| v.trim().parse::<u16>().ok()).filter(|&n| n != 0);
    Some((port("port-c")?, port("port-s")?))
}

fn config_port(name: &str, n: i64) -> Result<u16, String> {
    u16::try_from(n).ok().filter(|&n| n != 0).ok_or_else(|| format!("ims_ipsec_pcscf: {name} must be 1..65535, not {n}"))
}

impl Ipsec {
    fn create(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        if ctx.msg.is_request() || ctx.msg.status() != Some(401) {
            return -1;
        }
        let Some(req) = self.tm.get().and_then(|t| t.request_of_reply(ctx)) else { return -1 };
        let (Some(sc), Some(ue)) = (header(&req, "Security-Client"), ue_of(&req)) else { return -1 };
        let p = params(&sc);
        let num = |k: &str| p.get(k).and_then(|v| v.parse::<u32>().ok());
        let Some((port_uc, port_us)) = client_ports(&p) else { return -1 };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let (spi_pc, spi_ps) = self.next_spis();
        let (port_pc, port_ps) = (self.port_pc.load(Ordering::Relaxed), self.port_ps.load(Ordering::Relaxed));
        let mut sa = Sa {
            port_uc,
            port_us,
            spi_uc: num("spi-c").unwrap_or(0),
            spi_us: num("spi-s").unwrap_or(0),
            spi_pc,
            spi_ps,
            alg: p.get("alg").cloned().unwrap_or_else(|| "hmac-sha-1-96".into()),
            ealg: p.get("ealg").cloned().unwrap_or_else(|| "null".into()),
            has_keys: false,
            port_pc,
            port_ps,
            ..Default::default()
        };
        // Strip ck/ik (they are for us, not the UE).
        let buf = ctx.msg.buf;
        let www: Vec<(usize, usize)> = ctx.msg.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"www-authenticate")).map(|h| (h.start, h.end)).collect();
        for (s, e) in www {
            let Some(raw) = buf.get(s..e) else { continue };
            let line = String::from_utf8_lossy(raw).into_owned();
            let (name, val) = line.split_once(':').unwrap_or((&line, ""));
            let kept: Vec<&str> = val
                .trim_end()
                .split(',')
                .filter(|x| {
                    let (k, v) = x.trim().split_once('=').unwrap_or((x.trim(), ""));
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim().trim_matches('"').to_ascii_lowercase();
                    if k == "ck" || k == "ik" {
                        sa.has_keys = true;
                        if k == "ck" {
                            sa.ck = v
                        } else {
                            sa.ik = v
                        }
                        return false;
                    }
                    true
                })
                .collect();
            ctx.lumps.replace(s, raw.len(), format!("{name}:{}\r\n", kept.join(",")).into_bytes());
        }
        let line = format!(
            "Security-Server: ipsec-3gpp;q=0.1;prot=esp;mod=trans;spi-c={};spi-s={};port-c={port_pc};port-s={port_ps};alg={};ealg={}\r\n",
            sa.spi_pc, sa.spi_ps, sa.alg, sa.ealg
        );
        let eoh = ctx.msg.eoh_offset().unwrap_or(buf.len());
        ctx.lumps.insert(eoh, line.into_bytes());
        sa.local = self.local_ip();
        if self.kernel.load(Ordering::Relaxed) == 2
            && sa.has_keys
            && sa.ik.len() >= 32
            && let Some(pc) = sa.local
        {
            // Replace an older association of this UE first.
            if let Some(old) = lock(&self.sas).remove(&ue).filter(|o| o.kernel) {
                self.uninstall(&old, ue.ip());
            }
            match xfrm_cmds(&sa, ue.ip(), pc, true).iter().try_for_each(|c| run_ip(c)) {
                Ok(()) => sa.kernel = true,
                Err(e) => {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("ims_ipsec_pcscf: {e}"));
                    sa.kernel = true; // remove what was added
                    self.uninstall(&sa, ue.ip());
                    sa.kernel = false;
                }
            }
        }
        lock(&self.sas).insert(ue, sa);
        1
    }

    fn local_ip(&self) -> Option<IpAddr> {
        (*lock(&self.listen)).or_else(|| self.net.get().and_then(|n| n.advertise(Proto::Udp)).map(|a| a.ip()))
    }

    fn uninstall(&self, sa: &Sa, ue: IpAddr) {
        if let (true, Some(pc)) = (sa.kernel, sa.local) {
            for c in xfrm_cmds(sa, ue, pc, false) {
                let _ = run_ip(&c);
            }
        }
    }

    /// The association of the UE at `addr`: its unprotected address, or
    /// one of its protected ports (a Contact usually names the protected
    /// server port).
    fn find(&self, addr: SocketAddr) -> Option<(SocketAddr, Sa)> {
        let sas = lock(&self.sas);
        if let Some(sa) = sas.get(&addr) {
            return Some((addr, sa.clone()));
        }
        let port = addr.port();
        sas.iter().find(|(k, sa)| k.ip() == addr.ip() && (sa.port_us == port || sa.port_uc == port)).map(|(k, sa)| (*k, sa.clone()))
    }

    fn forward(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let addr = match ctx.dst {
            Some(d) => Some(d.addr),
            None => sip_core::pvcore::dest_from_uri(ctx.ruri()).map(|d| d.addr),
        };
        let Some(addr) = addr else { return -1 };
        let Some((_, sa)) = self.find(addr) else { return -1 };
        ctx.dst = Some(Dest::new(Proto::Udp, SocketAddr::new(addr.ip(), sa.port_us)));
        1
    }

    fn destroy(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let addr = if ctx.msg.is_request() { Some(ctx.src.addr) } else { self.tm.get().and_then(|t| t.request_of_reply(ctx)).and_then(|r| ue_of(&r)) };
        let Some((key, _)) = addr.and_then(|a| self.find(a)) else { return -1 };
        let removed = lock(&self.sas).remove(&key);
        match removed {
            Some(sa) => {
                self.uninstall(&sa, key.ip());
                1
            }
            None => -1,
        }
    }
}

impl Module for Ipsec {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("ipsec_client_port", Ty::Int { min: 1, max: 65535 }, "5062", "Our protected client port"),
            p("ipsec_server_port", Ty::Int { min: 1, max: 65535 }, "5063", "Our protected server port"),
            p("ipsec_spi_id_start", Ty::Int { min: 1, max: i64::from(u32::MAX) }, "100", "First SPI we allocate"),
            p("ipsec_listen_addr", Ty::Str, "", "Our IP address for the security associations (default: the advertised UDP address)"),
            p("ipsec_kernel", Ty::Bool, "false", "Install the ESP security associations in the kernel with ip xfrm"),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_ipsec_pcscf"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{Ret, ctx, sig};
        const LOC: &[&str] = &["location"];
        Some(vec![
            sig("ipsec_create", "create", &[], Ret::Bool, "Set up IPsec security associations from the 401 challenge to a REGISTER")
                .fixed(LOC)
                .allowed(ctx::REPLY),
            sig("ipsec_forward", "forward", &[], Ret::Bool, "Send to the UE through its protected server port").fixed(LOC),
            sig("ipsec_destroy", "destroy", &[], Ret::Bool, "Remove the UE's IPsec security associations").fixed(LOC).allowed(ctx::ROUTE | ctx::REPLY),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "ipsec_client_port" => self.port_pc.store(config_port(name, v.int()?)?, Ordering::Relaxed),
            "ipsec_server_port" => self.port_ps.store(config_port(name, v.int()?)?, Ordering::Relaxed),
            "ipsec_spi_id_start" => {
                let n = v.int()?;
                let n =
                    u32::try_from(n).ok().filter(|&n| n != 0).ok_or_else(|| format!("ims_ipsec_pcscf: ipsec_spi_id_start must be 1..{}, not {n}", u32::MAX))?;
                self.spi.store(n, Ordering::Relaxed)
            }
            "ipsec_listen_addr" => *lock(&self.listen) = Some(v.str()?.parse().map_err(|_| "ims_ipsec_pcscf: bad ipsec_listen_addr")?),
            "ipsec_kernel" => self.kernel.store(u8::from(v.int()? != 0), Ordering::Relaxed),
            "ipsec_listen_addr6"
            | "ipsec_max_connections"
            | "ipsec_spi_id_range"
            | "ipsec_preferred_alg"
            | "ipsec_preferred_ealg"
            | "ipsec_reuse_server_port"
            | "ipsec_listen_name" => {}
            _ => return Err(format!("ims_ipsec_pcscf: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.tm.set(reg.api::<Tm>().ok_or("ims_ipsec_pcscf needs tm loaded first")?);
        let table = |a: &[Arg]| -> Result<(), String> {
            if a.is_empty() || a.len() > 2 {
                return Err("expected \"location\"[, flags]".into());
            }
            Ok(())
        };
        let m = "ims_ipsec_pcscf";
        let me = self.clone();
        reg.export(m, "ipsec_create", table, move |ctx: &mut Ctx, _: &()| me.create(ctx));
        let me = self.clone();
        reg.export(m, "ipsec_forward", table, move |ctx: &mut Ctx, _: &()| me.forward(ctx));
        let me = self.clone();
        reg.export(m, "ipsec_destroy", table, move |ctx: &mut Ctx, _: &()| me.destroy(ctx));
        let me = self.clone();
        reg.rpc.add("ipsec.list", "Security associations (no keys)", move |_| {
            Ok(lock(&me.sas)
                .iter()
                .map(|(ip, s)| {
                    let kernel = match me.kernel.load(Ordering::Relaxed) {
                        0 => "off",
                        3 => "unavailable",
                        _ if s.kernel => "installed",
                        _ => "not installed",
                    };
                    json!({"ue": ip.ip().to_string(), "ue_port": ip.port(), "port_uc": s.port_uc, "port_us": s.port_us, "spi_uc": s.spi_uc, "spi_us": s.spi_us,
                           "spi_pc": s.spi_pc, "spi_ps": s.spi_ps, "alg": s.alg, "ealg": s.ealg, "keys": s.has_keys, "kernel": kernel})
                })
                .collect())
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn sip_core::Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        if self.kernel.load(Ordering::Relaxed) == 0 {
            return Ok(());
        }
        // Can we install SAs at all? (CAP_NET_ADMIN, kernel XFRM support)
        let probe = |add: bool| {
            let a = ["xfrm", "state", if add { "add" } else { "delete" }, "src", "127.0.0.1", "dst", "127.0.0.1", "proto", "esp", "spi", "0xfffffff0"];
            let mut v: Vec<String> = a.iter().map(|s| s.to_string()).collect();
            if add {
                v.extend(
                    ["mode", "transport", "auth", "hmac(sha1)", "0x0000000000000000000000000000000000000000", "enc", "ecb(cipher_null)", ""]
                        .iter()
                        .map(|s| s.to_string()),
                );
            }
            run_ip(&v)
        };
        match probe(true) {
            Ok(()) => {
                let _ = probe(false);
                self.kernel.store(2, Ordering::Relaxed);
            }
            Err(e) => {
                sip_core::log::log(sip_core::log::L_WARN, &format!("ims_ipsec_pcscf: kernel IPsec unavailable ({e}); negotiating only"));
                self.kernel.store(3, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn spis_wrap_without_overflow() {
        use std::sync::atomic::Ordering;
        let ipsec = super::Ipsec::default();
        assert_eq!(ipsec.next_spis(), (100, 101));
        // ipsec_spi_id_start may be 4294967295: `base + 1` must not overflow.
        ipsec.spi.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(ipsec.next_spis(), (1, 2));
        ipsec.spi.store(u32::MAX - 1, Ordering::Relaxed);
        assert_eq!(ipsec.next_spis(), (u32::MAX - 1, u32::MAX));
        assert_eq!(ipsec.next_spis(), (2, 3), "0 is not an SPI");
    }

    #[test]
    fn security_client_ports_must_be_ports() {
        let ports = |h: &str| super::client_ports(&super::params(h));
        assert_eq!(ports("ipsec-3gpp;alg=hmac-sha-1-96;spi-c=1;spi-s=2;port-c=5100;port-s=5101"), Some((5100, 5101)));
        // 70000 must not wrap to 4464.
        assert_eq!(ports("ipsec-3gpp;spi-c=1;spi-s=2;port-c=70000;port-s=5101"), None);
        assert_eq!(ports("ipsec-3gpp;port-c=5100;port-s=65536"), None);
        assert_eq!(ports("ipsec-3gpp;port-c=0;port-s=5101"), None);
        assert_eq!(ports("ipsec-3gpp;port-c=-1;port-s=5101"), None);
        assert_eq!(ports("ipsec-3gpp;port-c=5100"), None);
        assert!(super::config_port("ipsec_client_port", 65536).is_err());
        assert_eq!(super::config_port("ipsec_client_port", 5062), Ok(5062));
    }

    #[test]
    fn xfrm_commands() {
        let sa = super::Sa {
            port_uc: 5100,
            port_us: 5101,
            spi_uc: 1111,
            spi_us: 2222,
            spi_pc: 100,
            spi_ps: 101,
            alg: "hmac-sha-1-96".into(),
            ealg: "aes-cbc".into(),
            ck: "aa".repeat(16),
            ik: "bb".repeat(16),
            port_pc: 5062,
            port_ps: 5063,
            ..Default::default()
        };
        let c = super::xfrm_cmds(&sa, "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), true);
        assert_eq!(c.len(), 8);
        let first = c[0].join(" ");
        assert!(first.starts_with("xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi 0x65 reqid 101 mode transport"), "{first}");
        assert!(first.contains(&format!("auth-trunc hmac(sha1) 0x{}00000000 96 enc cbc(aes) 0x{}", "bb".repeat(16), "aa".repeat(16))), "{first}");
        assert!(first.ends_with("sel src 10.0.0.2 dst 10.0.0.1 proto udp sport 5100 dport 5063"), "{first}");
        assert!(c[7].join(" ").contains("dir out tmpl src 10.0.0.1 dst 10.0.0.2 proto esp reqid 1111"));
        let d = super::xfrm_cmds(&sa, "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), false);
        assert_eq!(d[0].join(" "), "xfrm state delete src 10.0.0.2 dst 10.0.0.1 proto esp spi 0x65");
    }

    #[test]
    fn des3_key_from_non_ascii_ck_does_not_panic() {
        // A non-hex CK whose 16th byte falls inside a UTF-8 character used
        // to panic slicing `&ck[..16]`.
        let sa = super::Sa { ealg: "des-ede3-cbc".into(), ck: format!("{}é{}", "a".repeat(15), "b".repeat(16)), ..Default::default() };
        let c = super::xfrm_cmds(&sa, "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), true);
        assert!(c[0].join(" ").contains(&format!("0x{}{}é", sa.ck, "a".repeat(15))));
        let sa = super::Sa { ealg: "des-ede3-cbc".into(), ck: "0123456789abcdef".repeat(2), ..Default::default() };
        let c = super::xfrm_cmds(&sa, "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), true);
        assert!(c[0].join(" ").contains(&format!("0x{}0123456789abcdef", sa.ck)));
    }

    #[test]
    fn security_client_with_several_mechanisms_uses_the_first() {
        // UEs offer several algorithms in one Security-Client (RFC 3329 §2.2).
        let sc = "ipsec-3gpp;alg=hmac-md5-96;spi-c=1111;spi-s=2222;port-c=5100;port-s=5101, ipsec-3gpp;alg=hmac-sha-1-96;spi-c=3333;spi-s=4444;port-c=5200;port-s=5201";
        let p = super::params(sc);
        assert_eq!(super::client_ports(&p), Some((5100, 5101)));
        assert_eq!((p["alg"].as_str(), p["spi-c"].as_str(), p["spi-s"].as_str()), ("hmac-md5-96", "1111", "2222"));
        // Quoted values and spacing.
        let p = super::params("ipsec-3gpp ; ALG = \"hmac-sha-1-96\" ;ealg=aes-cbc; port-c=1;port-s=2;mod");
        assert_eq!((p["alg"].as_str(), p["ealg"].as_str()), ("hmac-sha-1-96", "aes-cbc"));
        assert!(super::params("ipsec-3gpp").is_empty());
    }

    #[test]
    fn ue_address_from_the_first_via() {
        let via = |v: &str| super::ue_of(format!("REGISTER sip:x SIP/2.0\r\n{v}\r\n\r\n").as_bytes());
        // (Via line, UE address)
        let cases = [
            ("Via: SIP/2.0/UDP 10.1.2.3;branch=z9hG4bKx", Some("10.1.2.3:5060")),
            ("v: SIP/2.0/UDP 10.1.2.3:5070;branch=z9hG4bKx", Some("10.1.2.3:5070")),
            ("Via: SIP/2.0/UDP 10.1.2.3:5070;rport;branch=z9hG4bKx", Some("10.1.2.3:5070")),
            ("Via: SIP/2.0/UDP [2001:db8::1]:5080;branch=z9hG4bKx", Some("[2001:db8::1]:5080")),
            ("Via: SIP/2.0/UDP [2001:db8::1];branch=z9hG4bKx", Some("[2001:db8::1]:5060")),
            ("Via: SIP/2.0/UDP 10.1.2.3:5070;received=192.0.2.1;rport=6000, SIP/2.0/UDP 10.9.9.9;received=192.0.2.99;rport=7000", Some("192.0.2.1:6000")),
            ("Via: SIP/2.0/UDP 10.1.2.3:5070, SIP/2.0/UDP 10.9.9.9;received=192.0.2.99;rport=7000", Some("10.1.2.3:5070")),
            ("Via: SIP/2.0/UDP host.example:5060", None),
        ];
        for (v, want) in cases {
            assert_eq!(via(v), want.map(|w| w.parse().unwrap()), "{v}");
        }
        assert_eq!(super::ue_of(b"REGISTER sip:x SIP/2.0\r\n\r\n"), None);
    }

    #[test]
    fn find_by_unprotected_address_or_protected_port() {
        let ipsec = super::Ipsec::default();
        let ue: std::net::SocketAddr = "10.1.2.3:5060".parse().unwrap();
        ipsec.sas.lock().unwrap().insert(ue, super::Sa { port_uc: 5100, port_us: 5101, ..Default::default() });
        for (addr, found) in [("10.1.2.3:5060", true), ("10.1.2.3:5101", true), ("10.1.2.3:5100", true), ("10.1.2.3:5102", false), ("10.1.2.4:5101", false)] {
            assert_eq!(ipsec.find(addr.parse().unwrap()).map(|(k, _)| k), found.then_some(ue), "{addr}");
        }
    }

    #[test]
    fn parsing() {
        let req = b"REGISTER sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bKx\r\nSecurity-Client: ipsec-3gpp;alg=hmac-md5-96;spi-c=1111;spi-s=2222;port-c=5100;port-s=5101\r\n\r\n";
        assert_eq!(super::ue_of(req), Some("10.1.2.3:5060".parse().unwrap()));
        let nat = b"REGISTER sip:x SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.2.3:5070;rport=40000;received=192.0.2.9;branch=z9hG4bKx\r\n\r\n";
        assert_eq!(super::ue_of(nat), Some("192.0.2.9:40000".parse().unwrap()));
        let bare = b"REGISTER sip:x SIP/2.0\r\nVia: SIP/2.0/UDP ue.example;branch=z9hG4bKx\r\n\r\n";
        assert_eq!(super::ue_of(bare), None);
        let p = super::params(&super::header(req, "Security-Client").unwrap());
        assert_eq!(p["port-s"], "5101");
        assert_eq!(p["alg"], "hmac-md5-96");
    }

    #[test]
    fn xfrm_md5_and_null_encryption() {
        let sa = super::Sa { alg: "hmac-md5-96".into(), ealg: "null".into(), ik: "bb".repeat(16), spi_ps: 7, ..Default::default() };
        let c = super::xfrm_cmds(&sa, "10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap(), true);
        let first = c[0].join(" ");
        assert!(first.contains(&format!("auth-trunc hmac(md5) 0x{} 96 enc ecb(cipher_null)  sel", "bb".repeat(16))), "IK unpadded, an empty key: {first}");
        assert_eq!(c[0].iter().filter(|a| a.is_empty()).count(), 1);
    }

    #[test]
    fn create_only_on_a_401() {
        use crate::testutil::{reply_msg, request, with_msg};
        let ipsec = super::Ipsec::default();
        assert_eq!(with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| ipsec.create(ctx)), -1);
        assert_eq!(with_msg(&reply_msg(200, "", ""), |ctx| ipsec.create(ctx)), -1);
        assert_eq!(with_msg(&reply_msg(401, "", ""), |ctx| ipsec.create(ctx)), -1, "no tm: no request to read");
    }

    #[test]
    fn forward_and_destroy() {
        use crate::testutil::{reply_msg, request, with_msg};
        let ipsec = super::Ipsec::default();
        let ue: std::net::SocketAddr = "192.0.2.9:5060".parse().unwrap();
        ipsec.sas.lock().unwrap().insert(ue, super::Sa { port_uc: 5100, port_us: 5101, ..Default::default() });
        let invite = request("INVITE", "sip:alice@192.0.2.99:5101", "sip:alice@ims.test", "", "");
        // $du wins over the R-URI.
        let dst = with_msg(&invite, |ctx| {
            ctx.dst = Some(sip_core::Dest::new(sip_core::Proto::Udp, "192.0.2.9:5100".parse().unwrap()));
            (ipsec.forward(ctx), ctx.dst.map(|d| d.addr))
        });
        assert_eq!(dst, (1, Some("192.0.2.9:5101".parse().unwrap())));
        assert_eq!(with_msg(&invite, |ctx| ipsec.forward(ctx)), -1, "the R-URI host has no association");
        let ruri = request("INVITE", "sip:alice@ims.test", "sip:alice@ims.test", "", "");
        assert_eq!(with_msg(&ruri, |ctx| ipsec.forward(ctx)), -1, "no address at all");
        // A reply without tm: the request (and so the UE) is unknown.
        assert_eq!(with_msg(&reply_msg(200, "", ""), |ctx| ipsec.destroy(ctx)), -1);
        // A request from the UE removes its association, once.
        let bye = request("BYE", "sip:pcscf.ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&bye, |ctx| ipsec.destroy(ctx)), 1);
        assert!(ipsec.sas.lock().unwrap().is_empty());
        assert_eq!(with_msg(&bye, |ctx| ipsec.destroy(ctx)), -1);
    }

    #[test]
    fn parameters() {
        use crate::testutil::s;
        use sip_core::{Arg, Module};
        let ipsec = super::Ipsec::default();
        for ignored in ["ipsec_listen_addr6", "ipsec_max_connections", "ipsec_listen_name"] {
            ipsec.set_param(ignored, &s("x")).unwrap();
        }
        assert!(ipsec.set_param("nope", &s("x")).unwrap_err().contains("unknown parameter"));
        assert!(ipsec.set_param("ipsec_spi_id_start", &Arg::Int(0)).unwrap_err().contains("ipsec_spi_id_start must be"));
        assert!(ipsec.set_param("ipsec_spi_id_start", &Arg::Int(1 << 32)).is_err());
        assert!(ipsec.set_param("ipsec_listen_addr", &s("not an ip")).is_err());
        assert!(ipsec.set_param("ipsec_server_port", &Arg::Int(0)).is_err());
        ipsec.set_param("ipsec_spi_id_start", &Arg::Int(5000)).unwrap();
        assert_eq!(ipsec.next_spis(), (5000, 5001));
        // The listen address wins over the advertised one.
        assert_eq!(ipsec.local_ip(), None);
        ipsec.set_param("ipsec_listen_addr", &s("10.0.0.1")).unwrap();
        assert_eq!(ipsec.local_ip(), Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn loading_spawning_and_the_rpc() {
        use crate::testutil::{Here, fixup_err, registry, rpc, s};
        use sip_core::Module;
        use std::sync::Arc;
        assert!(sip_core::Registry::default().load(Arc::new(super::Ipsec::default())).unwrap_err().contains("needs tm"));
        let ipsec = Arc::new(super::Ipsec::default());
        let mut reg = registry(true);
        reg.load(ipsec.clone()).unwrap();
        assert!(fixup_err(&reg, "ipsec_create", &[]).is_some());
        assert!(fixup_err(&reg, "ipsec_forward", &[s("location"), s("0"), s("x")]).is_some());
        // Kernel SAs off: spawning only takes the network.
        ipsec.clone().spawn(Arc::new(Here::default())).unwrap();
        assert_eq!(ipsec.local_ip(), Some("127.0.0.1".parse().unwrap()), "the advertised UDP address");
        let ue: std::net::SocketAddr = "192.0.2.9:5060".parse().unwrap();
        ipsec.sas.lock().unwrap().insert(ue, super::Sa { port_uc: 5100, port_us: 5101, alg: "hmac-sha-1-96".into(), has_keys: true, ..Default::default() });
        let kernel = |state: u8, installed: bool| {
            ipsec.kernel.store(state, std::sync::atomic::Ordering::Relaxed);
            ipsec.sas.lock().unwrap().get_mut(&ue).unwrap().kernel = installed;
            rpc(&reg, "ipsec.list", sip_core::serde_json::json!([])).unwrap()[0]["kernel"].as_str().unwrap().to_string()
        };
        assert_eq!(kernel(0, false), "off");
        assert_eq!(kernel(3, false), "unavailable");
        assert_eq!(kernel(2, false), "not installed");
        assert_eq!(kernel(2, true), "installed");
        let row = &rpc(&reg, "ipsec.list", sip_core::serde_json::json!([])).unwrap()[0];
        assert_eq!(
            (row["ue"].as_str(), row["ue_port"].as_u64(), row["port_us"].as_u64(), row["keys"].as_bool()),
            (Some("192.0.2.9"), Some(5060), Some(5101), Some(true))
        );
    }
}
