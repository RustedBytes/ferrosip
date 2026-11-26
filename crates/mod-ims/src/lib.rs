//! IMS (Kamailio names, one `loadmodule` each): `cdp`, `cdp_avp`,
//! `ims_auth`, `ims_usrloc_scscf`, `ims_registrar_scscf`, `ims_isc`,
//! `ims_usrloc_pcscf`, `ims_registrar_pcscf`, `ims_qos`, `ims_charging`,
//! `ims_icscf`, `ims_ipsec_pcscf`, `ims_diameter_server`.
//!
//! Diameter comes from the `sip-diameter` crate; the `cdp` module owns the
//! peer manager and publishes it to the others. The Cx exchanges (UAR, LIR,
//! MAR, SAR) suspend the transaction while the HSS answers, as in Kamailio
//! (`cx_async`), and continue in the named reply route when the script has
//! it; Rx and Ro are synchronous, bounded by the cdp transaction timeout.

use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::{Arg, Module, Outbound, Registry};
use sip_diameter::{Config, Peers, codes};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod charging;
mod cx_async;
mod diameter_server;
mod icscf;
mod ipsec;
mod isc;
mod pcscf;
mod qos;
mod scscf;
pub mod subscription;
#[cfg(test)]
mod testutil;

/// Every module this crate provides (ferrosip.toml, `ferrosip schema`).
pub const NAMES: &[&str] = &[
    "cdp",
    "cdp_avp",
    "ims_usrloc_scscf",
    "ims_registrar_scscf",
    "ims_auth",
    "ims_isc",
    "ims_usrloc_pcscf",
    "ims_registrar_pcscf",
    "ims_qos",
    "ims_charging",
    "ims_icscf",
    "ims_ipsec_pcscf",
    "ims_diameter_server",
];

/// The module called `name`, if it lives in this crate.
pub fn module(name: &str) -> Option<Arc<dyn Module>> {
    Some(match name {
        "cdp" => Arc::new(Cdp::default()),
        "cdp_avp" => Arc::new(CdpAvp),
        "ims_usrloc_scscf" => Arc::new(scscf::UsrlocScscf::default()),
        "ims_registrar_scscf" => Arc::new(scscf::RegistrarScscf::default()),
        "ims_auth" => Arc::new(scscf::ImsAuth::default()),
        "ims_isc" => Arc::new(isc::Isc::default()),
        "ims_usrloc_pcscf" => Arc::new(pcscf::UsrlocPcscf::default()),
        "ims_registrar_pcscf" => Arc::new(pcscf::RegistrarPcscf::default()),
        "ims_qos" => Arc::new(qos::Qos::default()),
        "ims_charging" => Arc::new(charging::Charging::default()),
        "ims_icscf" => Arc::new(icscf::Icscf::default()),
        "ims_ipsec_pcscf" => Arc::new(ipsec::Ipsec::default()),
        "ims_diameter_server" => Arc::new(diameter_server::DiameterServer::default()),
        _ => return None,
    })
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in data.chunks(3) {
        let byte = |i: usize| c.get(i).copied().map_or(0, u32::from);
        let n = byte(0) << 16 | byte(1) << 8 | byte(2);
        // c.len() + 1 sextets carry data; '=' pads to four.
        for (i, sextet) in [n >> 18, n >> 12, n >> 6, n].into_iter().enumerate() {
            o.push(if i <= c.len() { T.get((sextet & 63) as usize).map_or('=', |&b| char::from(b)) } else { '=' });
        }
    }
    o
}

/// Exactly `N` script arguments.
pub(crate) fn args<const N: usize>(a: &[Arg]) -> Result<&[Arg; N], String> {
    a.try_into().map_err(|_| format!("expected {N} argument(s), got {}", a.len()))
}

pub(crate) fn md5_hex(parts: &[&[u8]]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b":");
        }
        h.update(p);
    }
    hex(&h.finalize())
}

#[allow(clippy::cast_possible_truncation, reason = "entropy mixing (splitmix64): only the low bits of the clock and of each hash are wanted")]
pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static S: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    (0..n)
        .map(|_| {
            let mut x = S.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed) ^ SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            (x ^ (x >> 31)) as u8
        })
        .collect()
}

/// `sip:user@host` (lower-case host, no params) — IMPU key; `tel:` kept.
pub(crate) fn impu_of(uri: &[u8]) -> Option<String> {
    let u = sip_parser::parse_uri(uri)?;
    if u.scheme.eq_ignore_ascii_case(b"tel") {
        let s = String::from_utf8_lossy(uri);
        return Some(s.split(';').next().unwrap_or(&s).to_string());
    }
    Some(format!("sip:{}@{}", String::from_utf8_lossy(u.user?), String::from_utf8_lossy(u.host).to_ascii_lowercase()))
}

/// The cdp peers, published by the `cdp` module.
pub struct CdpApi {
    pub peers: Arc<Peers>,
}

/// `cdp` — the Diameter peer manager: `config_file` (Kamailio's XML), or
/// ferrosip parameters `identity`, `realm`, `peer`
/// ("fqdn=hss.ims;realm=ims;host=127.0.0.1;port=3868[;proto=tls|sctp]"),
/// `listen` ("[tls:|sctp:]ip:port"), `auth_app` ("vendor:app"),
/// `default_route` ("fqdn[;metric=N]"), `realm_route`
/// ("realm=ims;fqdn=hss1.ims[;metric=N]"), `tls_certificate`,
/// `tls_private_key`, `tls_ca_list`, `tls_require_certificate`,
/// `transaction_timeout` (s). RPC `cdp.list_peers`.
#[derive(Default)]
pub struct Cdp {
    cfg: Mutex<Config>,
    file: Mutex<Option<String>>,
    peers: OnceLock<Arc<Peers>>,
}

/// "k=v;k=v" parameters.
fn kv_params(s: &str) -> Vec<(String, String)> {
    s.split(';').filter_map(|p| p.split_once('=').map(|(a, b)| (a.trim().to_ascii_lowercase(), b.trim().to_string()))).collect()
}

impl Module for Cdp {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("config_file", Ty::Str, "", "Kamailio's cdp XML config file (replaces the other parameters)"),
            p("identity", Ty::Str, "ferrosip.localdomain", "Our Diameter identity (Origin-Host)"),
            p("realm", Ty::Str, "localdomain", "Our Diameter realm (Origin-Realm)"),
            p("peer", Ty::List(&Ty::Str), "", "A Diameter peer: \"fqdn=hss.ims;realm=ims;host=127.0.0.1;port=3868[;proto=tls|sctp]\""),
            p("listen", Ty::List(&Ty::Str), "", "Where to accept Diameter connections: \"[tls:|sctp:]ip:port\""),
            p("auth_app", Ty::List(&Ty::Str), "", "Advertised auth application \"vendor:app\" (default Cx, Rx, Ro); peers with none in common get 5010"),
            p("default_route", Ty::List(&Ty::Str), "", "Peer for realms without a route table: \"fqdn[;metric=N]\" (lowest metric first)"),
            p("realm_route", Ty::List(&Ty::Str), "", "A realm route: \"realm=ims.test;fqdn=hss1.ims.test[;metric=N]\" (lowest metric first)"),
            p("tls_certificate", Ty::Str, "", "Our certificate (PEM) for TLS acceptors, and as client certificate"),
            p("tls_private_key", Ty::Str, "", "The private key (PEM) of tls_certificate"),
            p("tls_ca_list", Ty::Str, "", "CAs (PEM) that verify TLS peers (and clients, with tls_require_certificate)"),
            p("tls_require_certificate", Ty::Bool, "false", "TLS acceptors require a verified client certificate"),
            p("transaction_timeout", Ty::Duration(Unit::Sec), "5s", "How long to wait for a Diameter answer"),
            p("tc", Ty::Duration(Unit::Sec), "30s", "Peer reconnect interval"),
        ])
    }

    fn name(&self) -> &'static str {
        "cdp"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let mut c = lock(&self.cfg);
        match name {
            "config_file" => *lock(&self.file) = Some(v.str()?.into()),
            "identity" => c.identity = v.str()?.into(),
            "realm" => c.realm = v.str()?.into(),
            "listen" => {
                let v = v.str()?;
                let (proto, addr) = match v.split_once(':') {
                    Some((pr, rest)) if matches!(pr.to_ascii_lowercase().as_str(), "tcp" | "tls" | "sctp") => (sip_diameter::Proto::parse(pr)?, rest),
                    _ => (sip_diameter::Proto::Tcp, v),
                };
                c.listen.push((proto, addr.to_string()));
            }
            "default_route" => {
                let kv = kv_params(&format!("fqdn={}", v.str()?));
                let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, y)| y.clone());
                let metric = get("metric").map(|m| m.parse().map_err(|_| format!("cdp default_route: bad metric {m:?}"))).transpose()?;
                c.default_routes.push(sip_diameter::Route { fqdn: get("fqdn").unwrap_or_default(), metric: metric.unwrap_or(0) });
            }
            "realm_route" => {
                let kv = kv_params(v.str()?);
                let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, y)| y.clone());
                let (Some(realm), Some(fqdn)) = (get("realm"), get("fqdn")) else { return Err("cdp realm_route: realm= and fqdn= are required".into()) };
                let metric = get("metric").map(|m| m.parse().map_err(|_| format!("cdp realm_route: bad metric {m:?}"))).transpose()?.unwrap_or(0);
                let route = sip_diameter::Route { fqdn, metric };
                match c.realm_routes.iter_mut().find(|(r, _)| r.eq_ignore_ascii_case(&realm)) {
                    Some((_, rs)) => rs.push(route),
                    None => c.realm_routes.push((realm, vec![route])),
                }
            }
            "tls_certificate" => c.tls.certificate = Some(v.str()?.into()),
            "tls_private_key" => c.tls.private_key = Some(v.str()?.into()),
            "tls_ca_list" => c.tls.ca_list = Some(v.str()?.into()),
            "tls_require_certificate" => c.tls.require_certificate = v.int()? != 0,
            "transaction_timeout" => c.timeout = Duration::from_secs(v.int()?.max(1).unsigned_abs()),
            "tc" => c.tc = v.int()?.max(1).unsigned_abs(),
            "peer" => {
                let kv = kv_params(v.str()?);
                let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, y)| y.clone());
                let fqdn = get("fqdn").ok_or("cdp peer: fqdn= is required")?;
                let proto = sip_diameter::Proto::parse(&get("proto").unwrap_or_default()).map_err(|e| format!("cdp peer {fqdn}: {e}"))?;
                c.peers.push(sip_diameter::PeerCfg {
                    host: get("host").unwrap_or_else(|| fqdn.clone()),
                    realm: get("realm").unwrap_or_default(),
                    port: get("port").and_then(|p| p.parse().ok()).unwrap_or(proto.default_port()),
                    fqdn,
                    proto,
                });
            }
            "auth_app" => {
                let s = v.str()?;
                let (vend, app) = s.split_once(':').unwrap_or(("0", s));
                c.auth_apps.push((
                    codes::VendorId(vend.trim().parse().map_err(|_| "cdp auth_app: vendor:app")?),
                    codes::AppId(app.trim().parse().map_err(|_| "cdp auth_app: vendor:app")?),
                ));
            }
            "workers" | "debug" | "latency_threshold" => {}
            _ => return Err(format!("cdp: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let mut cfg = match lock(&self.file).clone() {
            Some(f) => sip_diameter::parse_xml_config(&std::fs::read_to_string(&f).map_err(|e| format!("cdp config_file {f}: {e}"))?)?,
            None => lock(&self.cfg).clone(),
        };
        if cfg.auth_apps.is_empty() {
            cfg.auth_apps = vec![(codes::VENDOR_3GPP, codes::APP_CX), (codes::VENDOR_3GPP, codes::APP_RX), (codes::VendorId(0), codes::APP_CC)];
        }
        let peers = Peers::try_new(cfg).map_err(|e| format!("cdp: {e}"))?;
        let _ = self.peers.set(peers.clone());
        reg.provide(Arc::new(CdpApi { peers: peers.clone() }));
        reg.rpc.add("cdp.list_peers", "Diameter peers and their state", move |_| {
            Ok(json!(
                peers
                    .peers()
                    .iter()
                    .map(|p| json!({"FQDN": p.fqdn, "Realm": p.realm, "State": p.state, "Origin-Host": p.origin_host, "Proto": p.proto.as_str()}))
                    .collect::<Vec<_>>()
            ))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        if let Some(p) = self.peers.get() {
            p.start()?;
        }
        Ok(())
    }
}

/// `cdp_avp` — Kamailio's AVP helper library for the IMS modules; here the
/// codec lives in `sip-diameter`, so the module only exists for configs.
pub struct CdpAvp;

impl Module for CdpAvp {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![])
    }

    fn name(&self) -> &'static str {
        "cdp_avp"
    }
    fn set_param(&self, _name: &str, _v: &Arg) -> Result<(), String> {
        Ok(())
    }
    fn register(self: Arc<Self>, _reg: &mut Registry) -> Result<(), String> {
        Ok(())
    }
}

/// The cdp peers (modules must be loaded after `cdp`).
pub(crate) fn cdp(reg: &Registry, who: &str) -> Result<Arc<Peers>, String> {
    reg.api::<CdpApi>().map(|c| c.peers.clone()).ok_or_else(|| format!("{who} needs cdp: put loadmodule \"cdp\" before it"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impu_keys() {
        let cases: &[(&str, Option<&str>)] = &[
            ("sip:Alice@IMS.test:5060;transport=tcp", Some("sip:Alice@ims.test")),
            ("sips:bob@ims.test", Some("sip:bob@ims.test")),
            ("tel:+4930111;phone-context=ims.test", Some("tel:+4930111")),
            ("TEL:+1", Some("TEL:+1")),
            ("sip:ims.test", None),
            ("garbage", None),
        ];
        for (uri, want) in cases {
            assert_eq!(impu_of(uri.as_bytes()).as_deref(), *want, "{uri}");
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
        assert_eq!(b64(b"\x00\x00\x00\xff"), "AAAA/w==");
        // RFC 2617's HA1 for Mufasa.
        assert_eq!(md5_hex(&[b"Mufasa", b"testrealm@host.com", b"Circle Of Life"]), "939e7578ed9e3c518a452acee763bce9");
        assert_eq!(rand_bytes(16).len(), 16);
        assert_eq!(
            kv_params("fqdn=hss.ims; Realm = ims ;port=3868;bare;x=a=b"),
            [("fqdn", "hss.ims"), ("realm", "ims"), ("port", "3868"), ("x", "a=b")].map(|(a, b)| (a.to_string(), b.to_string()))
        );
        assert_eq!(args::<2>(&[Arg::Int(1), Arg::Int(2)]).map(|a| a.len()), Ok(2));
        assert!(args::<1>(&[]).unwrap_err().contains("expected 1"));
    }

    #[test]
    fn cdp_parameters_build_the_peer_config() {
        let c = Cdp::default();
        let set = |n: &str, v: &str| c.set_param(n, &Arg::Str(v.into()));
        // Two routes for one realm (any case) join its list.
        set("realm_route", "realm=ims.test;fqdn=hss1.ims.test;metric=2").unwrap();
        set("realm_route", "realm=IMS.test;fqdn=hss2.ims.test").unwrap();
        set("default_route", "hss9.ims.test;metric=7").unwrap();
        set("peer", "fqdn=hss1.ims.test;realm=ims.test;host=127.0.0.1;port=3999").unwrap();
        set("peer", "fqdn=hss2.ims.test;proto=sctp").unwrap();
        set("listen", "tls:127.0.0.1:3868").unwrap();
        set("listen", "127.0.0.1:3869").unwrap();
        set("auth_app", "10415:16777216").unwrap();
        set("auth_app", "4").unwrap();
        c.set_param("transaction_timeout", &Arg::Int(0)).unwrap();
        c.set_param("tls_require_certificate", &Arg::Int(1)).unwrap();
        for ignored in ["workers", "debug", "latency_threshold"] {
            c.set_param(ignored, &Arg::Int(4)).unwrap();
        }
        let cfg = lock(&c.cfg).clone();
        assert_eq!(cfg.realm_routes.len(), 1);
        assert_eq!(cfg.realm_routes[0].1.iter().map(|r| (r.fqdn.as_str(), r.metric)).collect::<Vec<_>>(), [("hss1.ims.test", 2), ("hss2.ims.test", 0)]);
        assert_eq!((cfg.default_routes[0].fqdn.as_str(), cfg.default_routes[0].metric), ("hss9.ims.test", 7));
        let p = &cfg.peers[1];
        assert_eq!(
            (p.host.as_str(), p.port, p.proto),
            ("hss2.ims.test", sip_diameter::Proto::Sctp.default_port(), sip_diameter::Proto::Sctp),
            "host defaults to the fqdn"
        );
        assert_eq!((cfg.peers[0].host.as_str(), cfg.peers[0].port), ("127.0.0.1", 3999));
        assert_eq!(cfg.listen, [(sip_diameter::Proto::Tls, "127.0.0.1:3868".to_string()), (sip_diameter::Proto::Tcp, "127.0.0.1:3869".to_string())]);
        assert_eq!(cfg.auth_apps, [(codes::VENDOR_3GPP, codes::APP_CX), (codes::VendorId(0), codes::AppId(4))]);
        assert_eq!(cfg.timeout, Duration::from_secs(1), "at least a second");
        assert!(cfg.tls.require_certificate);
        // Refused values.
        let errs = [
            ("realm_route", "fqdn=hss.ims.test"),
            ("realm_route", "realm=r;fqdn=f;metric=x"),
            ("default_route", "hss;metric=-1"),
            ("peer", "realm=ims.test"),
            ("peer", "fqdn=hss;proto=udp"),
            ("auth_app", "x:1"),
            ("auth_app", "1:y"),
            ("listen", "udp:1.2.3.4:5"),
        ];
        for (n, v) in errs {
            // "udp:" is not a transport: the whole value is the address.
            if n == "listen" {
                set(n, v).unwrap();
                assert_eq!(lock(&c.cfg).listen.last().map(|l| l.1.as_str()), Some(v));
                continue;
            }
            assert!(set(n, v).is_err(), "{n} {v}");
        }
        assert!(set("nope", "1").unwrap_err().contains("unknown parameter"));
        // Not registered: nothing to start.
        assert!(Arc::new(Cdp::default()).spawn(Arc::new(crate::testutil::NoNet)).is_ok());
    }

    #[test]
    fn cdp_registers_its_peers_and_rpc() {
        let c = Arc::new(Cdp::default());
        c.set_param("peer", &Arg::Str("fqdn=hss.ims.test;realm=ims.test;host=127.0.0.1".into())).unwrap();
        let mut reg = Registry::default();
        reg.load(c).unwrap();
        // The default applications: Cx, Rx and Ro.
        let peers = cdp(&reg, "test").unwrap();
        assert_eq!(peers.cfg.auth_apps.len(), 3);
        let list = crate::testutil::rpc(&reg, "cdp.list_peers", json!([])).unwrap();
        assert_eq!(list[0]["FQDN"], "hss.ims.test");
        assert_eq!(list[0]["State"], "Closed");
        assert_eq!(list[0]["Proto"], "tcp");
        // A module that needs cdp says so.
        assert!(cdp(&Registry::default(), "ims_qos").err().unwrap_or_default().contains("loadmodule \"cdp\""));
        // A missing config file.
        let f = Arc::new(Cdp::default());
        f.set_param("config_file", &Arg::Str("/nonexistent/cdp.xml".into())).unwrap();
        assert!(Registry::default().load(f).unwrap_err().contains("cdp config_file /nonexistent/cdp.xml"));
        // cdp_avp takes any parameter and registers nothing.
        let a = Arc::new(CdpAvp);
        assert_eq!(a.params().map(|p| p.len()), Some(0));
        assert!(a.set_param("anything", &Arg::Int(1)).is_ok());
        assert!(Registry::default().load(a).is_ok());
    }

    #[test]
    fn every_name_is_a_module() {
        for n in NAMES {
            assert_eq!(module(n).map(|m| m.name()), Some(*n));
        }
        assert!(module("ims_dialog").is_none());
    }
}
