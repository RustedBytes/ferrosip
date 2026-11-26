//! TLS configuration (Kamailio's `tls` module, via rustls + ring).
//!
//! * Server: one default certificate plus optional per-SNI certificates
//!   (Kamailio `server_name` in tls.cfg domains); optional client-certificate
//!   verification (`verify_certificate` / `require_certificate`).
//! * Client (outbound): servers are verified against `--tls-ca`, by host name
//!   when the destination was configured by name, else by IP. Our certificate
//!   is presented as a client certificate when we have one (mutual TLS).
//! * Profiles (`--tls-profile FILE`, Kamailio `tls.cfg` syntax):
//!   `[server:IP:PORT]` sections pick the certificate and client-certificate
//!   policy of one listener, `[client:IP:PORT]` sections our certificate, CA
//!   list, verification and `server_name` for one peer; `[server:default]` /
//!   `[client:default]` change the defaults. Keys: `certificate`,
//!   `private_key`, `ca_list`, `verify_certificate`, `require_certificate`,
//!   `server_name` (relative paths are relative to the profile file).
//! * Session resumption: a session cache (`--tls-session-cache N`, 0 = off)
//!   and stateless tickets (`--tls-tickets`).

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct TlsFiles {
    /// Server certificate chain (PEM) for TLS listeners; also our client cert.
    pub cert: Option<PathBuf>,
    /// Private key (PEM) for `cert`.
    pub key: Option<PathBuf>,
    /// CA bundle (PEM): verifies servers we connect to, and clients when
    /// `verify_client` is set.
    pub ca: Option<PathBuf>,
    /// Require and verify client certificates on TLS/WSS listeners.
    pub verify_client: bool,
    /// Extra certificates selected by SNI: (server name, cert, key).
    pub sni: Vec<(String, PathBuf, PathBuf)>,
    /// Per-listener / per-peer profiles (Kamailio tls.cfg syntax).
    pub profile: Option<PathBuf>,
    /// More profiles in the same syntax, given inline (ferrosip.toml's
    /// named `[tls.x]` sections; paths absolute).
    pub profile_text: Option<String>,
    /// Server-side session cache size (None = rustls default, 0 = off).
    pub session_cache: Option<usize>,
    /// Stateless session tickets (RFC 5077 / TLS 1.3 tickets).
    pub tickets: bool,
}

/// One `[server:…]` / `[client:…]` section.
#[derive(Clone, Debug, Default)]
struct Profile {
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ca_list: Option<PathBuf>,
    verify: Option<bool>,
    require: Option<bool>,
    server_name: Option<String>,
}

/// (is_server, "default" | "IP:PORT", profile)
type Section = (bool, String, Profile);

fn parse_profiles(text: &str, base: &std::path::Path) -> Result<Vec<Section>, String> {
    let mut out: Vec<Section> = Vec::new();
    for (n, raw) in (1usize..).zip(text.lines()) {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = |e: &str| format!("tls profile line {n}: {e}: {raw:?}");
        if let Some(h) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let (kind, target) = h.split_once(':').ok_or_else(|| bad("expected [server:...] or [client:...]"))?;
            let server = match kind.trim() {
                "server" => true,
                "client" => false,
                _ => return Err(bad("expected server or client")),
            };
            let target = match target.trim() {
                "default" | "any" => "default".to_string(),
                t => t.parse::<std::net::SocketAddr>().map_err(|_| bad("expected default or IP:PORT"))?.to_string(),
            };
            out.push((server, target, Profile::default()));
            continue;
        }
        let (k, v) = line.split_once('=').ok_or_else(|| bad("expected key = value"))?;
        let (k, v) = (k.trim(), v.trim().trim_matches('"'));
        let p = &mut out.last_mut().ok_or_else(|| bad("setting outside a section"))?.2;
        let path = || if std::path::Path::new(v).is_absolute() { PathBuf::from(v) } else { base.join(v) };
        let yes = || matches!(v.to_ascii_lowercase().as_str(), "yes" | "1" | "true" | "on");
        match k {
            "certificate" => p.certificate = Some(path()),
            "private_key" => p.private_key = Some(path()),
            "ca_list" => p.ca_list = Some(path()),
            "verify_certificate" => p.verify = Some(yes()),
            "require_certificate" => p.require = Some(yes()),
            "server_name" => p.server_name = Some(v.to_string()),
            "method" | "cipher_list" | "verify_depth" | "server_id" | "crl" | "server_name_mode" | "tls_method" => {}
            _ => return Err(bad("unknown key")),
        }
    }
    Ok(out)
}

/// `verify_certificate = no` towards a peer: accept any server certificate.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Clone)]
pub struct TlsConfig {
    pub server: Option<Arc<ServerConfig>>,
    pub client: Option<Arc<ClientConfig>>,
    /// `[server:IP:PORT]` profiles, by local listener address.
    pub server_by_local: HashMap<std::net::SocketAddr, Arc<ServerConfig>>,
    /// `[client:IP:PORT]` profiles: config and the name to verify/send as SNI.
    pub client_by_peer: HashMap<std::net::SocketAddr, (Arc<ClientConfig>, Option<String>)>,
}

impl TlsConfig {
    /// Server config for a connection accepted on `local`.
    pub fn server_for(&self, local: Option<std::net::SocketAddr>) -> Option<Arc<ServerConfig>> {
        local.and_then(|l| self.server_by_local.get(&l).cloned()).or_else(|| self.server.clone())
    }

    /// Client config (and name to verify) for an outbound connection.
    pub fn client_for(&self, peer: &std::net::SocketAddr) -> Option<(Arc<ClientConfig>, Option<String>)> {
        self.client_by_peer.get(peer).cloned().or_else(|| self.client.clone().map(|c| (c, None)))
    }
}

fn roots_of(ca: &PathBuf) -> Result<Arc<RootCertStore>, String> {
    let mut roots = RootCertStore::empty();
    for c in certs(ca)? {
        roots.add(c).map_err(|e| format!("{}: {e}", ca.display()))?;
    }
    Ok(Arc::new(roots))
}

/// Session resumption settings for a server config.
fn resumption(cfg: &mut ServerConfig, f: &TlsFiles) -> Result<(), String> {
    if let Some(n) = f.session_cache {
        cfg.session_storage = if n == 0 { Arc::new(rustls::server::NoServerSessionStorage {}) } else { rustls::server::ServerSessionMemoryCache::new(n) };
    }
    if f.tickets {
        cfg.ticketer = rustls::crypto::ring::Ticketer::new().map_err(|e| format!("tls tickets: {e}"))?;
    }
    Ok(())
}

fn certs(p: &PathBuf) -> Result<Vec<CertificateDer<'static>>, String> {
    let v = CertificateDer::pem_file_iter(p)
        .map_err(|e| format!("{}: {e}", p.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if v.is_empty() {
        return Err(format!("{}: no certificates found", p.display()));
    }
    Ok(v)
}

fn key(p: &PathBuf) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn certified(provider: &CryptoProvider, c: &PathBuf, k: &PathBuf) -> Result<Arc<CertifiedKey>, String> {
    let signing = provider.key_provider.load_private_key(key(k)?).map_err(|e| format!("{}: {e}", k.display()))?;
    Ok(Arc::new(CertifiedKey::new(certs(c)?, signing)))
}

/// SNI → certificate, falling back to the default certificate.
#[derive(Debug)]
struct SniResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        hello.server_name().and_then(|n| self.by_name.get(&n.to_ascii_lowercase())).or(self.default.as_ref()).cloned()
    }
}

pub fn load(f: &TlsFiles, need_server: bool) -> Result<TlsConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut sections = match &f.profile {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            parse_profiles(&text, p.parent().unwrap_or(std::path::Path::new(".")))?
        }
        None => Vec::new(),
    };
    if let Some(t) = &f.profile_text {
        sections.extend(parse_profiles(t, std::path::Path::new("/"))?);
    }
    // [server:default] / [client:default] amend the command-line defaults.
    let mut f = f.clone();
    let mut client_default = Profile::default();
    for (server, target, p) in sections.iter().filter(|s| s.1 == "default") {
        let _ = target;
        if *server {
            if p.certificate.is_some() {
                f.cert = p.certificate.clone();
                f.key = p.private_key.clone();
            }
            if p.ca_list.is_some() {
                f.ca = p.ca_list.clone();
            }
            if let Some(v) = p.verify.or(p.require) {
                f.verify_client = v;
            }
        } else {
            client_default = p.clone();
        }
    }
    let f = &f;
    let roots = match client_default.ca_list.as_ref().or(f.ca.as_ref()) {
        Some(ca) => Some(roots_of(ca)?),
        None => None,
    };
    let own = match (&f.cert, &f.key) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) => None,
        _ => return Err("--tls-cert and --tls-key go together".into()),
    };

    // Listeners with a [server:IP:PORT] profile of their own don't need
    // the global certificate (start() checks each listener has one).
    let per_listener = sections.iter().any(|s| s.0 && s.1 != "default");
    let server = if (need_server && !per_listener) || own.is_some() || !f.sni.is_empty() {
        if own.is_none() && f.sni.is_empty() {
            return Err("a TLS/WSS listener needs --tls-cert and --tls-key (or --tls-sni)".into());
        }
        let b = ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?;
        let b = if f.verify_client {
            let roots = roots.clone().ok_or("--tls-verify-client needs --tls-ca")?;
            let v = WebPkiClientVerifier::builder_with_provider(roots, provider.clone()).build().map_err(|e| format!("client verifier: {e}"))?;
            b.with_client_cert_verifier(v)
        } else {
            b.with_no_client_auth()
        };
        let mut by_name = HashMap::new();
        for (name, c, k) in &f.sni {
            by_name.insert(name.to_ascii_lowercase(), certified(&provider, c, k)?);
        }
        let default = own.map(|(c, k)| certified(&provider, c, k)).transpose()?;
        let mut cfg = b.with_cert_resolver(Arc::new(SniResolver { by_name, default }));
        resumption(&mut cfg, f)?;
        Some(Arc::new(cfg))
    } else {
        None
    };

    // [server:IP:PORT]: a config of its own for that listener.
    let mut server_by_local = HashMap::new();
    for (_, target, p) in sections.iter().filter(|s| s.0 && s.1 != "default") {
        let addr: std::net::SocketAddr = target.parse().map_err(|_| format!("tls profile: bad address {target}"))?;
        let (Some(c), Some(k)) = (p.certificate.as_ref().or(f.cert.as_ref()), p.private_key.as_ref().or(f.key.as_ref())) else {
            return Err(format!("tls profile [server:{target}]: needs certificate and private_key"));
        };
        let b = ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?;
        let verify = p.verify.unwrap_or(f.verify_client);
        let b = if verify {
            let ca = p.ca_list.as_ref().or(f.ca.as_ref()).ok_or_else(|| format!("tls profile [server:{target}]: verify_certificate needs ca_list"))?;
            let v = WebPkiClientVerifier::builder_with_provider(roots_of(ca)?, provider.clone());
            let v = if p.require.unwrap_or(true) { v } else { v.allow_unauthenticated() };
            b.with_client_cert_verifier(v.build().map_err(|e| format!("client verifier: {e}"))?)
        } else {
            b.with_no_client_auth()
        };
        let mut cfg = b.with_cert_resolver(Arc::new(SniResolver { by_name: HashMap::new(), default: Some(certified(&provider, c, k)?) }));
        resumption(&mut cfg, f)?;
        server_by_local.insert(addr, Arc::new(cfg));
    }

    // [client:IP:PORT]: our certificate, CA and verification for that peer.
    let mut client_by_peer = HashMap::new();
    for (_, target, p) in sections.iter().filter(|s| !s.0 && s.1 != "default") {
        let addr: std::net::SocketAddr = target.parse().map_err(|_| format!("tls profile: bad address {target}"))?;
        let b = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().map_err(|e| e.to_string())?;
        let b = if p.verify.or(client_default.verify).unwrap_or(true) {
            let ca = p.ca_list.as_ref().or(client_default.ca_list.as_ref()).or(f.ca.as_ref());
            let roots = ca.map(roots_of).transpose()?.ok_or_else(|| format!("tls profile [client:{target}]: needs ca_list (or verify_certificate = no)"))?;
            b.with_root_certificates(roots)
        } else {
            b.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider.clone())))
        };
        let cert = p.certificate.as_ref().or(client_default.certificate.as_ref()).or(f.cert.as_ref());
        let pkey = p.private_key.as_ref().or(client_default.private_key.as_ref()).or(f.key.as_ref());
        let cfg = match (cert, pkey) {
            (Some(c), Some(k)) => b.with_client_auth_cert(certs(c)?, key(k)?).map_err(|e| format!("client cert: {e}"))?,
            _ => b.with_no_client_auth(),
        };
        client_by_peer.insert(addr, (Arc::new(cfg), p.server_name.clone().or(client_default.server_name.clone())));
    }

    let client = match roots {
        Some(roots) => {
            let b =
                ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.with_root_certificates(roots);
            let own = match (&client_default.certificate, &client_default.private_key) {
                (Some(c), Some(k)) => Some((c, k)),
                _ => own,
            };
            let cfg = match own {
                Some((c, k)) => b.with_client_auth_cert(certs(c)?, key(k)?).map_err(|e| format!("client cert: {e}"))?,
                None => b.with_no_client_auth(),
            };
            Some(Arc::new(cfg))
        }
        None => None,
    };
    Ok(TlsConfig { server, client, server_by_local, client_by_peer })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::Path;

    #[test]
    fn profile_sections_and_keys() {
        let text = "# comment\n\
[server:default]\n\
certificate = cert.pem\n\
private_key = \"/abs/key.pem\"\n\
verify_certificate = YES\n\
\n\
[ client : 192.0.2.1:5061 ]\n\
server_name = sip.example # trailing comment\n\
require_certificate = off\n\
ca_list = ca/x.pem\n\
method = TLSv1.2+\n\
[client:[2001:db8:0::1]:5061]\n\
verify_certificate = 0\n\
[server:any]\n";
        let s = parse_profiles(text, Path::new("/etc/f")).unwrap();
        let heads: Vec<(bool, &str)> = s.iter().map(|x| (x.0, x.1.as_str())).collect();
        assert_eq!(heads, [(true, "default"), (false, "192.0.2.1:5061"), (false, "[2001:db8::1]:5061"), (true, "default")]);
        let p = &s[0].2;
        assert_eq!(p.certificate.as_deref(), Some(Path::new("/etc/f/cert.pem")), "relative to the profile");
        assert_eq!(p.private_key.as_deref(), Some(Path::new("/abs/key.pem")), "absolute kept, quotes removed");
        assert_eq!((p.verify, p.require), (Some(true), None));
        let p = &s[1].2;
        assert_eq!(p.server_name.as_deref(), Some("sip.example"));
        assert_eq!((p.verify, p.require), (None, Some(false)));
        assert_eq!(p.ca_list.as_deref(), Some(Path::new("/etc/f/ca/x.pem")));
        assert_eq!(s[2].2.verify, Some(false));
    }

    #[test]
    fn profile_errors_name_the_line() {
        let cases: &[(&str, &str)] = &[
            ("certificate = x\n", "line 1: setting outside a section"),
            ("[server]\n", "line 1: expected [server:...] or [client:...]"),
            ("[proxy:default]\n", "line 1: expected server or client"),
            ("[server:host.example:5061]\n", "line 1: expected default or IP:PORT"),
            ("[server:default]\nbogus = 1\n", "line 2: unknown key"),
            ("[server:default]\njust words\n", "line 2: expected key = value"),
        ];
        for (text, want) in cases {
            let e = parse_profiles(text, Path::new("/")).unwrap_err();
            assert!(e.contains(want), "{text:?}: {e}");
        }
    }

    fn dummy_server() -> Arc<ServerConfig> {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let b = ServerConfig::builder_with_provider(p).with_safe_default_protocol_versions().unwrap().with_no_client_auth();
        Arc::new(b.with_cert_resolver(Arc::new(SniResolver { by_name: HashMap::new(), default: None })))
    }

    fn dummy_client() -> Arc<ClientConfig> {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let b = ClientConfig::builder_with_provider(p).with_safe_default_protocol_versions().unwrap();
        Arc::new(b.with_root_certificates(RootCertStore::empty()).with_no_client_auth())
    }

    #[test]
    fn per_listener_and_per_peer_configs_win_over_the_default() {
        let (srv_default, srv_local, cli_default, cli_peer) = (dummy_server(), dummy_server(), dummy_client(), dummy_client());
        let local: SocketAddr = "192.0.2.10:5061".parse().unwrap();
        let peer: SocketAddr = "192.0.2.20:5061".parse().unwrap();
        let cfg = TlsConfig {
            server: Some(srv_default.clone()),
            client: Some(cli_default.clone()),
            server_by_local: HashMap::from([(local, srv_local.clone())]),
            client_by_peer: HashMap::from([(peer, (cli_peer.clone(), Some("sip.example".into())))]),
        };
        assert!(Arc::ptr_eq(&cfg.server_for(Some(local)).unwrap(), &srv_local));
        assert!(Arc::ptr_eq(&cfg.server_for(Some("192.0.2.10:5062".parse().unwrap())).unwrap(), &srv_default), "other port");
        assert!(Arc::ptr_eq(&cfg.server_for(None).unwrap(), &srv_default));
        let (c, name) = cfg.client_for(&peer).unwrap();
        assert!(Arc::ptr_eq(&c, &cli_peer) && name.as_deref() == Some("sip.example"));
        let (c, name) = cfg.client_for(&"192.0.2.21:5061".parse().unwrap()).unwrap();
        assert!(Arc::ptr_eq(&c, &cli_default) && name.is_none());
        let bare = TlsConfig { server: None, client: None, server_by_local: HashMap::new(), client_by_peer: HashMap::new() };
        assert!(bare.server_for(Some(local)).is_none() && bare.client_for(&peer).is_none());
    }

    #[test]
    fn load_checks_without_files() {
        let err = |f: &TlsFiles, need| load(f, need).err().unwrap_or_default();
        assert!(err(&TlsFiles::default(), true).contains("needs --tls-cert"), "a TLS listener needs a certificate");
        let half = TlsFiles { cert: Some("/nonexistent/c.pem".into()), ..TlsFiles::default() };
        assert_eq!(err(&half, false), "--tls-cert and --tls-key go together");
        let p = |t: &str| TlsFiles { profile_text: Some(t.into()), ..TlsFiles::default() };
        assert!(err(&p("[client:192.0.2.1:5061]\n"), false).contains("needs ca_list"), "verification needs a CA");
        assert!(err(&p("[server:192.0.2.1:5061]\n"), false).contains("needs certificate and private_key"));
        // No CA needed when the peer's certificate isn't verified.
        let cfg = load(&p("[client:192.0.2.1:5061]\nverify_certificate = no\nserver_name = sip.example\n"), false).unwrap();
        let (_, name) = cfg.client_for(&"192.0.2.1:5061".parse().unwrap()).unwrap();
        assert_eq!(name.as_deref(), Some("sip.example"));
        assert!(cfg.server.is_none() && cfg.client.is_none());
        // [client:default] settings reach the per-peer profiles.
        let cfg = load(&p("[client:default]\nverify_certificate = no\nserver_name = d.example\n[client:192.0.2.1:5061]\n"), false).unwrap();
        assert_eq!(cfg.client_for(&"192.0.2.1:5061".parse().unwrap()).unwrap().1.as_deref(), Some("d.example"));
        assert!(load(&TlsFiles::default(), false).unwrap().server.is_none(), "nothing configured, nothing needed");
    }

    use test_pki::{etc, handshake, own, pki};

    fn client_conn(cfg: Arc<ClientConfig>, name: &str) -> rustls::Connection {
        let name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
        rustls::ClientConnection::new(cfg, name).unwrap().into()
    }

    fn server_conn(cfg: Arc<ServerConfig>) -> rustls::Connection {
        rustls::ServerConnection::new(cfg).unwrap().into()
    }

    /// A client that verifies the server against the test CA but has no certificate.
    fn anonymous_client() -> Arc<ClientConfig> {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let b = ClientConfig::builder_with_provider(p).with_safe_default_protocol_versions().unwrap();
        Arc::new(b.with_root_certificates(roots_of(&etc("ca.pem")).unwrap()).with_no_client_auth())
    }

    fn connects(c: Arc<ClientConfig>, name: &str, s: Arc<ServerConfig>) -> Result<(), rustls::Error> {
        handshake(&mut client_conn(c, name), &mut server_conn(s))
    }

    #[test]
    fn verify_certificate_no_accepts_a_server_certificate_for_another_name() {
        let peer: std::net::SocketAddr = "127.0.0.1:5061".parse().unwrap();
        let f = TlsFiles { profile_text: Some("[client:127.0.0.1:5061]\nverify_certificate = no\n".into()), ..pki() };
        let cfg = load(&f, true).unwrap();
        let server = cfg.server.clone().unwrap();
        let (unverified, _) = cfg.client_for(&peer).unwrap();
        assert!(connects(cfg.client.clone().unwrap(), "localhost", server.clone()).is_ok(), "the default client verifies by name");
        assert!(connects(cfg.client.clone().unwrap(), "wrong.example", server.clone()).is_err(), "and refuses a name the certificate lacks");
        assert!(connects(unverified.clone(), "wrong.example", server).is_ok(), "TLS 1.3");
        // TLS 1.2 checks its signatures through the other verifier method.
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let (c, k) = own();
        let tls12 = ServerConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs(&c).unwrap(), key(&k).unwrap())
            .unwrap();
        let mut cli = client_conn(unverified, "wrong.example");
        handshake(&mut cli, &mut server_conn(Arc::new(tls12))).unwrap();
        assert_eq!(cli.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn session_cache_and_tickets_settings() {
        let server = |f: TlsFiles| load(&f, true).unwrap().server.unwrap();
        assert!(!server(TlsFiles { session_cache: Some(0), ..pki() }).session_storage.can_cache(), "0 turns the cache off");
        assert!(server(TlsFiles { session_cache: Some(16), ..pki() }).session_storage.can_cache());
        assert!(!server(pki()).ticketer.enabled(), "no tickets by default");
        assert!(server(TlsFiles { tickets: true, ..pki() }).ticketer.enabled());
    }

    #[test]
    fn unreadable_certificate_files_name_the_file() {
        let dir = std::env::temp_dir().join(format!("sip-transport-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let garbled = dir.join("garbled.pem");
        std::fs::write(&garbled, "-----BEGIN CERTIFICATE-----\n@@@@ not base64 @@@@\n-----END CERTIFICATE-----\n").unwrap();
        let (_, k) = own();
        let cases: &[(PathBuf, &str)] =
            &[(etc("missing.pem"), "missing.pem: "), (garbled.clone(), "garbled.pem: "), (etc("server.key.pem"), "server.key.pem: no certificates found")];
        for (cert, want) in cases {
            let f = TlsFiles { cert: Some(cert.clone()), key: Some(k.clone()), ..TlsFiles::default() };
            let e = load(&f, true).err().unwrap_or_default();
            assert!(e.contains(want), "{}: {e}", cert.display());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn server_default_profile_sets_certificate_ca_and_client_verification() {
        let (c, k) = own();
        let text = format!(
            "[server:default]\ncertificate = {}\nprivate_key = {}\nca_list = {}\nverify_certificate = yes\n",
            c.display(),
            k.display(),
            etc("ca.pem").display()
        );
        let cfg = load(&TlsFiles { profile_text: Some(text), ..TlsFiles::default() }, true).unwrap();
        let server = cfg.server.clone().unwrap();
        let client = cfg.client.clone().unwrap();
        assert!(client.client_auth_cert_resolver.has_certs(), "the server certificate doubles as our client certificate");
        assert!(connects(client, "localhost", server.clone()).is_ok());
        assert!(connects(anonymous_client(), "localhost", server).is_err(), "a client without a certificate is refused");
    }

    #[test]
    fn per_listener_client_verification() {
        let local: std::net::SocketAddr = "127.0.0.1:5061".parse().unwrap();
        let ca = etc("ca.pem");
        let listener = |extra: &str| {
            let text = format!("[server:127.0.0.1:5061]\nverify_certificate = yes\n{extra}");
            load(&TlsFiles { profile_text: Some(text), ..pki() }, false).map(|c| c.server_for(Some(local)).unwrap())
        };
        let optional = listener(&format!("require_certificate = no\nca_list = {}\n", ca.display())).unwrap();
        assert!(connects(anonymous_client(), "localhost", optional).is_ok(), "require_certificate = no");
        let required = listener(&format!("ca_list = {}\n", ca.display())).unwrap();
        assert!(connects(anonymous_client(), "localhost", required).is_err(), "required by default once verified");
        // The command-line CA serves when the profile has none.
        assert!(listener("").is_ok());
        let no_ca = |t: &str| TlsFiles { ca: None, profile_text: Some(t.into()), ..pki() };
        let e = load(&no_ca("[server:127.0.0.1:5061]\nverify_certificate = yes\n"), false).err().unwrap_or_default();
        assert!(e.contains("[server:127.0.0.1:5061]: verify_certificate needs ca_list"), "{e}");
    }

    #[test]
    fn client_default_certificate_is_presented_to_every_server() {
        let (c, k) = own();
        let ca_only = TlsFiles { ca: Some(etc("ca.pem")), ..TlsFiles::default() };
        assert!(!load(&ca_only, false).unwrap().client.unwrap().client_auth_cert_resolver.has_certs(), "no certificate of our own");
        let text = format!("[client:default]\ncertificate = {}\nprivate_key = {}\n", c.display(), k.display());
        let cfg = load(&TlsFiles { profile_text: Some(text), ..ca_only }, false).unwrap();
        assert!(cfg.server.is_none());
        assert!(cfg.client.unwrap().client_auth_cert_resolver.has_certs());
    }
}

/// The test PKI under etc/tls (etc/tls/gen-certs.sh) and an in-memory
/// handshake, for the TLS tests of this crate.
#[cfg(test)]
pub(crate) mod test_pki {
    use super::TlsFiles;
    use std::path::{Path, PathBuf};

    pub(crate) fn etc(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../etc/tls").join(name)
    }

    /// The certificate for 127.0.0.1 / localhost and its key.
    pub(crate) fn own() -> (PathBuf, PathBuf) {
        (etc("server.pem"), etc("server.key.pem"))
    }

    /// Our certificate and key, and the CA that signed it.
    pub(crate) fn pki() -> TlsFiles {
        let (c, k) = own();
        TlsFiles { cert: Some(c), key: Some(k), ca: Some(etc("ca.pem")), ..TlsFiles::default() }
    }

    fn pump(from: &mut rustls::Connection, to: &mut rustls::Connection) -> Result<(), rustls::Error> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets()?;
        }
        Ok(())
    }

    /// Run the handshake between `c` and `s` in memory, until neither has
    /// anything left to send (session tickets included).
    pub(crate) fn handshake(c: &mut rustls::Connection, s: &mut rustls::Connection) -> Result<(), rustls::Error> {
        for _ in 0..10 {
            pump(c, s)?;
            pump(s, c)?;
            if !c.is_handshaking() && !s.is_handshaking() && !c.wants_write() && !s.wants_write() {
                return Ok(());
            }
        }
        panic!("handshake did not finish");
    }
}
