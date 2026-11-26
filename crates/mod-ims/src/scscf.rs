//! S-CSCF: `ims_usrloc_scscf` (IMPU records with contacts, the implicit
//! registration set and the subscription), `ims_registrar_scscf`
//! (`save()` with Cx SAR/SAA, `lookup()`, `impu_registered()`,
//! `term_impu_registered()`; Service-Route and P-Associated-URI in the 200)
//! and `ims_auth` (Cx MAR/MAA: `ims_www_challenge` / `ims_proxy_challenge`
//! and `ims_www_authenticate` / `ims_proxy_authenticate` for SIP Digest and
//! Digest-AKAv1-MD5). Reg-event (RFC 3680): `subscribe_to_reg("location")`
//! answers a SUBSCRIBE for `Event: reg` with a full `reginfo+xml` NOTIFY,
//! then sends partial ones (the changed contacts) on every registration
//! change; `can_subscribe_to_reg` checks the
//! subscriber belongs to the implicit registration set. With `db_mode`, the
//! subscriptions are kept in `subscriber_scscf` (Kamailio's table) and
//! loaded at startup, so their NOTIFYs continue (CSeq, version).

use crate::subscription::{self, Subscription};
use crate::{b64, cdp, hex, impu_of, md5_hex, rand_bytes};
use sip_core::module::{DynStr, RC_ERR, rc};
use sip_core::schema::{ParamSpec, Ty, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Branch, Ctx, Dest, Module, Outbound, Registry, ShardedMap};
use sip_db::DbVal;
use sip_diameter::codes::*;
use sip_diameter::{Avp, DiameterError, Msg, Peers, find};
use sip_parser::uri::{name_addr, parse_contact, split_list};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// Kamailio's `CSCF_RETURN_ERROR`: the Cx request got no answer (the
/// `$avp(maa_return_code)` / `$avp(saa_return_code)` an error leaves).
const CSCF_RETURN_ERROR: i32 = -2;

// --------------------------------------------------------- ims_usrloc_scscf --

#[derive(Clone, Debug)]
pub struct ScContact {
    pub uri: String,
    pub expires_at: u64,
    pub received: Dest,
    pub path: Option<String>,
    pub callid: String,
    pub cseq: u32,
}

#[derive(Clone, Debug, Default)]
pub struct ImpuRecord {
    pub impu: String,
    pub impi: String,
    pub registered: bool,
    pub contacts: Vec<ScContact>,
    pub sub: Subscription,
    /// The User-Data XML `sub` was parsed from (kept for the database).
    pub user_data: String,
}

#[derive(Default)]
pub struct UsrlocScscf {
    /// Primary IMPU → record; every IMPU of the implicit set → primary.
    records: Mutex<std::collections::HashMap<String, ImpuRecord>>,
    alias: Mutex<std::collections::HashMap<String, String>>,
    db_url: Mutex<Option<String>>,
    /// 0 memory only; else write-through to `impu` / `contact`.
    db_mode: AtomicU8,
    db: OnceLock<Arc<dyn sip_db::DbConn>>,
}

const IMPU_COLS: &[&str] = &["impu", "impi", "reg_state", "ims_subscription_data"];
const CONTACT_COLS: &[&str] = &["impu", "contact", "received", "path", "expires", "callid", "cseq"];
/// Kamailio's `subscriber_scscf` columns (usrloc_db.c db_insert_subscriber()).
const SUB_COLS: &[&str] = &[
    "watcher_uri",
    "watcher_contact",
    "presentity_uri",
    "event",
    "expires",
    "version",
    "local_cseq",
    "call_id",
    "from_tag",
    "to_tag",
    "record_route",
    "sockinfo_str",
];
/// `event` of a reg-event subscription (Kamailio's IMS_EVENT_REG).
const IMS_EVENT_REG: i64 = 1;

impl UsrlocScscf {
    pub fn get(&self, impu: &str) -> Option<ImpuRecord> {
        let primary = lock(&self.alias).get(impu).cloned().unwrap_or_else(|| impu.to_string());
        let t = unix_secs();
        lock(&self.records).get(&primary).cloned().map(|mut r| {
            r.contacts.retain(|c| c.expires_at > t);
            r
        })
    }

    pub fn put(&self, r: ImpuRecord) {
        let mut a = lock(&self.alias);
        a.insert(r.impu.clone(), r.impu.clone());
        for id in &r.sub.public_ids {
            a.insert(id.clone(), r.impu.clone());
        }
        drop(a);
        self.db_write(&r);
        lock(&self.records).insert(r.impu.clone(), r);
    }

    pub fn remove(&self, impu: &str) {
        let primary = lock(&self.alias).get(impu).cloned().unwrap_or_else(|| impu.to_string());
        if let Some(r) = lock(&self.records).remove(&primary) {
            let mut a = lock(&self.alias);
            for id in r.sub.public_ids.iter().chain(std::iter::once(&r.impu)) {
                a.remove(id);
            }
        }
        self.db_delete(&primary);
    }

    /// Write-through: replace the rows of one record.
    fn db_write(&self, r: &ImpuRecord) {
        let Some(db) = self.db.get() else { return };
        let res = (|| -> Result<(), String> {
            self.db_delete_rows(db.as_ref(), &r.impu)?;
            db.insert(
                "impu",
                IMPU_COLS,
                &[DbVal::Str(r.impu.clone()), DbVal::Str(r.impi.clone()), DbVal::Int(i64::from(r.registered)), DbVal::Str(r.user_data.clone())],
            )?;
            for c in &r.contacts {
                db.insert(
                    "contact",
                    CONTACT_COLS,
                    &[
                        DbVal::Str(r.impu.clone()),
                        DbVal::Str(c.uri.clone()),
                        DbVal::Str(sip_core::pvcore::dest_to_uri(&c.received)),
                        c.path.clone().map_or(DbVal::Null, DbVal::Str),
                        DbVal::Int(db_int(c.expires_at)),
                        DbVal::Str(c.callid.clone()),
                        DbVal::Int(i64::from(c.cseq)),
                    ],
                )?;
            }
            Ok(())
        })();
        if let Err(e) = res {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: writing {}: {e}", r.impu));
        }
    }

    fn db_delete_rows(&self, db: &dyn sip_db::DbConn, impu: &str) -> Result<(), String> {
        db.delete("contact", &[("impu", DbVal::Str(impu.to_string()))])?;
        db.delete("impu", &[("impu", DbVal::Str(impu.to_string()))])?;
        Ok(())
    }

    fn db_delete(&self, impu: &str) {
        let Some(db) = self.db.get() else { return };
        if let Err(e) = self.db_delete_rows(db.as_ref(), impu) {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: deleting {impu}: {e}"));
        }
    }

    /// Load the records (and their unexpired contacts) at startup.
    fn db_load(&self) -> Result<usize, String> {
        let Some(db) = self.db.get() else { return Ok(0) };
        let t = unix_secs();
        let mut contacts: std::collections::HashMap<String, Vec<ScContact>> = std::collections::HashMap::new();
        for r in db.query("contact", CONTACT_COLS, &[])?.rows {
            let txt = |i: usize| r.get(i).filter(|v| !v.is_null()).map(|v| v.text());
            let int = |i: usize| r.get(i).and_then(DbVal::int);
            let Some(exp) = int(4).and_then(|e| u64::try_from(e).ok()).filter(|&e| e > t) else { continue };
            let (Some(impu), Some(uri)) = (txt(0), txt(1)) else { continue };
            let Some(received) = txt(2).and_then(|u| sip_core::pvcore::dest_from_uri(u.as_bytes())) else { continue };
            contacts.entry(impu).or_default().push(ScContact {
                uri,
                expires_at: exp,
                received,
                path: txt(3).filter(|p| !p.is_empty()),
                callid: txt(5).unwrap_or_default(),
                cseq: int(6).and_then(|c| u32::try_from(c).ok()).unwrap_or(0),
            });
        }
        let mut n = 0usize;
        for r in db.query("impu", IMPU_COLS, &[])?.rows {
            let txt = |i: usize| r.get(i).filter(|v| !v.is_null()).map(|v| v.text()).unwrap_or_default();
            let impu = txt(0);
            if impu.is_empty() {
                continue;
            }
            let user_data = txt(3);
            let mut sub = if user_data.is_empty() {
                Subscription::default()
            } else {
                subscription::parse(&user_data).unwrap_or_else(|e| {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: {impu}: stored User-Data: {e}"));
                    Subscription::default()
                })
            };
            if sub.public_ids.is_empty() {
                sub.public_ids.push(impu.clone());
            }
            let rec = ImpuRecord {
                contacts: contacts.remove(&impu).unwrap_or_default(),
                registered: r.get(2).and_then(DbVal::int).unwrap_or(0) == 1,
                impi: txt(1),
                impu,
                sub,
                user_data,
            };
            if rec.registered && rec.contacts.is_empty() {
                // Expired while we were down.
                self.db_delete(&rec.impu);
                continue;
            }
            let mut a = lock(&self.alias);
            a.insert(rec.impu.clone(), rec.impu.clone());
            for id in &rec.sub.public_ids {
                a.insert(id.clone(), rec.impu.clone());
            }
            drop(a);
            lock(&self.records).insert(rec.impu.clone(), rec);
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    /// Records whose last contact expired (for timeout deregistration),
    /// with those contacts.
    pub fn take_expired(&self) -> Vec<ImpuRecord> {
        let t = unix_secs();
        let mut gone = Vec::new();
        lock(&self.records).retain(|_, r| {
            let before = r.contacts.clone();
            r.contacts.retain(|c| c.expires_at > t);
            let keep = !(r.registered && r.contacts.is_empty());
            if !keep {
                // With the contacts that just expired (for the reg event).
                gone.push(ImpuRecord { contacts: before, ..r.clone() });
            }
            keep
        });
        let mut a = lock(&self.alias);
        for r in &gone {
            for id in r.sub.public_ids.iter().chain(std::iter::once(&r.impu)) {
                a.remove(id);
            }
        }
        drop(a);
        for r in &gone {
            self.db_delete(&r.impu);
        }
        gone
    }

    /// Write-through of a reg-event subscription: its `subscriber_scscf`
    /// row replaced (Kamailio's db_insert_subscriber() insert-update; the
    /// `impu_subscriber` link is the row's `presentity_uri`).
    fn db_put_sub(&self, s: &RegSub) {
        let Some(db) = self.db.get() else { return };
        let res = (|| -> Result<(), sip_db::DbError> {
            Self::db_del_sub_rows(db.as_ref(), s)?;
            db.insert(
                "subscriber_scscf",
                SUB_COLS,
                &[
                    DbVal::Str(s.their_uri.clone()),
                    DbVal::Str(s.target.clone()),
                    DbVal::Str(s.impu.clone()),
                    DbVal::Int(IMS_EVENT_REG),
                    DbVal::Int(db_int(s.expires_at)),
                    DbVal::Int(db_int(s.version)),
                    DbVal::Int(i64::from(s.cseq)),
                    DbVal::Str(s.callid.clone()),
                    DbVal::Str(s.their_tag.clone()),
                    DbVal::Str(s.our_tag.clone()),
                    DbVal::Str(s.route.join(",")),
                    DbVal::Str(sip_core::pvcore::dest_to_uri(&s.dst)),
                ],
            )
        })();
        if let Err(e) = res {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: writing the subscription of {}: {e}", s.impu));
        }
    }

    /// A subscription's row is found by its dialog (Call-ID and the
    /// watcher's tag).
    fn db_del_sub_rows(db: &dyn sip_db::DbConn, s: &RegSub) -> Result<usize, sip_db::DbError> {
        db.delete("subscriber_scscf", &[("call_id", DbVal::Str(s.callid.clone())), ("from_tag", DbVal::Str(s.their_tag.clone()))])
    }

    fn db_del_sub(&self, s: &RegSub) {
        let Some(db) = self.db.get() else { return };
        if let Err(e) = Self::db_del_sub_rows(db.as_ref(), s) {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: deleting the subscription of {}: {e}", s.impu));
        }
    }

    /// The stored reg-event subscriptions that haven't expired (Kamailio's
    /// preload_udomain() reads them with their IMPU); expired rows go.
    fn db_load_subs(&self) -> Vec<RegSub> {
        let Some(db) = self.db.get() else { return vec![] };
        let rows = match db.query("subscriber_scscf", SUB_COLS, &[]) {
            Ok(r) => r.rows,
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_usrloc_scscf: loading subscriptions: {e}"));
                return vec![];
            }
        };
        let t = unix_secs();
        let mut out = Vec::new();
        for r in rows {
            let txt = |i: usize| r.get(i).filter(|v| !v.is_null()).map(|v| v.text()).unwrap_or_default();
            let int = |i: usize| r.get(i).and_then(DbVal::int).unwrap_or(0);
            let sub = RegSub {
                impu: txt(2),
                callid: txt(7),
                our_tag: txt(9),
                their_tag: txt(8),
                their_uri: txt(0),
                target: txt(1),
                route: split_list(txt(10).as_bytes()).into_iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect(),
                dst: match sip_core::pvcore::dest_from_uri(txt(11).as_bytes()).or_else(|| sip_core::pvcore::dest_from_uri(txt(1).as_bytes())) {
                    Some(d) => d,
                    None => continue,
                },
                expires_at: int(4).max(0).unsigned_abs(),
                cseq: u32::try_from(int(6)).unwrap_or(0),
                version: int(5).max(0).unsigned_abs(),
            };
            if int(3) != IMS_EVENT_REG || sub.impu.is_empty() || sub.callid.is_empty() {
                continue;
            }
            if sub.expires_at <= t {
                self.db_del_sub(&sub);
                continue;
            }
            out.push(sub);
        }
        out
    }

    fn json(r: &ImpuRecord) -> sip_core::serde_json::Value {
        let t = unix_secs();
        json!({"impu": r.impu, "impi": r.impi, "state": if r.registered { "registered" } else { "not registered" },
            "public_identities": r.sub.public_ids, "ifcs": r.sub.ifcs.len(),
            "contacts": r.contacts.iter().map(|c| json!({"contact": c.uri, "expires": c.expires_at.saturating_sub(t), "path": c.path, "received": c.received.to_string(), "callid": c.callid, "cseq": c.cseq})).collect::<Vec<_>>()})
    }
}

impl Module for UsrlocScscf {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p(
                "db_mode",
                Ty::Enum(&[("off", "0"), ("write-through", "1"), ("write-back", "2"), ("db-only", "3")]),
                "off",
                "Registrations in memory only, or also in the database (every mode but off writes through)",
            ),
            p("db_url", Ty::Str, "", "Database for db_mode (sqlite://, mysql://, postgres://, text://)"),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_usrloc_scscf"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_mode" => {
                let m = v.int()?;
                if !(0..=3).contains(&m) {
                    return Err(format!("ims_usrloc_scscf: db_mode {m} (0..3)"));
                }
                self.db_mode.store(u8::try_from(m).map_err(|_| format!("ims_usrloc_scscf: db_mode {m} (0..3)"))?, Ordering::Relaxed);
            }
            "db_url" => *lock(&self.db_url) = Some(v.str()?.to_string()),
            _ => {} // hash sizes, timers, notification settings
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        if self.db_mode.load(Ordering::Relaxed) > 0 {
            let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("ims_usrloc_scscf"));
            let _ = self.db.set(sip_db::connect(&url)?);
            let n = self.db_load()?;
            sip_core::log::log(sip_core::log::L_INFO, &format!("ims_usrloc_scscf: loaded {n} IMPU records from the database"));
        }
        reg.provide(self.clone());
        let me = self.clone();
        reg.rpc.add("ulscscf.showimpu", "ulscscf.showimpu <impu>", move |p| {
            let i = sip_core::rpc::str_param(p, 0)?;
            me.get(&i).map(|r| UsrlocScscf::json(&r)).ok_or_else(|| "IMPU not found".into())
        });
        let me = self.clone();
        reg.rpc.add("ulscscf.status", "Registered IMPUs", move |_| Ok(json!(lock(&me.records).values().map(UsrlocScscf::json).collect::<Vec<_>>())));
        Ok(())
    }
}

// -------------------------------------------------------- shared S-CSCF bits --

/// Common Cx parameters (ims_auth and ims_registrar_scscf).
#[derive(Default)]
pub(crate) struct CxCfg {
    dest_realm: Mutex<String>,
    forced_peer: Mutex<Option<String>>,
    server_name: Mutex<String>,
}

impl CxCfg {
    pub(crate) fn set(&self, name: &str, v: &Arg) -> Result<bool, String> {
        match name {
            "cxdx_dest_realm" => *lock(&self.dest_realm) = v.str()?.into(),
            "cxdx_forced_peer" | "cxdx_dest_host" => *lock(&self.forced_peer) = Some(v.str()?.into()),
            "name" | "scscf_name" => *lock(&self.server_name) = v.str()?.into(),
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub(crate) fn base(&self, peers: &Peers, cmd: CmdCode) -> Msg {
        let mut m = Msg::request(cmd, APP_CX);
        m.add(Avp::str(SESSION_ID, None, &peers.session_id("cx")))
            .add(Avp::group(
                VENDOR_SPECIFIC_APPLICATION_ID,
                None,
                vec![Avp::u32(VENDOR_ID, None, VENDOR_3GPP.get()), Avp::u32(AUTH_APPLICATION_ID, None, APP_CX.get())],
            ))
            .add(Avp::u32(AUTH_SESSION_STATE, None, 1));
        m
    }

    pub(crate) fn send(&self, peers: &Peers, m: Msg) -> Result<Msg, DiameterError> {
        let realm = lock(&self.dest_realm).clone();
        let realm = if realm.is_empty() { peers.cfg.realm.clone() } else { realm };
        let host = lock(&self.forced_peer).clone();
        peers.request(m, &realm, host.as_deref())
    }

    /// `send` without blocking: `cb` gets the answer (on a Diameter thread).
    pub(crate) fn send_async(&self, peers: &Peers, m: Msg, cb: sip_diameter::AnswerFn) {
        let realm = lock(&self.dest_realm).clone();
        let realm = if realm.is_empty() { peers.cfg.realm.clone() } else { realm };
        let host = lock(&self.forced_peer).clone();
        peers.request_cb(m, &realm, host.as_deref(), cb)
    }
}

/// IMPI and IMPU of a request: Authorization username / To (REGISTER) or From.
pub(crate) fn identities(ctx: &mut Ctx<'_, '_>, hdr: &[u8]) -> Option<(String, String)> {
    ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
    let kind = if ctx.msg.method() == Some(Method::Register) { HdrKind::To } else { HdrKind::From };
    let impu = impu_of(name_addr(ctx.msg.get(kind)?.body).0)?;
    let impi = ctx
        .msg
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(hdr))
        .and_then(|h| creds_field(&String::from_utf8_lossy(h.body), "username"))
        .unwrap_or_else(|| impu.trim_start_matches("sip:").to_string());
    Some((impi, impu))
}

/// A unix time / counter as a DB integer column (saturating; never wraps
/// to a negative value).
fn db_int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn creds_field(s: &str, k: &str) -> Option<String> {
    // ASCII lower-casing keeps byte offsets, so `at` indexes `s` too. A
    // key holds no '=', so "k=" matches cannot overlap.
    let lower = s.to_ascii_lowercase();
    let pat = format!("{k}=");
    for (at, _) in lower.match_indices(&pat) {
        let before = lower.get(..at).and_then(|p| p.bytes().last());
        if matches!(before, None | Some(b' ' | b',' | b'\t')) {
            let v = s.get(at..)?.get(pat.len()..)?.trim_start();
            return Some(match v.strip_prefix('"') {
                Some(q) => q.split('"').next().unwrap_or_default().to_string(),
                None => v.split([',', ' ']).next().unwrap_or_default().to_string(),
            });
        }
    }
    None
}

// ------------------------------------------------------------------ ims_auth --

#[derive(Clone, Debug)]
struct Vector {
    nonce: String,
    aka: bool,
    /// SIP Digest: HA1 from the HSS. AKA: XRES.
    secret: Vec<u8>,
    expires: u64,
}

pub struct ImsAuth {
    cx: CxCfg,
    algorithm: Mutex<String>,
    qop: Mutex<String>,
    vector_timeout: AtomicU64,
    vectors: ShardedMap<String, Vec<Vector>>,
    peers: OnceLock<Arc<Peers>>,
    tm: OnceLock<Arc<mod_txn::Tm>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

impl Default for ImsAuth {
    fn default() -> Self {
        Self {
            cx: CxCfg::default(),
            algorithm: Mutex::new("AKAv1-MD5".into()),
            qop: Mutex::new(String::new()),
            vector_timeout: AtomicU64::new(60),
            vectors: ShardedMap::new(64),
            peers: OnceLock::new(),
            tm: OnceLock::new(),
            hub: OnceLock::new(),
        }
    }
}

/// The IMPI that last authenticated in this request (ims_registrar_scscf).
pub struct AuthedImpi(pub String);

impl ImsAuth {
    /// MAR, then 401/407 with the vector (or 480/403/500). The transaction is
    /// suspended while the HSS answers when it can be (`cx_async`); the
    /// reply is sent on the resumed request, `$avp(maa_return_code)` says
    /// how it went (1 challenged, -1 not), and a Kamailio-style call goes on
    /// in its reply route.
    fn challenge(self: &Arc<Self>, ctx: &mut Ctx<'_, '_>, route: &str, realm: &str, alg: Option<String>, proxy: bool) -> i32 {
        let Some(peers) = self.peers.get() else { return -1 };
        let hdr: &[u8] = if proxy { b"Proxy-Authorization" } else { b"Authorization" };
        let Some((impi, impu)) = identities(ctx, hdr) else {
            let _ = ctx.reply(400, "Bad Request");
            return -1;
        };
        let alg = alg.unwrap_or_else(|| lock(&self.algorithm).clone());
        let scheme = if alg.eq_ignore_ascii_case("AKAv1-MD5") { "Digest-AKAv1-MD5" } else { "SIP Digest" };
        let mut mar = self.cx.base(peers, CMD_MAR);
        mar.add(Avp::str(USER_NAME, None, &impi))
            .add(Avp::str(PUBLIC_IDENTITY, V, &impu))
            .add(Avp::u32(SIP_NUMBER_AUTH_ITEMS, V, 1))
            .add(Avp::group(SIP_AUTH_DATA_ITEM, V, vec![Avp::str(SIP_AUTHENTICATION_SCHEME, V, scheme)]))
            .add(Avp::str(SERVER_NAME, V, &lock(&self.cx.server_name)));
        if let (Some(tm), Some(hub)) = (self.tm.get(), self.hub.get()) {
            let (me, me2, p, m2) = (self.clone(), self.clone(), peers.clone(), mar.clone());
            let (realm, impi, impu) = (realm.to_string(), impi.clone(), impu.clone());
            let sent = crate::cx_async::run(
                tm,
                hub,
                ctx,
                route,
                peers.cfg.timeout,
                move |done| me.cx.send_async(&p, m2, done),
                Box::new(move |res, c| {
                    let rc = me2.challenge_answer(res, c, &impi, &impu, &realm, proxy);
                    c.ext_mut::<sip_core::TxnVars>().avps.insert("maa_return_code".into(), vec![sip_core::pv::Val::Int(rc.into())]);
                }),
            );
            if let Some(rc) = sent {
                return rc;
            }
        }
        let res = self.cx.send(peers, mar);
        self.challenge_answer(res, ctx, &impi, &impu, realm, proxy)
    }

    /// The MAA → the vector stored and the challenge sent (or 480/403;
    /// 500 when the HSS doesn't answer in time).
    fn challenge_answer(&self, res: Result<Msg, DiameterError>, ctx: &mut Ctx<'_, '_>, impi: &str, impu: &str, realm: &str, proxy: bool) -> i32 {
        let maa = match res {
            Ok(a) => a,
            // Kamailio's ims_auth sends nothing on an MAA timeout and
            // resumes with $avp(maa_return_code) = -2 (CSCF_RETURN_ERROR);
            // its sample S-CSCF config then answers 500 "MAR failed". Sent
            // here, so `.fsr` callers (where the call is an action) get it.
            Err(e) if e.is_timeout() => {
                sip_core::stats::inc(sip_core::stats::counter("ims_auth", "mar_timeouts"));
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_auth: MAR: {e}"));
                let _ = ctx.reply(500, "MAR failed");
                return CSCF_RETURN_ERROR;
            }
            // Not sent (no peer, a write error): 480, as Kamailio does when
            // the MAR can't be sent.
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_auth: MAR: {e}"));
                let _ = ctx.reply(480, "Temporarily Unavailable");
                return RC_ERR;
            }
        };
        if maa.result() != Some(DIAMETER_SUCCESS) {
            let _ = ctx.reply(403, "Forbidden - HSS refused");
            return -1;
        }
        let Some(item) = maa.get(SIP_AUTH_DATA_ITEM, V).map(Avp::group_avps) else {
            let _ = ctx.reply(403, "Forbidden - no auth vector");
            return -1;
        };
        let sch = find(&item, SIP_AUTHENTICATION_SCHEME, V).map(Avp::as_str).unwrap_or_default();
        let exp = unix_secs().saturating_add(self.vector_timeout.load(Ordering::Relaxed));
        let (vector, extra) = if sch.eq_ignore_ascii_case("Digest-AKAv1-MD5") {
            let (Some(auth), Some(xres)) = (find(&item, SIP_AUTHENTICATE, V), find(&item, SIP_AUTHORIZATION, V)) else {
                let _ = ctx.reply(403, "Forbidden - bad AKA vector");
                return -1;
            };
            let ck = find(&item, CONFIDENTIALITY_KEY, V).map(|a| hex(&a.data)).unwrap_or_default();
            let ik = find(&item, INTEGRITY_KEY, V).map(|a| hex(&a.data)).unwrap_or_default();
            (Vector { nonce: b64(&auth.data), aka: true, secret: xres.data.clone(), expires: exp }, format!(", algorithm=AKAv1-MD5, ck=\"{ck}\", ik=\"{ik}\""))
        } else {
            let Some(dig) = find(&item, SIP_DIGEST_AUTHENTICATE, V).map(Avp::group_avps) else {
                let _ = ctx.reply(403, "Forbidden - bad digest vector");
                return -1;
            };
            let ha1 = find(&dig, DIGEST_HA1, None).map(Avp::as_str).unwrap_or_default();
            (Vector { nonce: b64(&rand_bytes(24)), aka: false, secret: ha1.into_bytes(), expires: exp }, ", algorithm=MD5".to_string())
        };
        let qop = lock(&self.qop).clone();
        let qop = if qop.is_empty() { String::new() } else { format!(", qop=\"{qop}\"") };
        let h =
            format!("{}: Digest realm=\"{realm}\", nonce=\"{}\"{extra}{qop}\r\n", if proxy { "Proxy-Authenticate" } else { "WWW-Authenticate" }, vector.nonce);
        self.vectors.alter(format!("{impi}\n{impu}"), |cur| {
            let mut v = cur.unwrap_or_default();
            v.retain(|x| x.expires > unix_secs());
            v.push(vector);
            (Some(v), ())
        });
        let _ = ctx.reply_with(
            if proxy { 407 } else { 401 },
            if proxy { "Proxy Authentication Required" } else { "Unauthorized - Challenging the UE" },
            h.as_bytes(),
        );
        1
    }

    fn authenticate(&self, ctx: &mut Ctx<'_, '_>, realm: &str, proxy: bool) -> i32 {
        let hdr: &[u8] = if proxy { b"Proxy-Authorization" } else { b"Authorization" };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let method = match ctx.msg.first {
            sip_parser::FirstLine::Request { method_raw, .. } => String::from_utf8_lossy(method_raw).into_owned(),
            _ => return -1,
        };
        let creds = ctx
            .msg
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(hdr))
            .map(|h| String::from_utf8_lossy(h.body).into_owned())
            .find(|c| creds_field(c, "realm").as_deref() == Some(realm));
        let Some(creds) = creds else { return -4 };
        let Some((impi, impu)) = identities(ctx, hdr) else { return -1 };
        let (Some(nonce), Some(uri), Some(resp)) = (creds_field(&creds, "nonce"), creds_field(&creds, "uri"), creds_field(&creds, "response")) else {
            return -5;
        };
        let key = format!("{impi}\n{impu}");
        let Some(v) = self.vectors.get_cloned(&key).and_then(|l| l.into_iter().find(|v| v.nonce == nonce && v.expires > unix_secs())) else { return -3 };
        let ha1 = if v.aka { md5_hex(&[impi.as_bytes(), realm.as_bytes(), &v.secret]) } else { String::from_utf8_lossy(&v.secret).to_ascii_lowercase() };
        let ha2 = md5_hex(&[method.as_bytes(), uri.as_bytes()]);
        let expected = match (creds_field(&creds, "qop"), creds_field(&creds, "nc"), creds_field(&creds, "cnonce")) {
            (Some(q), Some(nc), Some(cn)) => md5_hex(&[ha1.as_bytes(), nonce.as_bytes(), nc.as_bytes(), cn.as_bytes(), q.as_bytes(), ha2.as_bytes()]),
            _ => md5_hex(&[ha1.as_bytes(), nonce.as_bytes(), ha2.as_bytes()]),
        };
        if !expected.eq_ignore_ascii_case(&resp) {
            return -2;
        }
        // One use per vector (a new REGISTER gets a new challenge).
        self.vectors.with(&key, |l| l.retain(|x| x.nonce != nonce));
        ctx.ext.push(Box::new(AuthedImpi(impi)));
        1
    }
}

impl Module for ImsAuth {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("cxdx_dest_realm", Ty::Str, "", "Destination realm of Cx requests (default: the cdp realm)"),
            p("cxdx_forced_peer", Ty::Str, "", "Send Cx requests to this Diameter peer"),
            p("cxdx_dest_host", Ty::Str, "", "Alias of cxdx_forced_peer"),
            p("name", Ty::Str, "", "Our S-CSCF name (the Server-Name AVP)"),
            p("scscf_name", Ty::Str, "", "Alias of name"),
            p("registration_default_algorithm", Ty::Str, "AKAv1-MD5", "Authentication algorithm asked from the HSS when the call names none"),
            p("registration_qop", Ty::Str, "", "qop offered in challenges (empty: none)"),
            p("auth_vector_timeout", Ty::Duration(Unit::Sec), "60s", "How long an unused authentication vector stays valid"),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_auth"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, arg, opt, sig};
        const REALM: &[Param] = &[arg("realm", Str)];
        const CHAL: &[Param] = &[arg("realm", Str), opt("algorithm", Str).lit()];
        Some(vec![
            sig(
                "ims_www_challenge",
                "www_challenge",
                CHAL,
                Ret::Action,
                "MAR, then a 401 with the vector (or its 400/403/480; 500 when the HSS does not answer)",
            )
            .fixed(&[""]),
            sig(
                "ims_proxy_challenge",
                "proxy_challenge",
                CHAL,
                Ret::Action,
                "MAR, then a 407 with the vector (or its 400/403/480; 500 when the HSS does not answer)",
            )
            .fixed(&[""]),
            sig(
                "ims_www_authenticate",
                "www_authenticate",
                REALM,
                Ret::Bool,
                "Check the Authorization credentials for this realm against the challenge's vector",
            ),
            sig(
                "ims_proxy_authenticate",
                "proxy_authenticate",
                REALM,
                Ret::Bool,
                "Check the Proxy-Authorization credentials for this realm against the challenge's vector",
            ),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        if self.cx.set(name, v)? {
            return Ok(());
        }
        match name {
            "registration_default_algorithm" => *lock(&self.algorithm) = v.str()?.into(),
            "registration_qop" => *lock(&self.qop) = v.str()?.into(),
            "auth_vector_timeout" => self.vector_timeout.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "auth_data_hash_size"
            | "auth_used_vector_timeout"
            | "auth_data_timeout"
            | "max_nonce_reuse"
            | "add_authinfo_hdr"
            | "av_request_at_once"
            | "av_request_at_sync"
            | "av_mode"
            | "invite_qop"
            | "ignore_failed_auth"
            | "av_check_only_impu" => {}
            _ => return Err(format!("ims_auth: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.peers.set(cdp(reg, "ims_auth")?);
        let m = "ims_auth";
        if let Some(tm) = reg.api::<mod_txn::Tm>() {
            let _ = self.tm.set(tm);
        }
        let _ = self.hub.set(reg.hub.clone());
        // (reply route, realm, algorithm)
        type Chal = (String, DynStr, Option<String>);
        let chal = |a: &[Arg]| -> Result<Chal, String> {
            let route = a.first().and_then(|r| r.str().ok()).unwrap_or("").to_string();
            match a {
                [_, realm] => Ok((route, realm.dyn_str()?, None)),
                [_, realm, alg] => Ok((route, realm.dyn_str()?, Some(alg.str()?.to_string()))),
                _ => Err("expected route, realm[, algorithm]".into()),
            }
        };
        for (name, proxy) in [("ims_www_challenge", false), ("ims_proxy_challenge", true)] {
            let me = self.clone();
            reg.export(m, name, chal, move |ctx: &mut Ctx, (route, r, alg): &Chal| {
                let r = r.eval(ctx).into_owned();
                me.challenge(ctx, route, &r, alg.clone(), proxy)
            });
        }
        for (name, proxy) in [("ims_www_authenticate", false), ("ims_proxy_authenticate", true)] {
            let me = self.clone();
            reg.export(
                m,
                name,
                |a: &[Arg]| match a {
                    [realm] | [realm, _] => realm.dyn_str(),
                    _ => Err("expected realm".into()),
                },
                move |ctx: &mut Ctx, r: &DynStr| {
                    let r = r.eval(ctx).into_owned();
                    me.authenticate(ctx, &r, proxy)
                },
            );
        }
        Ok(())
    }
}

// ------------------------------------------------------- ims_registrar_scscf --

/// What a reg-event NOTIFY reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegChange {
    /// REGISTER: contacts added, refreshed or removed.
    Registered,
    /// Deregistration by the user.
    Unregistered,
    /// The last contact expired.
    Expired,
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn reginfo_head(version: u64, state: &str) -> String {
    format!("<?xml version=\"1.0\"?>\n<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"{version}\" state=\"{state}\">\n")
}

/// The record's AoRs: its implicit set.
fn aors(rec: &ImpuRecord) -> Vec<&String> {
    if rec.sub.public_ids.is_empty() { vec![&rec.impu] } else { rec.sub.public_ids.iter().collect() }
}

/// Element ids that stay the same across documents (partial ones refer
/// to them).
fn reg_id(aor: &str) -> String {
    format!("a{}", short_hash(aor))
}

/// The first 8 hex digits of the MD5 of `s`.
fn short_hash(s: &str) -> String {
    let mut h = md5_hex(&[s.as_bytes()]);
    h.truncate(8); // ASCII hex: always a char boundary
    h
}

fn contact_xml(c: &ScContact, state: &str, event: &str, expires: u64) -> String {
    format!("    <contact id=\"c{}\" state=\"{state}\" event=\"{event}\" expires=\"{expires}\"><uri>{}</uri></contact>\n", short_hash(&c.uri), xml_esc(&c.uri))
}

/// A reg-event subscription (we are the notifier).
#[derive(Clone, Debug)]
struct RegSub {
    impu: String,
    callid: String,
    our_tag: String,
    their_tag: String,
    their_uri: String,
    target: String,
    route: Vec<String>,
    dst: Dest,
    expires_at: u64,
    cseq: u32,
    version: u64,
}

pub struct RegistrarScscf {
    regsubs: Mutex<Vec<RegSub>>,
    tm: OnceLock<Arc<mod_txn::Tm>>,
    cx: CxCfg,
    default_expires: AtomicU64,
    min_expires: AtomicU64,
    max_expires: AtomicU64,
    peers: OnceLock<Arc<Peers>>,
    ul: OnceLock<Arc<UsrlocScscf>>,
    net: OnceLock<Arc<dyn Outbound>>,
    hub: OnceLock<Arc<sip_core::RouteHub>>,
}

impl Default for RegistrarScscf {
    fn default() -> Self {
        Self {
            regsubs: Mutex::default(),
            tm: OnceLock::new(),
            cx: CxCfg::default(),
            default_expires: AtomicU64::new(3600),
            min_expires: AtomicU64::new(10),
            max_expires: AtomicU64::new(3600),
            peers: OnceLock::new(),
            ul: OnceLock::new(),
            net: OnceLock::new(),
            hub: OnceLock::new(),
        }
    }
}

/// What `save` read from the REGISTER, for when the SAA comes.
#[derive(Clone)]
struct SavePlan {
    rec: ImpuRecord,
    before: ImpuRecord,
    kind: u32,
    impi: String,
    impu: String,
    path: Option<String>,
    t: u64,
}

impl RegistrarScscf {
    fn sar_msg(&self, peers: &Peers, impi: &str, impu: &str, kind: u32) -> Msg {
        let mut sar = self.cx.base(peers, CMD_SAR);
        sar.add(Avp::str(USER_NAME, None, impi))
            .add(Avp::str(PUBLIC_IDENTITY, V, impu))
            .add(Avp::str(SERVER_NAME, V, &lock(&self.cx.server_name)))
            .add(Avp::u32(SERVER_ASSIGNMENT_TYPE, V, kind))
            .add(Avp::u32(USER_DATA_ALREADY_AVAILABLE, V, u32::from(kind == SAT_RE_REGISTRATION)));
        sar
    }

    fn sar(&self, impi: &str, impu: &str, kind: u32) -> Result<Msg, DiameterError> {
        let peers = self.peers.get().ok_or(DiameterError::NoCdp)?;
        self.cx.send(peers, self.sar_msg(peers, impi, impu, kind))
    }

    /// REGISTER: the new bindings, SAR, then usrloc, reg-event NOTIFYs and
    /// the 200 (or 500). The transaction is suspended while the HSS
    /// answers when it can be (`cx_async`); `$avp(saa_return_code)` says
    /// how it went, and a Kamailio-style call goes on in its reply route.
    fn save(self: &Arc<Self>, ctx: &mut Ctx<'_, '_>, route: &str) -> i32 {
        let Some(ul) = self.ul.get() else { return -1 };
        if ctx.msg.method() != Some(Method::Register) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let Some(impu) = ctx.msg.get(HdrKind::To).and_then(|h| impu_of(name_addr(h.body).0)) else { return -1 };
        let impi = ctx.ext::<AuthedImpi>().map(|a| a.0.clone()).or_else(|| identities(ctx, b"Authorization").map(|x| x.0)).unwrap_or_default();
        let m = &*ctx.msg;
        let callid = m.get(HdrKind::CallId).map(|h| s(h.body)).unwrap_or_default();
        let cseq = m.get(HdrKind::CSeq).and_then(|h| std::str::from_utf8(h.body).ok()?.split_whitespace().next()?.parse().ok()).unwrap_or(0);
        let hexp =
            m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"expires")).and_then(|h| std::str::from_utf8(h.body).ok()?.trim().parse::<u64>().ok());
        let path: Vec<String> = m.headers.iter().filter(|h| h.name.eq_ignore_ascii_case(b"path")).map(|h| s(h.body)).collect();
        let path = (!path.is_empty()).then(|| path.join(","));
        let (min, max, def) =
            (self.min_expires.load(Ordering::Relaxed), self.max_expires.load(Ordering::Relaxed), self.default_expires.load(Ordering::Relaxed));
        let mut updates: Vec<(String, u64)> = Vec::new();
        let mut star = false;
        for h in m.headers.iter().filter(|h| h.kind == HdrKind::Contact) {
            for it in split_list(h.body) {
                let c = parse_contact(it);
                if c.star {
                    star = true;
                    continue;
                }
                let e = c.expires.map(u64::from).or(hexp).unwrap_or(def);
                // max wins over a larger min (clamp would panic on that config).
                updates.push((s(c.uri), if e == 0 { 0 } else { e.max(min).min(max) }));
            }
        }
        let mut rec = ul.get(&impu).unwrap_or_else(|| ImpuRecord { impu: impu.clone(), impi: impi.clone(), ..Default::default() });
        let before = rec.clone();
        let t = unix_secs();
        if star {
            rec.contacts.clear();
        }
        for (uri, e) in &updates {
            rec.contacts.retain(|c| &c.uri != uri);
            if *e > 0 {
                rec.contacts.push(ScContact {
                    uri: uri.clone(),
                    expires_at: t.saturating_add(*e),
                    received: ctx.src,
                    path: path.clone(),
                    callid: callid.clone(),
                    cseq,
                });
            }
        }
        let kind = if rec.contacts.is_empty() {
            SAT_USER_DEREGISTRATION
        } else if rec.registered {
            SAT_RE_REGISTRATION
        } else {
            SAT_REGISTRATION
        };
        if kind == SAT_USER_DEREGISTRATION && !rec.registered {
            // Query / nothing to remove.
            let _ = ctx.reply(200, "OK");
            return 1;
        }
        let plan = SavePlan { rec, before, kind, impi, impu, path, t };
        if let (Some(tm), Some(hub), Some(peers)) = (self.tm.get(), self.hub.get(), self.peers.get()) {
            let (me, me2, p, plan2) = (self.clone(), self.clone(), peers.clone(), plan.clone());
            let sar = self.sar_msg(peers, &plan.impi, &plan.impu, kind);
            let sent = crate::cx_async::run(
                tm,
                hub,
                ctx,
                route,
                peers.cfg.timeout,
                move |done| me.cx.send_async(&p, sar, done),
                Box::new(move |res, c| {
                    let rc = me2.save_answer(res, c, plan2);
                    c.ext_mut::<sip_core::TxnVars>().avps.insert("saa_return_code".into(), vec![sip_core::pv::Val::Int(rc.into())]);
                }),
            );
            if let Some(rc) = sent {
                return rc;
            }
        }
        let res = self.sar(&plan.impi, &plan.impu, kind);
        self.save_answer(res, ctx, plan)
    }

    /// The SAA → usrloc, NOTIFYs and the reply.
    fn save_answer(&self, res: Result<Msg, DiameterError>, ctx: &mut Ctx<'_, '_>, plan: SavePlan) -> i32 {
        let Some(ul) = self.ul.get() else { return -1 };
        let SavePlan { mut rec, before, kind, impi, impu, path, t } = plan;
        let saa = match res {
            Ok(a) => a,
            // Kamailio's ims_registrar_scscf answers a SAR it couldn't send
            // or that timed out with 500 "SAR failed" (R_SAR_FAILED) and
            // $avp(saa_return_code) = -2 (CSCF_RETURN_ERROR).
            Err(e) => {
                if e.is_timeout() {
                    sip_core::stats::inc(sip_core::stats::counter("ims_registrar_scscf", "sar_timeouts"));
                }
                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_registrar_scscf: SAR: {e}"));
                let _ = ctx.reply(500, "SAR failed");
                return CSCF_RETURN_ERROR;
            }
        };
        // Any other SAA (a Diameter error, UNABLE_TO_COMPLY, an unknown
        // result) takes Kamailio's same error path (cxdx_sar.c): 500 "SAR
        // failed" and $avp(saa_return_code) = -2.
        if saa.result() != Some(DIAMETER_SUCCESS) {
            sip_core::log::log(sip_core::log::L_ERR, &format!("ims_registrar_scscf: SAA result {:?}", saa.result()));
            let _ = ctx.reply(500, "SAR failed");
            return CSCF_RETURN_ERROR;
        }
        if let Some(ud) = saa.get(USER_DATA, V) {
            let xml = ud.as_str();
            match subscription::parse(&xml) {
                Ok(sub) => {
                    rec.sub = sub;
                    rec.user_data = xml;
                }
                Err(e) => sip_core::log::log(sip_core::log::L_ERR, &format!("ims_registrar_scscf: User-Data: {e}")),
            }
        }
        if rec.sub.public_ids.is_empty() {
            rec.sub.public_ids.push(impu.clone());
        }
        rec.impi = impi;
        let mut h = String::new();
        if kind == SAT_USER_DEREGISTRATION {
            ul.remove(&impu);
            self.notify_reg(&ImpuRecord { sub: rec.sub.clone(), ..before }, &rec, RegChange::Unregistered);
        } else {
            rec.registered = true;
            for c in &rec.contacts {
                h.push_str(&format!("Contact: <{}>;expires={}\r\n", c.uri, c.expires_at.saturating_sub(t)));
            }
            let me = self.net.get().and_then(|n| n.advertise(ctx.src.proto)).map(|a| a.to_string()).unwrap_or_else(|| "127.0.0.1".into());
            h.push_str(&format!("Service-Route: <sip:orig@{me};lr>\r\n"));
            h.push_str(&format!("P-Associated-URI: {}\r\n", rec.sub.public_ids.iter().map(|p| format!("<{p}>")).collect::<Vec<_>>().join(", ")));
            if let Some(p) = &path {
                h.push_str(&format!("Path: {p}\r\nSupported: path\r\n"));
            }
            ul.put(rec.clone());
            self.notify_reg(&before, &rec, RegChange::Registered);
        }
        let _ = ctx.reply_with(200, "OK", h.as_bytes());
        1
    }

    /// Full reginfo document for a record (RFC 3680): the first NOTIFY of
    /// a subscription (and the one answering a refresh).
    fn reginfo(rec: &ImpuRecord, version: u64, terminated: bool) -> String {
        let t = unix_secs();
        let mut x = reginfo_head(version, "full");
        for id in aors(rec) {
            let state = if terminated || rec.contacts.is_empty() { "terminated" } else { "active" };
            x.push_str(&format!("  <registration aor=\"{}\" id=\"{}\" state=\"{state}\">\n", xml_esc(id), reg_id(id)));
            for c in &rec.contacts {
                let (cs, ev, exp) = if terminated { ("terminated", "unregistered", 0) } else { ("active", "registered", c.expires_at.saturating_sub(t)) };
                x.push_str(&contact_xml(c, cs, ev, exp));
            }
            x.push_str("  </registration>\n");
        }
        x.push_str("</reginfo>\n");
        x
    }

    /// Partial reginfo document (RFC 3680 §5): only the contacts that
    /// changed between `before` and `after`, with the event that changed
    /// them (registered, refreshed / shortened, unregistered, expired).
    fn reginfo_partial(before: &ImpuRecord, after: &ImpuRecord, version: u64, change: RegChange) -> String {
        let t = unix_secs();
        let mut x = reginfo_head(version, "partial");
        let mut changed = String::new();
        for c in &after.contacts {
            match before.contacts.iter().find(|b| b.uri == c.uri) {
                None => changed.push_str(&contact_xml(c, "active", "registered", c.expires_at.saturating_sub(t))),
                // Re-registered (a new CSeq) or its expiry changed.
                Some(b) if b.expires_at != c.expires_at || b.cseq != c.cseq || b.callid != c.callid => {
                    let ev = if c.expires_at < b.expires_at { "shortened" } else { "refreshed" };
                    changed.push_str(&contact_xml(c, "active", ev, c.expires_at.saturating_sub(t)));
                }
                Some(_) => {}
            }
        }
        let gone = if change == RegChange::Expired { "expired" } else { "unregistered" };
        for b in before.contacts.iter().filter(|b| !after.contacts.iter().any(|c| c.uri == b.uri)) {
            changed.push_str(&contact_xml(b, "terminated", gone, 0));
        }
        let rec = if after.sub.public_ids.is_empty() { before } else { after };
        let state = if after.contacts.is_empty() { "terminated" } else { "active" };
        for id in aors(rec) {
            x.push_str(&format!("  <registration aor=\"{}\" id=\"{}\" state=\"{state}\">\n", xml_esc(id), reg_id(id)));
            x.push_str(&changed);
            x.push_str("  </registration>\n");
        }
        x.push_str("</reginfo>\n");
        x
    }

    /// NOTIFY every subscriber of this record's implicit set: a partial
    /// document with what changed, its version one more than the last.
    fn notify_reg(&self, before: &ImpuRecord, after: &ImpuRecord, change: RegChange) {
        let ids: Vec<&String> = after.sub.public_ids.iter().chain(&before.sub.public_ids).chain(std::iter::once(&after.impu)).collect();
        let subs: Vec<RegSub> = {
            let mut g = lock(&self.regsubs);
            self.drop_expired_subs(&mut g);
            g.iter_mut()
                .filter(|s| ids.contains(&&s.impu))
                .map(|s| {
                    s.cseq = s.cseq.saturating_add(1);
                    s.version = s.version.saturating_add(1);
                    s.clone()
                })
                .collect()
        };
        for s in subs {
            // The new CSeq and version are stored first, so the NOTIFYs
            // after a restart continue from them.
            if let Some(ul) = self.ul.get() {
                ul.db_put_sub(&s);
            }
            self.send_notify(&s, Self::reginfo_partial(before, after, s.version, change), false);
        }
    }

    /// Forget the subscriptions that expired (and their rows).
    fn drop_expired_subs(&self, g: &mut Vec<RegSub>) {
        let t = unix_secs();
        let ul = self.ul.get();
        g.retain(|s| {
            let keep = s.expires_at > t;
            if !keep && let Some(ul) = ul {
                ul.db_del_sub(s);
            }
            keep
        });
    }

    fn send_notify(&self, s: &RegSub, body: String, ended: bool) {
        let Some(tm) = self.tm.get() else { return };
        let state = if ended { "terminated;reason=timeout".to_string() } else { format!("active;expires={}", s.expires_at.saturating_sub(unix_secs())) };
        let mut headers = format!(
            "From: <{}>;tag={}\r\nTo: <{}>;tag={}\r\nEvent: reg\r\nSubscription-State: {state}\r\nContent-Type: application/reginfo+xml\r\n",
            s.impu, s.our_tag, s.their_uri, s.their_tag
        );
        for r in &s.route {
            headers.push_str(&format!("Route: {r}\r\n"));
        }
        let req = mod_txn::UacRequest {
            method: "NOTIFY".into(),
            ruri: s.target.clone(),
            dst: Some(s.dst),
            call_id: Some(s.callid.clone()),
            cseq: s.cseq,
            headers,
            body: body.into_bytes(),
            ..Default::default()
        };
        if let Err(e) = tm.t_uac(req, None) {
            sip_core::log::log(sip_core::log::L_WARN, &format!("ims_registrar_scscf: reg NOTIFY: {e}"));
        }
    }

    /// `subscribe_to_reg("location")`: accept a reg-event SUBSCRIBE.
    fn subscribe(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let is_sub = matches!(ctx.msg.first, sip_parser::FirstLine::Request { method_raw, .. } if method_raw.eq_ignore_ascii_case(b"SUBSCRIBE"));
        if !is_sub || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let m = &*ctx.msg;
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let event =
            m.headers.iter().find(|h| h.name.eq_ignore_ascii_case(b"event") || h.name.eq_ignore_ascii_case(b"o")).map(|h| s(h.body)).unwrap_or_default();
        if !event.trim().to_ascii_lowercase().starts_with("reg") {
            let _ = ctx.reply(489, "Bad Event");
            return -1;
        }
        let Some(impu) = impu_of(ctx.ruri()) else { return -1 };
        let m = &*ctx.msg;
        let (their_uri, their_tag) = match m.get(HdrKind::From) {
            Some(h) => {
                let (u, p) = name_addr(h.body);
                (s(u), sip_parser::uri::param(p, b"tag").map(s).unwrap_or_default())
            }
            None => return -1,
        };
        let callid = m.get(HdrKind::CallId).map(|h| s(h.body)).unwrap_or_default();
        let target = m.get(HdrKind::Contact).map(|h| s(name_addr(h.body).0)).unwrap_or_else(|| their_uri.clone());
        let route: Vec<String> = m
            .headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(b"record-route"))
            .flat_map(|h| split_list(h.body).into_iter().map(s).collect::<Vec<_>>())
            .collect();
        let expires = m
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"expires"))
            .and_then(|h| std::str::from_utf8(h.body).ok()?.trim().parse::<u64>().ok())
            .unwrap_or(600_000)
            .min(600_000);
        let to_tag = m.get(HdrKind::To).and_then(|h| sip_parser::uri::param(name_addr(h.body).1, b"tag")).map(s);
        // The 200 carries our To-tag: capture it (it is our From-tag in NOTIFYs).
        ctx.ext.push(Box::new(sip_core::module::ReplyCapture(None)));
        let _ = ctx.reply_with(
            200,
            "OK",
            format!(
                "Expires: {expires}\r\nContact: <sip:{}>\r\n",
                self.net.get().and_then(|n| n.advertise(ctx.src.proto)).map(|a| a.to_string()).unwrap_or_default()
            )
            .as_bytes(),
        );
        let reply = ctx.ext_get_mut::<sip_core::module::ReplyCapture>().and_then(|c| c.0.take()).unwrap_or_default();
        let our_tag = to_tag.unwrap_or_else(|| {
            let r = String::from_utf8_lossy(&reply).into_owned();
            r.lines()
                .find(|l| l.to_ascii_lowercase().starts_with("to:"))
                .and_then(|l| l.split(";tag=").nth(1))
                .map(|t| t.trim().to_string())
                .unwrap_or_default()
        });
        let t = unix_secs();
        let sub = {
            let mut g = lock(&self.regsubs);
            // A refresh continues the subscription's CSeq and version.
            let (cseq, version) =
                g.iter().find(|x| x.callid == callid && x.their_tag == their_tag).map_or((1, 0), |x| (x.cseq.saturating_add(1), x.version.saturating_add(1)));
            g.retain(|x| !(x.callid == callid && x.their_tag == their_tag));
            let sub = RegSub {
                impu: impu.clone(),
                callid,
                our_tag,
                their_tag,
                their_uri,
                target,
                route,
                dst: ctx.src,
                expires_at: t.saturating_add(expires),
                cseq,
                version,
            };
            if let Some(ul) = self.ul.get() {
                if expires > 0 { ul.db_put_sub(&sub) } else { ul.db_del_sub(&sub) }
            }
            if expires > 0 {
                g.push(sub.clone());
            }
            sub
        };
        let rec = self.ul.get().and_then(|u| u.get(&impu)).unwrap_or_else(|| ImpuRecord { impu: impu.clone(), ..Default::default() });
        self.send_notify(&sub, Self::reginfo(&rec, sub.version, false), expires == 0);
        1
    }

    /// `can_subscribe_to_reg("location")`: the subscriber (P-Asserted-
    /// Identity, else From) is in the target's implicit set.
    fn can_subscribe(&self, ctx: &mut Ctx<'_, '_>) -> bool {
        let _ = ctx.msg.parse_headers(HdrFlags::EOH);
        let Some(target) = impu_of(ctx.ruri()) else { return false };
        let who = ctx
            .msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"p-asserted-identity"))
            .or_else(|| ctx.msg.get(HdrKind::From))
            .and_then(|h| impu_of(name_addr(h.body).0));
        let Some(who) = who else { return false };
        match self.ul.get().and_then(|u| u.get(&target)) {
            Some(r) => who == r.impu || r.sub.public_ids.contains(&who),
            None => who == target,
        }
    }

    fn lookup(&self, ctx: &mut Ctx<'_, '_>) -> i32 {
        let Some(ul) = self.ul.get() else { return -1 };
        let Some(impu) = impu_of(ctx.ruri()) else { return -1 };
        let Some(r) = ul.get(&impu).filter(|r| r.registered) else { return -1 };
        let mut cs = r.contacts;
        if cs.is_empty() {
            return -1;
        }
        cs.sort_by_key(|c| std::cmp::Reverse(c.expires_at));
        let route = |c: &ScContact| -> Dest {
            c.path.as_deref().and_then(|p| split_list(p.as_bytes()).first().and_then(|f| sip_core::pvcore::dest_from_uri(name_addr(f).0))).unwrap_or(c.received)
        };
        let best = cs.remove(0);
        ctx.dst = Some(route(&best));
        if let Some(p) = &best.path {
            *ctx.ext_mut::<sip_core::module::RuriPath>() = sip_core::module::RuriPath(p.clone().into_bytes());
        }
        ctx.new_ruri = Some(best.uri.clone().into_bytes());
        for c in cs {
            ctx.branches.push(Branch {
                dst: Some(route(&c)),
                q: None,
                uri: c.uri.clone().into_bytes(),
                path: c.path.map(String::into_bytes),
                ..Default::default()
            });
        }
        1
    }

    /// Originating user (P-Asserted-Identity, else From) registered?
    fn orig_registered(&self, ctx: &mut Ctx<'_, '_>) -> bool {
        let Some(ul) = self.ul.get() else { return false };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return false;
        }
        let pai = ctx
            .msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"p-asserted-identity"))
            .and_then(|h| impu_of(name_addr(split_list(h.body).first().copied().unwrap_or(b"")).0));
        let impu = pai.or_else(|| ctx.msg.get(HdrKind::From).and_then(|h| impu_of(name_addr(h.body).0)));
        impu.and_then(|i| ul.get(&i)).is_some_and(|r| r.registered)
    }
}

impl Module for RegistrarScscf {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("cxdx_dest_realm", Ty::Str, "", "Destination realm of Cx requests (default: the cdp realm)"),
            p("cxdx_forced_peer", Ty::Str, "", "Send Cx requests to this Diameter peer"),
            p("cxdx_dest_host", Ty::Str, "", "Alias of cxdx_forced_peer"),
            p("name", Ty::Str, "", "Our S-CSCF name (the Server-Name AVP)"),
            p("scscf_name", Ty::Str, "", "Alias of name"),
            p("default_expires", Ty::Duration(Unit::Sec), "3600s", "Registration expiry when the REGISTER gives none"),
            p("min_expires", Ty::Duration(Unit::Sec), "10s", "Shortest registration expiry accepted"),
            p("max_expires", Ty::Duration(Unit::Sec), "3600s", "Longest registration expiry granted"),
        ])
    }

    fn name(&self) -> &'static str {
        "ims_registrar_scscf"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{Ret, ctx, sig};
        const LOC: &[&str] = &["location"];
        Some(vec![
            sig(
                "save",
                "save",
                &[],
                Ret::Action,
                "SAR, then the REGISTER's reply (200 with the bindings; 500 \"SAR failed\" when the HSS refuses or doesn't answer)",
            )
            .fixed(&["", "location"])
            .allowed(ctx::REQUEST),
            sig("lookup", "lookup", &[], Ret::Bool, "Send to the R-URI's registered contacts (best first, the rest as branches)").fixed(LOC),
            sig("subscribe_to_reg", "subscribe", &[], Ret::Action, "Handle a reg-event SUBSCRIBE and answer it").fixed(LOC).allowed(ctx::REQUEST),
            sig("can_subscribe_to_reg", "can_subscribe", &[], Ret::Bool, "The subscriber may watch this IMPU's registration state").fixed(LOC),
            sig("impu_registered", "orig_registered", &[], Ret::Bool, "The originating IMPU (P-Asserted-Identity / From) is registered").fixed(LOC),
            sig("term_impu_registered", "term_registered", &[], Ret::Bool, "The terminating IMPU (R-URI) is registered").fixed(LOC),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        if self.cx.set(name, v)? {
            return Ok(());
        }
        let n = || v.int().map(|x| x.max(0).unsigned_abs());
        match name {
            "default_expires" => self.default_expires.store(n()?, Ordering::Relaxed),
            "min_expires" => self.min_expires.store(n()?, Ordering::Relaxed),
            "max_expires" => self.max_expires.store(n()?, Ordering::Relaxed),
            "user_data_dtd"
            | "user_data_xsd"
            | "support_wildcardPSI"
            | "store_profile_dereg"
            | "subscription_default_expires"
            | "notification_list_size_threshold"
            | "append_branches"
            | "method_filtering"
            | "ue_unsubscribe_on_dereg"
            | "contact_expires_buffer" => {}
            _ => return Err(format!("ims_registrar_scscf: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let _ = self.peers.set(cdp(reg, "ims_registrar_scscf")?);
        let ul = reg.api::<UsrlocScscf>().ok_or("ims_registrar_scscf needs ims_usrloc_scscf loaded first")?;
        // Reg-event subscriptions stored by ims_usrloc_scscf (db_mode):
        // their NOTIFYs continue with the stored CSeq and version.
        let subs = ul.db_load_subs();
        if !subs.is_empty() {
            sip_core::log::log(sip_core::log::L_INFO, &format!("ims_registrar_scscf: loaded {} reg-event subscriptions from the database", subs.len()));
        }
        lock(&self.regsubs).extend(subs);
        let _ = self.ul.set(ul);
        let m = "ims_registrar_scscf";
        let table = |a: &[Arg]| -> Result<(), String> {
            if a.is_empty() || a.len() > 3 {
                return Err("expected [route,] \"location\"".into());
            }
            Ok(())
        };
        let me = self.clone();
        let _ = self.hub.set(reg.hub.clone());
        // save([route,] "location"): the Kamailio reply route, if given.
        let save_args = |a: &[Arg]| -> Result<String, String> {
            match a {
                [_] => Ok(String::new()),
                [route, _] | [route, _, _] => Ok(route.str().unwrap_or("").to_string()),
                _ => Err("expected [route,] \"location\"".into()),
            }
        };
        reg.export(m, "save", save_args, move |ctx: &mut Ctx, route: &String| me.save(ctx, route));
        let me = self.clone();
        reg.export(m, "lookup", table, move |ctx: &mut Ctx, _: &()| me.lookup(ctx));
        if let Some(tm) = reg.api::<mod_txn::Tm>() {
            let _ = self.tm.set(tm);
        }
        let me = self.clone();
        reg.export(m, "subscribe_to_reg", table, move |ctx: &mut Ctx, _: &()| me.subscribe(ctx));
        let me = self.clone();
        reg.export(m, "can_subscribe_to_reg", table, move |ctx: &mut Ctx, _: &()| rc(me.can_subscribe(ctx)));
        let me = self.clone();
        reg.export(m, "impu_registered", table, move |ctx: &mut Ctx, _: &()| rc(me.orig_registered(ctx)));
        let me = self.clone();
        reg.export(m, "term_impu_registered", table, move |ctx: &mut Ctx, _: &()| {
            let ok = impu_of(ctx.ruri()).and_then(|i| me.ul.get()?.get(&i)).is_some_and(|r| r.registered);
            rc(ok)
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        std::thread::Builder::new()
            .name("ims-registrar".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    if let Some(ul) = self.ul.get() {
                        for r in ul.take_expired() {
                            // SAR TIMEOUT_DEREGISTRATION (4).
                            if let Err(e) = self.sar(&r.impi, &r.impu, 4) {
                                sip_core::log::log(sip_core::log::L_ERR, &format!("ims_registrar_scscf: SAR timeout de-registration of {}: {e}", r.impu));
                            }
                            self.notify_reg(&r, &ImpuRecord { contacts: vec![], ..r.clone() }, RegChange::Expired);
                        }
                    }
                }
            })
            .map_err(|e| format!("cannot start the ims registrar timer thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::testutil::{hdr, reply, request, with_msg};

    const AUTH_RAND_AUTN: &[u8] = b"0123456789abcdefFEDCBA9876543210";
    const XRES: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4];

    fn maa(code: u32, item: Option<Vec<super::Avp>>) -> super::Msg {
        use super::*;
        let mut a = Msg::request(CMD_MAR, APP_CX).answer();
        a.add(Avp::u32(RESULT_CODE, None, code));
        if let Some(i) = item {
            a.add(Avp::group(SIP_AUTH_DATA_ITEM, V, i));
        }
        a
    }

    fn aka_item() -> Vec<super::Avp> {
        use super::*;
        vec![
            Avp::str(SIP_AUTHENTICATION_SCHEME, V, "Digest-AKAv1-MD5"),
            Avp::new(SIP_AUTHENTICATE, V, AUTH_RAND_AUTN.to_vec()),
            Avp::new(SIP_AUTHORIZATION, V, XRES.to_vec()),
            Avp::new(CONFIDENTIALITY_KEY, V, vec![0xcc; 16]),
            Avp::new(INTEGRITY_KEY, V, vec![0x11; 16]),
        ]
    }

    fn digest_item(ha1: &str) -> Vec<super::Avp> {
        use super::*;
        vec![Avp::str(SIP_AUTHENTICATION_SCHEME, V, "SIP Digest"), Avp::group(SIP_DIGEST_AUTHENTICATE, V, vec![Avp::str(DIGEST_HA1, None, ha1)])]
    }

    const REG_AUTH: &str = "Authorization: Digest username=\"alice@ims.test\", realm=\"ims.test\", nonce=\"\", uri=\"sip:ims.test\", response=\"\"\n";

    /// challenge_answer on a REGISTER: (return, code, reply).
    fn challenge(a: &super::ImsAuth, res: Result<super::Msg, super::DiameterError>, proxy: bool) -> (i32, u16, String) {
        with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", REG_AUTH, ""), |ctx| {
            let rc = a.challenge_answer(res, ctx, "alice@ims.test", "sip:alice@ims.test", "ims.test", proxy);
            let (code, out) = reply(ctx);
            (rc, code, out)
        })
    }

    /// The `name="value"` of a challenge header.
    fn field(h: &str, name: &str) -> Option<String> {
        super::creds_field(h.split_once("Digest ")?.1, name)
    }

    #[test]
    fn maa_answers_to_sip_replies() {
        use super::*;
        let a = ImsAuth::default();
        // (answer, return, reply code)
        let cases: Vec<(&str, Result<Msg, DiameterError>, i32, u16)> = vec![
            ("timeout", Err(DiameterError::Timeout { peer: Some("hss".into()) }), CSCF_RETURN_ERROR, 500),
            ("not sent", Err(DiameterError::NoRoute { realm: "ims.test".into() }), RC_ERR, 480),
            ("user unknown", Ok(maa(5001, Some(aka_item()))), -1, 403),
            ("unable to comply", Ok(maa(5012, None)), -1, 403),
            ("no vector", Ok(maa(2001, None)), -1, 403),
            ("AKA without XRES", Ok(maa(2001, Some(aka_item()[..2].to_vec()))), -1, 403),
            ("digest without its group", Ok(maa(2001, Some(vec![Avp::str(SIP_AUTHENTICATION_SCHEME, V, "SIP Digest")]))), -1, 403),
            ("AKA", Ok(maa(2001, Some(aka_item()))), 1, 401),
            ("digest", Ok(maa(2001, Some(digest_item("abc")))), 1, 401),
        ];
        for (what, res, rc, code) in cases {
            let (r, c, out) = challenge(&a, res, false);
            assert_eq!((r, c), (rc, code), "{what}: {out}");
        }
    }

    #[test]
    fn aka_challenge_carries_the_vector_and_keys() {
        use super::*;
        let a = ImsAuth::default();
        let (_, code, out) = challenge(&a, Ok(maa(2001, Some(aka_item()))), false);
        assert!(out.starts_with("SIP/2.0 401 Unauthorized - Challenging the UE\r\n"), "{out}");
        let h = hdr(&out, "WWW-Authenticate").unwrap();
        assert_eq!(code, 401);
        assert_eq!(field(&h, "nonce").as_deref(), Some(b64(AUTH_RAND_AUTN).as_str()));
        assert_eq!(field(&h, "realm").as_deref(), Some("ims.test"));
        assert_eq!(field(&h, "algorithm").as_deref(), Some("AKAv1-MD5"));
        assert_eq!(field(&h, "ck").as_deref(), Some("cc".repeat(16).as_str()));
        assert_eq!(field(&h, "ik").as_deref(), Some("11".repeat(16).as_str()));
        assert_eq!(field(&h, "qop"), None);
        // Proxy form, with the qop parameter.
        a.set_param("registration_qop", &Arg::Str("auth".into())).unwrap();
        let (_, code, out) = challenge(&a, Ok(maa(2001, Some(digest_item("x")))), true);
        assert_eq!(code, 407);
        let h = hdr(&out, "Proxy-Authenticate").unwrap();
        assert_eq!((field(&h, "algorithm").as_deref(), field(&h, "qop").as_deref()), (Some("MD5"), Some("auth")), "{h}");
        assert_eq!(a.vectors.get_cloned("alice@ims.test\nsip:alice@ims.test").map(|v| v.len()), Some(2));
    }

    /// An Authorization answering `nonce` with `ha1`, for `method` / `uri`.
    fn response(ha1: &str, nonce: &str, method: &str, uri: &str, qop: Option<(&str, &str)>) -> String {
        let ha2 = super::md5_hex(&[method.as_bytes(), uri.as_bytes()]);
        match qop {
            Some((nc, cn)) => format!(
                "response=\"{}\", qop=auth, nc={nc}, cnonce=\"{cn}\"",
                super::md5_hex(&[ha1.as_bytes(), nonce.as_bytes(), nc.as_bytes(), cn.as_bytes(), b"auth", ha2.as_bytes()])
            ),
            None => format!("response=\"{}\"", super::md5_hex(&[ha1.as_bytes(), nonce.as_bytes(), ha2.as_bytes()])),
        }
    }

    fn authenticate(a: &super::ImsAuth, auth_line: &str) -> (i32, Option<String>) {
        with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", auth_line, ""), |ctx| {
            let rc = a.authenticate(ctx, "ims.test", false);
            (rc, ctx.ext::<super::AuthedImpi>().map(|x| x.0.clone()))
        })
    }

    #[test]
    fn aka_and_digest_responses() {
        use super::*;
        let a = ImsAuth::default();
        challenge(&a, Ok(maa(2001, Some(aka_item()))), false);
        let nonce = b64(AUTH_RAND_AUTN);
        // AKAv1-MD5: the password is XRES (RFC 3310).
        let ha1 = md5_hex(&[b"alice@ims.test", b"ims.test", XRES]);
        let line = |resp: &str, nonce: &str| {
            format!(
                "Authorization: Digest username=\"alice@ims.test\", realm=\"ims.test\", nonce=\"{nonce}\", uri=\"sip:ims.test\", {resp}, algorithm=AKAv1-MD5\n"
            )
        };
        let wrong = md5_hex(&[b"alice@ims.test", b"ims.test", b"not xres"]);
        assert_eq!(authenticate(&a, &line(&response(&wrong, &nonce, "REGISTER", "sip:ims.test", None), &nonce)).0, -2);
        assert_eq!(authenticate(&a, &line(&response(&ha1, &nonce, "INVITE", "sip:ims.test", None), &nonce)).0, -2, "HA2 has the method");
        let ok = line(&response(&ha1, &nonce, "REGISTER", "sip:ims.test", Some(("00000001", "c1"))), &nonce);
        assert_eq!(authenticate(&a, &ok), (1, Some("alice@ims.test".into())));
        assert_eq!(authenticate(&a, &ok).0, -3, "a vector is used once");
        // SIP Digest: the HSS's HA1 (any case).
        let ha1 = md5_hex(&[b"alice@ims.test", b"ims.test", b"secret"]);
        challenge(&a, Ok(maa(2001, Some(digest_item(&ha1.to_ascii_uppercase())))), false);
        let nonce = a.vectors.get_cloned("alice@ims.test\nsip:alice@ims.test").unwrap().last().unwrap().nonce.clone();
        let ok = line(&response(&ha1, &nonce, "REGISTER", "sip:ims.test", None).to_ascii_uppercase().replace("RESPONSE", "response"), &nonce);
        assert_eq!(authenticate(&a, &ok).0, 1);
        // The other answers.
        assert_eq!(authenticate(&a, "").0, -4, "no credentials");
        assert_eq!(authenticate(&a, &line("response=\"x\"", "n").replace("realm=\"ims.test\"", "realm=\"other\"")).0, -4, "another realm");
        assert_eq!(authenticate(&a, &line("x=1", "n")).0, -5, "no response");
        assert_eq!(authenticate(&a, &line("response=\"x\"", "unknown")).0, -3, "no such nonce");
    }

    #[test]
    fn expired_vectors_are_not_used() {
        use super::*;
        let a = ImsAuth::default();
        challenge(&a, Ok(maa(2001, Some(aka_item()))), false);
        a.vectors.with("alice@ims.test\nsip:alice@ims.test", |v| v.iter_mut().for_each(|x| x.expires = 0));
        let nonce = b64(AUTH_RAND_AUTN);
        let ha1 = md5_hex(&[b"alice@ims.test", b"ims.test", XRES]);
        let line = format!(
            "Authorization: Digest username=\"alice@ims.test\", realm=\"ims.test\", nonce=\"{nonce}\", uri=\"sip:ims.test\", {}\n",
            response(&ha1, &nonce, "REGISTER", "sip:ims.test", None)
        );
        assert_eq!(authenticate(&a, &line).0, -3);
    }

    /// A registrar with its usrloc (memory only).
    fn registrar() -> (std::sync::Arc<super::RegistrarScscf>, std::sync::Arc<super::UsrlocScscf>) {
        let r = std::sync::Arc::new(super::RegistrarScscf::default());
        let ul = std::sync::Arc::new(super::UsrlocScscf::default());
        let _ = r.ul.set(ul.clone());
        (r, ul)
    }

    #[test]
    fn save_with_min_expires_above_max_expires_does_not_panic() {
        use super::*;
        let (r, _) = registrar();
        r.set_param("min_expires", &Arg::Int(7200)).unwrap();
        r.set_param("max_expires", &Arg::Int(3600)).unwrap();
        // No HSS: the SAR fails, after the expiry was worked out.
        let (rc, code) = with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "Expires: 600\n", ""), |ctx| (r.save(ctx, ""), reply(ctx).0));
        assert_eq!((rc, code), (CSCF_RETURN_ERROR, 500));
    }

    fn plan(rec: super::ImpuRecord, kind: u32, path: Option<&str>) -> super::SavePlan {
        super::SavePlan {
            before: super::ImpuRecord { impu: rec.impu.clone(), ..Default::default() },
            rec,
            kind,
            impi: "alice@ims.test".into(),
            impu: "sip:alice@ims.test".into(),
            path: path.map(str::to_string),
            t: super::unix_secs(),
        }
    }

    fn contact(uri: &str, secs: u64) -> super::ScContact {
        super::ScContact {
            uri: uri.into(),
            expires_at: super::unix_secs().saturating_add(secs),
            received: super::Dest::new(sip_core::Proto::Udp, "192.0.2.9:5060".parse().unwrap()),
            path: None,
            callid: "c".into(),
            cseq: 1,
        }
    }

    #[test]
    fn saa_answers() {
        use super::*;
        let (r, ul) = registrar();
        let rec = ImpuRecord { impu: "sip:alice@ims.test".into(), contacts: vec![contact("sip:alice@192.0.2.9", 600)], ..Default::default() };
        let saa = |code: u32, user_data: Option<&str>| {
            let mut a = Msg::request(CMD_SAR, APP_CX).answer();
            a.add(Avp::u32(RESULT_CODE, None, code));
            if let Some(x) = user_data {
                a.add(Avp::str(USER_DATA, V, x));
            }
            a
        };
        let run = |res: Result<Msg, DiameterError>, p: SavePlan| {
            with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| {
                let rc = r.save_answer(res, ctx, p);
                let (code, out) = reply(ctx);
                (rc, code, out)
            })
        };
        // Failures: 500 "SAR failed", -2.
        for res in [Err(DiameterError::Timeout { peer: None }), Err(DiameterError::NoCdp), Ok(saa(5012, None)), Ok(saa(2002, None))] {
            let (rc, code, out) = run(res, plan(rec.clone(), SAT_REGISTRATION, None));
            assert_eq!((rc, code), (CSCF_RETURN_ERROR, 500));
            assert!(out.starts_with("SIP/2.0 500 SAR failed\r\n"));
        }
        assert!(ul.get("sip:alice@ims.test").is_none());
        // Success: the bindings, Service-Route, P-Associated-URI (the implicit set from User-Data) and Path.
        let ud = "<IMSSubscription><PrivateID>alice@ims.test</PrivateID><ServiceProfile><PublicIdentity><Identity>sip:alice@ims.test</Identity></PublicIdentity><PublicIdentity><Identity>tel:+4930111</Identity></PublicIdentity></ServiceProfile></IMSSubscription>";
        let (rc, code, out) = run(Ok(saa(2001, Some(ud))), plan(rec.clone(), SAT_REGISTRATION, Some("<sip:pcscf.ims.test;lr>")));
        assert_eq!((rc, code), (1, 200), "{out}");
        let exp: u64 = hdr(&out, "Contact").unwrap().strip_prefix("<sip:alice@192.0.2.9>;expires=").unwrap().parse().unwrap();
        assert!((599..=600).contains(&exp), "{out}");
        assert_eq!(hdr(&out, "Service-Route").as_deref(), Some("<sip:orig@127.0.0.1;lr>"));
        assert_eq!(hdr(&out, "P-Associated-URI").as_deref(), Some("<sip:alice@ims.test>, <tel:+4930111>"));
        assert_eq!(hdr(&out, "Path").as_deref(), Some("<sip:pcscf.ims.test;lr>"));
        assert_eq!(hdr(&out, "Supported").as_deref(), Some("path"));
        let stored = ul.get("tel:+4930111").unwrap();
        assert!(stored.registered && stored.impi == "alice@ims.test" && stored.user_data == ud);
        // Without User-Data the IMPU is the implicit set; a bad document is ignored.
        let (_, _, out) = run(Ok(saa(2001, Some("<ServiceProfile><InitialFilterCriteria/></ServiceProfile>"))), plan(rec.clone(), SAT_RE_REGISTRATION, None));
        assert_eq!(hdr(&out, "P-Associated-URI").as_deref(), Some("<sip:alice@ims.test>"));
        assert_eq!(hdr(&out, "Path"), None);
        // De-registration: removed, 200 without bindings.
        let gone = ImpuRecord { contacts: vec![], ..rec };
        let (rc, code, out) = run(Ok(saa(2001, None)), plan(gone, SAT_USER_DEREGISTRATION, None));
        assert_eq!((rc, code), (1, 200));
        assert_eq!(hdr(&out, "Contact"), None);
        assert!(ul.get("sip:alice@ims.test").is_none() && ul.get("tel:+4930111").is_none());
    }

    #[test]
    fn deregistering_an_unknown_user_answers_200_without_a_sar() {
        let (r, _) = registrar();
        let (rc, code) = with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "Expires: 0\n", ""), |ctx| (r.save(ctx, ""), reply(ctx).0));
        assert_eq!((rc, code), (1, 200));
    }

    #[test]
    fn full_reginfo_and_escaping() {
        use super::*;
        let rec = ImpuRecord {
            impu: "sip:a@t".into(),
            contacts: vec![contact("sip:a@1;x=\"<y>\"&z", 100)],
            sub: Subscription { public_ids: vec!["sip:a@t".into(), "tel:+1".into()], ..Default::default() },
            ..Default::default()
        };
        let x = RegistrarScscf::reginfo(&rec, 7, false);
        assert!(x.starts_with("<?xml version=\"1.0\"?>\n<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"7\" state=\"full\">\n"), "{x}");
        assert_eq!(x.matches(r#"state="active" event="registered""#).count(), 2);
        assert!(x.contains("<uri>sip:a@1;x=&quot;&lt;y&gt;&quot;&amp;z</uri>"), "{x}");
        assert!(x.contains(&format!("<registration aor=\"tel:+1\" id=\"{}\" state=\"active\">", reg_id("tel:+1"))));
        let t = RegistrarScscf::reginfo(&rec, 8, true);
        assert_eq!(t.matches(r#"state="terminated" event="unregistered" expires="0""#).count(), 2, "{t}");
        assert!(t.contains(r#"<registration aor="sip:a@t" id="#) && !t.contains(r#"state="active""#));
        // Without contacts the registrations are terminated; without an implicit set the IMPU stands alone.
        let empty = ImpuRecord { impu: "sip:b@t".into(), ..Default::default() };
        let e = RegistrarScscf::reginfo(&empty, 0, false);
        assert_eq!(e.matches("<registration ").count(), 1);
        assert!(e.contains(r#"aor="sip:b@t""#) && e.contains(r#"state="terminated">"#), "{e}");
        assert_eq!(short_hash("x").len(), 8);
        assert_eq!(reg_id("sip:a@t"), reg_id("sip:a@t"));
        assert_ne!(reg_id("sip:a@t"), reg_id("sip:b@t"));
    }

    #[test]
    fn partial_reginfo_shortened_contacts() {
        use super::*;
        let before = ImpuRecord { impu: "sip:a@t".into(), contacts: vec![contact("sip:a@1", 600)], ..Default::default() };
        let after = ImpuRecord { contacts: vec![contact("sip:a@1", 60)], ..before.clone() };
        let x = RegistrarScscf::reginfo_partial(&before, &after, 1, RegChange::Registered);
        assert!(x.contains(r#"state="active" event="shortened""#), "{x}");
        // A new CSeq alone is a refresh.
        let mut again = before.clone();
        again.contacts[0].cseq = 2;
        let x = RegistrarScscf::reginfo_partial(&before, &again, 2, RegChange::Registered);
        assert!(x.contains(r#"event="refreshed""#), "{x}");
        // Nothing changed: the registration without contacts.
        let x = RegistrarScscf::reginfo_partial(&before, &before, 3, RegChange::Registered);
        assert!(!x.contains("<contact"), "{x}");
    }

    #[test]
    fn lookup_orders_contacts_and_follows_path() {
        use super::*;
        let (r, ul) = registrar();
        let mut via_path = contact("sip:alice@10.0.0.2", 300);
        via_path.path = Some("<sip:192.0.2.50:5070;lr>,<sip:192.0.2.51;lr>".into());
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            registered: true,
            contacts: vec![contact("sip:alice@10.0.0.1", 100), via_path, contact("sip:alice@10.0.0.3", 0)],
            sub: Subscription { public_ids: vec!["sip:alice@ims.test".into(), "tel:+1".into()], ..Default::default() },
            ..Default::default()
        });
        with_msg(&request("INVITE", "tel:+1", "tel:+1", "", ""), |ctx| {
            assert_eq!(r.lookup(ctx), 1);
            assert_eq!(ctx.new_ruri.as_deref(), Some(&b"sip:alice@10.0.0.2"[..]), "longest-lived first");
            assert_eq!(ctx.dst.map(|d| d.addr), Some("192.0.2.50:5070".parse().unwrap()), "via the first Path hop");
            assert_eq!(ctx.branches.len(), 1, "the expired contact is left out");
            assert_eq!(ctx.branches[0].uri, b"sip:alice@10.0.0.1");
        });
        assert_eq!(with_msg(&request("INVITE", "sip:carol@ims.test", "sip:carol@ims.test", "", ""), |ctx| r.lookup(ctx)), -1);
    }

    #[test]
    fn reg_subscribers_must_be_in_the_implicit_set() {
        use super::*;
        let (r, ul) = registrar();
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            registered: true,
            sub: Subscription { public_ids: vec!["sip:alice@ims.test".into(), "tel:+1".into()], ..Default::default() },
            ..Default::default()
        });
        let can = |ruri: &str, extra: &str| with_msg(&request("SUBSCRIBE", ruri, ruri, extra, ""), |ctx| r.can_subscribe(ctx));
        assert!(can("sip:alice@ims.test", ""));
        assert!(can("tel:+1", ""), "From alice, target in her set");
        assert!(!can("sip:alice@ims.test", "P-Asserted-Identity: <sip:eve@ims.test>\n"));
        assert!(can("sip:alice@ims.test", "P-Asserted-Identity: <tel:+1>\n"));
        assert!(!can("sip:bob@ims.test", ""), "unknown target: only itself");
    }

    #[test]
    fn creds() {
        let c = r#"Digest username="alice@ims.test", realm="ims.test", nonce="abc=", uri="sip:ims.test", response="00", qop=auth, nc=00000001"#;
        assert_eq!(super::creds_field(c, "username").as_deref(), Some("alice@ims.test"));
        assert_eq!(super::creds_field(c, "nonce").as_deref(), Some("abc="));
        assert_eq!(super::creds_field(c, "qop").as_deref(), Some("auth"));
        assert_eq!(super::creds_field(c, "nc").as_deref(), Some("00000001"));
    }

    #[test]
    fn creds_key_boundaries() {
        let f = super::creds_field;
        // Only a whole key counts, in any case; a missing value is empty.
        assert_eq!(f(r#"Digest xusername="x", USERNAME=u"#, "username").as_deref(), Some("u"));
        assert_eq!(f("username=", "username").as_deref(), Some(""));
        assert_eq!(f("Ünï,username=\"é\"", "username").as_deref(), Some("é"));
        assert_eq!(f("realm=r", "username"), None);
    }

    #[test]
    fn base64() {
        for (raw, b64) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(super::b64(raw.as_bytes()), b64);
        }
        assert_eq!(super::b64(&[0xFF, 0xFE]), "//4=");
    }

    #[test]
    fn partial_reginfo() {
        use super::*;
        let dst = Dest::new(sip_core::Proto::Udp, std::net::SocketAddr::from(([127, 0, 0, 1], 5060)));
        let c = |uri: &str, exp: u64| ScContact { uri: uri.into(), expires_at: unix_secs() + exp, received: dst, path: None, callid: "x".into(), cseq: 1 };
        let sub = Subscription { public_ids: vec!["sip:a@t".into(), "tel:+1".into()], ..Default::default() };
        let before = ImpuRecord {
            impu: "sip:a@t".into(),
            registered: true,
            contacts: vec![c("sip:a@1", 100), c("sip:a@2", 100), c("sip:a@3", 100)],
            sub: sub.clone(),
            ..Default::default()
        };
        let after = ImpuRecord { contacts: vec![c("sip:a@1", 100), c("sip:a@2", 600), c("sip:a@4", 600)], ..before.clone() };
        let x = RegistrarScscf::reginfo_partial(&before, &after, 3, RegChange::Registered);
        assert!(x.contains(r#"version="3" state="partial""#), "{x}");
        assert_eq!(x.matches("<registration ").count(), 2);
        // a@1 unchanged: left out; a@2 refreshed; a@4 new; a@3 gone.
        assert!(!x.contains("sip:a@1"), "{x}");
        assert!(x.contains(r#"state="active" event="refreshed""#) && x.contains("<uri>sip:a@2</uri>"), "{x}");
        assert!(x.contains(r#"state="active" event="registered""#) && x.contains("<uri>sip:a@4</uri>"), "{x}");
        assert!(x.contains(r#"state="terminated" event="unregistered" expires="0"><uri>sip:a@3</uri>"#), "{x}");
        // The contact ids match the full document's.
        let full = RegistrarScscf::reginfo(&after, 0, false);
        let id = |doc: &str, uri: &str| doc.lines().find(|l| l.contains(&format!("<uri>{uri}</uri>"))).and_then(|l| l.split('"').nth(1)).map(str::to_string);
        assert_eq!(id(&full, "sip:a@2"), id(&x, "sip:a@2"));
        assert!(full.contains(r#"state="full""#));
        // Expiry: every contact terminated with event "expired", registration terminated.
        let gone = ImpuRecord { contacts: vec![], ..before.clone() };
        let x = RegistrarScscf::reginfo_partial(&before, &gone, 4, RegChange::Expired);
        assert_eq!(x.matches(r#"state="terminated" event="expired""#).count(), 6, "{x}");
        assert!(x.contains(r#"id="a"#) && x.contains(r#"state="terminated">"#), "{x}");
    }

    /// A usrloc writing through to an in-memory database.
    fn ul_with_db() -> (std::sync::Arc<super::UsrlocScscf>, std::sync::Arc<crate::testutil::MemDb>) {
        let db = std::sync::Arc::new(crate::testutil::MemDb::default());
        let ul = std::sync::Arc::new(super::UsrlocScscf::default());
        let _ = ul.db.set(db.clone());
        (ul, db)
    }

    const UD: &str = "<IMSSubscription><PrivateID>alice@ims.test</PrivateID><ServiceProfile><PublicIdentity><Identity>sip:alice@ims.test</Identity></PublicIdentity><PublicIdentity><Identity>tel:+1</Identity></PublicIdentity></ServiceProfile></IMSSubscription>";
    /// User-Data that does not parse (an iFC without its server).
    const BAD_UD: &str = "<ServiceProfile><InitialFilterCriteria><Priority>1</Priority></InitialFilterCriteria></ServiceProfile>";

    #[test]
    fn usrloc_writes_through_and_loads_back() {
        use super::*;
        let (ul, db) = ul_with_db();
        let mut c = contact("sip:alice@192.0.2.9", 600);
        c.path = Some("<sip:pcscf.ims.test;lr>".into());
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            impi: "alice@ims.test".into(),
            registered: true,
            contacts: vec![c],
            sub: subscription::parse(UD).unwrap(),
            user_data: UD.into(),
        });
        let impu = db.rows("impu");
        assert_eq!(impu.len(), 1);
        assert_eq!(impu[0]["reg_state"], DbVal::Int(1));
        assert_eq!(db.rows("contact")[0]["received"], DbVal::Str("sip:192.0.2.9:5060".into()));
        // Rows the loader skips or repairs, next to the good ones.
        let now = i64::try_from(unix_secs()).unwrap();
        let contact_row = |impu: &str, received: &str, exp: i64| {
            db.put(
                "contact",
                &[
                    ("impu", impu.into()),
                    ("contact", "sip:x@192.0.2.1".into()),
                    ("received", received.into()),
                    ("path", "".into()),
                    ("expires", DbVal::Int(exp)),
                    ("callid", DbVal::Null),
                    ("cseq", DbVal::Int(-1)),
                ],
            )
        };
        contact_row("sip:bob@ims.test", "garbage", now + 600);
        contact_row("sip:carol@ims.test", "sip:192.0.2.3:5060", now + 600);
        contact_row("sip:carol@ims.test", "sip:192.0.2.4:5060", now - 1);
        let impu_row = |impu: &str, state: i64, ud: &str| {
            db.put("impu", &[("impu", impu.into()), ("impi", "i".into()), ("reg_state", DbVal::Int(state)), ("ims_subscription_data", ud.into())])
        };
        impu_row("", 1, "");
        impu_row("sip:bob@ims.test", 1, ""); // its only contact had no usable address: gone
        impu_row("sip:carol@ims.test", 1, BAD_UD);
        impu_row("sip:dave@ims.test", 0, "");
        let fresh = UsrlocScscf::default();
        let _ = fresh.db.set(db.clone());
        assert_eq!(fresh.db_load(), Ok(3));
        let a = fresh.get("tel:+1").unwrap();
        assert_eq!((a.impu.as_str(), a.contacts.len(), a.contacts[0].path.as_deref()), ("sip:alice@ims.test", 1, Some("<sip:pcscf.ims.test;lr>")));
        let carol = fresh.get("sip:carol@ims.test").unwrap();
        assert_eq!(carol.sub.public_ids, ["sip:carol@ims.test"], "bad User-Data: the IMPU alone");
        assert_eq!((carol.contacts.len(), carol.contacts[0].callid.as_str(), carol.contacts[0].cseq), (1, "", 0));
        let dave = fresh.get("sip:dave@ims.test").unwrap();
        assert!(!dave.registered && dave.sub.public_ids == ["sip:dave@ims.test"]);
        assert!(fresh.get("sip:bob@ims.test").is_none());
        assert!(!db.rows("impu").iter().any(|r| r["impu"] == DbVal::Str("sip:bob@ims.test".into())), "deleted while loading");
        // No database: nothing to load.
        assert_eq!(UsrlocScscf::default().db_load(), Ok(0));
        // A database that is down: the memory state still changes.
        db.fail.store(true, Ordering::Relaxed);
        assert!(fresh.db_load().is_err());
        fresh.remove("sip:dave@ims.test");
        assert!(fresh.get("sip:dave@ims.test").is_none());
        fresh.put(ImpuRecord { impu: "sip:erin@ims.test".into(), ..Default::default() });
        assert!(fresh.get("sip:erin@ims.test").is_some());
        db.fail.store(false, Ordering::Relaxed);
        // Removing an unknown IMPU only clears its rows.
        ul.remove("sip:nobody@ims.test");
        assert!(ul.get("sip:alice@ims.test").is_some());
    }

    #[test]
    fn expired_registrations_are_taken_with_their_contacts() {
        use super::*;
        let (ul, db) = ul_with_db();
        let mut old = contact("sip:alice@192.0.2.9", 0);
        old.expires_at = unix_secs().saturating_sub(5);
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            registered: true,
            contacts: vec![old],
            sub: subscription::parse(UD).unwrap(),
            ..Default::default()
        });
        ul.put(ImpuRecord { impu: "sip:bob@ims.test".into(), registered: true, contacts: vec![contact("sip:bob@192.0.2.8", 600)], ..Default::default() });
        // Not registered (only profile data): kept.
        ul.put(ImpuRecord { impu: "sip:carol@ims.test".into(), ..Default::default() });
        let gone = ul.take_expired();
        assert_eq!(gone.len(), 1);
        assert_eq!((gone[0].impu.as_str(), gone[0].contacts.len()), ("sip:alice@ims.test", 1), "with the contacts that expired");
        assert!(ul.get("tel:+1").is_none() && ul.get("sip:alice@ims.test").is_none(), "every alias goes");
        assert!(ul.get("sip:bob@ims.test").is_some() && ul.get("sip:carol@ims.test").is_some());
        assert_eq!(db.rows("impu").len(), 2);
        assert!(ul.take_expired().is_empty());
    }

    /// A reg-event subscription of alice's registration.
    fn regsub(callid: &str, expires_in: u64) -> super::RegSub {
        super::RegSub {
            impu: "sip:alice@ims.test".into(),
            callid: callid.into(),
            our_tag: "ot".into(),
            their_tag: "tt".into(),
            their_uri: "sip:watcher@ims.test".into(),
            target: "sip:watcher@192.0.2.20:5070".into(),
            route: vec!["<sip:pcscf.ims.test;lr>".into(), "<sip:p2.ims.test;lr>".into()],
            dst: super::Dest::new(sip_core::Proto::Udp, "192.0.2.20:5070".parse().unwrap()),
            expires_at: super::unix_secs().saturating_add(expires_in),
            cseq: 3,
            version: 2,
        }
    }

    #[test]
    fn reg_subscriptions_round_trip_through_the_db() {
        use super::*;
        let (ul, db) = ul_with_db();
        ul.db_put_sub(&regsub("c1", 600));
        // Written again (a refresh): still one row.
        ul.db_put_sub(&regsub("c1", 600));
        assert_eq!(db.rows("subscriber_scscf").len(), 1);
        assert_eq!(db.rows("subscriber_scscf")[0]["event"], DbVal::Int(1));
        let loaded = ul.db_load_subs();
        assert_eq!(loaded.len(), 1);
        let (a, b) = (&loaded[0], regsub("c1", 600));
        assert_eq!(
            (&a.impu, &a.callid, &a.our_tag, &a.their_tag, &a.their_uri, &a.target),
            (&b.impu, &b.callid, &b.our_tag, &b.their_tag, &b.their_uri, &b.target)
        );
        assert_eq!((&a.route, a.dst, a.cseq, a.version), (&b.route, b.dst, 3, 2));
        // Rows that are skipped: no usable address, another event, no
        // Call-ID; an expired one is also deleted.
        let row = |callid: &str, event: i64, sock: &str, contact: &str, exp: i64| {
            let now = i64::try_from(unix_secs()).unwrap();
            db.put(
                "subscriber_scscf",
                &[
                    ("watcher_uri", "sip:w@ims.test".into()),
                    ("watcher_contact", contact.into()),
                    ("presentity_uri", "sip:alice@ims.test".into()),
                    ("event", DbVal::Int(event)),
                    ("expires", DbVal::Int(now + exp)),
                    ("version", DbVal::Int(-4)),
                    ("local_cseq", DbVal::Int(-1)),
                    ("call_id", callid.into()),
                    ("from_tag", "ft".into()),
                    ("to_tag", "tt".into()),
                    ("record_route", "".into()),
                    ("sockinfo_str", sock.into()),
                ],
            )
        };
        row("c2", 1, "garbage", "garbage", 600);
        row("c3", 2, "sip:192.0.2.1:5060", "", 600);
        row("", 1, "sip:192.0.2.1:5060", "", 600);
        row("c4", 1, "garbage", "sip:192.0.2.4:5080", -10);
        row("c5", 1, "", "sip:192.0.2.5:5090", 600);
        let loaded = ul.db_load_subs();
        assert_eq!(loaded.iter().map(|s| s.callid.as_str()).collect::<Vec<_>>(), ["c1", "c5"]);
        let c5 = &loaded[1];
        assert_eq!((c5.dst.addr, c5.version, c5.cseq, c5.route.len()), ("192.0.2.5:5090".parse().unwrap(), 0, 0, 0), "the contact when the socket is unknown");
        assert!(!db.rows("subscriber_scscf").iter().any(|r| r["call_id"] == DbVal::Str("c4".into())), "expired row deleted");
        // A subscription's row goes by its dialog.
        ul.db_del_sub(&regsub("c1", 0));
        assert!(!db.rows("subscriber_scscf").iter().any(|r| r["call_id"] == DbVal::Str("c1".into())));
        // Without a database, and with one that is down: nothing (logged).
        assert!(UsrlocScscf::default().db_load_subs().is_empty());
        UsrlocScscf::default().db_del_sub(&regsub("c1", 0));
        db.fail.store(true, Ordering::Relaxed);
        assert!(ul.db_load_subs().is_empty());
        ul.db_put_sub(&regsub("c9", 600));
        ul.db_del_sub(&regsub("c9", 600));
        db.fail.store(false, Ordering::Relaxed);
        assert!(!db.rows("subscriber_scscf").iter().any(|r| r["call_id"] == DbVal::Str("c9".into())));
    }

    #[test]
    fn usrloc_parameters() {
        use super::*;
        let ul = UsrlocScscf::default();
        for bad in [-1, 4] {
            assert!(ul.set_param("db_mode", &Arg::Int(bad)).unwrap_err().contains("(0..3)"), "{bad}");
        }
        ul.set_param("db_mode", &Arg::Int(2)).unwrap();
        assert_eq!(ul.db_mode.load(Ordering::Relaxed), 2);
        ul.set_param("db_url", &Arg::Str("text:///tmp/x".into())).unwrap();
        ul.set_param("hash_size", &Arg::Int(9)).unwrap();
        assert_eq!(lock(&ul.db_url).as_deref(), Some("text:///tmp/x"));
    }

    #[test]
    fn challenge_errors_before_and_without_the_hss() {
        use super::*;
        let a = std::sync::Arc::new(ImsAuth::default());
        // No cdp: nothing is sent, no reply.
        let r =
            with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| (a.challenge(ctx, "", "ims.test", None, false), reply(ctx).0));
        assert_eq!(r, (-1, 0));
        let _ = a.peers.set(crate::testutil::peers());
        // No IMPU in To: 400.
        let r = with_msg(&request("REGISTER", "sip:ims.test", "sip:ims.test", "", ""), |ctx| (a.challenge(ctx, "", "ims.test", None, false), reply(ctx).0));
        assert_eq!(r, (-1, 400));
        // No tm: the MAR is sent at once; with no peer for the realm, 480.
        let r = with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", REG_AUTH, ""), |ctx| {
            (a.challenge(ctx, "", "ims.test", Some("MD5".into()), true), reply(ctx).0)
        });
        assert_eq!(r, (RC_ERR, 480));
        // A reply carries no credentials to check.
        let r = with_msg(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: <sip:a@ims.test>;tag=1\nTo: <sip:a@ims.test>\nCall-ID: x\nCSeq: 1 REGISTER\nContent-Length: 0\n\n",
            |ctx| a.authenticate(ctx, "ims.test", false),
        );
        assert_eq!(r, -1);
    }

    #[test]
    fn ims_auth_parameters_and_exports() {
        use super::*;
        use crate::testutil::{call, fixup_err, registry, s};
        let a = std::sync::Arc::new(ImsAuth::default());
        for (n, v) in [
            ("registration_default_algorithm", s("MD5")),
            ("auth_vector_timeout", Arg::Int(0)),
            ("cxdx_dest_realm", s("hss.realm")),
            ("scscf_name", s("sip:scscf.ims.test")),
        ] {
            a.set_param(n, &v).unwrap();
        }
        for ignored in ["av_mode", "max_nonce_reuse", "ignore_failed_auth", "av_check_only_impu"] {
            a.set_param(ignored, &Arg::Int(1)).unwrap();
        }
        assert!(a.set_param("nope", &Arg::Int(1)).unwrap_err().contains("unknown parameter"));
        assert_eq!((lock(&a.algorithm).as_str(), a.vector_timeout.load(Ordering::Relaxed)), ("MD5", 1));
        assert_eq!(lock(&a.cx.dest_realm).as_str(), "hss.realm");
        // Without cdp the module does not load.
        assert!(sip_core::Registry::default().load(std::sync::Arc::new(ImsAuth::default())).unwrap_err().contains("needs cdp"));
        let mut reg = registry(false);
        reg.load(a.clone()).unwrap();
        assert!(fixup_err(&reg, "ims_www_challenge", &[s("")]).unwrap().contains("expected route, realm"));
        assert!(fixup_err(&reg, "ims_www_authenticate", &[]).unwrap().contains("expected realm"));
        let msg = request("REGISTER", "sip:ims.test", "sip:alice@ims.test", REG_AUTH, "");
        // The algorithm argument picks the scheme; no peer for hss.realm: 480.
        let r = with_msg(&msg, |ctx| (call(&reg, ctx, "ims_www_challenge", &[s(""), s("ims.test"), s("MD5")]), reply(ctx).0));
        assert_eq!(r, (RC_ERR, 480));
        let r = with_msg(&msg, |ctx| (call(&reg, ctx, "ims_proxy_challenge", &[s(""), s("ims.test")]), reply(ctx).0));
        assert_eq!(r, (RC_ERR, 480));
        assert_eq!(with_msg(&msg, |ctx| call(&reg, ctx, "ims_www_authenticate", &[s("ims.test")])), -3, "no vector for that nonce");
        assert_eq!(with_msg(&msg, |ctx| call(&reg, ctx, "ims_proxy_authenticate", &[s("ims.test"), s("x")])), -4, "no Proxy-Authorization");
    }

    #[test]
    fn save_refuses_other_requests_and_star_removes_every_contact() {
        use super::*;
        let (r, ul) = registrar();
        let invite = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "", "");
        assert_eq!(with_msg(&invite, |ctx| r.save(ctx, "")), -1);
        assert_eq!(with_msg(&request("REGISTER", "sip:ims.test", "sip:ims.test", "", ""), |ctx| r.save(ctx, "")), -1, "no IMPU");
        assert_eq!(with_msg(&invite, |ctx| std::sync::Arc::new(RegistrarScscf::default()).save(ctx, "")), -1, "no usrloc");
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            registered: true,
            contacts: vec![contact("sip:alice@192.0.2.9", 600), contact("sip:alice@192.0.2.10", 600)],
            ..Default::default()
        });
        // "Contact: *" with Expires 0: a de-registration (whose SAR fails here).
        let star = "Contact: *\nExpires: 0\n".to_string();
        let msg = request("REGISTER", "sip:ims.test", "sip:alice@ims.test", &star, "").replace("Contact: <sip:alice@192.0.2.9:5060>\n", "");
        let (rc, code) = with_msg(&msg, |ctx| (r.save(ctx, ""), reply(ctx).0));
        assert_eq!((rc, code), (CSCF_RETURN_ERROR, 500));
        assert_eq!(ul.get("sip:alice@ims.test").map(|x| x.contacts.len()), Some(2), "kept: the HSS was not told");
        // With cdp but no peer: the SAR is sent at once and fails.
        let _ = r.peers.set(crate::testutil::peers());
        let (rc, code) = with_msg(&msg, |ctx| (r.save(ctx, ""), reply(ctx).0));
        assert_eq!((rc, code), (CSCF_RETURN_ERROR, 500));
    }

    #[test]
    fn saa_with_bad_user_data_keeps_the_impu_alone() {
        use super::*;
        let (r, ul) = registrar();
        let rec = ImpuRecord { impu: "sip:alice@ims.test".into(), contacts: vec![contact("sip:alice@192.0.2.9", 600)], ..Default::default() };
        let mut saa = Msg::request(CMD_SAR, APP_CX).answer();
        saa.add(Avp::u32(RESULT_CODE, None, 2001)).add(Avp::str(USER_DATA, V, BAD_UD));
        let (rc, out) = with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| {
            (r.save_answer(Ok(saa), ctx, plan(rec, SAT_REGISTRATION, None)), reply(ctx).1)
        });
        assert_eq!(rc, 1);
        assert_eq!(hdr(&out, "P-Associated-URI").as_deref(), Some("<sip:alice@ims.test>"));
        assert_eq!(ul.get("sip:alice@ims.test").map(|x| x.user_data), Some(String::new()), "the bad document is not stored");
        // save_answer without usrloc does nothing.
        let none = RegistrarScscf::default();
        let rec = ImpuRecord { impu: "sip:alice@ims.test".into(), ..Default::default() };
        assert_eq!(
            with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| none.save_answer(
                Err(DiameterError::NoCdp),
                ctx,
                plan(rec, SAT_REGISTRATION, None)
            )),
            -1
        );
    }

    #[test]
    fn lookup_without_live_contacts_fails() {
        use super::*;
        let (r, ul) = registrar();
        ul.put(ImpuRecord { impu: "sip:alice@ims.test".into(), registered: true, contacts: vec![contact("sip:alice@192.0.2.9", 0)], ..Default::default() });
        ul.put(ImpuRecord { impu: "sip:bob@ims.test".into(), contacts: vec![contact("sip:bob@192.0.2.9", 60)], ..Default::default() });
        let look = |r: &RegistrarScscf, ruri: &str| with_msg(&request("INVITE", ruri, ruri, "", ""), |ctx| r.lookup(ctx));
        assert_eq!(look(&r, "sip:alice@ims.test"), -1, "only an expired contact");
        assert_eq!(look(&r, "sip:bob@ims.test"), -1, "not registered");
        assert_eq!(look(&r, "sip:ims.test"), -1, "no user");
        assert_eq!(look(&RegistrarScscf::default(), "sip:bob@ims.test"), -1, "no usrloc");
    }

    #[test]
    fn expired_subscriptions_are_dropped_before_notifying() {
        use super::*;
        let (ul, db) = ul_with_db();
        let r = RegistrarScscf::default();
        let _ = r.ul.set(ul.clone());
        ul.db_put_sub(&regsub("old", 0));
        lock(&r.regsubs).extend([regsub("old", 0), regsub("live", 600)]);
        let rec = ImpuRecord { impu: "sip:alice@ims.test".into(), registered: true, contacts: vec![contact("sip:alice@192.0.2.9", 60)], ..Default::default() };
        r.notify_reg(&ImpuRecord { contacts: vec![], ..rec.clone() }, &rec, RegChange::Registered);
        let subs = lock(&r.regsubs).clone();
        assert_eq!(subs.iter().map(|s| (s.callid.as_str(), s.cseq, s.version)).collect::<Vec<_>>(), [("live", 4, 3)], "CSeq and version move on");
        let rows = db.rows("subscriber_scscf");
        assert_eq!(rows.len(), 1, "the expired row deleted, the live one stored");
        assert_eq!((rows[0]["call_id"].clone(), rows[0]["local_cseq"].clone()), (DbVal::Str("live".into()), DbVal::Int(4)));
        // Without usrloc the NOTIFY state still moves on.
        let bare = RegistrarScscf::default();
        lock(&bare.regsubs).push(regsub("x", 600));
        bare.notify_reg(&rec, &rec, RegChange::Registered);
        assert_eq!(lock(&bare.regsubs)[0].cseq, 4);
    }

    const SUB: &str = "Event: reg\nExpires: 600\nRecord-Route: <sip:pcscf.ims.test;lr>, <sip:p2.ims.test;lr>\n";

    #[test]
    fn subscribe_to_reg_answers_and_notifies() {
        use super::*;
        use crate::testutil::{Here, registry, with_msg_on};
        let reg = registry(true);
        let tm = reg.api::<mod_txn::Tm>().unwrap();
        let net = std::sync::Arc::new(Here::default());
        tm.clone().spawn(net.clone()).unwrap();
        let (r, ul) = registrar();
        let _ = r.tm.set(tm);
        let _ = r.net.set(net.clone());
        ul.put(ImpuRecord {
            impu: "sip:alice@ims.test".into(),
            registered: true,
            contacts: vec![contact("sip:alice@192.0.2.9", 600)],
            sub: subscription::parse(UD).unwrap(),
            ..Default::default()
        });
        let sub = |extra: &str| request("SUBSCRIBE", "sip:alice@ims.test", "sip:alice@ims.test", extra, "");
        let (rc, out) = with_msg_on(&sub(SUB), &*net, |ctx| (r.subscribe(ctx), reply(ctx).1));
        assert_eq!(rc, 1);
        assert!(out.starts_with("SIP/2.0 200 OK\r\n"), "{out}");
        assert_eq!(hdr(&out, "Expires").as_deref(), Some("600"));
        assert_eq!(hdr(&out, "Contact").as_deref(), Some("<sip:127.0.0.1:5060>"));
        let to_tag = hdr(&out, "To").unwrap().split(";tag=").nth(1).unwrap().to_string();
        let notify = net.sent().into_iter().find(|m| m.starts_with("NOTIFY ")).expect("a NOTIFY");
        assert!(notify.starts_with("NOTIFY sip:alice@192.0.2.9:5060 SIP/2.0\r\n"), "to the Contact: {notify}");
        assert_eq!(hdr(&notify, "From"), Some(format!("<sip:alice@ims.test>;tag={to_tag}")), "our tag is the 200's To-tag");
        assert_eq!(hdr(&notify, "Subscription-State").as_deref().map(|s| s.starts_with("active;expires=")), Some(true));
        assert_eq!(hdr(&notify, "Route").as_deref(), Some("<sip:pcscf.ims.test;lr>"), "the Record-Route set");
        assert!(notify.contains(r#"version="0" state="full""#) && notify.contains("<uri>sip:alice@192.0.2.9</uri>"), "{notify}");
        // A refresh in the same dialog continues CSeq and version.
        with_msg_on(&sub(SUB).replace("To: <sip:alice@ims.test>", &format!("To: <sip:alice@ims.test>;tag={to_tag}")), &*net, |ctx| r.subscribe(ctx));
        let subs = lock(&r.regsubs).clone();
        assert_eq!(subs.iter().map(|s| (s.cseq, s.version, s.our_tag.clone())).collect::<Vec<_>>(), [(2, 1, to_tag.clone())]);
        // Expires 0 ends it with a final NOTIFY.
        let before = net.sent().len();
        with_msg_on(&sub("Event: reg\nExpires: 0\n"), &*net, |ctx| assert_eq!(r.subscribe(ctx), 1));
        assert!(lock(&r.regsubs).is_empty());
        let last = net.sent().into_iter().skip(before).find(|m| m.starts_with("NOTIFY ")).expect("a final NOTIFY");
        assert_eq!(hdr(&last, "Subscription-State").as_deref(), Some("terminated;reason=timeout"));
        // Other events and other methods.
        let (rc, code) = with_msg(&sub("Event: presence\n"), |ctx| (r.subscribe(ctx), reply(ctx).0));
        assert_eq!((rc, code), (-1, 489));
        assert_eq!(with_msg(&request("INVITE", "sip:alice@ims.test", "sip:alice@ims.test", SUB, ""), |ctx| r.subscribe(ctx)), -1);
        assert_eq!(with_msg(&request("SUBSCRIBE", "sip:ims.test", "sip:ims.test", SUB, ""), |ctx| r.subscribe(ctx)), -1, "no IMPU");
    }

    #[test]
    fn reg_notify_without_a_running_tm_is_only_logged() {
        use super::*;
        let reg = crate::testutil::registry(true);
        let (r, _) = registrar();
        let _ = r.tm.set(reg.api::<mod_txn::Tm>().unwrap());
        // No usrloc record: a full document with the IMPU alone.
        let rc = with_msg(&request("SUBSCRIBE", "sip:bob@ims.test", "sip:bob@ims.test", "o: reg\n", ""), |ctx| r.subscribe(ctx));
        assert_eq!(rc, 1);
        let left = lock(&r.regsubs)[0].expires_at.saturating_sub(unix_secs());
        assert!((599_990..=600_000).contains(&left), "Expires defaults to (and is capped at) 600000: {left}");
    }

    #[test]
    fn registrar_parameters_and_exports() {
        use super::*;
        use crate::testutil::{call, fixup_err, registry, s};
        let r = std::sync::Arc::new(RegistrarScscf::default());
        for ignored in ["append_branches", "contact_expires_buffer", "user_data_xsd"] {
            r.set_param(ignored, &Arg::Int(1)).unwrap();
        }
        r.set_param("default_expires", &Arg::Int(-5)).unwrap();
        assert_eq!(r.default_expires.load(Ordering::Relaxed), 0, "negative is 0");
        r.set_param("name", &s("sip:scscf.ims.test")).unwrap();
        assert!(r.set_param("nope", &Arg::Int(1)).unwrap_err().contains("unknown parameter"));
        let mut reg = registry(false);
        assert!(reg.load(r.clone()).unwrap_err().contains("ims_usrloc_scscf loaded first"));
        let mut reg2 = registry(false);
        reg2.load(std::sync::Arc::new(UsrlocScscf::default())).unwrap();
        let r = std::sync::Arc::new(RegistrarScscf::default());
        reg2.load(r.clone()).unwrap();
        assert!(fixup_err(&reg2, "lookup", &[]).unwrap().contains("location"));
        assert!(fixup_err(&reg2, "lookup", &[s("a"), s("b"), s("c"), s("d")]).is_some());
        assert!(fixup_err(&reg2, "save", &[]).is_some());
        assert!(fixup_err(&reg2, "save", &[s("R"), s("location"), s("0x01"), s("x")]).is_some());
        // save("location") without tm: the SAR is sent at once (no peer: 500).
        let (rc, code) =
            with_msg(&request("REGISTER", "sip:ims.test", "sip:alice@ims.test", "", ""), |ctx| (call(&reg2, ctx, "save", &[s("location")]), reply(ctx).0));
        assert_eq!((rc, code), (CSCF_RETURN_ERROR, 500));
        let ul = reg2.api::<UsrlocScscf>().unwrap();
        ul.put(ImpuRecord { impu: "sip:alice@ims.test".into(), registered: true, contacts: vec![contact("sip:alice@192.0.2.9", 60)], ..Default::default() });
        let invite = request("INVITE", "sip:alice@ims.test", "sip:alice@ims.test", "", "");
        assert_eq!(with_msg(&invite, |ctx| call(&reg2, ctx, "lookup", &[s("location")])), 1);
        assert_eq!(with_msg(&invite, |ctx| call(&reg2, ctx, "term_impu_registered", &[s("location")])), 1);
        assert_eq!(with_msg(&invite, |ctx| call(&reg2, ctx, "impu_registered", &[s("location")])), 1, "From alice");
        let sub = request("SUBSCRIBE", "sip:alice@ims.test", "sip:alice@ims.test", "", "");
        assert_eq!(with_msg(&sub, |ctx| call(&reg2, ctx, "can_subscribe_to_reg", &[s("location")])), 1);
        let bob = request("INVITE", "sip:bob@ims.test", "sip:bob@ims.test", "P-Asserted-Identity: <sip:bob@ims.test>\n", "");
        assert_eq!(with_msg(&bob, |ctx| call(&reg2, ctx, "term_impu_registered", &[s("location")])), -1);
        assert_eq!(with_msg(&bob, |ctx| call(&reg2, ctx, "impu_registered", &[s("location")])), -1, "P-Asserted-Identity first");
    }

    #[test]
    fn save_and_challenge_suspend_while_the_hss_answers() {
        use super::*;
        use crate::testutil::{call, registry, s, script};
        let mut reg = registry(true);
        script(&reg.hub, &[], &["REG_REPLY", "MAR_REPLY"], Box::new(|_, _| true));
        reg.load(std::sync::Arc::new(UsrlocScscf::default())).unwrap();
        reg.load(std::sync::Arc::new(RegistrarScscf::default())).unwrap();
        reg.load(std::sync::Arc::new(ImsAuth::default())).unwrap();
        let msg = |branch: &str| request("REGISTER", "sip:ims.test", "sip:alice@ims.test", REG_AUTH, "").replace("z9hG4bK1", branch);
        // Sent at once (a Kamailio reply route), nothing answered yet.
        let r = with_msg(&msg("z9hG4bKs1"), |ctx| (call(&reg, ctx, "save", &[s("REG_REPLY"), s("location")]), reply(ctx).0));
        assert_eq!(r, (0, 0));
        let r = with_msg(&msg("z9hG4bKs2"), |ctx| (call(&reg, ctx, "ims_www_challenge", &[s("MAR_REPLY"), s("ims.test")]), reply(ctx).0));
        assert_eq!(r, (0, 0));
        // `.fsr` (no route): sent once the script unwinds.
        let r = with_msg(&msg("z9hG4bKs3"), |ctx| (call(&reg, ctx, "save", &[s(""), s("location")]), ctx.ext::<sip_core::AsyncPending>().is_some()));
        assert_eq!(r, (0, true));
    }
}
