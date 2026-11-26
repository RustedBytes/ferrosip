//! usrloc — the user location table (Kamailio `usrloc`, `db_mode=0`: memory
//! only). Address-of-record → contacts, with expiry. Other modules bind to it
//! through `Registry::api::<Usrloc>()` (Kamailio's `load_ul_api()`).
//!
//! Storage is the same sharded, per-bucket-locked shared map as tm uses, so
//! REGISTERs and lookups for different users never contend.
//!
//! Parameters (`modparam("usrloc", …)`):
//! * `use_domain` (0) — AoR is `user@domain` instead of just `user`.
//! * `handle_lost_tcp` (0) — drop contacts whose TCP/TLS/WS connection closed
//!   (essential for WebSocket clients, which can't be reached otherwise).
//! * `timer_interval` (10) — seconds between sweeps of expired contacts
//!   (lookups ignore expired contacts regardless).
//! * `db_url` + `db_mode` — persistence in the `location` table through
//!   sip-db (`text:///dir`, `sqlite:///file`): 0 memory only; 1
//!   write-through (each change is written at once); 2 write-back (changed
//!   AoRs are flushed every `timer_interval`); 3 behaves like 1 (the memory
//!   table stays the cache). With db_mode > 0 the table is loaded at
//!   startup. `expires` and `last_modified` are stored as Unix seconds;
//!   `received` as a SIP URI (connections can't survive a restart).

use sip_core::schema::{ParamSpec, Ty, Unit, p, pr};
use sip_core::sig::FnSig;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, ConnId, Ctx, Dest, Module, Outbound, Registry, ShardedMap, TransportEvent, want_args};
use std::collections::{HashMap, HashSet};

/// Contact URIs of one AoR.
type ContactUris = HashSet<Vec<u8>>;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub uri: Vec<u8>,
    /// Expiry on the usrloc clock (ms, see `Usrloc::now`).
    pub expires_at: u64,
    /// q-value in thousandths; `None` = not given.
    pub q: Option<u16>,
    pub callid: Vec<u8>,
    pub cseq: u32,
    /// Where the REGISTER came from (incl. connection id): NAT-safe route.
    pub received: Dest,
    pub user_agent: Vec<u8>,
    /// RFC 5626 `+sip.instance` / `reg-id`.
    pub instance: Option<Vec<u8>>,
    pub reg_id: Option<u32>,
    pub last_modified: u64,
    /// RFC 3327 Path route set (`<sip:edge;lr>,…`), when saved with Path.
    pub path: Option<Vec<u8>>,
    /// Branch flags at save time (Kamailio `cflags`, e.g. the NAT flag).
    pub cflags: u32,
    /// usrloc flags (`FL_MEM`: never written to the database).
    pub flags: u32,
    /// Methods the UA accepts (Allow header; Kamailio's METHOD_* bits),
    /// `u32::MAX` when it didn't say.
    pub methods: u32,
    /// Unique record id (Kamailio `ruid`), kept when the binding is
    /// refreshed: `unregister(table, uri, ruid)` removes one binding by it.
    pub ruid: String,
}

/// `Contact::flags`: kept in memory only (registrar `save()` flag 0x01).
pub const FL_MEM: u32 = 1;

/// A new unique record id: `uloc-<start time>-<pid>-<counter>`, as Kamailio.
pub fn new_ruid() -> String {
    static START: OnceLock<u64> = OnceLock::new();
    static N: AtomicU64 = AtomicU64::new(0);
    let start = *START.get_or_init(unix_secs);
    format!("uloc-{start:x}-{:x}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed).wrapping_add(1))
}

/// A u64 time or count as an i64 (saturating, never negative).
fn int_of(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// A q value in 0.0..=1.0 as thousandths.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "clamped to 0.0..=1.0 first, so the rounded value is within 0..=1000")]
fn q_thousandths(q: f64) -> u16 {
    (q.clamp(0.0, 1.0) * 1000.0).round() as u16
}

impl Contact {
    pub fn remaining_secs(&self, now: u64) -> u32 {
        u32::try_from(self.expires_at.saturating_sub(now).div_ceil(1000)).unwrap_or(u32::MAX)
    }
}

pub struct Usrloc {
    table: ShardedMap<Box<[u8]>, Vec<Contact>>,
    /// Connection → AoRs with contacts on it (for `handle_lost_tcp`). A set:
    /// an edge proxy/SBC may register thousands of AoRs over one connection.
    by_conn: ShardedMap<ConnId, HashSet<Box<[u8]>>>,
    use_domain: AtomicBool,
    handle_lost_tcp: AtomicBool,
    timer_interval: AtomicU64,
    epoch: Instant,
    db_url: Mutex<Option<String>>,
    db_mode: AtomicU8,
    db: OnceLock<Arc<dyn sip_db::DbConn>>,
    /// AoRs changed since the last flush (db_mode 2).
    dirty: Mutex<HashSet<Box<[u8]>>>,
    /// The contact rows of each AoR this process wrote or loaded: the only
    /// rows it replaces or deletes (another registrar on the same table owns
    /// the rest, as with Kamailio's per-contact writes).
    written: Mutex<HashMap<Box<[u8]>, ContactUris>>,
    /// Seconds within which a REGISTER with the same Call-ID and CSeq as a
    /// binding is taken as a retransmission (Kamailio's `cseq_delay`).
    cseq_delay: AtomicU32,
}

impl Default for Usrloc {
    fn default() -> Self {
        Self {
            table: ShardedMap::new(1024),
            by_conn: ShardedMap::new(256),
            use_domain: AtomicBool::new(false),
            handle_lost_tcp: AtomicBool::new(false),
            timer_interval: AtomicU64::new(10),
            epoch: Instant::now(),
            db_url: Mutex::new(None),
            db_mode: AtomicU8::new(0),
            db: OnceLock::new(),
            dirty: Mutex::new(HashSet::new()),
            written: Mutex::new(HashMap::new()),
            cseq_delay: AtomicU32::new(20),
        }
    }
}

impl Usrloc {
    /// Milliseconds since start (monotonic).
    /// `cseq_delay` in seconds.
    pub fn cseq_delay(&self) -> u32 {
        self.cseq_delay.load(Ordering::Relaxed)
    }

    pub fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A time on the usrloc clock (ms) as Unix seconds.
    pub fn unix_secs(&self, ms: u64) -> i64 {
        int_of(unix_secs()).saturating_add(int_of(ms).saturating_sub(int_of(self.now())).div_euclid(1000))
    }

    /// Address-of-record key: `user` or `user@domain` (domain lower-cased).
    pub fn aor(&self, user: &[u8], host: &[u8]) -> Box<[u8]> {
        let mut k = user.to_vec();
        if self.use_domain.load(Ordering::Relaxed) {
            k.push(b'@');
            k.extend(host.iter().map(u8::to_ascii_lowercase));
        }
        k.into()
    }

    /// Unexpired contacts of `aor`.
    pub fn lookup(&self, aor: &[u8]) -> Vec<Contact> {
        let now = self.now();
        let mut v = self.table.get_cloned(aor).unwrap_or_default();
        v.retain(|c| c.expires_at > now);
        v
    }

    /// Atomically edit the contacts of `aor` (expired ones already removed).
    /// `f` gets the list and the current time; an empty list deletes the AoR.
    pub fn update<R>(&self, aor: &[u8], f: impl FnOnce(&mut Vec<Contact>, u64) -> R) -> R {
        let now = self.now();
        let key: Box<[u8]> = aor.into();
        let track = self.handle_lost_tcp.load(Ordering::Relaxed);
        let (r, conns) = self.table.alter(key.clone(), |cur| {
            let mut v = cur.unwrap_or_default();
            v.retain(|c| c.expires_at > now);
            let r = f(&mut v, now);
            let conns: Vec<ConnId> = if track { v.iter().filter_map(|c| c.received.conn).collect() } else { vec![] };
            ((!v.is_empty()).then_some(v), (r, conns))
        });
        self.changed(&key);
        for id in conns {
            self.by_conn.alter(id, |cur| {
                let mut l = cur.unwrap_or_default();
                if !l.contains(&key) {
                    l.insert(key.clone());
                }
                (Some(l), ())
            });
        }
        r
    }

    /// Visit every unexpired contact (for NAT keep-alives, dumps).
    pub fn for_each_contact(&self, mut f: impl FnMut(&[u8], &Contact)) {
        let now = self.now();
        self.table.for_each_mut(|aor, v| {
            for c in v.iter().filter(|c| c.expires_at > now) {
                f(aor, c);
            }
        });
    }

    /// (AoRs, contacts) currently stored, including not-yet-swept expired ones.
    pub fn stats(&self) -> (usize, usize) {
        let (mut a, mut c) = (0usize, 0usize);
        self.table.for_each_mut(|_, v| {
            a = a.saturating_add(1);
            c = c.saturating_add(v.len());
        });
        (a, c)
    }

    fn expire(&self) {
        let now = self.now();
        let track = self.db_mode.load(Ordering::Relaxed) > 0;
        let mut changed = Vec::new();
        self.table.retain(|k, v| {
            let n = v.len();
            v.retain(|c| c.expires_at > now);
            if track && v.len() != n {
                changed.push(k.clone());
            }
            !v.is_empty()
        });
        for k in changed {
            self.changed(&k);
        }
        self.flush_dirty();
    }

    /// db_mode 2 (write-back): persist the AoRs changed since the last flush.
    fn flush_dirty(&self) {
        if self.db_mode.load(Ordering::Relaxed) == 2 {
            let dirty: Vec<_> = std::mem::take(&mut *lock(&self.dirty)).into_iter().collect();
            for k in dirty {
                self.db_write(&k);
            }
        }
    }

    /// Persist the contacts of `aor` (per db_mode).
    fn changed(&self, aor: &[u8]) {
        match self.db_mode.load(Ordering::Relaxed) {
            0 => {}
            2 => {
                lock(&self.dirty).insert(aor.into());
            }
            _ => self.db_write(aor),
        }
    }

    fn split_aor(&self, aor: &[u8]) -> (String, String) {
        let s = String::from_utf8_lossy(aor).into_owned();
        if self.use_domain.load(Ordering::Relaxed)
            && let Some((u, d)) = s.rsplit_once('@')
        {
            return (u.to_string(), d.to_string());
        }
        (s, String::new())
    }

    /// Replace the rows of `aor` in the `location` table.
    fn db_write(&self, aor: &[u8]) {
        use sip_db::DbVal;
        let Some(db) = self.db.get() else { return };
        let (user, dom) = self.split_aor(aor);
        let mut f: Vec<(&str, DbVal)> = vec![("username", DbVal::Str(user.clone()))];
        if self.use_domain.load(Ordering::Relaxed) {
            f.push(("domain", DbVal::Str(dom.clone())));
        }
        let mut contacts = self.lookup(aor);
        contacts.retain(|c| c.flags & FL_MEM == 0);
        let now_set: HashSet<Vec<u8>> = contacts.iter().map(|c| c.uri.clone()).collect();
        let before = {
            let mut w = lock(&self.written);
            let old = if now_set.is_empty() { w.remove(aor) } else { w.insert(aor.into(), now_set.clone()) };
            old.unwrap_or_default()
        };
        let res = before.union(&now_set).try_for_each(|uri| {
            let mut f = f.clone();
            f.push(("contact", DbVal::Str(String::from_utf8_lossy(uri).into_owned())));
            db.delete("location", &f).map(drop)
        });
        let res = res.and_then(|()| {
            let (now, unix) = (self.now(), unix_secs());
            for c in contacts {
                let s = |b: &[u8]| DbVal::Str(String::from_utf8_lossy(b).into_owned());
                let ts = |ms: u64| DbVal::Int(int_of(unix).saturating_add(int_of(ms).saturating_sub(int_of(now)) / 1000));
                db.insert(
                    "location",
                    &[
                        "username",
                        "domain",
                        "contact",
                        "received",
                        "path",
                        "expires",
                        "q",
                        "callid",
                        "cseq",
                        "cflags",
                        "user_agent",
                        "instance",
                        "reg_id",
                        "last_modified",
                    ],
                    &[
                        DbVal::Str(user.clone()),
                        DbVal::Str(dom.clone()),
                        s(&c.uri),
                        DbVal::Str(sip_core::pvcore::dest_to_uri(&c.received)),
                        c.path.as_deref().map_or(DbVal::Null, s),
                        ts(c.expires_at),
                        c.q.map_or(DbVal::Null, |q| DbVal::Double(f64::from(q) / 1000.0)),
                        s(&c.callid),
                        DbVal::Int(i64::from(c.cseq)),
                        DbVal::Int(i64::from(c.cflags)),
                        s(&c.user_agent),
                        c.instance.as_deref().map_or(DbVal::Null, s),
                        c.reg_id.map_or(DbVal::Null, |r| DbVal::Int(i64::from(r))),
                        ts(c.last_modified),
                    ],
                )?;
            }
            Ok(())
        });
        if let Err(e) = res {
            sip_core::log::log(sip_core::log::L_ERR, &format!("usrloc: writing {}: {e}", String::from_utf8_lossy(aor)));
        }
    }

    /// Load unexpired rows of the `location` table.
    fn db_load(&self) -> Result<usize, String> {
        let Some(db) = self.db.get() else { return Ok(0) };
        let rows = db.query(
            "location",
            &[
                "username",
                "domain",
                "contact",
                "received",
                "path",
                "expires",
                "q",
                "callid",
                "cseq",
                "cflags",
                "user_agent",
                "instance",
                "reg_id",
                "last_modified",
            ],
            &[],
        )?;
        let (now, unix) = (int_of(self.now()), int_of(unix_secs()));
        // A DB time (Unix seconds) on the usrloc clock (ms), saturating.
        let ms_of = |t: i64| t.saturating_sub(unix).saturating_mul(1000).saturating_add(now).max(0).unsigned_abs();
        let mut n = 0usize;
        for r in rows.rows {
            let int = |i: usize| r.get(i).and_then(sip_db::DbVal::int);
            let txt = |i: usize| r.get(i).filter(|v| !v.is_null()).map(|v| v.text());
            let Some(exp) = int(5).filter(|&e| e > unix) else { continue };
            let Some(received) = txt(3).and_then(|u| sip_core::pvcore::dest_from_uri(u.as_bytes())) else { continue };
            let (Some(user), Some(uri)) = (r.first().map(sip_db::DbVal::text), r.get(2).map(sip_db::DbVal::text)) else { continue };
            let dom = txt(1).unwrap_or_default();
            let aor: Box<[u8]> = if self.use_domain.load(Ordering::Relaxed) && !dom.is_empty() { format!("{user}@{dom}") } else { user }.into_bytes().into();
            // q in thousandths (0..=1000); the counters as stored.
            let q = match r.get(6) {
                Some(sip_db::DbVal::Double(q)) if (0.0..=1.0).contains(q) => Ok(Some(q_thousandths(*q))),
                Some(sip_db::DbVal::Double(q)) if *q < 0.0 => Ok(None),
                Some(sip_db::DbVal::Double(_)) => Err(()),
                Some(v) => v.int().filter(|q| *q >= 0).map(|q| u16::try_from(q).ok().filter(|q| *q <= 1000).ok_or(())).transpose(),
                None => Ok(None),
            };
            let (Ok(q), Ok(cseq), Ok(cflags), Ok(reg_id)) =
                (q, u32::try_from(int(8).unwrap_or(0)), u32::try_from(int(9).unwrap_or(0)), int(12).map(u32::try_from).transpose())
            else {
                sip_core::log::log(sip_core::log::L_ERR, &format!("usrloc: {}: q, cseq, cflags or reg_id out of range, contact not loaded", uri));
                continue;
            };
            let c = Contact {
                uri: uri.into_bytes(),
                expires_at: ms_of(exp),
                q,
                callid: txt(7).unwrap_or_default().into_bytes(),
                cseq,
                received,
                user_agent: txt(10).unwrap_or_default().into_bytes(),
                instance: txt(11).map(String::into_bytes),
                reg_id,
                last_modified: ms_of(int(13).unwrap_or(unix)),
                path: txt(4).map(String::into_bytes),
                cflags,
                flags: 0,
                methods: u32::MAX,
                ruid: new_ruid(),
            };
            lock(&self.written).entry(aor.clone()).or_default().insert(c.uri.clone());
            self.table.alter(aor, |cur| {
                let mut v = cur.unwrap_or_default();
                v.push(c);
                (Some(v), ())
            });
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    fn lost_connection(&self, id: ConnId) {
        let Some(aors) = self.by_conn.remove(&id) else { return };
        if !self.handle_lost_tcp.load(Ordering::Relaxed) {
            return;
        }
        for aor in aors {
            self.table.alter(aor.clone(), |cur| {
                let mut v = cur.unwrap_or_default();
                v.retain(|c| c.received.conn != Some(id));
                ((!v.is_empty()).then_some(v), ())
            });
            self.changed(&aor);
        }
    }
}

fn flag(name: &str, v: &Arg) -> Result<bool, String> {
    match v.int()? {
        0 => Ok(false),
        1 => Ok(true),
        n => Err(format!("{name}: expected 0 or 1, got {n}")),
    }
}

impl Module for Usrloc {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p(
                "db_mode",
                Ty::Enum(&[("off", "0"), ("write-through", "1"), ("write-back", "2"), ("db-only", "3")]),
                "off",
                "Contact storage: memory only, or also the database",
            ),
            p("db_url", Ty::Str, "", "Database for db_mode (sqlite://, mysql://, postgres://, text://)"),
            pr("timer_interval", Ty::Duration(Unit::Sec), "10s", "Expired-contact cleanup (and write-back) interval"),
            p("use_domain", Ty::Bool, "false", "AoRs include the domain (user@domain)"),
            p("handle_lost_tcp", Ty::Bool, "false", "Drop contacts whose TCP/TLS/WS connection closed"),
            pr("cseq_delay", Ty::Duration(Unit::Sec), "20s", "A REGISTER repeating a binding's Call-ID and CSeq within this time is a retransmission"),
        ])
    }

    fn name(&self) -> &'static str {
        "usrloc"
    }

    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{Ret, ctx, sig};
        Some(vec![sig("ul_dump", "dump", &[], Ret::Void, "Log every registered contact").allowed(ctx::ANY)])
    }

    /// Graceful shutdown: write-back changes since the last timer flush
    /// would otherwise be lost.
    fn shutdown(&self) {
        self.flush_dirty();
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "use_domain" => self.use_domain.store(flag(name, v)?, Ordering::Relaxed),
            "handle_lost_tcp" => self.handle_lost_tcp.store(flag(name, v)?, Ordering::Relaxed),
            "timer_interval" => self.timer_interval.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "db_mode" => {
                let m = v.int()?;
                match u8::try_from(m) {
                    Ok(m @ 0..=3) => self.db_mode.store(m, Ordering::Relaxed),
                    _ => return Err(format!("usrloc: db_mode {m} (0..3)")),
                }
            }
            "db_url" => *lock(&self.db_url) = Some(v.str()?.to_string()),
            "cseq_delay" => self.cseq_delay.store(u32::try_from(v.int()?).map_err(|_| "usrloc: cseq_delay out of range".to_string())?, Ordering::Relaxed),
            "nat_bflag" | "desc_time_order" | "matching_mode" | "user_column" | "domain_column" | "contact_column" => {}
            _ => return Err(format!("usrloc: unknown or unsupported parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        if self.db_mode.load(Ordering::Relaxed) > 0 {
            let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("usrloc"));
            let _ = self.db.set(sip_db::connect(&url)?);
            let n = self.db_load()?;
            sip_core::log::log(sip_core::log::L_INFO, &format!("usrloc: loaded {n} contacts from the database"));
        }
        reg.provide(self.clone());
        let me = self.clone();
        sip_core::stats::gauge("usrloc", "registered_users", move || i64::try_from(me.stats().0).unwrap_or(i64::MAX));
        let me = self.clone();
        sip_core::stats::gauge("usrloc", "location-contacts", move || i64::try_from(me.stats().1).unwrap_or(i64::MAX));
        let contact_json = |c: &Contact, now: u64| {
            sip_core::serde_json::json!({
                "contact": String::from_utf8_lossy(&c.uri),
                "expires": c.remaining_secs(now),
                "q": c.q.map(|q| f64::from(q) / 1000.0),
                "callid": String::from_utf8_lossy(&c.callid),
                "cseq": c.cseq,
                "received": c.received.to_string(),
                "user_agent": String::from_utf8_lossy(&c.user_agent),
                "path": c.path.as_ref().map(|p| String::from_utf8_lossy(p).into_owned()),
                "cflags": c.cflags,
                "ruid": c.ruid,
            })
        };
        let me = self.clone();
        reg.rpc.add("ul.dump", "All AoRs and their contacts", move |_| {
            let now = me.now();
            let mut out = sip_core::serde_json::Map::new();
            me.table.for_each_mut(|aor, v| {
                let cs: Vec<_> = v.iter().filter(|c| c.expires_at > now).map(|c| contact_json(c, now)).collect();
                if !cs.is_empty() {
                    out.insert(String::from_utf8_lossy(aor).into_owned(), cs.into());
                }
            });
            Ok(sip_core::serde_json::Value::Object(out))
        });
        let me = self.clone();
        reg.rpc.add("ul.lookup", "Contacts of one AoR: ul.lookup location <aor>", move |p| {
            let aor = sip_core::rpc::str_param(p, if p.len() > 1 { 1 } else { 0 })?;
            let now = me.now();
            let cs: Vec<_> = me.lookup(aor.as_bytes()).iter().map(|c| contact_json(c, now)).collect();
            if cs.is_empty() {
                return Err("AoR not found".into());
            }
            Ok(cs.into())
        });
        let me = self.clone();
        reg.rpc.add("ul.rm", "Remove an AoR: ul.rm location <aor>", move |p| {
            let aor = sip_core::rpc::str_param(p, if p.len() > 1 { 1 } else { 0 })?;
            let n = me.update(aor.as_bytes(), |v, _| std::mem::take(v).len());
            Ok(sip_core::serde_json::json!(n))
        });
        let ul = self.clone();
        // ul_dump(): print the location table (Kamailio: `kamctl ul show`).
        reg.export(
            "usrloc",
            "ul_dump",
            |a: &[Arg]| want_args(a, 0),
            move |ctx: &mut Ctx, _: &()| {
                let now = ul.now();
                ul.table.for_each_mut(|aor, v| {
                    for c in v.iter().filter(|c| c.expires_at > now) {
                        sip_core::elog!(
                            "[w{}] ul: {} → {} expires={}s q={:?} via {}",
                            ctx.worker,
                            String::from_utf8_lossy(aor),
                            String::from_utf8_lossy(&c.uri),
                            c.remaining_secs(now),
                            c.q,
                            c.received
                        );
                    }
                });
                1
            },
        );
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        thread::Builder::new()
            .name("usrloc-timer".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(self.timer_interval.load(Ordering::Relaxed)));
                    self.expire();
                }
            })
            .map_err(|e| format!("cannot start the usrloc timer thread: {e}"))?;
        Ok(())
    }

    fn on_transport_event(&self, ev: &TransportEvent) {
        if let TransportEvent::Closed { conn: Dest { conn: Some(id), .. }, .. } = *ev {
            self.lost_connection(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_core::Proto;
    use sip_db::DbVal;

    fn contact(uri: &str, ttl_ms: u64, ul: &Usrloc, conn: Option<ConnId>) -> Contact {
        Contact {
            uri: uri.into(),
            expires_at: ul.now().saturating_add(ttl_ms),
            q: None,
            callid: b"c".to_vec(),
            cseq: 1,
            received: Dest { proto: Proto::Tcp, addr: "127.0.0.1:1".parse().unwrap(), conn, no_connect: false },
            user_agent: vec![],
            instance: None,
            reg_id: None,
            last_modified: ul.now(),
            path: None,
            cflags: 0,
            flags: 0,
            methods: u32::MAX,
            ruid: new_ruid(),
        }
    }

    #[test]
    fn update_lookup_expire_and_lost_connection() {
        let ul = Usrloc::default();
        ul.handle_lost_tcp.store(true, Ordering::Relaxed);
        ul.update(b"alice", |v, _| {
            v.push(contact("sip:a@1", 60_000, &ul, Some(7)));
            v.push(contact("sip:a@2", 1, &ul, None));
        });
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(ul.lookup(b"alice").len(), 1, "expired contact hidden from lookup");
        ul.expire();
        assert_eq!(ul.stats(), (1, 1));
        ul.lost_connection(7);
        assert!(ul.lookup(b"alice").is_empty());
        assert_eq!(ul.stats(), (0, 0), "AoR removed with its last contact");
    }

    #[test]
    fn aor_with_and_without_domain() {
        let ul = Usrloc::default();
        assert_eq!(&*ul.aor(b"Bob", b"Example.COM"), b"Bob");
        ul.use_domain.store(true, Ordering::Relaxed);
        assert_eq!(&*ul.aor(b"Bob", b"Example.COM"), b"Bob@example.com");
    }

    /// A `location` table that returns fixed rows.
    struct Rows(Vec<Vec<DbVal>>);
    impl sip_db::DbConn for Rows {
        fn query(&self, _: &str, cols: &[&str], _: sip_db::Filter<'_>) -> Result<sip_db::Rows, sip_db::DbError> {
            Ok(sip_db::Rows { cols: cols.iter().map(|c| (*c).to_string()).collect(), rows: self.0.clone() })
        }
        fn insert(&self, _: &str, _: &[&str], _: &[DbVal]) -> Result<(), sip_db::DbError> {
            Ok(())
        }
        fn update(&self, _: &str, _: sip_db::Filter<'_>, _: &[(&str, DbVal)]) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
        fn delete(&self, _: &str, _: sip_db::Filter<'_>) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
    }

    #[test]
    fn db_load_far_future_times_saturate() {
        use DbVal::{Int, Null, Str};
        let row = |user: &str, expires: i64, modified: i64| {
            let mut r: Vec<DbVal> = ["", "", "sip:a@1.2.3.4", "sip:1.2.3.4:5060"].map(|s| Str(s.into())).to_vec();
            r[0] = Str(user.into());
            r.extend([Null, Int(expires), Null, Str("c".into()), Int(1), Int(0), Null, Null, Null, Int(modified)]);
            r
        };
        let ul = Usrloc::default();
        let _ = ul.db.set(Arc::new(Rows(vec![row("alice", i64::MAX, i64::MIN), row("bob", int_of(unix_secs()) + 60, int_of(unix_secs()))])));
        // `(exp - unix) * 1000` saturates rather than overflowing (a panic
        // in debug builds, an already expired time in release).
        assert_eq!(ul.db_load(), Ok(2));
        let a = ul.lookup(b"alice");
        assert_eq!((a.len(), a[0].expires_at, a[0].last_modified), (1, i64::MAX.unsigned_abs(), 0));
        let b = ul.lookup(b"bob");
        assert!((59..=61).contains(&b[0].remaining_secs(ul.now())));
    }

    #[test]
    fn remaining_seconds_round_up() {
        let c = |exp: u64| Contact { expires_at: exp, ..contact("sip:x", 0, &Usrloc::default(), None) };
        for (exp, now, want) in [(10_000, 0, 10), (10_001, 0, 11), (9_999, 0, 10), (5, 5, 0), (5, 9, 0), (u64::MAX, 0, u32::MAX)] {
            assert_eq!(c(exp).remaining_secs(now), want, "expires_at {exp} now {now}");
        }
    }

    #[test]
    fn q_values_to_thousandths() {
        for (q, want) in [(0.0, 0), (0.5, 500), (1.0, 1000), (0.1234, 123), (0.9995, 1000), (-3.0, 0), (7.0, 1000)] {
            assert_eq!(q_thousandths(q), want, "{q}");
        }
    }

    #[test]
    fn update_removes_an_emptied_aor_and_tracks_connections() {
        let ul = Usrloc::default();
        ul.handle_lost_tcp.store(true, Ordering::Relaxed);
        ul.update(b"a", |v, _| v.extend([contact("sip:a@1", 60_000, &ul, Some(1)), contact("sip:a@2", 60_000, &ul, Some(2))]));
        ul.update(b"b", |v, _| v.push(contact("sip:b@1", 60_000, &ul, Some(1))));
        assert_eq!(ul.stats(), (2, 3));
        ul.lost_connection(1);
        assert_eq!(ul.lookup(b"a").iter().map(|c| c.uri.clone()).collect::<Vec<_>>(), [b"sip:a@2".to_vec()]);
        assert!(ul.lookup(b"b").is_empty());
        assert_eq!(ul.stats(), (1, 1));
        ul.lost_connection(1);
        assert_eq!(ul.stats(), (1, 1), "a second close changes nothing");
        assert_eq!(ul.update(b"a", |v, _| std::mem::take(v).len()), 1);
        assert_eq!(ul.stats(), (0, 0));
        // Without handle_lost_tcp, a closed connection keeps its contacts.
        let ul = Usrloc::default();
        ul.update(b"a", |v, _| v.push(contact("sip:a@1", 60_000, &ul, Some(1))));
        ul.lost_connection(1);
        assert_eq!(ul.lookup(b"a").len(), 1);
    }

    #[test]
    fn update_sees_only_unexpired_contacts() {
        let ul = Usrloc::default();
        ul.update(b"a", |v, now| v.extend([Contact { expires_at: now, ..contact("sip:gone", 0, &ul, None) }, contact("sip:live", 60_000, &ul, None)]));
        let seen = ul.update(b"a", |v, _| v.len());
        assert_eq!(seen, 1, "the one expiring at `now` is already gone");
        let mut n = 0;
        ul.for_each_contact(|aor, c| {
            assert_eq!((aor, c.uri.as_slice()), (&b"a"[..], &b"sip:live"[..]));
            n += 1;
        });
        assert_eq!(n, 1);
    }

    #[test]
    fn usrloc_clock_to_unix_seconds() {
        let ul = Usrloc::default();
        let (now, unix) = (ul.now(), int_of(unix_secs()));
        let at = |ms: u64| ul.unix_secs(ms) - unix;
        assert!((-1..=1).contains(&at(now)), "now");
        assert!((59..=61).contains(&at(now + 60_000)));
        assert!(ul.unix_secs(0) <= unix, "the epoch is in the past");
        assert_eq!(int_of(u64::MAX), i64::MAX);
    }

    #[test]
    fn usrloc_parameters() {
        let ul = Usrloc::default();
        assert!(ul.set_param("use_domain", &Arg::Int(2)).unwrap_err().contains("expected 0 or 1"));
        assert!(ul.set_param("db_mode", &Arg::Int(4)).is_err() && ul.set_param("db_mode", &Arg::Int(-1)).is_err());
        assert!(ul.set_param("cseq_delay", &Arg::Int(-1)).is_err());
        ul.set_param("timer_interval", &Arg::Int(0)).unwrap();
        assert_eq!(ul.timer_interval.load(Ordering::Relaxed), 1);
        assert!(ul.set_param("nat_bflag", &Arg::Int(3)).is_ok());
        assert!(ul.set_param("bogus", &Arg::Int(1)).is_err());
        ul.set_param("use_domain", &Arg::Int(1)).unwrap();
        assert_eq!(ul.split_aor(b"bob@x@example.com"), ("bob@x".into(), "example.com".into()), "the last @");
        assert_eq!(ul.split_aor(b"bob"), ("bob".into(), String::new()));
        assert!(new_ruid().starts_with("uloc-") && new_ruid() != new_ruid());
    }

    /// A `location` table kept in memory (delete by every filter column).
    #[derive(Default)]
    struct Table(Mutex<Vec<(Vec<String>, Vec<DbVal>)>>);
    impl sip_db::DbConn for Table {
        fn query(&self, _: &str, cols: &[&str], _: sip_db::Filter<'_>) -> Result<sip_db::Rows, sip_db::DbError> {
            let rows = lock(&self.0)
                .iter()
                .map(|(names, vals)| cols.iter().map(|c| names.iter().position(|n| n == c).map_or(DbVal::Null, |i| vals[i].clone())).collect())
                .collect();
            Ok(sip_db::Rows { cols: cols.iter().map(|c| (*c).to_string()).collect(), rows })
        }
        fn insert(&self, _: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), sip_db::DbError> {
            lock(&self.0).push((cols.iter().map(|c| (*c).to_string()).collect(), vals.to_vec()));
            Ok(())
        }
        fn update(&self, _: &str, _: sip_db::Filter<'_>, _: &[(&str, DbVal)]) -> Result<usize, sip_db::DbError> {
            Ok(0)
        }
        fn delete(&self, _: &str, f: sip_db::Filter<'_>) -> Result<usize, sip_db::DbError> {
            let mut t = lock(&self.0);
            let n = t.len();
            t.retain(|(names, vals)| !f.iter().all(|(k, v)| names.iter().position(|n| n == k).is_some_and(|i| vals[i] == *v)));
            Ok(n.saturating_sub(t.len()))
        }
    }

    fn with_table(mode: i64, table: &Arc<Table>) -> Usrloc {
        let ul = Usrloc::default();
        ul.set_param("db_mode", &Arg::Int(mode)).unwrap();
        ul.set_param("use_domain", &Arg::Int(1)).unwrap();
        let _ = ul.db.set(table.clone());
        ul
    }

    #[test]
    fn db_write_through_and_load_round_trip() {
        let t = Arc::new(Table::default());
        let ul = with_table(1, &t);
        let mut c = contact("sip:a@10.0.0.1;transport=tcp", 120_000, &ul, Some(9));
        c.received = Dest::new(Proto::Tcp, "198.51.100.1:40000".parse().unwrap());
        (c.q, c.callid, c.cseq, c.user_agent, c.instance, c.reg_id, c.path, c.cflags) =
            (Some(250), b"cid".to_vec(), 77, b"UA/1".to_vec(), Some(b"<urn:uuid:1>".to_vec()), Some(2), Some(b"<sip:edge;lr>".to_vec()), 8);
        let mem = Contact { flags: FL_MEM, ..contact("sip:mem@10.0.0.2", 120_000, &ul, None) };
        ul.update(b"alice@a.example", |v, _| v.extend([c.clone(), mem]));
        assert_eq!(lock(&t.0).len(), 1, "memory-only bindings are not written");
        let back = with_table(1, &t);
        assert_eq!(back.db_load(), Ok(1));
        let got = &back.lookup(b"alice@a.example")[0];
        assert_eq!((&got.uri, got.q, &got.callid, got.cseq, &got.user_agent), (&c.uri, Some(250), &c.callid, 77, &c.user_agent));
        assert_eq!((&got.instance, got.reg_id, &got.path, got.cflags), (&c.instance, Some(2), &c.path, 8));
        assert_eq!((got.received.proto, got.received.addr, got.received.conn), (Proto::Tcp, c.received.addr, None), "a connection doesn't survive");
        assert!((119..=121).contains(&got.remaining_secs(back.now())));
        // Removing the binding deletes its row; another registrar's row stays.
        lock(&t.0).push((
            vec!["username".into(), "domain".into(), "contact".into()],
            vec![DbVal::Str("alice".into()), DbVal::Str("a.example".into()), DbVal::Str("sip:other".into())],
        ));
        ul.update(b"alice@a.example", |v, _| v.retain(|x| x.flags == FL_MEM));
        let left: Vec<DbVal> = lock(&t.0).iter().map(|(_, v)| v[2].clone()).collect();
        assert_eq!(left, [DbVal::Str("sip:other".into())]);
    }

    #[test]
    fn db_write_back_waits_for_the_flush() {
        let t = Arc::new(Table::default());
        let ul = with_table(2, &t);
        ul.update(b"alice@a.example", |v, _| v.push(contact("sip:a@1", 60_000, &ul, None)));
        assert!(lock(&t.0).is_empty());
        ul.shutdown();
        assert_eq!(lock(&t.0).len(), 1, "flushed at shutdown");
        ul.update(b"alice@a.example", |v, now| v.iter_mut().for_each(|c| c.expires_at = now));
        ul.expire();
        assert!(lock(&t.0).is_empty(), "the timer's sweep flushes the expiry");
    }

    #[test]
    fn db_load_skips_bad_rows() {
        use DbVal::{Double, Int, Null, Str};
        let now = int_of(unix_secs());
        let row = |contact: &str, received: &str, q: DbVal, cseq: i64, reg_id: DbVal, expires: i64| {
            let mut r = vec![Str("alice".into()), Str("a.example".into()), Str(contact.into()), Str(received.into()), Null, Int(expires), q];
            r.extend([Str("c".into()), Int(cseq), Int(0), Null, Null, reg_id, Int(now)]);
            r
        };
        let rows = vec![
            row("sip:ok", "sip:1.2.3.4:5060", Double(0.5), 1, Null, now + 60),
            row("sip:int-q", "sip:1.2.3.4:5060", Int(1000), 1, Int(3), now + 60),
            row("sip:neg-q", "sip:1.2.3.4:5060", Double(-1.0), 1, Null, now + 60),
            row("sip:big-q", "sip:1.2.3.4:5060", Double(1.5), 1, Null, now + 60),
            row("sip:big-int-q", "sip:1.2.3.4:5060", Int(1001), 1, Null, now + 60),
            row("sip:big-cseq", "sip:1.2.3.4:5060", Null, 1 << 32, Null, now + 60),
            row("sip:big-regid", "sip:1.2.3.4:5060", Null, 1, Int(-1), now + 60),
            row("sip:expired", "sip:1.2.3.4:5060", Null, 1, Null, now),
            row("sip:no-received", "garbage", Null, 1, Null, now + 60),
        ];
        let ul = Usrloc::default();
        ul.set_param("use_domain", &Arg::Int(1)).unwrap();
        let _ = ul.db.set(Arc::new(Rows(rows)));
        assert_eq!(ul.db_load(), Ok(3));
        let mut got: Vec<(Vec<u8>, Option<u16>, Option<u32>)> = ul.lookup(b"alice@a.example").into_iter().map(|c| (c.uri, c.q, c.reg_id)).collect();
        got.sort();
        assert_eq!(got, [(b"sip:int-q".to_vec(), Some(1000), Some(3)), (b"sip:neg-q".to_vec(), None, None), (b"sip:ok".to_vec(), Some(500), None)]);
    }
}
