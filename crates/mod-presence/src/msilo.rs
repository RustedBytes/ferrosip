//! `msilo` — store MESSAGEs for offline users and deliver them when they
//! register (table `silo`: src_addr, dst_addr, username, domain, inc_time,
//! exp_time, ctype, body).
//!
//! `m_store([owner])` stores the current MESSAGE (the script then usually
//! answers 202); `m_dump([owner])`, called for a REGISTER after `save()`,
//! sends the owner's stored messages through tm — to the registering
//! Contact, via the address the REGISTER came from — and deletes each one
//! once it's answered with 2xx. Expired messages are removed every
//! `clean_period` seconds. Parameters: `db_url`, `db_table`, `expire_time`
//! (259200 s), `clean_period` (60 s), `add_date` (1: a Date header with
//! the time the message was stored), `max_messages` (0 = unlimited).

use crate::aor;
use mod_txn::{Tm, UacRequest};
use sip_core::module::DynStr;
use sip_core::schema::{ParamSpec, Ty, UINT, Unit, p};
use sip_core::serde_json::json;
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Module, Outbound, Registry};
use sip_db::DbVal;
use sip_parser::uri::{name_addr, split_list};
use sip_parser::{HdrFlags, HdrKind, Method};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub struct Msilo {
    db_url: Mutex<Option<String>>,
    table: Mutex<String>,
    expire: AtomicU64,
    clean_period: AtomicU64,
    add_date: AtomicBool,
    max_messages: AtomicU64,
    db: OnceLock<Arc<dyn sip_db::DbConn>>,
    tm: OnceLock<Arc<Tm>>,
}

impl Default for Msilo {
    fn default() -> Self {
        Self {
            db_url: Mutex::new(None),
            table: Mutex::new("silo".into()),
            expire: AtomicU64::new(259200),
            clean_period: AtomicU64::new(60),
            add_date: AtomicBool::new(true),
            max_messages: AtomicU64::new(0),
            db: OnceLock::new(),
            tm: OnceLock::new(),
        }
    }
}

fn user_domain(a: &str) -> (String, String) {
    let s = a.trim_start_matches("sip:").trim_start_matches("sips:");
    match s.split_once('@') {
        Some((u, d)) => (u.to_string(), d.to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// A Unix time as a DB integer (saturating).
fn int_of(t: u64) -> i64 {
    i64::try_from(t).unwrap_or(i64::MAX)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "days = t / 86400 < 2^48, so the civil-from-days steps stay far inside i64; days % 7 < 7 and mo is 1..=12"
)]
fn http_date(t: u64) -> String {
    // RFC 1123 date from Unix seconds (UTC).
    let days = t / 86400;
    let (h, m, s) = ((t % 86400) / 3600, (t % 3600) / 60, t % 60);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
    // Civil from days (Howard Hinnant).
    // days < 2^48 for any u64 t: always fits.
    let z = i64::try_from(days).unwrap_or_default() + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][usize::try_from(mo - 1).unwrap_or_default()]; // mo is 1..=12
    format!("{wd}, {d:02} {mon} {y} {h:02}:{m:02}:{s:02} GMT")
}

impl Msilo {
    fn db(&self) -> Option<&Arc<dyn sip_db::DbConn>> {
        self.db.get()
    }

    fn store(&self, ctx: &mut Ctx<'_, '_>, owner: Option<String>) -> i32 {
        if ctx.msg.method() != Some(Method::Message) || ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let Some(db) = self.db() else { return -1 };
        let owner = owner.and_then(|o| aor(o.as_bytes()).or(Some(o))).or_else(|| aor(ctx.ruri()));
        let Some(owner) = owner else { return -1 };
        let (user, dom) = user_domain(&owner);
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let src = ctx.msg.get(HdrKind::From).map(|h| s(name_addr(h.body).0)).unwrap_or_default();
        let dst = ctx.msg.get(HdrKind::To).map(|h| s(name_addr(h.body).0)).unwrap_or_default();
        let ctype = ctx
            .msg
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(b"content-type") || h.name.eq_ignore_ascii_case(b"c"))
            .map(|h| s(h.body))
            .unwrap_or_else(|| "text/plain".into());
        let body = s(&ctx.body());
        let max = self.max_messages.load(Ordering::Relaxed);
        let table = lock(&self.table).clone();
        if max > 0 {
            let n = db.query(&table, &["id"], &[("username", DbVal::Str(user.clone())), ("domain", DbVal::Str(dom.clone()))]).map_or(0, |r| r.rows.len());
            if n as u64 >= max {
                return -1;
            }
        }
        let t = unix_secs();
        let res = db.insert(
            &table,
            &["src_addr", "dst_addr", "username", "domain", "inc_time", "exp_time", "ctype", "body"],
            &[
                DbVal::Str(src),
                DbVal::Str(dst),
                DbVal::Str(user),
                DbVal::Str(dom),
                DbVal::Int(int_of(t)),
                DbVal::Int(int_of(t.saturating_add(self.expire.load(Ordering::Relaxed)))),
                DbVal::Str(ctype),
                DbVal::Str(body),
            ],
        );
        match res {
            Ok(()) => 1,
            Err(e) => {
                sip_core::log::log(sip_core::log::L_ERR, &format!("msilo: storing: {e}"));
                -1
            }
        }
    }

    fn dump(&self, ctx: &mut Ctx<'_, '_>, owner: Option<String>) -> i32 {
        let (Some(db), Some(tm)) = (self.db(), self.tm.get()) else { return -1 };
        if ctx.msg.parse_headers(HdrFlags::EOH).is_err() {
            return -1;
        }
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let to_aor = ctx.msg.get(HdrKind::To).and_then(|h| aor(name_addr(h.body).0));
        let Some(owner) = owner.and_then(|o| aor(o.as_bytes()).or(Some(o))).or(to_aor) else { return -1 };
        let contact = ctx.msg.get(HdrKind::Contact).and_then(|h| split_list(h.body).first().map(|c| s(name_addr(c).0)));
        let Some(contact) = contact.filter(|c| c != "*") else { return -1 };
        let (user, dom) = user_domain(&owner);
        let table = lock(&self.table).clone();
        let Ok(rows) = db.query(
            &table,
            &["id", "src_addr", "dst_addr", "inc_time", "exp_time", "ctype", "body"],
            &[("username", DbVal::Str(user)), ("domain", DbVal::Str(dom))],
        ) else {
            return -1;
        };
        let t = unix_secs();
        let mut sent = false;
        for r in rows.rows {
            let [id, src, dst, inc, exp, ctype, body, ..] = r.as_slice() else { continue };
            let id = id.int().unwrap_or(0);
            // Expired (a negative exp_time too, rather than wrapping to "never").
            if u64::try_from(exp.int().unwrap_or(0)).map_or(true, |exp| exp <= t) {
                continue;
            }
            let mut h = format!("From: <{}>;tag=ms{id:x}\r\nTo: <{}>\r\nContent-Type: {}\r\n", src.text(), dst.text(), ctype.text());
            // No Date for a negative inc_time.
            if self.add_date.load(Ordering::Relaxed)
                && let Ok(inc) = u64::try_from(inc.int().unwrap_or(0))
            {
                h.push_str(&format!("Date: {}\r\n", http_date(inc)));
            }
            let req = UacRequest {
                method: "MESSAGE".into(),
                ruri: contact.clone(),
                dst: Some(ctx.src),
                headers: h,
                body: body.text().into_bytes(),
                ..Default::default()
            };
            let (db2, table2) = (db.clone(), table.clone());
            let ok = tm
                .t_uac(
                    req,
                    Some(Box::new(move |code, _| {
                        if (200..300).contains(&code) {
                            // Left in the table, the message is delivered again.
                            if let Err(e) = db2.delete(&table2, &[("id", DbVal::Int(id))]) {
                                sip_core::log::log(sip_core::log::L_ERR, &format!("msilo: delete of delivered message {id}: {e}"));
                            }
                        }
                    })),
                )
                .is_ok();
            sent |= ok;
        }
        if sent { 1 } else { -1 }
    }

    fn clean(&self) {
        let Some(db) = self.db() else { return };
        let table = lock(&self.table).clone();
        let t = int_of(unix_secs());
        if let Ok(rows) = db.query(&table, &["id", "exp_time"], &[]) {
            for r in rows.rows {
                let [id, exp, ..] = r.as_slice() else { continue };
                if exp.int().unwrap_or(0) <= t
                    && let Err(e) = db.delete(&table, &[("id", id.clone())])
                {
                    sip_core::log::log(sip_core::log::L_ERR, &format!("msilo: delete of expired message {id:?}: {e}"));
                }
            }
        }
    }
}

fn owner_fix(a: &[Arg]) -> Result<Option<DynStr>, String> {
    match a {
        [] => Ok(None),
        [owner] | [owner, _] => Ok(Some(owner.dyn_str()?)),
        _ => Err("expected [owner]".into()),
    }
}

impl Module for Msilo {
    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("db_url", Ty::Str, "", "Database for stored messages (default: the module's default database)"),
            p("db_table", Ty::Str, "silo", "Table for stored messages"),
            p("expire_time", Ty::Duration(Unit::Sec), "259200s", "Stored messages expire after this long"),
            p("clean_period", Ty::Duration(Unit::Sec), "60s", "How often expired messages are removed"),
            p("add_date", Ty::Bool, "true", "Add a Date header with the time the message was stored"),
            p("max_messages", UINT, "0", "Most stored messages per user (0: unlimited)"),
        ])
    }

    fn name(&self) -> &'static str {
        "msilo"
    }

    fn functions(&self) -> Option<Vec<sip_core::sig::FnSig>> {
        use sip_core::sig::{ArgTy::*, Param, Ret, ctx, opt, sig};
        const OWNER: &[Param] = &[opt("owner", Uri)];
        Some(vec![
            sig("m_store", "store", OWNER, Ret::Bool, "Store this MESSAGE for later delivery to owner (default: the R-URI)"),
            sig("m_dump", "dump", OWNER, Ret::Bool, "Send owner's stored messages (default: To) to the REGISTER's Contact").allowed(ctx::REQUEST),
        ])
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        match name {
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "db_table" => *lock(&self.table) = v.str()?.into(),
            "expire_time" => self.expire.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "clean_period" => self.clean_period.store(v.int()?.max(1).unsigned_abs(), Ordering::Relaxed),
            "add_date" => self.add_date.store(v.int()? != 0, Ordering::Relaxed),
            "max_messages" => self.max_messages.store(v.int()?.max(0).unsigned_abs(), Ordering::Relaxed),
            "from_address" | "contact_hdr" | "content_type_hdr" | "offline_message" | "reminder" | "outbound_proxy" | "check_time" | "send_time"
            | "use_contact" | "sc_mid" | "sc_from" | "sc_to" | "sc_uri_user" | "sc_uri_host" | "sc_body" | "sc_ctype" | "sc_exp_time" | "sc_inc_time"
            | "sc_snd_time" | "sc_stored_hdrs" | "snd_time_avp" | "extra_hdrs_avp" | "notify_offline" => {}
            _ => return Err(format!("msilo: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let url = lock(&self.db_url).clone().unwrap_or_else(|| sip_db::default_url("msilo"));
        let _ = self.db.set(sip_db::connect(&url)?);
        let tm = reg.api::<Tm>().ok_or("msilo needs tm loaded first")?;
        let _ = self.tm.set(tm);
        let me = self.clone();
        reg.export("msilo", "m_store", owner_fix, move |ctx: &mut Ctx, o: &Option<DynStr>| {
            let o = o.as_ref().map(|o| o.eval(ctx).into_owned());
            me.store(ctx, o)
        });
        let me = self.clone();
        reg.export("msilo", "m_dump", owner_fix, move |ctx: &mut Ctx, o: &Option<DynStr>| {
            let o = o.as_ref().map(|o| o.eval(ctx).into_owned());
            me.dump(ctx, o)
        });
        let me = self.clone();
        reg.rpc.add("msilo.count", "Stored messages", move |_| {
            let db = me.db().ok_or("no db")?;
            Ok(json!(db.query(&lock(&me.table), &["id"], &[])?.rows.len()))
        });
        Ok(())
    }

    fn spawn(self: Arc<Self>, _net: Arc<dyn Outbound>) -> Result<(), String> {
        let every = self.clean_period.load(Ordering::Relaxed);
        std::thread::Builder::new()
            .name("msilo-clean".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(every));
                    self.clean();
                }
            })
            .map_err(|e| format!("cannot start the msilo cleaner thread: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::with_msg;
    use sip_db::{DbConn, DbError, Filter, Rows};

    #[test]
    fn date() {
        assert_eq!(super::http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(super::http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
    }

    #[test]
    fn dates_across_leap_days_and_centuries() {
        let cases = [
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (951_868_799, "Tue, 29 Feb 2000 23:59:59 GMT"),
            (1_709_164_800, "Thu, 29 Feb 2024 00:00:00 GMT"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (4_107_456_000, "Sun, 28 Feb 2100 00:00:00 GMT"),
            (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 GMT"),
        ];
        for (t, want) in cases {
            assert_eq!(http_date(t), want, "{t}");
        }
        // Far-future times don't panic.
        assert!(http_date(u64::MAX).ends_with(" GMT"));
    }

    #[test]
    fn owner_user_and_domain() {
        let cases = [("sip:alice@ex.com", ("alice", "ex.com")), ("sips:bob@ex.com", ("bob", "ex.com")), ("carol", ("carol", "")), ("d@e@f", ("d", "e@f"))];
        for (a, (u, d)) in cases {
            assert_eq!(user_domain(a), (u.to_string(), d.to_string()), "{a}");
        }
        assert_eq!((int_of(5), int_of(u64::MAX)), (5, i64::MAX));
    }

    /// An in-memory table: rows of (column, value), equality filters.
    #[derive(Default)]
    struct MemDb(Mutex<Vec<Vec<(String, DbVal)>>>);

    impl MemDb {
        fn matches(row: &[(String, DbVal)], filter: Filter<'_>) -> bool {
            filter.iter().all(|(c, v)| row.iter().any(|(rc, rv)| rc == c && rv == v))
        }
        fn col(row: &[(String, DbVal)], c: &str) -> DbVal {
            row.iter().find(|(rc, _)| rc == c).map_or(DbVal::Null, |(_, v)| v.clone())
        }
    }

    impl DbConn for MemDb {
        fn query(&self, _: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError> {
            let rows = lock(&self.0).iter().filter(|r| Self::matches(r, filter)).map(|r| cols.iter().map(|c| Self::col(r, c)).collect()).collect();
            Ok(Rows { cols: cols.iter().map(|c| c.to_string()).collect(), rows })
        }
        fn insert(&self, _: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
            let mut t = lock(&self.0);
            let id = i64::try_from(t.len()).unwrap().checked_add(1).unwrap();
            let mut row = vec![("id".to_string(), DbVal::Int(id))];
            row.extend(cols.iter().map(|c| c.to_string()).zip(vals.iter().cloned()));
            t.push(row);
            Ok(())
        }
        fn update(&self, _: &str, _: Filter<'_>, _: &[(&str, DbVal)]) -> Result<usize, DbError> {
            Ok(0)
        }
        fn delete(&self, _: &str, filter: Filter<'_>) -> Result<usize, DbError> {
            let mut t = lock(&self.0);
            let n = t.len();
            t.retain(|r| !Self::matches(r, filter));
            Ok(n.checked_sub(t.len()).unwrap())
        }
    }

    fn silo() -> (Msilo, Arc<MemDb>) {
        let m = Msilo::default();
        let db = Arc::new(MemDb::default());
        let _ = m.db.set(db.clone());
        (m, db)
    }

    fn message(ruri: &str, extra: &str, body: &str) -> String {
        format!(
            "MESSAGE {ruri} SIP/2.0\nVia: SIP/2.0/UDP 192.0.2.9;branch=z9hG4bK1\nFrom: \"A\" <sip:alice@ex.com>;tag=1\nTo: <sip:Bob@EX.com>\nCall-ID: m1\nCSeq: 1 MESSAGE\n{extra}Content-Length: {}\n\n{body}",
            body.len()
        )
    }

    #[test]
    fn store_keeps_the_fields_and_expiry() {
        let (m, db) = silo();
        m.set_param("expire_time", &Arg::Int(100)).unwrap();
        let before = unix_secs();
        assert_eq!(with_msg(&message("sip:Bob@EX.com:5060", "Content-Type: text/html\n", "<b>hi</b>"), |ctx| m.store(ctx, None)), 1);
        let rows = db.query("silo", &["src_addr", "dst_addr", "username", "domain", "inc_time", "exp_time", "ctype", "body"], &[]).unwrap().rows;
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        let text: Vec<String> = r.iter().map(DbVal::text).collect();
        assert_eq!(
            (text[0].as_str(), text[1].as_str(), text[2].as_str(), text[3].as_str(), text[6].as_str(), text[7].as_str()),
            ("sip:alice@ex.com", "sip:Bob@EX.com", "Bob", "ex.com", "text/html", "<b>hi</b>")
        );
        let (inc, exp) = (r[4].int().unwrap(), r[5].int().unwrap());
        assert!(inc >= int_of(before) && exp == inc + 100, "{inc} {exp}");
        // Without Content-Type: text/plain; an explicit owner.
        assert_eq!(with_msg(&message("sip:x@ex.com", "", "hi"), |ctx| m.store(ctx, Some("sip:carol@ex.com".into()))), 1);
        let carol = db.query("silo", &["ctype", "username"], &[("username", DbVal::Str("carol".into()))]).unwrap().rows;
        assert_eq!(carol[0][0].text(), "text/plain");
    }

    #[test]
    fn store_refuses_non_messages_and_full_silos() {
        let (m, db) = silo();
        let options = message("sip:bob@ex.com", "", "").replacen("MESSAGE", "OPTIONS", 1);
        assert_eq!(with_msg(&options, |ctx| m.store(ctx, None)), -1);
        assert_eq!(with_msg(&message("sip:ex.com", "", "x"), |ctx| m.store(ctx, None)), -1, "R-URI without a user");
        m.set_param("max_messages", &Arg::Int(2)).unwrap();
        for want in [1, 1, -1] {
            assert_eq!(with_msg(&message("sip:bob@ex.com", "", "x"), |ctx| m.store(ctx, None)), want);
        }
        // Another user still has room.
        assert_eq!(with_msg(&message("sip:dave@ex.com", "", "x"), |ctx| m.store(ctx, None)), 1);
        assert_eq!(db.query("silo", &["id"], &[]).unwrap().rows.len(), 3);
        // No database: -1.
        assert_eq!(with_msg(&message("sip:bob@ex.com", "", "x"), |ctx| Msilo::default().store(ctx, None)), -1);
    }

    #[test]
    fn clean_drops_expired_messages_only() {
        let (m, db) = silo();
        let now = int_of(unix_secs());
        for (user, exp) in [("past", now - 10), ("now", now), ("future", now + 1000), ("negative", -1)] {
            db.insert("silo", &["username", "exp_time"], &[DbVal::Str(user.into()), DbVal::Int(exp)]).unwrap();
        }
        m.clean();
        let left: Vec<String> = db.query("silo", &["username"], &[]).unwrap().rows.iter().map(|r| r[0].text()).collect();
        assert_eq!(left, ["future"]);
    }

    #[test]
    fn parameters() {
        let m = Msilo::default();
        m.set_param("expire_time", &Arg::Int(0)).unwrap();
        assert_eq!(m.expire.load(Ordering::Relaxed), 1, "at least 1 s");
        m.set_param("max_messages", &Arg::Int(-3)).unwrap();
        assert_eq!(m.max_messages.load(Ordering::Relaxed), 0);
        assert!(m.set_param("from_address", &Arg::Str("x".into())).is_ok(), "Kamailio parameters are accepted");
        assert!(m.set_param("bogus", &Arg::Int(1)).is_err());
        assert!(owner_fix(&[]).unwrap().is_none());
        assert!(owner_fix(&[Arg::Str("a".into()), Arg::Str("b".into()), Arg::Str("c".into())]).is_err());
    }
}
