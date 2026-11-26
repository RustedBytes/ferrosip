//! `acc` — transaction accounting and CDRs.
//!
//! Transactions are recorded when tm sends their final reply upstream
//! (`Tm::on_reply_out`) if the request carried the configured flags:
//! `log_flag` / `db_flag` (answered; with `failed_transaction_flag` also
//! failed ones), `log_missed_flag` / `db_missed_flag` (final ≥ 300, into
//! `db_table_missed_calls`). `early_media=1` also records a 183.
//! Records: method, from_tag, to_tag, callid, sip_code, sip_reason, time
//! (Unix seconds) plus `log_extra` / `db_extra` (`name=$pv;…`, evaluated
//! on the request).
//!
//! `acc_log_request(comment)` / `acc_db_request(comment, table)` record the
//! current request right away (`comment` = "code reason").
//!
//! CDRs (`cdr_enable=1`, needs `dialog`): one record per confirmed call
//! when it ends — logged, and written to `cdrs_table` when `db_url` is set:
//! sip_call_id, sip_from_tag, sip_to_tag, src_username, src_domain,
//! dst_username, dst_domain, call_start_time, duration (+ `cdr_extra`
//! entries `name=$dlg_var(x)`).

use crate::args;
use bumpalo::Bump;
use mod_txn::{ReplyOut, Tm};
use sip_core::module::DynStr;
use sip_core::pv::{Fmt, parse_fmt};
use sip_core::schema::{ParamSpec, Ty, p};
use sip_core::sig::{FnSig, Param};
use sip_core::sync::lock;
use sip_core::time::unix_secs;
use sip_core::{Arg, Ctx, Dest, Lumps, Module, Outbound, Proto, Registry, TxnVars};
use sip_db::DbVal;
use sip_parser::uri::{name_addr, param};
use sip_parser::{HdrFlags, HdrKind, Msg, parse_uri};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

type Extras = Vec<(String, Fmt)>;

pub struct Acc {
    log_flag: AtomicI64,
    log_missed_flag: AtomicI64,
    db_flag: AtomicI64,
    db_missed_flag: AtomicI64,
    failed_flag: AtomicI64,
    early_media: AtomicBool,
    cdr_enable: AtomicBool,
    db_url: Mutex<Option<String>>,
    tables: Mutex<[String; 3]>,
    extra_specs: Mutex<[String; 3]>,
    log_extra: OnceLock<Extras>,
    db_extra: OnceLock<Extras>,
    cdr_extra: OnceLock<Vec<(String, String)>>,
    db: OnceLock<Arc<dyn sip_db::DbConn>>,
    net: OnceLock<Arc<dyn Outbound>>,
}

impl Default for Acc {
    fn default() -> Self {
        Self {
            log_flag: AtomicI64::new(-1),
            log_missed_flag: AtomicI64::new(-1),
            db_flag: AtomicI64::new(-1),
            db_missed_flag: AtomicI64::new(-1),
            failed_flag: AtomicI64::new(-1),
            early_media: AtomicBool::new(false),
            cdr_enable: AtomicBool::new(false),
            db_url: Mutex::new(None),
            tables: Mutex::new(["acc".into(), "missed_calls".into(), "cdrs".into()]),
            extra_specs: Mutex::new(Default::default()),
            log_extra: OnceLock::new(),
            db_extra: OnceLock::new(),
            cdr_extra: OnceLock::new(),
            db: OnceLock::new(),
            net: OnceLock::new(),
        }
    }
}

/// One accounting record.
struct Record {
    method: String,
    from_tag: String,
    to_tag: String,
    callid: String,
    code: u16,
    reason: String,
    extra: Vec<(String, String)>,
}

fn parse_extras(spec: &str, reg: &Registry) -> Result<Extras, String> {
    spec.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').ok_or_else(|| format!("acc extra {kv:?}: expected name=$pv"))?;
            Ok((k.trim().to_string(), parse_fmt(v.trim(), reg.pvs())?))
        })
        .collect()
}

fn flag(f: &AtomicI64, vars: &TxnVars) -> bool {
    let f = f.load(Ordering::Relaxed);
    (0..64).contains(&f) && vars.flags & (1 << f) != 0
}

impl Acc {
    /// Fields of a request + reply status.
    fn record(&self, ctx: &mut Ctx<'_, '_>, code: u16, reason: &str, to_tag: Option<String>, extras: Option<&Extras>) -> Option<Record> {
        ctx.msg.parse_headers(HdrFlags::EOH).ok()?;
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let method = match ctx.msg.first {
            sip_parser::FirstLine::Request { method_raw, .. } => s(method_raw),
            _ => return None,
        };
        let callid = ctx.msg.get(HdrKind::CallId).map(|h| s(h.body)).unwrap_or_default();
        let from_tag = ctx.msg.get(HdrKind::From).and_then(|h| param(name_addr(h.body).1, b"tag")).map(s).unwrap_or_default();
        let to_tag = to_tag.or_else(|| ctx.msg.get(HdrKind::To).and_then(|h| param(name_addr(h.body).1, b"tag")).map(s)).unwrap_or_default();
        let extra = extras.map(|e| e.iter().map(|(k, f)| (k.clone(), f.eval(ctx))).collect()).unwrap_or_default();
        Some(Record { method, from_tag, to_tag, callid, code, reason: reason.to_string(), extra })
    }

    fn log(&self, what: &str, r: &Record) {
        let mut line = format!(
            "ACC: {what}: timestamp={};method={};from_tag={};to_tag={};call_id={};code={};reason={}",
            unix_secs(),
            r.method,
            r.from_tag,
            r.to_tag,
            r.callid,
            r.code,
            r.reason
        );
        for (k, v) in &r.extra {
            line.push_str(&format!(";{k}={v}"));
        }
        sip_core::log::log(sip_core::log::L_NOTICE, &line);
    }

    fn db_write(&self, table: &str, r: &Record) {
        let Some(db) = self.db.get() else { return };
        let mut cols: Vec<&str> = vec!["method", "from_tag", "to_tag", "callid", "sip_code", "sip_reason", "time"];
        let mut vals = vec![
            DbVal::Str(r.method.clone()),
            DbVal::Str(r.from_tag.clone()),
            DbVal::Str(r.to_tag.clone()),
            DbVal::Str(r.callid.clone()),
            DbVal::Str(r.code.to_string()),
            DbVal::Str(r.reason.clone()),
            DbVal::Int(i64::try_from(unix_secs()).unwrap_or(i64::MAX)),
        ];
        for (k, v) in &r.extra {
            cols.push(k);
            vals.push(DbVal::Str(v.clone()));
        }
        if let Err(e) = db.insert(table, &cols, &vals) {
            sip_core::log::log(sip_core::log::L_ERR, &format!("acc: writing {table}: {e}"));
        }
    }

    /// tm sent a reply upstream.
    fn on_reply(&self, o: &ReplyOut<'_>) {
        let code = crate::uac::status(o.reply);
        let early = code == 183 && self.early_media.load(Ordering::Relaxed);
        if code < 200 && !early {
            return;
        }
        let v = o.vars;
        let failed = code >= 300;
        let any_flag = |f: &AtomicI64| flag(f, v);
        let ok_or_failed = !failed || any_flag(&self.failed_flag);
        let (log, db) = (any_flag(&self.log_flag) && ok_or_failed, any_flag(&self.db_flag) && ok_or_failed);
        let (log_m, db_m) = (failed && any_flag(&self.log_missed_flag), failed && any_flag(&self.db_missed_flag));
        if !(log || db || log_m || db_m) {
            return;
        }
        let Some(net) = self.net.get() else { return };
        let reason = crate::uac::reason(o.reply);
        let to_tag = crate::uac::to_tag(o.reply);
        let arena = Bump::new();
        let Ok(mut msg) = Msg::parse(o.request, &arena) else { return };
        let (mut lumps, mut out) = (Lumps::default(), Vec::new());
        let mut ctx = Ctx::new(&mut msg, &mut lumps, &mut out, &**net, None, Dest::new(Proto::Udp, SocketAddr::from(([127, 0, 0, 1], 0))), 0);
        ctx.ext.push(Box::new(v.clone()));
        let tables = lock(&self.tables).clone();
        if (log || log_m)
            && let Some(r) = self.record(&mut ctx, code, &reason, to_tag.clone(), self.log_extra.get())
        {
            self.log(if failed { "call missed" } else { "transaction answered" }, &r);
        }
        if (db || db_m)
            && let Some(r) = self.record(&mut ctx, code, &reason, to_tag, self.db_extra.get())
        {
            if db {
                self.db_write(&tables[0], &r);
            }
            if db_m {
                self.db_write(&tables[1], &r);
            }
        }
    }

    fn cdr(&self, e: &mod_dialog::DlgEnd) {
        let uh = |u: &str| {
            parse_uri(u.as_bytes())
                .map(|p| (String::from_utf8_lossy(p.user.unwrap_or(b"")).into_owned(), String::from_utf8_lossy(p.host).into_owned()))
                .unwrap_or_default()
        };
        let (su, sd) = uh(&e.from_uri);
        let (du, dd) = uh(&e.to_uri);
        let dur = e.end_ts.saturating_sub(e.start_ts);
        let extra: Vec<(String, String)> =
            self.cdr_extra.get().map(|x| x.iter().map(|(k, var)| (k.clone(), e.vars.get(var).cloned().unwrap_or_default())).collect()).unwrap_or_default();
        let mut line = format!(
            "CDR: call_start_time={};duration={dur};sip_call_id={};sip_from_tag={};sip_to_tag={};src_username={su};src_domain={sd};dst_username={du};dst_domain={dd}",
            e.start_ts, e.callid, e.from_tag, e.to_tag
        );
        for (k, v) in &extra {
            line.push_str(&format!(";{k}={v}"));
        }
        sip_core::log::log(sip_core::log::L_NOTICE, &line);
        if let Some(db) = self.db.get() {
            let [_, _, table] = lock(&self.tables).clone();
            let mut cols: Vec<&str> =
                vec!["sip_call_id", "sip_from_tag", "sip_to_tag", "src_username", "src_domain", "dst_username", "dst_domain", "call_start_time", "duration"];
            let mut vals = vec![
                DbVal::Str(e.callid.clone()),
                DbVal::Str(e.from_tag.clone()),
                DbVal::Str(e.to_tag.clone()),
                DbVal::Str(su),
                DbVal::Str(sd),
                DbVal::Str(du),
                DbVal::Str(dd),
                DbVal::Int(i64::try_from(e.start_ts).unwrap_or(i64::MAX)),
                DbVal::Int(i64::try_from(dur).unwrap_or(i64::MAX)),
            ];
            for (k, v) in &extra {
                cols.push(k);
                vals.push(DbVal::Str(v.clone()));
            }
            if let Err(err) = db.insert(&table, &cols, &vals) {
                sip_core::log::log(sip_core::log::L_ERR, &format!("acc: writing {table}: {err}"));
            }
        }
    }
}

/// "200 OK" → (200, "OK").
fn comment(c: &str) -> (u16, String) {
    let c = c.trim();
    match c.split_once(' ') {
        Some((code, r)) if code.parse::<u16>().is_ok() => (code.parse().unwrap_or(0), r.to_string()),
        _ => (c.parse().unwrap_or(0), String::new()),
    }
}

impl Module for Acc {
    fn functions(&self) -> Option<Vec<FnSig>> {
        use sip_core::sig::{ArgTy::*, Ret, arg, sig};
        const DB: &[Param] = &[arg("comment", Str), arg("table", Str)];
        const COMMENT: &[Param] = &[arg("comment", Str)];
        Some(vec![
            sig("acc_log_request", "log_request", COMMENT, Ret::Bool, "Log an accounting record for this request (comment: \"<code> <reason>\")"),
            sig("acc_db_request", "db_request", DB, Ret::Bool, "Write an accounting record for this request to a database table"),
        ])
    }

    fn params(&self) -> Option<Vec<ParamSpec>> {
        Some(vec![
            p("log_flag", Ty::Int { min: -1, max: 63 }, "-1", "Flag: log the transaction"),
            p("log_missed_flag", Ty::Int { min: -1, max: 63 }, "-1", "Flag: log failed calls"),
            p("db_flag", Ty::Int { min: -1, max: 63 }, "-1", "Flag: write the transaction to the database"),
            p("db_missed_flag", Ty::Int { min: -1, max: 63 }, "-1", "Flag: write failed calls to the database"),
            p("failed_transaction_flag", Ty::Int { min: -1, max: 63 }, "-1", "Flag: account failed transactions"),
            p("early_media", Ty::Bool, "false", "Account on 183 with SDP"),
            p("cdr_enable", Ty::Bool, "false", "CDRs from dialogs (needs dialog)"),
            p("db_url", Ty::Str, "", "Accounting database"),
            p("db_table_acc", Ty::Str, "acc", "Table for transactions"),
            p("db_table_missed_calls", Ty::Str, "missed_calls", "Table for failed calls"),
            p("cdrs_table", Ty::Str, "cdrs", "Table for CDRs"),
            p("log_extra", Ty::Str, "", "Extra log fields, \"name=$pv;…\""),
            p("db_extra", Ty::Str, "", "Extra database columns, \"column=$pv;…\""),
            p("cdr_extra", Ty::Str, "", "Extra CDR columns"),
        ])
    }

    fn name(&self) -> &'static str {
        "acc"
    }

    fn set_param(&self, name: &str, v: &Arg) -> Result<(), String> {
        let n = || v.int();
        let mut tables = lock(&self.tables);
        let [acc_table, missed_table, cdrs_table] = &mut *tables;
        let mut extras = lock(&self.extra_specs);
        let [log_extra, db_extra, cdr_extra] = &mut *extras;
        match name {
            "log_flag" => self.log_flag.store(n()?, Ordering::Relaxed),
            "log_missed_flag" => self.log_missed_flag.store(n()?, Ordering::Relaxed),
            "db_flag" => self.db_flag.store(n()?, Ordering::Relaxed),
            "db_missed_flag" => self.db_missed_flag.store(n()?, Ordering::Relaxed),
            "failed_transaction_flag" => self.failed_flag.store(n()?, Ordering::Relaxed),
            "early_media" => self.early_media.store(n()? != 0, Ordering::Relaxed),
            "cdr_enable" => self.cdr_enable.store(n()? != 0, Ordering::Relaxed),
            "db_url" => *lock(&self.db_url) = Some(v.str()?.into()),
            "db_table_acc" => *acc_table = v.str()?.into(),
            "db_table_missed_calls" => *missed_table = v.str()?.into(),
            "cdrs_table" => *cdrs_table = v.str()?.into(),
            "log_extra" => *log_extra = v.str()?.into(),
            "db_extra" => *db_extra = v.str()?.into(),
            "cdr_extra" => *cdr_extra = v.str()?.into(),
            "log_level"
            | "log_facility"
            | "report_ack"
            | "report_cancels"
            | "detect_direction"
            | "multi_leg_info"
            | "db_insert_mode"
            | "time_mode"
            | "cdr_start_on_confirmed"
            | "cdr_log_enable"
            | "acc_time_column"
            | "acc_sip_code_column"
            | "acc_sip_reason_column" => {}
            _ => return Err(format!("acc: unknown parameter {name:?}")),
        }
        Ok(())
    }

    fn register(self: Arc<Self>, reg: &mut Registry) -> Result<(), String> {
        let specs = lock(&self.extra_specs).clone();
        let _ = self.log_extra.set(parse_extras(&specs[0], reg)?);
        let _ = self.db_extra.set(parse_extras(&specs[1], reg)?);
        let cdr: Vec<(String, String)> = specs[2]
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (k, v) = kv.split_once('=').ok_or_else(|| format!("cdr_extra {kv:?}: expected name=$dlg_var(x)"))?;
                let var = v
                    .trim()
                    .strip_prefix("$dlg_var(")
                    .and_then(|x| x.strip_suffix(')'))
                    .ok_or_else(|| format!("cdr_extra {kv:?}: only $dlg_var(name) is supported"))?;
                Ok((k.trim().to_string(), var.to_string()))
            })
            .collect::<Result<_, String>>()?;
        let _ = self.cdr_extra.set(cdr);
        if let Some(url) = lock(&self.db_url).clone() {
            let _ = self.db.set(sip_db::connect(&url)?);
        }
        let tm = reg.api::<Tm>().ok_or("acc needs tm: put loadmodule \"tm\" before \"acc\"")?;
        let me = self.clone();
        tm.on_reply_out(Arc::new(move |o| me.on_reply(o)));
        if self.cdr_enable.load(Ordering::Relaxed) {
            let dlg = reg.api::<mod_dialog::Dialog>().ok_or("acc cdr_enable needs dialog loaded first")?;
            let me = self.clone();
            dlg.on_end(Arc::new(move |e| me.cdr(e)));
        }
        let me = self.clone();
        reg.export(
            "acc",
            "acc_log_request",
            |a: &[Arg]| {
                let [note] = args(a)?;
                note.dyn_str()
            },
            move |ctx: &mut Ctx, c: &DynStr| {
                let (code, reason) = comment(&c.eval(ctx));
                match me.record(ctx, code, &reason, None, me.log_extra.get()) {
                    Some(r) => {
                        me.log("request accounted", &r);
                        1
                    }
                    None => -1,
                }
            },
        );
        let me = self.clone();
        reg.export(
            "acc",
            "acc_db_request",
            |a: &[Arg]| {
                let [note, table] = args(a)?;
                Ok((note.dyn_str()?, table.dyn_str()?))
            },
            move |ctx: &mut Ctx, (c, t): &(DynStr, DynStr)| {
                let (code, reason) = comment(&c.eval(ctx));
                let t = t.eval(ctx).into_owned();
                if me.db.get().is_none() {
                    return -1;
                }
                match me.record(ctx, code, &reason, None, me.db_extra.get()) {
                    Some(r) => {
                        me.db_write(&t, &r);
                        1
                    }
                    None => -1,
                }
            },
        );
        Ok(())
    }

    fn spawn(self: Arc<Self>, net: Arc<dyn Outbound>) -> Result<(), String> {
        let _ = self.net.set(net);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeNet, Inserts, crlf, request, udp, with_ctx};

    #[test]
    fn acc_comment_parsing() {
        let cases =
            [("200 OK", (200, "OK")), (" 486 Busy Here ", (486, "Busy Here")), ("404", (404, "")), ("abc def", (0, "")), ("", (0, "")), ("99999 Big", (0, ""))];
        for (c, (code, reason)) in cases {
            assert_eq!(comment(c), (code, reason.to_string()), "{c:?}");
        }
    }

    #[test]
    fn acc_flags_outside_0_to_63_are_off() {
        let vars = TxnVars { flags: u64::MAX, ..Default::default() };
        for (f, want) in [(-1, false), (0, true), (63, true), (64, false), (i64::MIN, false)] {
            assert_eq!(flag(&AtomicI64::new(f), &vars), want, "flag {f}");
        }
        assert!(!flag(&AtomicI64::new(3), &TxnVars { flags: 1 << 2, ..Default::default() }));
    }

    #[test]
    fn acc_record_fields() {
        let acc = Acc::default();
        let net = FakeNet(None);
        let msg = request("INVITE", "sip:bob@b.example", "").replace("To: <sip:bob@b.example>", "To: <sip:bob@b.example>;tag=tt");
        let r = with_ctx(&msg, udp("192.0.2.1:5060"), &net, |ctx| acc.record(ctx, 486, "Busy Here", None, None)).unwrap();
        assert_eq!(
            (r.method.as_str(), r.from_tag.as_str(), r.to_tag.as_str(), r.callid.as_str(), r.code, r.reason.as_str()),
            ("INVITE", "ft", "tt", "cid-1", 486, "Busy Here")
        );
        let r = with_ctx(&msg, udp("192.0.2.1:5060"), &net, |ctx| acc.record(ctx, 200, "OK", Some("from-reply".into()), None)).unwrap();
        assert_eq!(r.to_tag, "from-reply", "the reply's To tag wins");
        let r = with_ctx(&request("MESSAGE", "sip:b@x", ""), udp("192.0.2.1:5060"), &net, |ctx| acc.record(ctx, 0, "", None, None)).unwrap();
        assert_eq!((r.method.as_str(), r.to_tag.as_str()), ("MESSAGE", ""));
        let reply = crlf(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n",
        );
        assert!(with_ctx(&reply, udp("192.0.2.1:5060"), &net, |ctx| acc.record(ctx, 200, "OK", None, None)).is_none(), "not a request");
    }

    /// An acc with db_flag 1, db_missed_flag 2, failed_transaction_flag 3
    /// and a database that records inserts.
    fn acc_with_db() -> (Acc, Arc<Inserts>) {
        let acc = Acc::default();
        for (name, v) in [("db_flag", 1), ("db_missed_flag", 2), ("failed_transaction_flag", 3)] {
            acc.set_param(name, &Arg::Int(v)).unwrap();
        }
        let db = Arc::new(Inserts::default());
        let _ = acc.db.set(db.clone());
        let _ = acc.net.set(Arc::new(FakeNet(None)));
        (acc, db)
    }

    fn reply_out(acc: &Acc, status: &str, flags: &[u32]) {
        let request = crlf(&request("INVITE", "sip:bob@b.example", ""));
        let reply = crlf(&format!(
            "SIP/2.0 {status}\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKt\nFrom: <sip:alice@a.example>;tag=ft\nTo: <sip:bob@b.example>;tag=tt\n\
Call-ID: cid-1\nCSeq: 1 INVITE\nContent-Length: 0\n\n"
        ));
        let vars = TxnVars { flags: flags.iter().map(|f| 1u64 << f).sum(), ..Default::default() };
        let dst = udp("192.0.2.1:5060");
        acc.on_reply(&ReplyOut { reply: reply.as_bytes(), dst: &dst, request: request.as_bytes(), vars: &vars });
    }

    #[test]
    fn acc_which_replies_are_written_where() {
        let cases: &[(&str, &[u32], &[&str])] = &[
            ("200 OK", &[1], &["acc"]),
            ("200 OK", &[], &[]),
            ("200 OK", &[2, 3], &[]),
            ("404 Not Here", &[1], &[]),
            ("404 Not Here", &[1, 3], &["acc"]),
            ("404 Not Here", &[2], &["missed_calls"]),
            ("404 Not Here", &[1, 2, 3], &["acc", "missed_calls"]),
            ("180 Ringing", &[1, 2, 3], &[]),
            ("183 Session Progress", &[1], &[]),
        ];
        let (acc, db) = acc_with_db();
        for (status, flags, want) in cases {
            reply_out(&acc, status, flags);
            let tables: Vec<String> = db.take().into_iter().map(|(t, _, _)| t).collect();
            assert_eq!(tables, *want, "{status} with flags {flags:?}");
        }
        acc.set_param("early_media", &Arg::Int(1)).unwrap();
        reply_out(&acc, "183 Session Progress", &[1]);
        assert_eq!(db.take().len(), 1, "early_media records a 183");
    }

    #[test]
    fn acc_row_columns_and_values() {
        let (acc, db) = acc_with_db();
        acc.set_param("db_table_missed_calls", &Arg::Str("missed".into())).unwrap();
        reply_out(&acc, "486 Busy Here", &[2]);
        let rows = db.take();
        assert_eq!(rows.len(), 1);
        let (table, cols, vals) = &rows[0];
        assert_eq!(table, "missed");
        assert_eq!(cols, &["method", "from_tag", "to_tag", "callid", "sip_code", "sip_reason", "time"]);
        let s = |v: &str| DbVal::Str(v.into());
        assert_eq!(vals[..6], [s("INVITE"), s("ft"), s("tt"), s("cid-1"), s("486"), s("Busy Here")]);
        assert!(matches!(vals[6], DbVal::Int(t) if t > 1_600_000_000), "{:?}", vals[6]);
    }

    #[test]
    fn acc_cdr_fields_and_duration() {
        let (acc, db) = acc_with_db();
        let _ = acc.cdr_extra.set(vec![("x_carrier".into(), "carrier".into()), ("x_none".into(), "missing".into())]);
        let mut e = mod_dialog::DlgEnd {
            callid: "c1".into(),
            from_uri: "sip:alice@a.example".into(),
            to_uri: "sip:bob@b.example:5070;user=phone".into(),
            from_tag: "f".into(),
            to_tag: "t".into(),
            start_ts: 1000,
            end_ts: 1042,
            vars: [("carrier".to_string(), "acme".to_string())].into_iter().collect(),
        };
        acc.cdr(&e);
        let rows = db.take();
        let (table, cols, vals) = &rows[0];
        assert_eq!(table, "cdrs");
        assert_eq!(
            cols,
            &[
                "sip_call_id",
                "sip_from_tag",
                "sip_to_tag",
                "src_username",
                "src_domain",
                "dst_username",
                "dst_domain",
                "call_start_time",
                "duration",
                "x_carrier",
                "x_none"
            ]
        );
        let s = |v: &str| DbVal::Str(v.into());
        assert_eq!(*vals, [s("c1"), s("f"), s("t"), s("alice"), s("a.example"), s("bob"), s("b.example"), DbVal::Int(1000), DbVal::Int(42), s("acme"), s("")]);
        (e.end_ts, e.from_uri) = (900, "garbage".into());
        acc.cdr(&e);
        let rows = db.take();
        assert_eq!(rows[0].2[8], DbVal::Int(0), "an end before the start: 0, not a wrap");
        assert_eq!((&rows[0].2[3], &rows[0].2[4]), (&s(""), &s("")), "unparsable URI: empty user and domain");
    }

    #[test]
    fn acc_parameters() {
        let acc = Acc::default();
        assert!(acc.set_param("report_ack", &Arg::Int(1)).is_ok());
        assert!(acc.set_param("bogus", &Arg::Int(1)).is_err());
        assert!(acc.set_param("log_flag", &Arg::Str("x".into())).is_err());
        acc.set_param("cdr_extra", &Arg::Str("a=$dlg_var(b)".into())).unwrap();
        assert_eq!(lock(&acc.extra_specs)[2], "a=$dlg_var(b)");
    }

    use crate::testutil::{call, registry};

    fn acc_registered(params: &[(&str, &str)]) -> Result<(Arc<Acc>, Registry), String> {
        let acc = Arc::new(Acc::default());
        for (n, v) in params {
            acc.set_param(n, &Arg::Str((*v).into())).unwrap();
        }
        let (mut reg, _) = registry();
        reg.load(acc.clone())?;
        Ok((acc, reg))
    }

    #[test]
    fn acc_register_checks_extras_and_dependencies() {
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[("cdr_extra", "carrier")], "cdr_extra \"carrier\": expected name=$dlg_var(x)"),
            (&[("cdr_extra", "c=$avp(x)")], "cdr_extra \"c=$avp(x)\": only $dlg_var(name) is supported"),
            (&[("cdr_extra", "c=$dlg_var(x")], "cdr_extra \"c=$dlg_var(x\": only $dlg_var(name) is supported"),
            (&[("log_extra", "ua")], "acc extra \"ua\": expected name=$pv"),
            (&[("cdr_enable", "1")], "acc cdr_enable needs dialog loaded first"),
        ];
        for (params, want) in cases {
            let e = acc_registered(params).err().unwrap_or_default();
            assert!(e.contains(want), "{params:?}: {e}");
        }
        let (acc, _) = acc_registered(&[("cdr_extra", " a = $dlg_var(b) ;; c=$dlg_var(d);")]).unwrap();
        assert_eq!(acc.cdr_extra.get().unwrap(), &[("a".to_string(), "b".to_string()), ("c".to_string(), "d".to_string())]);
        let mut reg = Registry::default();
        reg.load(Arc::new(sip_core::corefns::CoreModule)).unwrap();
        assert!(reg.load(Arc::new(Acc::default())).unwrap_err().contains("acc needs tm"));
    }

    #[test]
    fn acc_request_functions() {
        let (acc, reg) = acc_registered(&[("db_extra", "ua=$fU")]).unwrap();
        let net = FakeNet(None);
        let req = request("MESSAGE", "sip:bob@b.example", "");
        let reply = crlf(
            "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\nFrom: <sip:a@x>;tag=1\nTo: <sip:b@x>\nCall-ID: c\nCSeq: 1 INVITE\nContent-Length: 0\n\n",
        );
        let s = |v: &str| Arg::Str(v.into());
        let run = |msg: &str, f: &str, args: &[Arg]| with_ctx(msg, udp("192.0.2.1:5060"), &net, |ctx| call(&reg, ctx, f, args));
        assert_eq!(run(&req, "acc_log_request", &[s("200 Logged")]), 1);
        assert_eq!(run(&reply, "acc_log_request", &[s("200 Logged")]), -1, "not a request");
        assert_eq!(run(&req, "acc_db_request", &[s("202 Accepted"), s("acc")]), -1, "no database");
        let db = Arc::new(Inserts::default());
        let _ = acc.db.set(db.clone());
        assert_eq!(run(&req, "acc_db_request", &[s("202 Accepted"), s("acc_msg")]), 1);
        let rows = db.take();
        let (table, cols, vals) = &rows[0];
        assert_eq!((table.as_str(), cols.last().map(String::as_str)), ("acc_msg", Some("ua")));
        let v = |x: &str| DbVal::Str(x.into());
        assert_eq!((&vals[0], &vals[4], &vals[5], &vals[7]), (&v("MESSAGE"), &v("202"), &v("Accepted"), &v("alice")), "db_extra evaluated");
        assert_eq!(run(&reply, "acc_db_request", &[s("200 OK"), s("acc")]), -1);
        assert!(db.take().is_empty());
    }

    #[test]
    fn acc_cdr_without_a_database_is_only_logged() {
        let acc = Acc::default();
        let e = mod_dialog::DlgEnd {
            callid: "c1".into(),
            from_uri: "sip:a@x".into(),
            to_uri: "sip:b@y".into(),
            from_tag: "f".into(),
            to_tag: "t".into(),
            start_ts: 1,
            end_ts: 2,
            vars: Default::default(),
        };
        acc.cdr(&e);
        assert!(acc.db.get().is_none());
    }
}
