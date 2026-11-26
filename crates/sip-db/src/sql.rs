//! Production SQL drivers: `mysql://user:pass@host[:port]/db` (Kamailio
//! `db_mysql`) and `postgres://user:pass@host[:port]/db` (`db_postgres`).
//! Both share one query builder (identifier quoting and placeholders per
//! dialect) and a small connection pool: a connection that fails at the
//! transport level is dropped and the statement retried once on a fresh
//! one, so a restarted database server is picked up without a restart.
//!
//! TLS: `postgres://…?sslmode=require` (encrypted, server not verified, as
//! in libpq), `sslmode=verify-full&sslrootcert=/path/ca.pem` (verified);
//! `mysql://…?ssl=1[&ssl_ca=/path/ca.pem][&ssl_verify=0|1]` (verified
//! against `ssl_ca` when given).

use crate::{DbConn, DbError, DbVal, Filter, Rows};
use std::sync::Mutex;

#[cfg_attr(not(all(feature = "mysql", feature = "postgres")), allow(dead_code, reason = "one driver alone leaves the other dialect unused"))]
#[derive(Clone, Copy)]
enum Dialect {
    MySql,
    Pg,
}

impl Dialect {
    fn ident(self, s: &str) -> Result<String, String> {
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("bad identifier {s:?}"));
        }
        Ok(match self {
            Dialect::MySql => format!("`{s}`"),
            Dialect::Pg => format!("\"{s}\""),
        })
    }

    fn ph(self, i: usize) -> String {
        match self {
            Dialect::MySql => "?".into(),
            Dialect::Pg => format!("${i}"),
        }
    }

    fn where_clause(self, filter: Filter<'_>, first: usize) -> Result<String, String> {
        if filter.is_empty() {
            return Ok(String::new());
        }
        let parts: Vec<String> =
            filter.iter().zip(first..).map(|((c, _), n)| Ok(format!("{} = {}", self.ident(c)?, self.ph(n)))).collect::<Result<_, String>>()?;
        Ok(format!(" WHERE {}", parts.join(" AND ")))
    }

    fn select(self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<(String, Vec<DbVal>), String> {
        let c = if cols.is_empty() { "*".to_string() } else { cols.iter().map(|c| self.ident(c)).collect::<Result<Vec<_>, _>>()?.join(", ") };
        Ok((format!("SELECT {c} FROM {}{}", self.ident(table)?, self.where_clause(filter, 1)?), filter.iter().map(|(_, v)| v.clone()).collect()))
    }

    fn insert(self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(String, Vec<DbVal>), String> {
        let c = cols.iter().map(|c| self.ident(c)).collect::<Result<Vec<_>, _>>()?.join(", ");
        let q = (1..=vals.len()).map(|i| self.ph(i)).collect::<Vec<_>>().join(", ");
        Ok((format!("INSERT INTO {} ({c}) VALUES ({q})", self.ident(table)?), vals.to_vec()))
    }

    fn update(self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<(String, Vec<DbVal>), String> {
        let s = set.iter().zip(1..).map(|((c, _), n)| Ok(format!("{} = {}", self.ident(c)?, self.ph(n)))).collect::<Result<Vec<_>, String>>()?.join(", ");
        let sql = format!("UPDATE {} SET {s}{}", self.ident(table)?, self.where_clause(filter, set.len().saturating_add(1))?);
        Ok((sql, set.iter().map(|(_, v)| v.clone()).chain(filter.iter().map(|(_, v)| v.clone())).collect()))
    }

    fn delete(self, table: &str, filter: Filter<'_>) -> Result<(String, Vec<DbVal>), String> {
        Ok((format!("DELETE FROM {}{}", self.ident(table)?, self.where_clause(filter, 1)?), filter.iter().map(|(_, v)| v.clone()).collect()))
    }
}

/// Split ferrosip's own query parameters off a URL (they are not the
/// driver's): returns the URL without `keys`, and their values.
fn take_params(url: &str, keys: &[&str]) -> (String, std::collections::HashMap<String, String>) {
    let Some((base, q)) = url.split_once('?') else { return (url.to_string(), Default::default()) };
    let mut taken = std::collections::HashMap::new();
    let kept: Vec<&str> = q
        .split('&')
        .filter(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            if keys.contains(&k) {
                taken.insert(k.to_string(), percent_decode(v));
                false
            } else {
                true
            }
        })
        .collect();
    (if kept.is_empty() { base.to_string() } else { format!("{base}?{}", kept.join("&")) }, taken)
}

/// A URL query value with `%XX` escapes decoded (a malformed escape stays
/// as written).
fn percent_decode(v: &str) -> String {
    let mut out = Vec::with_capacity(v.len());
    let mut b = v.as_bytes().iter();
    while let Some(&c) = b.next() {
        if c == b'%' {
            let rest = b.as_slice();
            let hex = rest.get(..2).and_then(|h| std::str::from_utf8(h).ok()).filter(|h| h.bytes().all(|d| d.is_ascii_hexdigit()));
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                b.nth(1);
                continue;
            }
        }
        out.push(c);
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_select(sql: &str) -> bool {
    let t = sql.trim_start().to_ascii_lowercase();
    t.starts_with("select") || t.starts_with("with") || t.starts_with("show") || t.starts_with("explain") || t.starts_with("describe")
}

/// Idle connections; at most `max` kept.
struct Pool<C> {
    idle: Mutex<Vec<C>>,
    max: usize,
}

impl<C> Pool<C> {
    /// Seeded with the connection opened to validate the URL (MySQL).
    #[cfg(feature = "mysql")]
    fn new(first: C) -> Self {
        Self { idle: Mutex::new(vec![first]), max: 8 }
    }

    /// Connections are opened lazily (PostgreSQL).
    #[cfg(feature = "postgres")]
    fn new_empty() -> Self {
        Self { idle: Mutex::new(Vec::new()), max: 8 }
    }

    /// Runs `f` on a pooled connection. A broken connection
    /// ([`DbError::Conn`]) is dropped and `f` retried once on a fresh one;
    /// a refused statement is returned as is.
    fn run<R>(&self, connect: impl Fn() -> Result<C, DbError>, mut f: impl FnMut(&mut C) -> Result<R, DbError>) -> Result<R, DbError> {
        for attempt in 0..2 {
            let pooled = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
            let mut c = match pooled {
                Some(c) if attempt == 0 => c,
                _ => connect()?,
            };
            match f(&mut c) {
                Ok(r) => {
                    self.put(c);
                    return Ok(r);
                }
                Err(e @ (DbError::Stmt(_) | DbError::Config(_))) => {
                    self.put(c);
                    return Err(e);
                }
                Err(e @ DbError::Conn(_)) if attempt == 1 => return Err(e),
                Err(DbError::Conn(_)) => {} // dropped; retry on a fresh connection
            }
        }
        Err(DbError::Conn("no connection".into()))
    }

    fn put(&self, c: C) {
        let mut g = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() < self.max {
            g.push(c);
        }
    }
}

#[cfg(feature = "mysql")]
mod my;
#[cfg(feature = "postgres")]
mod pg;
#[cfg(feature = "mysql")]
pub use my::MySqlDb;
#[cfg(feature = "postgres")]
pub use pg::PgDb;

#[cfg(test)]
mod tests {
    use super::*;

    /// A local TCP port nothing listens on (bound, then released): a
    /// connection attempt is refused at once.
    pub(super) fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    #[test]
    fn builder() {
        let (s, p) = Dialect::Pg.update("location", &[("username", "a".into())], &[("expires", DbVal::Int(5))]).unwrap();
        assert_eq!(s, r#"UPDATE "location" SET "expires" = $1 WHERE "username" = $2"#);
        assert_eq!(p, vec![DbVal::Int(5), DbVal::Str("a".into())]);
        let (s, _) = Dialect::MySql.select("subscriber", &["ha1"], &[("username", "a".into()), ("domain", "d".into())]).unwrap();
        assert_eq!(s, "SELECT `ha1` FROM `subscriber` WHERE `username` = ? AND `domain` = ?");
        assert!(Dialect::Pg.select("x; drop", &[], &[]).is_err());
    }

    #[test]
    fn url_params() {
        let (u, p) = take_params("postgres://u@h/db?sslmode=verify-full&sslrootcert=/ca.pem&connect_timeout=5", &["sslmode", "sslrootcert"]);
        assert_eq!(u, "postgres://u@h/db?connect_timeout=5");
        assert_eq!(p["sslmode"], "verify-full");
        assert_eq!(take_params("mysql://u@h/db?ssl=1", &["ssl"]).0, "mysql://u@h/db");
        let (_, p) = take_params("postgres://h/db?sslrootcert=%2Fetc%2Fmy%20ca.pem&sslmode=bad%zz%4", &["sslrootcert", "sslmode"]);
        assert_eq!(p["sslrootcert"], "/etc/my ca.pem", "values are percent-decoded");
        assert_eq!(p["sslmode"], "bad%zz%4", "malformed escapes stay as written");
    }

    fn s(v: &str) -> DbVal {
        DbVal::Str(v.into())
    }

    #[test]
    fn statements_per_dialect() {
        let f: &[(&str, DbVal)] = &[("username", s("a")), ("domain", s("d"))];
        let set: &[(&str, DbVal)] = &[("expires", DbVal::Int(5)), ("q", DbVal::Null)];
        type Built = Result<(String, Vec<DbVal>), String>;
        let cases: Vec<(Built, &str)> = vec![
            (Dialect::MySql.select("t", &[], &[]), "SELECT * FROM `t`"),
            (Dialect::Pg.select("t", &[], &[]), r#"SELECT * FROM "t""#),
            (Dialect::Pg.select("t", &["a", "b"], f), r#"SELECT "a", "b" FROM "t" WHERE "username" = $1 AND "domain" = $2"#),
            (Dialect::MySql.insert("t", &["a", "b", "c"], &[DbVal::Int(1), s("x"), DbVal::Null]), "INSERT INTO `t` (`a`, `b`, `c`) VALUES (?, ?, ?)"),
            (Dialect::Pg.insert("t", &["a", "b", "c"], &[DbVal::Int(1), s("x"), DbVal::Null]), r#"INSERT INTO "t" ("a", "b", "c") VALUES ($1, $2, $3)"#),
            (Dialect::MySql.update("t", f, set), "UPDATE `t` SET `expires` = ?, `q` = ? WHERE `username` = ? AND `domain` = ?"),
            (Dialect::Pg.update("t", f, set), r#"UPDATE "t" SET "expires" = $1, "q" = $2 WHERE "username" = $3 AND "domain" = $4"#),
            (Dialect::Pg.update("t", &[], set), r#"UPDATE "t" SET "expires" = $1, "q" = $2"#),
            (Dialect::MySql.delete("t", f), "DELETE FROM `t` WHERE `username` = ? AND `domain` = ?"),
            (Dialect::Pg.delete("t", &[]), r#"DELETE FROM "t""#),
        ];
        for (got, want) in cases {
            assert_eq!(got.unwrap().0, want);
        }
        let (_, params) = Dialect::Pg.update("t", f, set).unwrap();
        assert_eq!(params, [DbVal::Int(5), DbVal::Null, s("a"), s("d")], "SET values first, then the filter");
        let (_, params) = Dialect::MySql.select("t", &[], f).unwrap();
        assert_eq!(params, [s("a"), s("d")]);
    }

    #[test]
    fn identifiers_are_checked_everywhere() {
        let bad = ["", "a b", "a;b", "a`b", "a\"b", "a-b", "a.b", "é", "x)--"];
        for d in [Dialect::MySql, Dialect::Pg] {
            for b in bad {
                assert!(d.ident(b).is_err(), "{b:?}");
                assert!(d.select(b, &[], &[]).is_err() && d.select("t", &[b], &[]).is_err() && d.select("t", &[], &[(b, DbVal::Null)]).is_err(), "{b:?}");
                assert!(d.insert("t", &[b], &[DbVal::Null]).is_err() && d.update("t", &[], &[(b, DbVal::Null)]).is_err(), "{b:?}");
                assert!(d.delete("t", &[(b, DbVal::Null)]).is_err(), "{b:?}");
            }
            assert!(d.ident("Abc_123").is_ok());
        }
    }

    #[test]
    fn url_param_edge_cases() {
        // (url, url without our parameters, parameters taken)
        type Case = (&'static str, &'static str, &'static [(&'static str, &'static str)]);
        let cases: &[Case] = &[
            ("mysql://u@h/db", "mysql://u@h/db", &[]),
            ("mysql://u@h/db?", "mysql://u@h/db?", &[]),
            ("mysql://u@h/db?ssl", "mysql://u@h/db", &[("ssl", "")]),
            ("mysql://u@h/db?a=1&ssl=1&b=2", "mysql://u@h/db?a=1&b=2", &[("ssl", "1")]),
            ("mysql://u@h/db?ssl_ca=/a=b.pem&ssl=1", "mysql://u@h/db", &[("ssl_ca", "/a=b.pem"), ("ssl", "1")]),
            ("mysql://u@h/db?ssl=0&ssl=1", "mysql://u@h/db", &[("ssl", "1")]),
            ("mysql://u@h/db?sslx=1", "mysql://u@h/db?sslx=1", &[]),
        ];
        for (url, base, taken) in cases {
            let (u, p) = take_params(url, &["ssl", "ssl_ca"]);
            assert_eq!(u, *base, "{url}");
            let want: std::collections::HashMap<String, String> = taken.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            assert_eq!(p, want, "{url}");
        }
    }

    #[test]
    fn select_like_statements() {
        let cases = [
            ("SELECT 1", true),
            ("  select * from t", true),
            ("\nWITH x AS (SELECT 1) SELECT * FROM x", true),
            ("show tables", true),
            ("EXPLAIN SELECT 1", true),
            ("describe t", true),
            ("INSERT INTO t VALUES (1)", false),
            ("update t set a = 1", false),
            ("", false),
        ];
        for (sql, want) in cases {
            assert_eq!(is_select(sql), want, "{sql:?}");
        }
    }

    /// A pool of numbered fake connections; `connect` hands out new numbers.
    fn pool(max: usize, idle: Vec<u32>) -> Pool<u32> {
        Pool { idle: Mutex::new(idle), max }
    }

    #[test]
    fn pool_retries_a_broken_connection_once() {
        use std::cell::Cell;
        let next = Cell::new(100u32);
        let connect = || {
            next.set(next.get() + 1);
            Ok(next.get())
        };
        let p = pool(8, vec![1]);
        // A statement error: no retry, the connection goes back.
        let calls = Cell::new(0);
        let r: Result<(), _> = p.run(connect, |_| {
            calls.set(calls.get() + 1);
            Err(DbError::Stmt("syntax".into()))
        });
        assert_eq!((r, calls.get()), (Err(DbError::Stmt("syntax".into())), 1));
        assert_eq!(*p.idle.lock().unwrap(), [1]);
        // A broken pooled connection: dropped, the statement runs again on a new one.
        let used = std::cell::RefCell::new(Vec::new());
        let r = p.run(connect, |c| {
            used.borrow_mut().push(*c);
            if *c == 1 { Err(DbError::Conn("reset".into())) } else { Ok(*c) }
        });
        assert_eq!(r, Ok(101));
        assert_eq!(*used.borrow(), [1, 101]);
        assert_eq!(*p.idle.lock().unwrap(), [101], "the broken one is gone, the new one kept");
        // Broken twice: the error is returned and nothing is pooled.
        let r: Result<(), _> = p.run(connect, |_| Err(DbError::Conn("down".into())));
        assert_eq!(r, Err(DbError::Conn("down".into())));
        assert!(p.idle.lock().unwrap().is_empty());
        // Connecting fails: that error.
        let r: Result<(), _> = p.run(|| Err(DbError::Conn("refused".into())), |_| Ok(()));
        assert_eq!(r, Err(DbError::Conn("refused".into())));
    }

    #[test]
    fn pool_keeps_at_most_max_idle() {
        let p = pool(2, vec![]);
        for c in 1..=5 {
            p.put(c);
        }
        assert_eq!(*p.idle.lock().unwrap(), [1, 2]);
        let r = p.run(|| Ok(9), |c| Ok(*c));
        assert_eq!(r, Ok(2), "the most recently pooled connection is used first");
    }
}
