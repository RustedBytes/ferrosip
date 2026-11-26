//! SQLite (`sqlite://`, rusqlite with a bundled SQLite), feature `sqlite`.
//! Also runs raw SQL (`sqlops`).

use crate::{DbConn, DbError, DbVal, Filter, Rows};
use std::sync::Mutex;

pub(crate) struct SqliteDb {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteDb {
    /// `path` or `:memory:`.
    pub(crate) fn open(path: &str) -> Result<Self, DbError> {
        let conn = if path == ":memory:" { rusqlite::Connection::open_in_memory() } else { rusqlite::Connection::open(path) }
            .map_err(|e| DbError::Conn(format!("sqlite {path}: {e}")))?;
        #[allow(clippy::let_underscore_must_use, reason = "best effort: the socket works without it")]
        let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
        Ok(Self { conn: Mutex::new(conn) })
    }
}

fn ident(s: &str) -> Result<String, DbError> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(DbError::Stmt(format!("bad identifier {s:?}")));
    }
    // Backticks, not double quotes: SQLite treats an unknown "column" as a
    // string literal, which would silently hide typos.
    Ok(format!("`{s}`"))
}

fn to_sql(v: &DbVal) -> rusqlite::types::Value {
    use rusqlite::types::Value;
    match v {
        DbVal::Null => Value::Null,
        DbVal::Int(i) => Value::Integer(*i),
        DbVal::Double(d) => Value::Real(*d),
        DbVal::Str(s) => Value::Text(s.clone()),
    }
}

fn from_sql(v: rusqlite::types::ValueRef<'_>) -> DbVal {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => DbVal::Null,
        ValueRef::Integer(i) => DbVal::Int(i),
        ValueRef::Real(d) => DbVal::Double(d),
        ValueRef::Text(t) | ValueRef::Blob(t) => DbVal::Str(String::from_utf8_lossy(t).into_owned()),
    }
}

/// The database file can't be used (busy, locked, unreadable) vs. a
/// statement SQLite refused.
fn sqlite_err(e: rusqlite::Error) -> DbError {
    use rusqlite::ErrorCode::{CannotOpen, DatabaseBusy, DatabaseLocked, DiskFull, NotADatabase, SystemIoFailure};
    match e.sqlite_error_code() {
        Some(CannotOpen | DatabaseBusy | DatabaseLocked | DiskFull | NotADatabase | SystemIoFailure) => DbError::Conn(e.to_string()),
        _ => DbError::Stmt(e.to_string()),
    }
}

fn where_clause(filter: Filter<'_>, first: usize) -> Result<String, DbError> {
    if filter.is_empty() {
        return Ok(String::new());
    }
    let parts: Vec<String> = filter.iter().zip(first..).map(|((c, _), n)| Ok(format!("{} = ?{n}", ident(c)?))).collect::<Result<_, DbError>>()?;
    Ok(format!(" WHERE {}", parts.join(" AND ")))
}

impl SqliteDb {
    fn select(&self, sql: &str, params: &[rusqlite::types::Value]) -> Result<Rows, DbError> {
        let c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut st = c.prepare(sql).map_err(sqlite_err)?;
        let cols: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
        let n = cols.len();
        let mut q = st.query(rusqlite::params_from_iter(params)).map_err(sqlite_err)?;
        let mut rows = Vec::new();
        while let Some(r) = q.next().map_err(sqlite_err)? {
            rows.push((0..n).map(|i| r.get_ref(i).map(from_sql).unwrap_or(DbVal::Null)).collect());
        }
        Ok(Rows { cols, rows })
    }

    fn exec(&self, sql: &str, params: &[rusqlite::types::Value]) -> Result<usize, DbError> {
        let c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        c.execute(sql, rusqlite::params_from_iter(params)).map_err(sqlite_err)
    }
}

impl DbConn for SqliteDb {
    fn query(&self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError> {
        let c = if cols.is_empty() { "*".to_string() } else { cols.iter().map(|c| ident(c)).collect::<Result<Vec<_>, _>>()?.join(", ") };
        let sql = format!("SELECT {c} FROM {}{}", ident(table)?, where_clause(filter, 1)?);
        self.select(&sql, &filter.iter().map(|(_, v)| to_sql(v)).collect::<Vec<_>>())
    }

    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
        let c = cols.iter().map(|c| ident(c)).collect::<Result<Vec<_>, _>>()?.join(", ");
        let q = (1..=vals.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        self.exec(&format!("INSERT INTO {} ({c}) VALUES ({q})", ident(table)?), &vals.iter().map(to_sql).collect::<Vec<_>>()).map(|_| ())
    }

    fn update(&self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<usize, DbError> {
        let s = set.iter().zip(1usize..).map(|((c, _), n)| Ok(format!("{} = ?{n}", ident(c)?))).collect::<Result<Vec<_>, DbError>>()?.join(", ");
        let sql = format!("UPDATE {} SET {s}{}", ident(table)?, where_clause(filter, set.len().saturating_add(1))?);
        let params: Vec<_> = set.iter().map(|(_, v)| to_sql(v)).chain(filter.iter().map(|(_, v)| to_sql(v))).collect();
        self.exec(&sql, &params)
    }

    fn delete(&self, table: &str, filter: Filter<'_>) -> Result<usize, DbError> {
        let sql = format!("DELETE FROM {}{}", ident(table)?, where_clause(filter, 1)?);
        self.exec(&sql, &filter.iter().map(|(_, v)| to_sql(v)).collect::<Vec<_>>())
    }

    fn raw(&self, sql: &str) -> Result<Rows, DbError> {
        let t = sql.trim_start().to_ascii_lowercase();
        if t.starts_with("select") || t.starts_with("with") || t.starts_with("pragma") {
            self.select(sql, &[])
        } else {
            let c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            c.execute_batch(sql).map_err(sqlite_err)?;
            Ok(Rows { cols: vec!["affected".into()], rows: vec![vec![DbVal::Int(crate::count_i64(c.changes()))]] })
        }
    }
}
