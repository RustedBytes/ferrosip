//! MySQL / MariaDB (`mysql://`, Kamailio `db_mysql`), feature `mysql`.

use super::*;

pub struct MySqlDb {
    opts: mysql::Opts,
    pool: Pool<mysql::Conn>,
}

fn my_param(v: &DbVal) -> mysql::Value {
    match v {
        DbVal::Null => mysql::Value::NULL,
        DbVal::Int(i) => mysql::Value::Int(*i),
        DbVal::Double(d) => mysql::Value::Double(*d),
        DbVal::Str(s) => mysql::Value::Bytes(s.clone().into_bytes()),
    }
}

/// An unsigned column (`BIGINT UNSIGNED`): values past `i64::MAX` clamp
/// there instead of wrapping negative.
fn uint(u: u64) -> DbVal {
    DbVal::Int(crate::count_i64(u))
}

fn my_val(v: mysql::Value, col: &mysql::Column) -> DbVal {
    use mysql::Value as V;
    use mysql::consts::ColumnType as T;
    match v {
        V::NULL => DbVal::Null,
        V::Int(i) => DbVal::Int(i),
        V::UInt(u) => uint(u),
        V::Float(f) => DbVal::Double(f64::from(f)),
        V::Double(d) => DbVal::Double(d),
        V::Date(y, mo, d, h, mi, s, _) => DbVal::Str(format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")),
        V::Time(neg, d, h, mi, s, _) => {
            DbVal::Str(format!("{}{:02}:{mi:02}:{s:02}", if neg { "-" } else { "" }, d.saturating_mul(24).saturating_add(u32::from(h))))
        }
        V::Bytes(b) => {
            let s = String::from_utf8_lossy(&b).into_owned();
            // Text protocol (raw queries): numbers arrive as text.
            match col.column_type() {
                T::MYSQL_TYPE_TINY | T::MYSQL_TYPE_SHORT | T::MYSQL_TYPE_LONG | T::MYSQL_TYPE_LONGLONG | T::MYSQL_TYPE_INT24 | T::MYSQL_TYPE_YEAR => {
                    s.parse().map_or(DbVal::Str(s), DbVal::Int)
                }
                T::MYSQL_TYPE_FLOAT | T::MYSQL_TYPE_DOUBLE | T::MYSQL_TYPE_DECIMAL | T::MYSQL_TYPE_NEWDECIMAL => s.parse().map_or(DbVal::Str(s), DbVal::Double),
                _ => DbVal::Str(s),
            }
        }
    }
}

fn my_fail(e: mysql::Error) -> DbError {
    match e {
        mysql::Error::MySqlError(e) => DbError::Stmt(e.to_string()),
        e => DbError::Conn(e.to_string()),
    }
}

fn my_rows<P: mysql::prelude::Protocol>(mut r: mysql::QueryResult<'_, '_, '_, P>) -> Result<(Rows, u64), DbError> {
    let cols: Vec<mysql::Column> = r.columns().as_ref().to_vec();
    let mut rows = Vec::new();
    let mut affected = 0;
    if let Some(set) = r.iter() {
        affected = set.affected_rows();
        for row in set {
            let row = row.map_err(my_fail)?;
            rows.push(row.unwrap().into_iter().zip(cols.iter()).map(|(v, c)| my_val(v, c)).collect());
        }
    }
    Ok((Rows { cols: cols.iter().map(|c| c.name_str().into_owned()).collect(), rows }, affected))
}

impl MySqlDb {
    pub fn open(url: &str) -> Result<Self, DbError> {
        let (url, p) = take_params(url, &["ssl", "ssl_ca", "ssl_verify"]);
        let mut opts = mysql::Opts::from_url(&url).map_err(|e| DbError::Config(format!("mysql url: {e}")))?;
        if matches!(p.get("ssl").map(String::as_str), Some("1" | "true" | "on")) {
            let verify = p.get("ssl_verify").map_or(p.contains_key("ssl_ca"), |v| v != "0" && v != "false");
            let mut ssl = mysql::SslOpts::default().with_danger_accept_invalid_certs(!verify).with_danger_skip_domain_validation(!verify);
            if let Some(ca) = p.get("ssl_ca") {
                ssl = ssl.with_root_cert_path(Some(std::path::PathBuf::from(ca)));
            }
            opts = mysql::OptsBuilder::from_opts(opts).ssl_opts(Some(ssl)).into();
        }
        let first = mysql::Conn::new(opts.clone()).map_err(|e| DbError::Conn(format!("mysql connect: {e}")))?;
        Ok(Self { opts, pool: Pool::new(first) })
    }

    fn exec(&self, sql: &str, params: &[DbVal]) -> Result<(Rows, u64), DbError> {
        use mysql::prelude::Queryable;
        let p: Vec<mysql::Value> = params.iter().map(my_param).collect();
        self.pool.run(
            || mysql::Conn::new(self.opts.clone()).map_err(|e| DbError::Conn(format!("mysql connect: {e}"))),
            |c| {
                let r = if p.is_empty() { c.exec_iter(sql, ()) } else { c.exec_iter(sql, mysql::Params::Positional(p.clone())) };
                my_rows(r.map_err(my_fail)?)
            },
        )
    }
}

impl DbConn for MySqlDb {
    fn query(&self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError> {
        let (sql, p) = Dialect::MySql.select(table, cols, filter).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(|r| r.0)
    }
    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
        let (sql, p) = Dialect::MySql.insert(table, cols, vals).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(|_| ())
    }
    fn update(&self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<usize, DbError> {
        let (sql, p) = Dialect::MySql.update(table, filter, set).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(|r| crate::count_usize(r.1))
    }
    fn delete(&self, table: &str, filter: Filter<'_>) -> Result<usize, DbError> {
        let (sql, p) = Dialect::MySql.delete(table, filter).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(|r| crate::count_usize(r.1))
    }
    fn raw(&self, sql: &str) -> Result<Rows, DbError> {
        use mysql::prelude::Queryable;
        let (rows, affected) = self.pool.run(
            || mysql::Conn::new(self.opts.clone()).map_err(|e| DbError::Conn(format!("mysql connect: {e}"))),
            |c| my_rows(c.query_iter(sql).map_err(my_fail)?),
        )?;
        if is_select(sql) { Ok(rows) } else { Ok(Rows { cols: vec!["affected".into()], rows: vec![vec![DbVal::Int(crate::count_i64(affected))]] }) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A BIGINT UNSIGNED past i64::MAX clamps to i64::MAX, never negative.
    #[test]
    fn unsigned_clamps() {
        assert_eq!(uint(7), DbVal::Int(7));
        assert_eq!(uint(u64::MAX), DbVal::Int(i64::MAX));
    }

    #[test]
    fn parameters_keep_their_type() {
        let cases = [
            (DbVal::Null, mysql::Value::NULL),
            (DbVal::Int(-7), mysql::Value::Int(-7)),
            (DbVal::Double(0.5), mysql::Value::Double(0.5)),
            (DbVal::Str("x'y".into()), mysql::Value::Bytes(b"x'y".to_vec())),
        ];
        for (v, want) in cases {
            assert_eq!(my_param(&v), want, "{v:?}");
        }
    }

    #[test]
    fn result_values_decode_by_type() {
        use mysql::Value as V;
        use mysql::consts::ColumnType as T;
        let col = |t: T| mysql::Column::new(t);
        let text = |t: T, s: &str| my_val(V::Bytes(s.as_bytes().to_vec()), &col(t));
        let blob = col(T::MYSQL_TYPE_BLOB);
        let cases: Vec<(DbVal, DbVal)> = vec![
            (my_val(V::NULL, &blob), DbVal::Null),
            (my_val(V::Int(-3), &blob), DbVal::Int(-3)),
            (my_val(V::UInt(u64::MAX), &blob), DbVal::Int(i64::MAX)),
            (my_val(V::Float(1.5), &blob), DbVal::Double(1.5)),
            (my_val(V::Double(-0.25), &blob), DbVal::Double(-0.25)),
            (my_val(V::Date(2026, 1, 2, 3, 4, 5, 999), &blob), DbVal::Str("2026-01-02 03:04:05".into())),
            (my_val(V::Date(0, 0, 0, 0, 0, 0, 0), &blob), DbVal::Str("0000-00-00 00:00:00".into())),
            (my_val(V::Time(false, 0, 1, 2, 3, 0), &blob), DbVal::Str("01:02:03".into())),
            (my_val(V::Time(true, 2, 1, 0, 9, 0), &blob), DbVal::Str("-49:00:09".into())),
            (my_val(V::Time(false, u32::MAX, 23, 59, 59, 0), &blob), DbVal::Str(format!("{}:59:59", u32::MAX))),
            // Text protocol: numbers arrive as text and are parsed by column type.
            (text(T::MYSQL_TYPE_LONG, "42"), DbVal::Int(42)),
            (text(T::MYSQL_TYPE_TINY, "-1"), DbVal::Int(-1)),
            (text(T::MYSQL_TYPE_LONGLONG, "9223372036854775807"), DbVal::Int(i64::MAX)),
            (text(T::MYSQL_TYPE_LONGLONG, "18446744073709551615"), DbVal::Str("18446744073709551615".into())),
            (text(T::MYSQL_TYPE_YEAR, "2026"), DbVal::Int(2026)),
            (text(T::MYSQL_TYPE_INT24, "x"), DbVal::Str("x".into())),
            (text(T::MYSQL_TYPE_DOUBLE, "2.5"), DbVal::Double(2.5)),
            (text(T::MYSQL_TYPE_NEWDECIMAL, "10.10"), DbVal::Double(10.1)),
            (text(T::MYSQL_TYPE_FLOAT, "nan?"), DbVal::Str("nan?".into())),
            (text(T::MYSQL_TYPE_VAR_STRING, "42"), DbVal::Str("42".into())),
            (my_val(V::Bytes(vec![0xff, b'a']), &blob), DbVal::Str("\u{fffd}a".into())),
        ];
        for (got, want) in cases {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn server_errors_are_statement_errors_others_connection_errors() {
        let e = my_fail(mysql::Error::MySqlError(mysql::MySqlError { state: "42S02".into(), message: "no table".into(), code: 1146 }));
        assert!(matches!(&e, DbError::Stmt(m) if m.contains("no table")), "{e:?}");
        assert!(my_fail(mysql::Error::IoError(std::io::Error::other("reset"))).is_conn());
    }

    fn refused() -> String {
        format!("mysql://u:p@127.0.0.1:{}/db", super::super::tests::closed_port())
    }

    #[test]
    fn tls_parameters_are_taken_before_connecting() {
        for q in ["?ssl=1", "?ssl=on&ssl_verify=0", "?ssl=true&ssl_ca=/nonexistent/ca.pem", "?ssl=1&ssl_ca=/x.pem&ssl_verify=false", "?ssl=0&ssl_ca=/x.pem"] {
            let e = MySqlDb::open(&format!("{}{q}", refused())).err().unwrap();
            assert!(e.is_conn() && e.to_string().contains("mysql connect"), "{q}: {e}");
        }
        assert!(matches!(MySqlDb::open("mysql://u@h/db?nosuchoption=1"), Err(DbError::Config(_))), "a driver parameter it doesn't know");
    }

    #[test]
    fn statements_are_built_before_connecting() {
        let db = MySqlDb { opts: mysql::Opts::from_url(&refused()).unwrap(), pool: Pool { idle: Mutex::new(Vec::new()), max: 8 } };
        let f: &[(&str, DbVal)] = &[("username", "a".into())];
        let set: &[(&str, DbVal)] = &[("expires", DbVal::Int(1))];
        for e in [
            db.query("bad;t", &[], f).unwrap_err(),
            db.insert("t", &["a b"], &[DbVal::Null]).unwrap_err(),
            db.update("t", &[("x-y", DbVal::Null)], set).unwrap_err(),
            db.delete("t`", f).unwrap_err(),
        ] {
            assert!(matches!(&e, DbError::Stmt(m) if m.contains("bad identifier")), "{e:?}");
        }
        for e in [
            db.query("t", &[], f).unwrap_err(),
            db.insert("t", &["a"], &[DbVal::Null]).unwrap_err(),
            db.update("t", f, set).unwrap_err(),
            db.delete("t", f).unwrap_err(),
            db.raw("SELECT 1").unwrap_err(),
        ] {
            assert!(e.is_conn(), "{e:?}");
        }
    }
}
