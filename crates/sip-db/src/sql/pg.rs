//! PostgreSQL (`postgres://`, Kamailio `db_postgres`), feature `postgres`.

use super::*;
use std::sync::Arc;

fn roots(ca: &str) -> Result<rustls::RootCertStore, String> {
    use rustls::pki_types::pem::PemObject;
    let mut r = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_file_iter(ca).map_err(|e| format!("{ca}: {e}"))? {
        r.add(c.map_err(|e| format!("{ca}: {e}"))?).map_err(|e| format!("{ca}: {e}"))?;
    }
    Ok(r)
}

/// `sslmode=require`: encrypt, don't verify the server (libpq semantics).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct PgDb {
    url: String,
    tls: Option<postgres_rustls::MakeTlsConnector>,
    pool: Pool<postgres::Client>,
}

/// A parameter sent in text format, so Postgres converts it to whatever
/// the column is (int4, bigint, timestamp, bool…).
#[derive(Debug)]
struct PgText(Option<String>);

impl postgres::types::ToSql for PgText {
    fn to_sql(&self, _ty: &postgres::types::Type, out: &mut bytes::BytesMut) -> Result<postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match &self.0 {
            None => Ok(postgres::types::IsNull::Yes),
            Some(s) => {
                out.extend_from_slice(s.as_bytes());
                Ok(postgres::types::IsNull::No)
            }
        }
    }
    fn accepts(_ty: &postgres::types::Type) -> bool {
        true
    }
    fn encode_format(&self, _ty: &postgres::types::Type) -> postgres::types::Format {
        postgres::types::Format::Text
    }
    postgres::types::to_sql_checked!();
}

fn pg_param(v: &DbVal) -> PgText {
    PgText(match v {
        DbVal::Null => None,
        DbVal::Int(i) => Some(i.to_string()),
        DbVal::Double(d) => Some(d.to_string()),
        DbVal::Str(s) => Some(s.clone()),
    })
}

/// Any result column, decoded from Postgres' binary format by type.
struct PgAny(DbVal);

fn be<const N: usize>(raw: &[u8]) -> Result<[u8; N], Box<dyn std::error::Error + Sync + Send>> {
    raw.try_into().map_err(|_| "bad length".into())
}

/// Days since 1970-01-01 → (y, m, d) (civil calendar).
#[allow(clippy::arithmetic_side_effects, reason = "callers pass |days| < 2^37 (an i64 of µs or an i32 of days), so no step comes near i64::MAX")]
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    // In range by construction: day 1..=31, month 1..=12.
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

impl<'a> postgres::types::FromSql<'a> for PgAny {
    fn from_sql(ty: &postgres::types::Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        use postgres::types::Type as T;
        const PG_EPOCH_DAYS: i64 = 10_957; // 2000-01-01 − 1970-01-01
        Ok(PgAny(match *ty {
            T::INT2 => DbVal::Int(i64::from(i16::from_be_bytes(be(raw)?))),
            T::INT4 | T::OID => DbVal::Int(i64::from(i32::from_be_bytes(be(raw)?))),
            T::INT8 => DbVal::Int(i64::from_be_bytes(be(raw)?)),
            T::FLOAT4 => DbVal::Double(f64::from(f32::from_be_bytes(be(raw)?))),
            T::FLOAT8 => DbVal::Double(f64::from_be_bytes(be(raw)?)),
            T::BOOL => DbVal::Int(i64::from(raw.first() == Some(&1))),
            T::TIMESTAMP | T::TIMESTAMPTZ => {
                let us = i64::from_be_bytes(be(raw)?);
                let secs = us.div_euclid(1_000_000).saturating_add(PG_EPOCH_DAYS * 86_400);
                let (y, m, d) = civil(secs.div_euclid(86_400));
                let t = secs.rem_euclid(86_400);
                DbVal::Str(format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", t / 3600, t / 60 % 60, t % 60))
            }
            T::DATE => {
                let (y, m, d) = civil(i64::from(i32::from_be_bytes(be(raw)?)).saturating_add(PG_EPOCH_DAYS));
                DbVal::Str(format!("{y:04}-{m:02}-{d:02}"))
            }
            _ => DbVal::Str(String::from_utf8_lossy(raw).into_owned()),
        }))
    }
    fn from_sql_null(_ty: &postgres::types::Type) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(PgAny(DbVal::Null))
    }
    fn accepts(_ty: &postgres::types::Type) -> bool {
        true
    }
}

fn pg_fail(c: &postgres::Client, e: postgres::Error) -> DbError {
    if c.is_closed() || e.as_db_error().is_none() && e.to_string().contains("connection") {
        DbError::Conn(e.to_string())
    } else {
        DbError::Stmt(e.as_db_error().map_or_else(|| e.to_string(), |d| d.message().to_string()))
    }
}

impl PgDb {
    pub fn open(url: &str) -> Result<Self, DbError> {
        let (mut url, p) = take_params(url, &["sslrootcert", "sslmode"]);
        let mode = p.get("sslmode").map(String::as_str).unwrap_or("disable");
        let tls = match mode {
            "disable" | "allow" | "prefer" => None,
            "require" | "verify-ca" | "verify-full" => {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let b = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .map_err(|e| DbError::Config(e.to_string()))?;
                let cfg = if mode == "require" {
                    b.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
                } else {
                    let ca = p.get("sslrootcert").ok_or_else(|| DbError::Config("postgres: sslmode=verify-* needs sslrootcert=<CA file>".into()))?;
                    b.with_root_certificates(roots(ca).map_err(DbError::Config)?).with_no_client_auth()
                };
                Some(postgres_rustls::MakeTlsConnector::new(tokio_rustls::TlsConnector::from(Arc::new(cfg))))
            }
            m => return Err(DbError::Config(format!("postgres: unknown sslmode {m:?}"))),
        };
        if tls.is_some() {
            // tokio-postgres itself only knows disable/prefer/require.
            url.push_str(if url.contains('?') { "&sslmode=require" } else { "?sslmode=require" });
        }
        let me = Self { url, tls, pool: Pool::new_empty() };
        let first = me.connect()?;
        me.pool.put(first);
        Ok(me)
    }

    fn connect(&self) -> Result<postgres::Client, DbError> {
        let r = match &self.tls {
            Some(t) => postgres::Client::connect(&self.url, t.clone()),
            None => postgres::Client::connect(&self.url, postgres::NoTls),
        };
        r.map_err(|e| DbError::Conn(format!("postgres connect: {e}")))
    }

    fn select(&self, sql: &str, params: &[DbVal]) -> Result<Rows, DbError> {
        let p: Vec<PgText> = params.iter().map(pg_param).collect();
        self.pool.run(
            || self.connect(),
            |c| {
                let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = p.iter().map(|x| x as &(dyn postgres::types::ToSql + Sync)).collect();
                let st = c.prepare(sql).map_err(|e| pg_fail(c, e))?;
                let rows = c.query(&st, &refs).map_err(|e| pg_fail(c, e))?;
                let cols: Vec<String> = st.columns().iter().map(|c| c.name().to_string()).collect();
                let rows = rows.iter().map(|r| (0..cols.len()).map(|i| r.try_get::<_, PgAny>(i).map_or(DbVal::Null, |v| v.0)).collect()).collect();
                Ok(Rows { cols: cols.clone(), rows })
            },
        )
    }

    fn exec(&self, sql: &str, params: &[DbVal]) -> Result<u64, DbError> {
        let p: Vec<PgText> = params.iter().map(pg_param).collect();
        self.pool.run(
            || self.connect(),
            |c| {
                let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = p.iter().map(|x| x as &(dyn postgres::types::ToSql + Sync)).collect();
                c.execute(sql, &refs).map_err(|e| pg_fail(c, e))
            },
        )
    }
}

impl DbConn for PgDb {
    fn query(&self, table: &str, cols: &[&str], filter: Filter<'_>) -> Result<Rows, DbError> {
        let (sql, p) = Dialect::Pg.select(table, cols, filter).map_err(DbError::Stmt)?;
        self.select(&sql, &p)
    }
    fn insert(&self, table: &str, cols: &[&str], vals: &[DbVal]) -> Result<(), DbError> {
        let (sql, p) = Dialect::Pg.insert(table, cols, vals).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(|_| ())
    }
    fn update(&self, table: &str, filter: Filter<'_>, set: &[(&str, DbVal)]) -> Result<usize, DbError> {
        let (sql, p) = Dialect::Pg.update(table, filter, set).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(crate::count_usize)
    }
    fn delete(&self, table: &str, filter: Filter<'_>) -> Result<usize, DbError> {
        let (sql, p) = Dialect::Pg.delete(table, filter).map_err(DbError::Stmt)?;
        self.exec(&sql, &p).map(crate::count_usize)
    }
    fn raw(&self, sql: &str) -> Result<Rows, DbError> {
        if is_select(sql) {
            return self.select(sql, &[]);
        }
        let n = self.pool.run(|| self.connect(), |c| c.execute(sql, &[]).map_err(|e| pg_fail(c, e)))?;
        Ok(Rows { cols: vec!["affected".into()], rows: vec![vec![DbVal::Int(crate::count_i64(n))]] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(10_957), (2000, 1, 1));
        assert_eq!(civil(20_454), (2026, 1, 1));
    }

    #[test]
    fn tls_options_are_checked_before_connecting() {
        let err = |url: &str| PgDb::open(url).err().map(|e| (e.is_conn(), e.to_string())).unwrap();
        let (conn, m) = err("postgres://u@127.0.0.1:1/db?sslmode=bogus");
        assert!(!conn && m.contains("unknown sslmode \"bogus\""), "{m}");
        for mode in ["verify-ca", "verify-full"] {
            let (conn, m) = err(&format!("postgres://u@127.0.0.1:1/db?sslmode={mode}"));
            assert!(!conn && m.contains("needs sslrootcert"), "{m}");
        }
        let (conn, m) = err("postgres://u@127.0.0.1:1/db?sslmode=verify-full&sslrootcert=/nonexistent/ca.pem");
        assert!(!conn && m.contains("/nonexistent/ca.pem"), "{m}");
    }

    #[test]
    fn parameters_are_sent_as_text() {
        let cases = [(DbVal::Null, None), (DbVal::Int(-5), Some("-5")), (DbVal::Double(0.5), Some("0.5")), (DbVal::Str("x'y".into()), Some("x'y"))];
        for (v, want) in cases {
            assert_eq!(pg_param(&v).0.as_deref(), want, "{v:?}");
        }
    }

    #[test]
    fn binary_results_decode_by_type() {
        use postgres::types::{FromSql, Type};
        let dec = |ty: &Type, raw: &[u8]| PgAny::from_sql(ty, raw).map(|v| v.0).map_err(|e| e.to_string());
        let ts = |us: i64| dec(&Type::TIMESTAMP, &us.to_be_bytes());
        let cases: Vec<(Result<DbVal, String>, DbVal)> = vec![
            (dec(&Type::INT2, &(-2i16).to_be_bytes()), DbVal::Int(-2)),
            (dec(&Type::INT4, &7i32.to_be_bytes()), DbVal::Int(7)),
            (dec(&Type::INT8, &i64::MIN.to_be_bytes()), DbVal::Int(i64::MIN)),
            (dec(&Type::FLOAT4, &1.5f32.to_be_bytes()), DbVal::Double(1.5)),
            (dec(&Type::FLOAT8, &(-0.25f64).to_be_bytes()), DbVal::Double(-0.25)),
            (dec(&Type::BOOL, &[1]), DbVal::Int(1)),
            (dec(&Type::BOOL, &[0]), DbVal::Int(0)),
            (dec(&Type::TEXT, "ünï".as_bytes()), DbVal::Str("ünï".into())),
            (ts(0), DbVal::Str("2000-01-01 00:00:00".into())),
            (ts(-1), DbVal::Str("1999-12-31 23:59:59".into())),
            (ts(86_399_999_999), DbVal::Str("2000-01-01 23:59:59".into())),
            (dec(&Type::DATE, &(-1i32).to_be_bytes()), DbVal::Str("1999-12-31".into())),
            (dec(&Type::DATE, &59i32.to_be_bytes()), DbVal::Str("2000-02-29".into())),
        ];
        for (got, want) in cases {
            assert_eq!(got, Ok(want));
        }
        assert!(dec(&Type::INT4, &[0, 1]).is_err(), "a wrong length is an error");
        assert_eq!(PgAny::from_sql_null(&Type::INT4).unwrap().0, DbVal::Null);
    }

    #[test]
    fn civil_dates_around_leap_years() {
        let cases = [
            (-1, (1969, 12, 31)),
            (59, (1970, 3, 1)),
            (11_016, (2000, 2, 29)),
            (11_017, (2000, 3, 1)),
            (-25_509, (1900, 2, 28)),
            (-25_508, (1900, 3, 1)),
            (47_540, (2100, 2, 28)),
        ];
        for (days, want) in cases {
            assert_eq!(civil(days), want, "{days}");
        }
    }

    fn refused(query: &str) -> String {
        format!("postgres://u@127.0.0.1:{}/db{query}", super::super::tests::closed_port())
    }

    #[test]
    fn tls_modes_build_a_connector_then_connect() {
        for q in ["", "?sslmode=disable", "?sslmode=allow", "?sslmode=prefer", "?sslmode=require", "?connect_timeout=5&sslmode=require"] {
            let e = PgDb::open(&refused(q)).err().unwrap();
            assert!(e.is_conn() && e.to_string().contains("postgres connect"), "{q}: {e}");
        }
    }

    #[test]
    fn require_mode_accepts_any_server_certificate() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::internal::msgs::codec::Codec;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = NoVerify(provider);
        let cert = CertificateDer::from(vec![0u8; 4]);
        let name = ServerName::try_from("db.example").unwrap();
        assert!(v.verify_server_cert(&cert, &[], &name, &[], UnixTime::now()).is_ok(), "no chain or name check");
        // Signatures are still checked (here: a certificate that doesn't parse).
        let dss = rustls::DigitallySignedStruct::read_bytes(&[0x04, 0x03, 0x00, 0x01, 0xaa]).unwrap();
        assert!(v.verify_tls12_signature(b"msg", &cert, &dss).is_err());
        assert!(v.verify_tls13_signature(b"msg", &cert, &dss).is_err());
        assert!(v.supported_verify_schemes().contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn statements_are_built_before_connecting() {
        let db = PgDb { url: refused(""), tls: None, pool: Pool::new_empty() };
        let f: &[(&str, DbVal)] = &[("username", "a".into())];
        let set: &[(&str, DbVal)] = &[("expires", DbVal::Int(1))];
        for e in [
            db.query("bad;t", &[], f).unwrap_err(),
            db.insert("t", &["a b"], &[DbVal::Null]).unwrap_err(),
            db.update("t", &[("x-y", DbVal::Null)], set).unwrap_err(),
            db.delete("t\"", f).unwrap_err(),
        ] {
            assert!(matches!(&e, DbError::Stmt(m) if m.contains("bad identifier")), "{e:?}");
        }
        for e in [
            db.query("t", &[], f).unwrap_err(),
            db.insert("t", &["a"], &[DbVal::Null]).unwrap_err(),
            db.update("t", f, set).unwrap_err(),
            db.delete("t", f).unwrap_err(),
            db.raw("SELECT 1").unwrap_err(),
            db.raw("DELETE FROM t").unwrap_err(),
        ] {
            assert!(e.is_conn(), "{e:?}");
        }
    }
}
